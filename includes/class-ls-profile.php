<?php
/**
 * Mapping identity provider.
 *
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

class LS_SSO_Profile {


	const SUBJECT_OPTION = 'openid-connect-generic-subject-identity';
    
	protected static $applying_remote = false;

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'openid-connect-generic-user-create', array( __CLASS__, 'on_profile' ), 10, 2 );
		add_action( 'openid-connect-generic-update-user-using-current-claim', array( __CLASS__, 'on_profile' ), 10, 2 );

		if ( LS_SSO_Config::is_store() ) {
			add_action( 'woocommerce_save_account_details', array( __CLASS__, 'on_profile_saved' ), 10, 1 );
			add_action( 'woocommerce_customer_save_address', array( __CLASS__, 'on_profile_saved' ), 10, 1 );
			add_action( 'woocommerce_checkout_update_customer', array( __CLASS__, 'on_checkout_customer' ), 10, 2 );
		}
	}

	public static function is_applying_remote() {
		return self::$applying_remote;
	}

	public static function without_broadcast( callable $callback ) {
		$previous              = self::$applying_remote;
		self::$applying_remote = true;
		try {
			return $callback();
		} finally {
			self::$applying_remote = $previous;
		}
	}

	public static function on_profile( $user, $profile ) {
		if ( ! $user instanceof WP_User || ! is_array( $profile ) ) {
			return;
		}

		self::without_broadcast(
			function () use ( $user, $profile ) {
				self::apply_roles( $user, $profile );
				if ( LS_SSO_Config::is_store() ) {
					self::apply_woocommerce_profile( $user, $profile );
				}
				self::apply_allowlisted_meta( $user, $profile );
			}
		);

		do_action( 'ls_sso_profile_applied', $user, $profile );
	}


	protected static function apply_roles( WP_User $user, array $profile ) {
        
		if ( user_can( $user, 'manage_options' ) ) {
			return;
		}

		$role_key = LS_SSO_Config::role_claim();

		$incoming = ( '' !== $role_key && isset( $profile[ $role_key ] ) )
			? (array) $profile[ $role_key ]
			: array();

		$roles = apply_filters( 'ls_sso_map_roles', array(), $incoming, $user );

		$roles = array_values(
			array_filter(
				array_map( 'sanitize_key', (array) $roles ),
				function ( $role ) {
					return 'administrator' !== $role && ! empty( get_role( $role ) );
				}
			)
		);

		if ( empty( $roles ) ) {
			return;
		}

		$user->set_role( array_shift( $roles ) );
		foreach ( $roles as $extra ) {
			$user->add_role( $extra );
		}
	}

	protected static function apply_woocommerce_profile( WP_User $user, array $profile ) {
		$address = isset( $profile['address'] ) && is_array( $profile['address'] ) ? $profile['address'] : array();

		$map = array(
			'billing_first_name' => $profile['given_name'] ?? '',
			'billing_last_name'  => $profile['family_name'] ?? '',
			'billing_email'      => $profile['email'] ?? '',
			'billing_phone'      => $profile['phone_number'] ?? '',
			'billing_address_1'  => $address['street_address'] ?? '',
			'billing_city'       => $address['locality'] ?? '',
			'billing_state'      => $address['region'] ?? '',
			'billing_postcode'   => $address['postal_code'] ?? '',
			'billing_country'    => $address['country'] ?? '',
		);

		foreach ( $map as $key => $value ) {
			$value = trim( (string) $value );
			if ( '' === $value ) {
				continue;
			}

			$value = ( 'billing_email' === $key )
				? sanitize_email( $value )
				: sanitize_text_field( $value );

			if ( '' === $value ) {
				continue;
			}

			$existing = get_user_meta( $user->ID, $key, true );
			if ( '' === $existing ) {
				update_user_meta( $user->ID, $key, $value );
			}

			$shipping_key = str_replace( 'billing_', 'shipping_', $key );
			if ( 'shipping_email' === $shipping_key ) {
				continue; // WooCommerce has no shipping_email field.
			}
			if ( '' === get_user_meta( $user->ID, $shipping_key, true ) ) {
				update_user_meta( $user->ID, $shipping_key, $value );
			}
		}
	}


	protected static function apply_allowlisted_meta( WP_User $user, array $profile ) {
		foreach ( LS_SSO_Config::meta_keys() as $key ) {
			if ( ! isset( $profile[ $key ] ) ) {
				continue;
			}
			$value = $profile[ $key ];
			$value = is_scalar( $value ) ? sanitize_text_field( (string) $value ) : wp_json_encode( $value );
			update_user_meta( $user->ID, $key, $value );
		}
	}


	public static function on_profile_saved( $user_id ) {
		$user_id = (int) $user_id;
		if ( ! $user_id || self::is_applying_remote() ) {
			return;
		}

		$keys = LS_SSO_Config::meta_keys();
		if ( empty( $keys ) ) {
			return;
		}

		$subject = self::subject_for( $user_id );
		if ( '' === $subject ) {
			return; 
		}

		$meta = array();
		foreach ( $keys as $key ) {
			$meta[ $key ] = (string) get_user_meta( $user_id, $key, true );
		}

		LS_SSO_Http::queue(
			'/cross-site-sso-for-openid-connect/v1/usermeta',
			array(
				'subject' => $subject,
				'meta'    => $meta,
			)
		);
	}

	public static function on_checkout_customer( $customer, $data ) {
		unset( $data );
		if ( is_object( $customer ) && method_exists( $customer, 'get_id' ) && $customer->get_id() ) {
			self::on_profile_saved( $customer->get_id() );
		}
	}


	public static function subject_for( $user_id ) {
		$subject = get_user_option( self::SUBJECT_OPTION, $user_id );
		return is_string( $subject ) ? $subject : '';
	}

	public static function user_by_subject( $subject ) {
		global $wpdb;

		$subject = (string) $subject;
		if ( '' === $subject ) {
			return null;
		}

		$query = new WP_User_Query(
			array(
				'number'     => 1,
				'fields'     => 'ID',
				// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query
				'meta_query' => array(
					'relation' => 'OR',
					array(
						'key'   => self::SUBJECT_OPTION,
						'value' => $subject,
					),
					array(
						'key'   => $wpdb->get_blog_prefix() . self::SUBJECT_OPTION,
						'value' => $subject,
					),
				),
			)
		);

		$ids = $query->get_results();
		if ( empty( $ids ) ) {
			return null;
		}

		$user = get_user_by( 'id', (int) $ids[0] );
		return $user instanceof WP_User ? $user : null;
	}
}
