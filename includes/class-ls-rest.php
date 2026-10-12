<?php
/**
 * Inbound REST endpoints.
 *
 *   POST /usermeta
 *   GET  /orders 
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;


class LS_SSO_Rest {

	const NAMESPACE_V1 = 'cross-site-sso-for-openid-connect/v1';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_routes' ) );
		add_action( 'ls_sso_gc', array( 'LS_SSO_Signer', 'gc' ) );

		if ( ! wp_next_scheduled( 'ls_sso_gc' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'ls_sso_gc' );
		}
	}

	/**
	 * Register the routes.
	 *
	 * @return void
	 */
	public static function register_routes() {

		register_rest_route(
			self::NAMESPACE_V1,
			'/usermeta',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'receive_usermeta' ),
				'permission_callback' => array( 'LS_SSO_Signer', 'verify' ),
				'args'                => array(
					'subject' => array(
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
						'validate_callback' => function ( $value ) {
							return is_string( $value ) && '' !== trim( $value ) && strlen( $value ) <= 255;
						},
					),
					'meta'    => array(
						'required' => true,
						'type'     => 'object',
					),
				),
			)
		);

		// The order endpoint exists only where WooCommerce does. 
		if ( LS_SSO_Config::is_store() ) {
			register_rest_route(
				self::NAMESPACE_V1,
				'/orders',
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( __CLASS__, 'serve_orders' ),
					'permission_callback' => array( 'LS_SSO_Signer', 'verify' ),
					'args'                => array(
						'subject' => array(
							'required'          => true,
							'type'              => 'string',
							'sanitize_callback' => 'sanitize_text_field',
						),
						'limit'   => array(
							'required'          => false,
							'type'              => 'integer',
							'default'           => 10,
							'sanitize_callback' => 'absint',
							'validate_callback' => function ( $value ) {
								return $value >= 1 && $value <= 50;
							},
						),
					),
				)
			);
		}
	}

	/**
	 * Accept allowlisted user meta from a peer site.
	 *
	 * @param WP_REST_Request $request Inbound request.
	 * @return WP_REST_Response
	 */
	public static function receive_usermeta( WP_REST_Request $request ) {
		$subject = (string) $request->get_param( 'subject' );
		$meta    = (array) $request->get_param( 'meta' );

		$user = LS_SSO_Profile::user_by_subject( $subject );
		if ( ! $user ) {
			return new WP_REST_Response( array( 'ok' => true, 'applied' => 0, 'reason' => 'unknown_subject' ), 200 );
		}

		$allowed = LS_SSO_Config::meta_keys();
		$applied = 0;

		LS_SSO_Profile::without_broadcast(
			function () use ( $meta, $allowed, $user, &$applied ) {
				foreach ( $meta as $key => $value ) {
					$key = sanitize_key( (string) $key );

					if ( ! in_array( $key, $allowed, true ) ) {
						continue;
					}
					if ( ! is_scalar( $value ) ) {
						continue;
					}

					update_user_meta( $user->ID, $key, sanitize_text_field( (string) $value ) );
					++$applied;
				}
			}
		);

		LS_SSO_Logger::log(
			'usermeta_received',
			array(
				'direction' => 'inbound',
				'peer'      => (string) $request->get_header( LS_SSO_Signer::HDR_ORIGIN ),
				'route'     => $request->get_route(),
				'user_id'   => $user->ID,
				'status'    => 'success',
				'detail'    => sprintf( '%d key(s) applied', $applied ),
			)
		);

		return new WP_REST_Response( array( 'ok' => true, 'applied' => $applied ), 200 );
	}

	/**
	 * Serve a customer's orders to a peer site.
	 *
	 * @param WP_REST_Request $request Inbound request.
	 * @return WP_REST_Response
	 */
	public static function serve_orders( WP_REST_Request $request ) {
		$subject = (string) $request->get_param( 'subject' );
		$limit   = (int) $request->get_param( 'limit' );

		$user = LS_SSO_Profile::user_by_subject( $subject );
		if ( ! $user ) {
			return new WP_REST_Response( array( 'orders' => array() ), 200 );
		}

		$orders = wc_get_orders(
			array(
				'customer_id' => $user->ID,
				'limit'       => $limit,
				'orderby'     => 'date',
				'order'       => 'DESC',
				'type'        => 'shop_order',
			)
		);

		$out = array();
		foreach ( $orders as $order ) {
			if ( ! is_a( $order, 'WC_Order' ) ) {
				continue;
			}
			$created = $order->get_date_created();

			$out[] = array(
				'number'   => (string) $order->get_order_number(),
				'date'     => $created ? $created->date( DATE_ATOM ) : '',
				'status'   => (string) $order->get_status(),
				'status_label' => (string) wc_get_order_status_name( $order->get_status() ),

				'total_html' => wp_strip_all_tags( html_entity_decode( wc_price( $order->get_total(), array( 'currency' => $order->get_currency() ) ) ) ),
				'view_url' => (string) $order->get_view_order_url(),
			);
		}

		LS_SSO_Logger::log(
			'orders_served',
			array(
				'direction' => 'inbound',
				'peer'      => (string) $request->get_header( LS_SSO_Signer::HDR_ORIGIN ),
				'route'     => $request->get_route(),
				'user_id'   => $user->ID,
				'status'    => 'success',
				'detail'    => sprintf( '%d order(s)', count( $out ) ),
			)
		);

		return new WP_REST_Response( array( 'orders' => $out ), 200 );
	}
}
