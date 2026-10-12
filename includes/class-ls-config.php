<?php
/**
 * Configuration reader.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;


class LS_SSO_Config {

	protected static $peers = null;

	/**
	 * Option names.
	 */
	const OPTIONS = array(
		'LS_SSO_SECRET'              => 'ls_sso_secret',
		'LS_SSO_PEERS'               => 'ls_sso_peers',
		'LS_SSO_STORE'               => 'ls_sso_store',
		'LS_SSO_ROLE_CLAIM'          => 'ls_sso_role_claim',
		'LS_SSO_META_KEYS'           => 'ls_sso_meta_keys',
		'LS_SSO_BLOCK_SILENT_ROLES'  => 'ls_sso_block_silent_roles',
		'LS_SSO_SILENT_MODE'         => 'ls_sso_silent_mode',
	);

	/**
	 * Constants.
	 *
	 * @param string $constant
	 * @param string $fallback
	 * @return string
	 */
	protected static function get( $constant, $fallback = '' ) {
		if ( defined( $constant ) ) {
			return (string) constant( $constant );
		}

		$option = isset( self::OPTIONS[ $constant ] ) ? self::OPTIONS[ $constant ] : '';
		if ( '' === $option ) {
			return $fallback;
		}

		$stored = get_option( $option, null );

		return ( null === $stored || '' === $stored ) ? $fallback : (string) $stored;
	}

	public static function source_of( $constant ) {
		if ( defined( $constant ) ) {
			return 'constant';
		}
		$option = isset( self::OPTIONS[ $constant ] ) ? self::OPTIONS[ $constant ] : '';
		if ( '' !== $option ) {
			$stored = get_option( $option, null );
			if ( null !== $stored && '' !== $stored ) {
				return 'option';
			}
		}
		return 'default';
	}

	/**
	 * Options table.
	 *
	 * @param string $constant
	 * @param string $value
	 * @return bool True
	 */
	public static function save( $constant, $value ) {
		if ( defined( $constant ) || ! isset( self::OPTIONS[ $constant ] ) ) {
			return false;
		}

		$option      = self::OPTIONS[ $constant ];
		$existing    = get_option( $option, false );
		self::$peers = null; 

		if ( '' === $value ) {
			delete_option( $option );
			return false !== $existing;
		}

		if ( (string) $existing === $value ) {
			return true;
		}

		if ( false === $existing ) {
			return add_option( $option, $value, '', 'no' );
		}
		return update_option( $option, $value, false );
	}

	/**
	 * A fingerprint of the shared secret.
	 *
	 * @return string Empty when no secret is set.
	 */
	public static function secret_fingerprint() {
		$secret = self::secret();
		return '' === $secret ? '' : substr( hash( 'sha256', $secret ), 0, 8 );
	}

	/**
	 * The shared HMAC secret.
	 *
	 * @return string Empty string when unset.
	 */
	public static function secret() {
		return self::get( 'LS_SSO_SECRET' );
	}

	public static function peers() {
		if ( null !== self::$peers ) {
			return self::$peers;
		}

		$raw = self::get( 'LS_SSO_PEERS' );
		$out = array();

		foreach ( explode( ',', $raw ) as $candidate ) {
			$origin = self::normalize_origin( $candidate );
			if ( '' !== $origin && $origin !== self::self_origin() ) {
				$out[] = $origin;
			}
		}

		self::$peers = array_values( array_unique( $out ) );
		return self::$peers;
	}

	/**
	 * Site origin that runs WooCommerce.
	 *
	 * @return string
	 */
	public static function store_origin() {
		return self::normalize_origin( self::get( 'LS_SSO_STORE' ) );
	}

	/**
	 * Check whether the site is the store.
	 *
	 * @return bool
	 */
	public static function is_store() {
		return self::store_origin() === self::self_origin() && class_exists( 'WooCommerce' );
	}

	public static function self_origin() {
		return self::normalize_origin( home_url( '/' ) );
	}

	/**
	 * Origins.
	 *
	 * @return array<int,string>
	 */
	public static function all_origins() {
		$all = self::peers();
		$all[] = self::self_origin();
		$store = self::store_origin();
		if ( '' !== $store ) {
			$all[] = $store;
		}
		return array_values( array_unique( array_filter( $all ) ) );
	}

	public static function role_claim() {
		return self::get( 'LS_SSO_ROLE_CLAIM' );
	}

	public static function meta_keys() {
		$raw = self::get( 'LS_SSO_META_KEYS' );
		$out = array();
		foreach ( explode( ',', $raw ) as $key ) {
			$key = sanitize_key( trim( $key ) );
			if ( '' !== $key ) {
				$out[] = $key;
			}
		}
		return array_values( array_unique( $out ) );
	}

	public static function silent_enabled() {
		return defined( 'LS_SSO_SILENT' ) ? (bool) LS_SSO_SILENT : true;
	}

	public static function silent_mode() {
		$mode = self::get( 'LS_SSO_SILENT_MODE', 'js' );
		return in_array( $mode, array( 'js', 'redirect' ), true ) ? $mode : 'js';
	}

	public static function blocked_silent_roles() {
		$raw = self::get( 'LS_SSO_BLOCK_SILENT_ROLES', 'administrator' );

		$roles = array();
		foreach ( explode( ',', $raw ) as $role ) {
			$role = sanitize_key( trim( $role ) );
			if ( '' !== $role ) {
				$roles[] = $role;
			}
		}

		return (array) apply_filters( 'ls_sso_block_silent_roles', array_values( array_unique( $roles ) ) );
	}

	public static function debug() {
		return defined( 'LS_SSO_DEBUG' ) && LS_SSO_DEBUG;
	}

	public static function is_configured() {
		return strlen( self::secret() ) >= 32 && ! empty( self::peers() );
	}

	public static function normalize_origin( $url ) {
		$url = trim( (string) $url );
		if ( '' === $url ) {
			return '';
		}

		$parts = wp_parse_url( $url );
		if ( empty( $parts['host'] ) ) {
			return '';
		}

		$scheme = isset( $parts['scheme'] ) ? strtolower( $parts['scheme'] ) : 'https';
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			return '';
		}

		$origin = $scheme . '://' . strtolower( $parts['host'] );
		if ( ! empty( $parts['port'] ) ) {
			$origin .= ':' . (int) $parts['port'];
		}
		return $origin;
	}

	public static function is_known_origin( $url ) {
		$origin = self::normalize_origin( $url );
		return '' !== $origin && in_array( $origin, self::all_origins(), true );
	}
}
