<?php
/**
 * Request signing and verification for site-to-site calls.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * HMAC signer/verifier for site-to-site requests.
 */
class LS_SSO_Signer {

	const HDR_TIMESTAMP = 'X-LS-Timestamp';
	const HDR_NONCE     = 'X-LS-Nonce';
	const HDR_SIGNATURE = 'X-LS-Signature';
	const HDR_ORIGIN    = 'X-LS-Origin';
	const MAX_SKEW = 300;
	const NONCE_TTL = 900;
	const NONCE_PREFIX = 'ls_sso_nonce_';

	/**
	 * Build the canonical string that gets signed.
	 *
	 * @param string $timestamp 
	 * @param string $nonce     
	 * @param string $route     
	 * @param string $body      
	 * @return string
	 */
	protected static function canonical( $timestamp, $nonce, $route, $query, $body ) {
		return implode(
			"\n",
			array(
				'LSSSO2',
				$timestamp,
				$nonce,
				$route,
				self::canonical_query( $query ),
				hash( 'sha256', (string) $body ),
			)
		);
	}

	/**
	 * Canonical form of a request's query parameters.
	 *
	 * @param array $query Query parameters.
	 * @return string
	 */
	protected static function canonical_query( $query ) {
		if ( ! is_array( $query ) ) {
			return '';
		}

		unset( $query['rest_route'] );
		ksort( $query );

		$pairs = array();
		foreach ( $query as $key => $value ) {
			if ( is_array( $value ) ) {
				$value = wp_json_encode( $value );
			}
			$pairs[] = rawurlencode( (string) $key ) . '=' . rawurlencode( (string) $value );
		}

		return implode( '&', $pairs );
	}

	/**
	 * Produce the signature headers for an outbound request.
	 *
	 * @param string $route 
	 * @param string $body  
	 * @param array  $query
	 * @return array<string,string>
	 */
	public static function headers( $route, $body = '', $query = array() ) {
		$timestamp = (string) time();
		$nonce     = bin2hex( random_bytes( 16 ) );

		$signature = hash_hmac(
			'sha256',
			self::canonical( $timestamp, $nonce, $route, $query, $body ),
			LS_SSO_Config::secret()
		);

		return array(
			self::HDR_TIMESTAMP => $timestamp,
			self::HDR_NONCE     => $nonce,
			self::HDR_SIGNATURE => $signature,
			self::HDR_ORIGIN    => LS_SSO_Config::self_origin(),
			'Content-Type'      => 'application/json; charset=utf-8',
			'Accept'            => 'application/json',
		);
	}

	/**
	 * Verify an inbound REST request.
	 *
	 * @param WP_REST_Request $request Inbound request.
	 * @return true|WP_Error
	 */
	public static function verify( WP_REST_Request $request ) {

		if ( ! LS_SSO_Config::is_configured() ) {
			return new WP_Error( 'ls_sso_unconfigured', 'Plugin is not configured.', array( 'status' => 503 ) );
		}

		$timestamp = (string) $request->get_header( self::HDR_TIMESTAMP );
		$nonce     = (string) $request->get_header( self::HDR_NONCE );
		$signature = (string) $request->get_header( self::HDR_SIGNATURE );
		$origin    = (string) $request->get_header( self::HDR_ORIGIN );

		if ( '' === $timestamp || '' === $nonce || '' === $signature ) {
			return self::deny( 'missing_headers' );
		}

		if ( ! preg_match( '/\A[a-f0-9]{32}\z/', $nonce ) ) {
			return self::deny( 'bad_nonce_format' );
		}

		if ( ! LS_SSO_Config::is_known_origin( $origin ) ) {
			return self::deny( 'unknown_origin' );
		}

		$skew = abs( time() - (int) $timestamp );
		if ( $skew > self::MAX_SKEW ) {
			return self::deny( 'stale_timestamp', array( 'skew' => $skew ) );
		}

		$expected = hash_hmac(
			'sha256',
			self::canonical(
				$timestamp,
				$nonce,
				$request->get_route(),
				$request->get_query_params(),
				$request->get_body()
			),
			LS_SSO_Config::secret()
		);

		if ( ! hash_equals( $expected, $signature ) ) {
			return self::deny( 'bad_signature' );
		}

		if ( ! self::consume_nonce( $nonce ) ) {
			return self::deny( 'replayed_nonce' );
		}

		return true;
	}

	protected static function consume_nonce( $nonce ) {
		$key = self::NONCE_PREFIX . $nonce;
		$reserved = add_option( $key, time() + self::NONCE_TTL, '', 'no' );

		if ( $reserved ) {
			if ( 0 === wp_rand( 0, 50 ) ) {
				self::gc();
			}
		}

		return (bool) $reserved;
	}

	/**
	 * Delete expired.
	 *
	 * @return int Rows removed.
	 */
	public static function gc() {
		global $wpdb;

		$now  = time();
		$like = $wpdb->esc_like( self::NONCE_PREFIX ) . '%';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s LIMIT 500",
				$like
			)
		);

		$removed = 0;
		foreach ( (array) $rows as $row ) {
			if ( (int) $row->option_value < $now ) {
				delete_option( $row->option_name );
				++$removed;
			}
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		return $removed;
	}

	/**
	 * Build a uniform denial. The client is told nothing beyond "no".
	 *
	 * @param string $reason  
	 * @param array  $context 
	 * @return WP_Error
	 */
	protected static function deny( $reason, $context = array() ) {
		ls_sso_log( 'request denied: ' . $reason, $context );
		LS_SSO_Logger::log(
			'request_denied',
			array(
				'direction' => 'inbound',
				'status'    => 'failure',
				'detail'    => $reason,
			)
		);
		return new WP_Error(
			'ls_sso_forbidden',
			'Request rejected.',
			array( 'status' => 403 )
		);
	}

	public static function sign_ticket( array $token_data ) {
		$token_data['ts'] = time();
		ksort( $token_data );

		$token_data['sig'] = hash_hmac(
			'sha256',
			'LSTICKET1|' . wp_json_encode( $token_data ),
			LS_SSO_Config::secret()
		);

		return $token_data;
	}


	public static function verify_ticket( array $token_data, $ttl = 120 ) {
		if ( empty( $token_data['sig'] ) || empty( $token_data['ts'] ) ) {
			return false;
		}

		$signature = (string) $token_data['sig'];
		unset( $token_data['sig'] );

		if ( abs( time() - (int) $token_data['ts'] ) > $ttl ) {
			return false;
		}

		ksort( $token_data );
		$expected = hash_hmac(
			'sha256',
			'LSTICKET1|' . wp_json_encode( $token_data ),
			LS_SSO_Config::secret()
		);

		return hash_equals( $expected, $signature );
	}
}
