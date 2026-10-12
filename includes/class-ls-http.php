<?php
/**
 * Outbound transport for site-to-site requests.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Signed HTTP client and deferred dispatcher.
 */
class LS_SSO_Http {

	const HOOK_WORKER = 'ls_sso_dispatch_worker';
	const MAX_ATTEMPTS = 4;

	/**
	 * Register the background worker.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( self::HOOK_WORKER, array( __CLASS__, 'run_job' ), 10, 4 );
	}

	/**
	 * Queue a signed POST to every peer.
	 *
	 * @param string $route
	 * @param array  $payload
	 * @param array  $targets 
	 * @return void
	 */
	public static function queue( $route, array $payload, array $targets = array() ) {
		if ( empty( $targets ) ) {
			$targets = LS_SSO_Config::peers();
		}

		foreach ( $targets as $origin ) {
			self::schedule( $origin, $route, $payload, 1 );
		}
	}

	/**
	 * Schedule one delivery attempt.
	 *
	 * @param string $origin 
	 * @param string $route  
	 * @param array  $payload 
	 * @param int    $attempt 
	 * @return void
	 */
	protected static function schedule( $origin, $route, array $payload, $attempt ) {
		$args = array( $origin, $route, $payload, $attempt );

		// Exponential-ish backoff
		$delays = array( 1 => 0, 2 => 60, 3 => 300, 4 => 900 );
		$delay  = isset( $delays[ $attempt ] ) ? $delays[ $attempt ] : 900;

		if ( function_exists( 'as_schedule_single_action' ) ) {
			as_schedule_single_action( time() + $delay, self::HOOK_WORKER, $args, 'cross-site-sso-for-openid-connect' );
			return;
		}

		// WP-Cron fallback deduplicated by WordPress on identical args
		wp_schedule_single_event( time() + $delay, self::HOOK_WORKER, $args );

		// WP-Cron only fires on a page view. On a quiet site that can be a long
		// wait, so nudge the loopback without blocking on it.
		if ( 1 === $attempt ) {
			spawn_cron();
		}
	}

	/**
	 * Background worker
	 *
	 * @param string $origin  
	 * @param string $route   
	 * @param array  $payload 
	 * @param int    $attempt 
	 * @return void
	 */
	public static function run_job( $origin, $route, $payload, $attempt = 1 ) {
		$result = self::post( $origin, $route, $payload, 15 );

		if ( ! is_wp_error( $result ) ) {
			return;
		}

		$attempt = (int) $attempt;
		if ( $attempt >= self::MAX_ATTEMPTS ) {
			ls_sso_log(
				'delivery abandoned',
				array(
					'origin'  => $origin,
					'route'   => $route,
					'error'   => $result->get_error_message(),
					'attempts' => $attempt,
				)
			);
			return;
		}

		self::schedule( $origin, $route, $payload, $attempt + 1 );
	}

	/**
	 * Perform a signed POST immediately.
	 *
	 * @param string $origin  
	 * @param string $route
	 * @param array  $payload
	 * @param int    $timeout 
     *
	 * @return array|WP_Error Decoded response body, or error.
	 */
	public static function post( $origin, $route, array $payload, $timeout = 10 ) {
		$origin = LS_SSO_Config::normalize_origin( $origin );
		if ( '' === $origin ) {
			return new WP_Error( 'ls_sso_bad_origin', 'Unusable target origin.' );
		}

		$body = wp_json_encode( $payload );
		$args = array(
			'timeout'     => $timeout,
			'redirection' => 0,
			'headers'     => LS_SSO_Signer::headers( $route, $body, array() ),
			'body'        => $body,
		);

		$url      = $origin . '/wp-json' . $route;
		$response = wp_remote_post( $url, $args );

		if ( self::is_404( $response ) ) {
			$url      = add_query_arg( 'rest_route', $route, $origin . '/' );
			$response = wp_remote_post( $url, $args );
		}

		return self::interpret( $response, $url );
	}

	/**
	 * Signed GET immediately.
	 *
	 * @param string $origin 
	 * @param string $route  
	 * @param array  $query
	 * @param int    $timeout 
	 * @return array|WP_Error
	 */
	public static function get( $origin, $route, array $query = array(), $timeout = 5 ) {
		$origin = LS_SSO_Config::normalize_origin( $origin );
		if ( '' === $origin ) {
			return new WP_Error( 'ls_sso_bad_origin', 'Unusable target origin.' );
		}

		$args = array(
			'timeout'     => $timeout,
			'redirection' => 0,
			'headers'     => LS_SSO_Signer::headers( $route, '', $query ),
		);

		$url      = add_query_arg( $query, $origin . '/wp-json' . $route );
		$response = wp_remote_get( $url, $args );

		if ( self::is_404( $response ) ) {
			$url      = add_query_arg( array_merge( array( 'rest_route' => $route ), $query ), $origin . '/' );
			$response = wp_remote_get( $url, $args );
		}

		return self::interpret( $response, $url );
	}

	/**
	 * Check if a response is a 404.
	 *
	 * @param array|WP_Error $response Raw result.
	 * @return bool
	 */
	protected static function is_404( $response ) {
		return ! is_wp_error( $response ) && 404 === (int) wp_remote_retrieve_response_code( $response );
	}

	/**
	 * wp_remote_* result turned into data or a WP_Error.
	 *
	 * @param array|WP_Error $response 
	 * @param string         $url
	 * @return array|WP_Error
	 */
	protected static function interpret( $response, $url ) {
		if ( is_wp_error( $response ) ) {
			ls_sso_log( 'transport error', array( 'url' => $url, 'error' => $response->get_error_message() ) );
			LS_SSO_Logger::log(
				'peer_request',
				array(
					'direction' => 'outbound',
					'peer'      => LS_SSO_Config::normalize_origin( $url ),
					'route'     => (string) wp_parse_url( $url, PHP_URL_PATH ),
					'status'    => 'failure',
					'detail'    => $response->get_error_message(),
				)
			);
			return $response;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( $code < 200 || $code > 299 ) {
			ls_sso_log( 'remote refused', array( 'url' => $url, 'status' => $code ) );
			LS_SSO_Logger::log(
				'peer_request',
				array(
					'direction' => 'outbound',
					'peer'      => LS_SSO_Config::normalize_origin( $url ),
					'route'     => (string) wp_parse_url( $url, PHP_URL_PATH ),
					'status'    => 'failure',
					/* translators: %d: HTTP status code. */
					'detail'    => sprintf( 'HTTP %d', $code ),
				)
			);
			return new WP_Error( 'ls_sso_http_' . $code, 'Peer returned HTTP ' . $code, array( 'status' => $code ) );
		}

		if ( ! is_array( $body ) ) {
			return new WP_Error( 'ls_sso_bad_body', 'Peer returned a non-JSON body.' );
		}

		return $body;
	}
}

LS_SSO_Http::init();
