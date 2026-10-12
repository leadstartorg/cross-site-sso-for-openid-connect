<?php
/**
 * Logout propagation across sites.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

class LS_SSO_Logout {

	const TICKET_VAR = 'ls_sso_logout';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {
		add_filter( 'allowed_redirect_hosts', array( __CLASS__, 'allow_peer_hosts' ) );
		add_filter( 'logout_redirect', array( __CLASS__, 'build_logout_chain' ), 200, 3 );
		add_action( 'init', array( __CLASS__, 'maybe_handle_ticket' ), 1 );
		add_action( 'rest_api_init', array( __CLASS__, 'register_backchannel_route' ) );
	}

	/**
	 * Allow redirects to our own sites and to the identity provider.
	 *
	 * @param array $hosts Allowed hosts.
	 * @return array
	 */
	public static function allow_peer_hosts( $hosts ) {
		foreach ( LS_SSO_Config::all_origins() as $origin ) {
			$host = wp_parse_url( $origin, PHP_URL_HOST );
			if ( $host ) {
				$hosts[] = $host;
			}
		}

		foreach ( array( self::end_session_endpoint(), self::authorize_endpoint() ) as $endpoint ) {
			if ( ! $endpoint ) {
				continue;
			}
			$host = wp_parse_url( $endpoint, PHP_URL_HOST );
			if ( $host ) {
				$hosts[] = $host;
			}
		}

		return array_values( array_unique( array_filter( $hosts ) ) );
	}

	/**
	 * The end-session endpoint configured in OpenID Connect Generic.
	 *
	 * @return string
	 */
	public static function authorize_endpoint() {
		if ( ! class_exists( 'OpenID_Connect_Generic' ) ) {
			return '';
		}
		$plugin = OpenID_Connect_Generic::instance();
		if ( ! $plugin || empty( $plugin->settings ) ) {
			return '';
		}
		return (string) $plugin->settings->endpoint_login;
	}

	/**
	 * The end-session endpoint configured in OpenID Connect Generic.
	 *
	 * @return string
	 */
	protected static function end_session_endpoint() {
		if ( ! class_exists( 'OpenID_Connect_Generic' ) ) {
			return '';
		}
		$plugin = OpenID_Connect_Generic::instance();
		if ( ! $plugin || empty( $plugin->settings ) ) {
			return '';
		}
		return (string) $plugin->settings->endpoint_end_session;
	}

	/**
	 * Logout redirect turned into a chain through every peer.
	 *
	 * @param string  $redirect_url Where logout would have gone.
	 * @param string  $requested    Originally requested destination.
	 * @param WP_User $user         The user logging out.
	 * @return string
	 */
	public static function build_logout_chain( $redirect_url, $requested, $user ) {
		unset( $requested, $user );

		$peers = LS_SSO_Config::peers();
		if ( empty( $peers ) ) {
			return $redirect_url;
		}

		$next = $redirect_url;

		// Reverse order 
		foreach ( array_reverse( $peers ) as $origin ) {
			$next = self::hop_url( $origin, $next );
		}

		ls_sso_log( 'logout chain built', array( 'hops' => count( $peers ) ) );

		return $next;
	}

	/**
	 * Build one signed URL.
	 *
	 * @param string $origin 
	 * @param string $next   
	 * @return string
	 */
	protected static function hop_url( $origin, $next ) {
		$ticket = LS_SSO_Signer::sign_ticket(
			array(
				'aud'  => $origin,
				'next' => $next,
				'act'  => 'logout',
			)
		);

		return add_query_arg(
			array( self::TICKET_VAR => rawurlencode( self::pack( $ticket ) ) ),
			trailingslashit( $origin )
		);
	}

	/**
	 * Handle an inbound logout ticket on this site.
	 *
	 * @return void
	 */
	public static function maybe_handle_ticket() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET[ self::TICKET_VAR ] ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$raw    = sanitize_text_field( wp_unslash( $_GET[ self::TICKET_VAR ] ) );
		$ticket = self::unpack( $raw );

		if ( ! is_array( $ticket ) || ! LS_SSO_Signer::verify_ticket( $ticket, 120 ) ) {
			ls_sso_log( 'logout ticket rejected' );
			wp_safe_redirect( home_url( '/' ) );
			exit;
		}

		if ( empty( $ticket['aud'] ) || LS_SSO_Config::normalize_origin( $ticket['aud'] ) !== LS_SSO_Config::self_origin() ) {
			ls_sso_log( 'logout ticket audience mismatch' );
			wp_safe_redirect( home_url( '/' ) );
			exit;
		}

		if ( 'logout' !== ( $ticket['act'] ?? '' ) ) {
			wp_safe_redirect( home_url( '/' ) );
			exit;
		}

		// Destroy the local session, wp_logout() revokes the session token
		$logged_out_user = get_current_user_id();
		if ( is_user_logged_in() ) {
			wp_logout();
		}

		LS_SSO_Logger::log(
			'logout_hop',
			array(
				'direction' => 'inbound',
				'user_id'   => $logged_out_user,
				'status'    => 'success',
			)
		);

		// Clear cookies
		self::clear_check_cookies();

		$next = isset( $ticket['next'] ) ? (string) $ticket['next'] : home_url( '/' );
		$end_session_host = wp_parse_url( self::end_session_endpoint(), PHP_URL_HOST );
		$next_host        = wp_parse_url( $next, PHP_URL_HOST );

		if ( ! LS_SSO_Config::is_known_origin( $next ) && $next_host !== $end_session_host ) {
			$next = home_url( '/' );
		}

		nocache_headers();
		wp_safe_redirect( $next );
		exit;
	}

	/**
	 * Expire the cookies.
	 *
	 * @return void
	 */
	protected static function clear_check_cookies() {
		if ( headers_sent() ) {
			return;
		}
		foreach ( array( LS_SSO_Silent_Login::COOKIE_CHECKED, LS_SSO_Silent_Login::COOKIE_RETURN, LS_SSO_Silent_Login::COOKIE_SILENT ) as $name ) {
			setcookie( $name, '', time() - 3600, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN, is_ssl(), false );
		}
	}

	/**
	 * Register the OIDC back-channel logout receiver.
	 *
	 * @return void
	 */
	public static function register_backchannel_route() {
		register_rest_route(
			'cross-site-sso-for-openid-connect/v1',
			'/backchannel-logout',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'handle_backchannel' ),
				'permission_callback' => '__return_true', // Authenticity comes from the signed logout_token.
				'args'                => array(
					'logout_token' => array(
						'required' => true,
						'type'     => 'string',
					),
				),
			)
		);
	}

	/**
	 * Handle an OIDC logout token.
	 *
	 * @param WP_REST_Request $request Inbound request.
	 * @return WP_REST_Response
	 */
	public static function handle_backchannel( WP_REST_Request $request ) {
		$token = (string) $request->get_param( 'logout_token' );

		if ( ! class_exists( 'OpenID_Connect_Generic' ) ) {
			return new WP_REST_Response( array( 'error' => 'unsupported' ), 501 );
		}

		$token_data = self::validate_logout_token( $token );
		if ( is_wp_error( $token_data ) ) {
			ls_sso_log( 'backchannel logout rejected', array( 'reason' => $token_data->get_error_code() ) );
			return new WP_REST_Response( array( 'error' => 'invalid_request' ), 400 );
		}

		$subject = isset( $token_data['sub'] ) ? (string) $token_data['sub'] : '';
		if ( '' === $subject ) {
			return new WP_REST_Response( array( 'error' => 'invalid_request' ), 400 );
		}

		$user = LS_SSO_Profile::user_by_subject( $subject );
		if ( ! $user ) {
			return new WP_REST_Response( array( 'ok' => true ), 200 );
		}

		// Destroying every session token for the user invalidates their cookies
		// on this site immediately without touching the browser.
		$manager = WP_Session_Tokens::get_instance( $user->ID );
		$manager->destroy_all();

		ls_sso_log( 'backchannel logout applied', array( 'user' => $user->ID ) );

		return new WP_REST_Response( array( 'ok' => true ), 200 );
	}

	/**
	 * Validate a logout token against the IdP JWKS.
	 *
	 * Reuses the firebase/php-jwt copy that ships inside OpenID Connect
	 * Generic.
	 *
	 * @param string $token Raw JWT.
	 * @return array|WP_Error Token data on success.
	 */
	protected static function validate_logout_token( $token ) {
		if ( ! class_exists( '\Firebase\JWT\JWT' ) || ! class_exists( '\Firebase\JWT\JWK' ) ) {
			return new WP_Error( 'no_jwt_library', 'JWT library unavailable.' );
		}

		$plugin = OpenID_Connect_Generic::instance();
		if ( ! $plugin || empty( $plugin->settings ) ) {
			return new WP_Error( 'no_settings', 'OIDC settings unavailable.' );
		}

		$jwks_uri = (string) $plugin->settings->endpoint_jwks;
		$issuer   = (string) $plugin->settings->issuer;
		$client_id = (string) $plugin->settings->client_id;

		if ( '' === $jwks_uri || '' === $issuer ) {
			return new WP_Error( 'no_jwks', 'JWKS or issuer not configured.' );
		}

		$jwks = get_transient( 'ls_sso_jwks' );
		if ( false === $jwks ) {
			$response = wp_remote_get( $jwks_uri, array( 'timeout' => 10 ) );
			if ( is_wp_error( $response ) ) {
				return new WP_Error( 'jwks_fetch_failed', 'Could not fetch JWKS.' );
			}
			$jwks = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( ! is_array( $jwks ) || empty( $jwks['keys'] ) ) {
				return new WP_Error( 'jwks_malformed', 'JWKS malformed.' );
			}
			set_transient( 'ls_sso_jwks', $jwks, HOUR_IN_SECONDS );
		}

		try {
			$decoded = \Firebase\JWT\JWT::decode( $token, \Firebase\JWT\JWK::parseKeySet( $jwks ) );
		} catch ( \Exception $e ) {
			return new WP_Error( 'bad_signature', $e->getMessage() );
		}

		$token_data = json_decode( wp_json_encode( $decoded ), true );
		if ( ! is_array( $token_data ) ) {
			return new WP_Error( 'bad_token_data', 'Unreadable token data.' );
		}

		if ( ( $token_data['iss'] ?? '' ) !== $issuer ) {
			return new WP_Error( 'bad_issuer', 'Issuer mismatch.' );
		}

		$audience = (array) ( $token_data['aud'] ?? array() );
		if ( '' !== $client_id && ! in_array( $client_id, $audience, true ) ) {
			return new WP_Error( 'bad_audience', 'Audience mismatch.' );
		}

		if ( abs( time() - (int) ( $token_data['iat'] ?? 0 ) ) > 300 ) {
			return new WP_Error( 'stale_token', 'Token too old.' );
		}

		// A logout token MUST NOT contain a nonce.
		if ( isset( $token_data['nonce'] ) ) {
			return new WP_Error( 'nonce_present', 'Not a logout token.' );
		}

		$events = $token_data['events'] ?? array();
		if ( ! is_array( $events ) || ! array_key_exists( 'http://schemas.openid.net/event/backchannel-logout', $events ) ) {
			return new WP_Error( 'missing_event', 'Missing backchannel-logout event.' );
		}

		// Replay protection on jti.
		$jti = (string) ( $token_data['jti'] ?? '' );
		if ( '' !== $jti && ! add_option( 'ls_sso_jti_' . md5( $jti ), time() + 900, '', 'no' ) ) {
			return new WP_Error( 'replayed_jti', 'Token replayed.' );
		}

		return $token_data;
	}

	/**
	 * Encode a ticket array for a URL.
	 *
	 * @param array $ticket Ticket payload.
	 * @return string
	 */
	protected static function pack( array $ticket ) {
		return rtrim( strtr( base64_encode( wp_json_encode( $ticket ) ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * Decode a packed ticket.
	 *
	 * @param string $raw Packed value.
	 * @return array|null
	 */
	protected static function unpack( $raw ) {
		$json = base64_decode( strtr( $raw, '-_', '+/' ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $json ) {
			return null;
		}
		$data = json_decode( $json, true );
		return is_array( $data ) ? $data : null;
	}
}
