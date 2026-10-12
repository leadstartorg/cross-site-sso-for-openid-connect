<?php
/**
 * Authentication against the identity provider session.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Authentication check.
 */
class LS_SSO_Silent_Login {


	const COOKIE_CHECKED = 'ls_sso_checked';
	const COOKIE_RETURN = 'ls_sso_return';
	const COOKIE_SILENT = 'ls_sso_silent';
	const CHECK_TTL = 1800;
	const FLAG = 'ls_sso_check';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {
		if ( ! LS_SSO_Config::silent_enabled() ) {
			return;
		}

		// Intercept the provider's "no session" answer before OpenID Connect Generic
		// the plugin's own callback, which is registered at the default 10.
		add_action( 'wp_ajax_nopriv_openid-connect-authorize', array( __CLASS__, 'intercept_silent_failure' ), 1 );
		add_action( 'wp_ajax_openid-connect-authorize', array( __CLASS__, 'intercept_silent_failure' ), 1 );
		add_action( 'parse_request', array( __CLASS__, 'intercept_silent_failure_alt' ), 1 );

		// Add prompt=none to the authorization URL, but only for our checks.
		add_filter( 'openid-connect-generic-auth-url', array( __CLASS__, 'add_prompt_none' ) );

		// Refuse a session for a role.
		add_action( 'openid-connect-generic-user-logged-in', array( __CLASS__, 'guard_privileged_silent_login' ), 5, 1 );

		if ( 'redirect' === LS_SSO_Config::silent_mode() ) {
			add_action( 'template_redirect', array( __CLASS__, 'maybe_redirect_check' ), 5 );
		} else {
			add_action( 'wp_enqueue_scripts', array( __CLASS__, 'enqueue_check_script' ) );
		}
	}

	public static function should_check() {
		if ( is_user_logged_in() ) {
			return false;
		}
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return false;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return false;
		}
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'GET' !== strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) ) {
			return false;
		}
		if ( is_feed() || is_robots() || is_favicon() || is_preview() ) {
			return false;
		}

		if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) {
			return false;
		}
		if ( ! empty( $_COOKIE[ self::COOKIE_CHECKED ] ) ) {
			return false;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET[ self::FLAG ] ) ) {
			return false;
		}
		if ( self::looks_like_a_bot() ) {
			return false;
		}

		return (bool) apply_filters( 'ls_sso_should_check', true );
	}

	protected static function looks_like_a_bot() {
		$agent = isset( $_SERVER['HTTP_USER_AGENT'] )
			? strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) )
			: '';

		if ( '' === $agent ) {
			return true;
		}

		foreach ( array( 'bot', 'crawl', 'spider', 'slurp', 'facebookexternalhit', 'preview', 'monitor', 'pingdom', 'curl', 'wget', 'headless' ) as $needle ) {
			if ( false !== strpos( $agent, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The URL that starts an authorization.
	 *
	 * @return string
	 */
	public static function check_url() {
		$plugin = OpenID_Connect_Generic::instance();
		if ( ! $plugin || empty( $plugin->client_wrapper ) ) {
			return '';
		}

		$current = self::current_url();

		// Remember where to come back to if the provider reports no session.
		self::set_cookie( self::COOKIE_RETURN, $current, time() + 300 );

		self::set_cookie( self::COOKIE_SILENT, '1', time() + 300 );

		$GLOBALS['ls_sso_checking'] = true;
		$url = $plugin->client_wrapper->get_authentication_url( array( 'redirect_to' => $current ) );
		unset( $GLOBALS['ls_sso_checking'] );

		return $url;
	}

	/**
	 * Append `prompt=none` to the authorization URL during a check only.
	 *
	 * @param string $url Authorization URL.
	 * @return string
	 */
	public static function add_prompt_none( $url ) {
		if ( empty( $GLOBALS['ls_sso_checking'] ) ) {
			return $url;
		}
		return add_query_arg( 'prompt', 'none', $url );
	}

	/**
	 * Server-side check (LS_SSO_SILENT_MODE = 'redirect').
	 *
	 * @return void
	 */
	public static function maybe_redirect_check() {
		if ( ! self::should_check() ) {
			return;
		}

		$url = self::check_url();
		if ( '' === $url ) {
			return;
		}

		self::mark_checked();

		nocache_headers();
		header( 'Cache-Control: no-store, no-cache, must-revalidate, private', true );

		wp_safe_redirect( $url );
		exit;
	}

	/**
	 * Browser-side check (default transport).
     *
	 * @return void
	 */
	public static function enqueue_check_script() {
		if ( ! self::should_check() ) {
			return;
		}

		$url = self::check_url();
		if ( '' === $url ) {
			return;
		}

		wp_register_script( 'ls-sso-check', false, array(), LS_SSO_VERSION, true );
		wp_enqueue_script( 'ls-sso-check' );

		$config = wp_json_encode(
			array(
				'url'    => $url,
				'cookie' => self::COOKIE_CHECKED,
				'ttl'    => self::CHECK_TTL,
			)
		);

		wp_add_inline_script(
			'ls-sso-check',
			'( function () {
	var c = ' . $config . ';
	try {
		if ( document.cookie.indexOf( c.cookie + "=" ) !== -1 ) { return; }
		if ( window.self !== window.top ) { return; }
		if ( navigator.webdriver ) { return; }
		document.cookie = c.cookie + "=1; path=/; max-age=" + c.ttl + "; SameSite=Lax" +
			( location.protocol === "https:" ? "; Secure" : "" );
		window.location.replace( c.url );
	} catch ( e ) {  }
} )();'
		);
	}

	/**
	 * Refuse a session for a role.
	 * @param WP_User $user The user who has just been logged in.
	 * @return void
	 */
	public static function guard_privileged_silent_login( $user ) {
		if ( ! $user instanceof WP_User ) {
			return;
		}

		if ( empty( $_COOKIE[ self::COOKIE_SILENT ] ) ) {
			return;
		}

		$blocked = LS_SSO_Config::blocked_silent_roles();
		if ( empty( $blocked ) ) {
			return;
		}

		// Roles have already been mapped from the profile at this point
		$held = array_map( 'sanitize_key', (array) $user->roles );

		// Capability
		$is_privileged = ! empty( array_intersect( $held, $blocked ) )
			|| ( in_array( 'administrator', $blocked, true ) && user_can( $user, 'manage_options' ) );

		if ( ! $is_privileged ) {
			return;
		}

		$return = isset( $_COOKIE[ self::COOKIE_RETURN ] )
			? esc_url_raw( wp_unslash( $_COOKIE[ self::COOKIE_RETURN ] ) )
			: home_url( '/' );

		if ( ! LS_SSO_Config::is_known_origin( $return ) ) {
			$return = home_url( '/' );
		}

		// Destory only this session not wp_logout()
		wp_destroy_current_session();
		wp_clear_auth_cookie();
		wp_set_current_user( 0 );

		self::mark_checked();
		self::set_cookie( self::COOKIE_SILENT, '', time() - 3600 );
		self::set_cookie( self::COOKIE_RETURN, '', time() - 3600 );

		LS_SSO_Logger::log(
			'silent_login_refused',
			array(
				'direction' => 'inbound',
				'user_id'   => $user->ID,
				'status'    => 'success',
				'detail'    => 'privileged role: ' . implode( ',', $held ),
			)
		);

		ls_sso_log( 'silent login refused for privileged user', array( 'user' => $user->ID ) );

		nocache_headers();
		wp_safe_redirect( add_query_arg( self::FLAG, 'privileged', $return ) );
		exit;
	}

	protected static function mark_checked() {
		self::set_cookie( self::COOKIE_CHECKED, '1', time() + self::CHECK_TTL );
	}

	/**
	 * Handle the provider's `error=login_required` on the default redirect URI.
	 *
	 * The visitor sees OpenID Connect Generic's authentication
	 * error page after simply browsing to the site while logged out without this.
	 *
	 * @return void
	 */
	public static function intercept_silent_failure() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$error = isset( $_GET['error'] ) ? sanitize_text_field( wp_unslash( $_GET['error'] ) ) : '';

		if ( ! self::is_silent_failure( $error ) ) {
			return;
		}

		$return = isset( $_COOKIE[ self::COOKIE_RETURN ] )
			? esc_url_raw( wp_unslash( $_COOKIE[ self::COOKIE_RETURN ] ) )
			: home_url( '/' );

		if ( ! LS_SSO_Config::is_known_origin( $return ) ) {
			$return = home_url( '/' );
		}

		self::mark_checked();
		self::set_cookie( self::COOKIE_RETURN, '', time() - 3600 );
		self::set_cookie( self::COOKIE_SILENT, '', time() - 3600 );

		ls_sso_log( 'check found no provider session', array( 'error' => $error ) );

		nocache_headers();
		wp_safe_redirect( add_query_arg( self::FLAG, 'none', $return ) );
		exit;
	}

	/**
	 * Same interception for the alternate (query-string-free) redirect URI.
	 *
	 * @param WP $query Current request.
	 * @return void
	 */
	public static function intercept_silent_failure_alt( $query ) {
		if ( isset( $query->query_vars['openid-connect-authorize'] ) ) {
			self::intercept_silent_failure();
		}
	}

	protected static function is_silent_failure( $error ) {
		return in_array(
			$error,
			array( 'login_required', 'interaction_required', 'consent_required', 'account_selection_required' ),
			true
		);
	}

	protected static function current_url() {
		$path = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
		return home_url( $path );
	}

	/**
	 * @param string $name    Cookie name.
	 * @param string $value   Value.
	 * @param int    $expires Unix expiry.
	 * @return void
	 */
	protected static function set_cookie( $name, $value, $expires ) {
		if ( headers_sent() ) {
			return;
		}

		setcookie(
			$name,
			$value,
			array(
				'expires'  => $expires,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => false, // The JS transport needs to read it.
				'samesite' => 'Lax',
			)
		);
	}
}
