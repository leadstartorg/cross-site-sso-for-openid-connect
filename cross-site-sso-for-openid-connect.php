<?php
/**
 * Plugin Name:       Cross-Site SSO for OpenID Connect
 * Plugin URI:        https://github.com/leadstartorg/cross-site-sso-for-openid-connect
 * Description:       Silent single sign-on, logout and shared order history across separate WordPress installs connected using one OpenID Connect provider. This plugin requires the OpenID Connect Generic plugin.
 * Version:           1.0.0
 * Requires at least: 5.9
 * Requires PHP:      7.4
 * Author:            Leadstart Media, Inc.
 * Author URI:        https://leadstart.org
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       cross-site-sso-for-openid-connect
 * Domain Path:       /languages
 *
 * @package Leadstart_SSO
 *
 * The plugin adds single sign-on and single logout across separate WordPress
 * installations that share one OpenID Connect provider, and lets sites without
 * WooCommerce display a customer's order history.
 *
 * User authentication is handled by the OpenID Connect Generic plugin, which
 * must be installed and configured on each site.
 *
 * Configuration (wp-config.php constants, or the plugin's settings screen):
 *
 *   LS_SSO_SECRET              Shared secret, identical on every site.
 *   LS_SSO_PEERS               Comma-separated origins of the other sites.
 *   LS_SSO_STORE               Origin of the site running WooCommerce.
 *   LS_SSO_ROLE_CLAIM          Optional. Claim carrying the user's roles.
 *   LS_SSO_META_KEYS           Optional. User meta keys allowed to sync.
 *   LS_SSO_BLOCK_SILENT_ROLES  Roles refused a silently created session.
 *   LS_SSO_SILENT              Enable or disable silent sign-on.
 *   LS_SSO_SILENT_MODE         'js' or 'redirect'.
 *   LS_SSO_DEBUG               Verbose logging to the PHP error log.
 */

defined( 'ABSPATH' ) || exit;

/*
 * This plugin can be installed as a must-use plugin
 */
if ( defined( 'LS_SSO_VERSION' ) ) {
	if ( ! function_exists( 'ls_sso_duplicate_notice' ) ) {

		function ls_sso_duplicate_notice() {
			if ( ! current_user_can( 'activate_plugins' ) ) {
				return;
			}
			echo '<div class="notice notice-warning"><p><strong>';
			esc_html_e( 'Cross-Site SSO is installed twice.', 'cross-site-sso-for-openid-connect' );
			echo '</strong> ';
			printf(
				/* translators: 1: path of the copy that is running, 2: version. */
				esc_html__( 'The copy at %1$s (version %2$s) is the one running. Remove the other copy — most likely a leftover in mu-plugins or plugins — so future updates take effect.', 'cross-site-sso-for-openid-connect' ),
				'<code>' . esc_html( str_replace( ABSPATH, '', LS_SSO_FILE ) ) . '</code>',
				esc_html( LS_SSO_VERSION )
			);
			echo '</p></div>';
		}
		add_action( 'admin_notices', 'ls_sso_duplicate_notice' );
	}
	return;
}

define( 'LS_SSO_VERSION', '1.0.0' );
define( 'LS_SSO_FILE', __FILE__ );
define( 'LS_SSO_DIR', plugin_dir_path( __FILE__ ) );
define( 'LS_SSO_URL', plugin_dir_url( __FILE__ ) );

require_once LS_SSO_DIR . 'includes/class-ls-config.php';
require_once LS_SSO_DIR . 'includes/class-ls-logger.php';
require_once LS_SSO_DIR . 'includes/class-ls-signer.php';
require_once LS_SSO_DIR . 'includes/class-ls-http.php';
require_once LS_SSO_DIR . 'includes/class-ls-profile.php';
require_once LS_SSO_DIR . 'includes/class-ls-silent-login.php';
require_once LS_SSO_DIR . 'includes/class-ls-logout.php';
require_once LS_SSO_DIR . 'includes/class-ls-rest.php';
require_once LS_SSO_DIR . 'includes/class-ls-orders.php';
require_once LS_SSO_DIR . 'includes/class-ls-admin.php';

add_action(
	'plugins_loaded',
	function () {

		LS_SSO_Rest::init();
		LS_SSO_Admin::init();

		if ( ! LS_SSO_Config::is_configured() ) {
			return;
		}

		LS_SSO_Logger::init();
		LS_SSO_Orders::init();
		LS_SSO_Logout::init();

		if ( class_exists( 'OpenID_Connect_Generic' ) ) {
			LS_SSO_Profile::init();
			LS_SSO_Silent_Login::init();
		}
	},
	20
);

/**
 * Never logs token values or the secret.
 *
 * @param string $message 
 * @param array  $context
 * @return void
 */
function ls_sso_log( $message, $context = array() ) {
	if ( ! LS_SSO_Config::debug() ) {
		return;
	}
	$line = '[cross-site-sso] ' . $message;
	if ( ! empty( $context ) ) {
		$line .= ' ' . wp_json_encode( $context );
	}
	error_log( $line ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
}
