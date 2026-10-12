<?php
/**
 * Uninstall.
 *
 * This runs when the plugin is deleted through the WordPress admin but not
 * on deactivation, or for a must-use installation, where removing the folder
 * leaves the table and options in place.
 *
 * Settings defined as wp-config.php constants are not modified.
 *
 * @package Leadstart_SSO
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

require_once __DIR__ . '/includes/class-ls-logger.php';

global $wpdb;

// Activity log table and its schema marker.
LS_SSO_Logger::drop();

// Settings stored via the admin screen (constants in wp-config.php are not
// ours to touch and are left exactly as they are).
foreach ( array( 'ls_sso_secret', 'ls_sso_peers', 'ls_sso_store', 'ls_sso_role_claim', 'ls_sso_meta_keys', 'ls_sso_block_silent_roles', 'ls_sso_silent_mode' ) as $ls_sso_option ) {
	delete_option( $ls_sso_option );
}
unset( $ls_sso_option );

// Scheduled jobs.
foreach ( array( 'ls_sso_gc', 'ls_sso_purge_log', 'ls_sso_dispatch_worker' ) as $ls_sso_hook ) {
	wp_clear_scheduled_hook( $ls_sso_hook );
}
unset( $ls_sso_hook );

// Cached JWKS.
delete_transient( 'ls_sso_jwks' );

// phpcs:disable WordPress.DB.DirectDatabaseQuery
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		$wpdb->esc_like( 'ls_sso_nonce_' ) . '%',
		$wpdb->esc_like( 'ls_sso_jti_' ) . '%'
	)
);

// Per-user cached order lists.
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		$wpdb->esc_like( '_transient_ls_sso_orders_' ) . '%',
		$wpdb->esc_like( '_transient_timeout_ls_sso_orders_' ) . '%'
	)
);
// phpcs:enable WordPress.DB.DirectDatabaseQuery
