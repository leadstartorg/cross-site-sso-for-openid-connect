<?php
/**
 * Activity log.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

class LS_SSO_Logger {


	const TABLE = 'ls_sso_activity';
	const SCHEMA_OPTION = 'ls_sso_schema_version';
	const SCHEMA_VERSION = 1;
	const RETENTION_DAYS = 30;

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {

		self::maybe_migrate();

		add_action( 'ls_sso_purge_log', array( __CLASS__, 'purge' ) );

		if ( ! wp_next_scheduled( 'ls_sso_purge_log' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'ls_sso_purge_log' );
		}
	}

	/**
	 * Table name.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . self::TABLE;
	}

	/**
	 * Create or upgrade the table if the stored schema version is late.
	 *
	 * @return void
	 */
	public static function maybe_migrate() {
		if ( (int) get_option( self::SCHEMA_OPTION ) === self::SCHEMA_VERSION ) {
			return;
		}

		global $wpdb;

		$table   = self::table();
		$collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			logged_at DATETIME NOT NULL,
			event VARCHAR(50) NOT NULL DEFAULT '',
			direction VARCHAR(10) NOT NULL DEFAULT 'outbound',
			peer VARCHAR(191) NOT NULL DEFAULT '',
			route VARCHAR(191) NOT NULL DEFAULT '',
			user_id BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
			status VARCHAR(10) NOT NULL DEFAULT 'success',
			detail TEXT NULL,
			PRIMARY KEY (id),
			KEY logged_at (logged_at),
			KEY event (event),
			KEY status (status),
			KEY user_id (user_id)
		) {$collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		update_option( self::SCHEMA_OPTION, self::SCHEMA_VERSION, false );
	}

	/**
	 * Check whether the log table is present and usable.
	 *
	 * @return bool
	 */
	public static function is_ready() {
		return (int) get_option( self::SCHEMA_OPTION ) === self::SCHEMA_VERSION;
	}

	/**
	 * Record an event.
	 *
	 * @param string $event event slug, e.g. 'usermeta.received'.
	 * @param array  $args
     *
	 * @return void
	 */
	public static function log( $event, array $args = array() ) {
		if ( ! self::is_ready() ) {
			return;
		}

		global $wpdb;

		$args = wp_parse_args(
			$args,
			array(
				'direction' => 'outbound',
				'peer'      => '',
				'route'     => '',
				'user_id'   => 0,
				'status'    => 'success',
				'detail'    => '',
			)
		);

		$direction = in_array( $args['direction'], array( 'inbound', 'outbound' ), true )
			? $args['direction']
			: 'outbound';

		$status = in_array( $args['status'], array( 'success', 'failure' ), true )
			? $args['status']
			: 'success';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->insert(
			self::table(),
			array(
				'logged_at' => current_time( 'mysql', true ),
				'event'     => substr( sanitize_key( $event ), 0, 50 ),
				'direction' => $direction,
				'peer'      => substr( (string) $args['peer'], 0, 191 ),
				'route'     => substr( (string) $args['route'], 0, 191 ),
				'user_id'   => absint( $args['user_id'] ),
				'status'    => $status,
				'detail'    => substr( (string) $args['detail'], 0, 500 ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s' )
		);
	}

	/**
	 * Read log rows.
	 *
	 * @param array $filters Optional: event, status, peer, page, per_page.
	 * @return array{rows:array,total:int,pages:int}
	 */
	public static function query( array $filters = array() ) {
		if ( ! self::is_ready() ) {
			return array(
				'rows'  => array(),
				'total' => 0,
				'pages' => 0,
			);
		}

		global $wpdb;

		$table    = self::table();
		$per_page = isset( $filters['per_page'] ) ? max( 1, min( 200, (int) $filters['per_page'] ) ) : 25;
		$page     = isset( $filters['page'] ) ? max( 1, (int) $filters['page'] ) : 1;
		$offset   = ( $page - 1 ) * $per_page;

		$clauses = array();
		$binds   = array();

		foreach ( array( 'event', 'status', 'peer' ) as $field ) {
			if ( ! empty( $filters[ $field ] ) ) {
				$clauses[] = "{$field} = %s";
				$binds[]   = (string) $filters[ $field ];
			}
		}

		$where = $clauses ? ( 'WHERE ' . implode( ' AND ', $clauses ) ) : '';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL, WordPress.DB.PreparedSQLPlaceholders, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$count_sql = "SELECT COUNT(*) FROM {$table} {$where}";
		$total     = (int) ( $binds
			? $wpdb->get_var( $wpdb->prepare( $count_sql, ...$binds ) )
			: $wpdb->get_var( $count_sql ) );

		$page_args = array_merge( $binds, array( $per_page, $offset ) );
		$rows      = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} {$where} ORDER BY id DESC LIMIT %d OFFSET %d",
				...$page_args
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL, WordPress.DB.PreparedSQLPlaceholders, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return array(
			'rows'  => is_array( $rows ) ? $rows : array(),
			'total' => $total,
			'pages' => (int) ceil( $total / $per_page ),
		);
	}

	/**
	 * Delete rows.
	 *
	 * @return int Rows removed.
	 */
	public static function purge() {
		if ( ! self::is_ready() ) {
			return 0;
		}

		global $wpdb;

		/**
		 * Filter the activity log retention period.
		 *
		 * @param int $days.
		 */
		$days = (int) apply_filters( 'ls_sso_log_retention_days', self::RETENTION_DAYS );
		$days = max( 1, $days );

		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );
		$table  = self::table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL, PluginCheck.Security.DirectDB.UnescapedDBParameter
		return (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE logged_at < %s", $cutoff ) );
	}

	/**
	 * Distinct values of a column for building filter dropdowns.
	 *
	 * @param string $column
	 * @return array<int,string>
	 */
	public static function distinct( $column ) {
		if ( ! self::is_ready() || ! in_array( $column, array( 'event', 'status', 'peer' ), true ) ) {
			return array();
		}

		global $wpdb;
		$table = self::table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$values = $wpdb->get_col( "SELECT DISTINCT {$column} FROM {$table} ORDER BY {$column} ASC LIMIT 100" );

		return array_values( array_filter( (array) $values ) );
	}

	/**
	 * Drop the table used by uninstall.php.
	 *
	 * @return void
	 */
	public static function drop() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		delete_option( self::SCHEMA_OPTION );
	}
}
