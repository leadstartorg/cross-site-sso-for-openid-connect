<?php
/**
 * Order history for sites that do not run WooCommerce.
 * Output is produced by the [cross_site_orders] shortcode.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Read-only order history.
 */
class LS_SSO_Orders {

	const CACHE_TTL = 300;

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {

		if ( LS_SSO_Config::is_store() ) {
			return;
		}

		add_shortcode( 'cross_site_orders', array( __CLASS__, 'render' ) );
		add_shortcode( 'leadstart_orders', array( __CLASS__, 'render' ) );
	}

	/**
	 * Fetch a user's orders from the store site.
	 *
	 * @param int $user_id User to fetch for.
	 * @return array<int,array> Possibly empty.
	 */
	public static function fetch( $user_id ) {
		$store = LS_SSO_Config::store_origin();
		if ( '' === $store || $store === LS_SSO_Config::self_origin() ) {
			return array();
		}

		$subject = LS_SSO_Profile::subject_for( $user_id );
		if ( '' === $subject ) {
			return array();
		}

		$cache_key = 'ls_sso_orders_' . md5( $subject );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$result = LS_SSO_Http::get(
			$store,
			'/cross-site-sso-for-openid-connect/v1/orders',
			array(
				'subject' => $subject,
				'limit'   => 10,
			),
			4
		);

		if ( is_wp_error( $result ) || ! isset( $result['orders'] ) || ! is_array( $result['orders'] ) ) {
			set_transient( $cache_key, array(), 60 );
			return array();
		}

		set_transient( $cache_key, $result['orders'], self::CACHE_TTL );

		return $result['orders'];
	}

	/**
	 * Shortcode output.
	 *
	 * @param array $atts Shortcode attributes.
	 * @return string
	 */
	public static function render( $atts ) {
		$atts = shortcode_atts(
			array(
				'empty' => __( 'No orders yet.', 'cross-site-sso-for-openid-connect' ),
			),
			$atts,
			'cross_site_orders'
		);

		if ( ! is_user_logged_in() ) {
			return '';
		}

		$orders = self::fetch( get_current_user_id() );

		if ( empty( $orders ) ) {
			return '<p class="ls-orders-empty">' . esc_html( $atts['empty'] ) . '</p>';
		}

		$store_label = wp_parse_url( LS_SSO_Config::store_origin(), PHP_URL_HOST );

		ob_start();
		?>
		<table class="ls-orders">
			<caption>
				<?php
				printf(
					/* translators: %s: hostname of the store site. */
					esc_html__( 'Your orders from %s', 'cross-site-sso-for-openid-connect' ),
					esc_html( $store_label )
				);
				?>
			</caption>
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Order', 'cross-site-sso-for-openid-connect' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Date', 'cross-site-sso-for-openid-connect' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Status', 'cross-site-sso-for-openid-connect' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Total', 'cross-site-sso-for-openid-connect' ); ?></th>
					<th scope="col"><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'cross-site-sso-for-openid-connect' ); ?></span></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $orders as $order ) : ?>
				<?php
				$number    = isset( $order['number'] ) ? (string) $order['number'] : '';
				$date_raw  = isset( $order['date'] ) ? (string) $order['date'] : '';
				$timestamp = $date_raw ? strtotime( $date_raw ) : false;
				$status    = isset( $order['status_label'] ) ? (string) $order['status_label'] : '';
				$total     = isset( $order['total_html'] ) ? (string) $order['total_html'] : '';
				$view_url  = isset( $order['view_url'] ) ? (string) $order['view_url'] : '';

				if ( '' !== $view_url && ! LS_SSO_Config::is_known_origin( $view_url ) ) {
					$view_url = '';
				}
				?>
				<tr>
					<th scope="row">#<?php echo esc_html( $number ); ?></th>
					<td>
						<?php
						echo $timestamp
							? esc_html( date_i18n( get_option( 'date_format' ), $timestamp ) )
							: '&mdash;';
						?>
					</td>
					<td><?php echo esc_html( $status ); ?></td>
					<td><?php echo esc_html( $total ); ?></td>
					<td>
						<?php if ( '' !== $view_url ) : ?>
							<a href="<?php echo esc_url( $view_url ); ?>" rel="noopener">
								<?php esc_html_e( 'View', 'cross-site-sso-for-openid-connect' ); ?>
							</a>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
		return (string) ob_get_clean();
	}

	public static function flush( $subject ) {
		delete_transient( 'ls_sso_orders_' . md5( (string) $subject ) );
	}
}
