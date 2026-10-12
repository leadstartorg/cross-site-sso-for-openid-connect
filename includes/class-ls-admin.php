<?php
/**
 * Admin screen.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Admin status page.
 */
class LS_SSO_Admin {

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'add_page' ) );
		add_action( 'admin_notices', array( __CLASS__, 'config_notice' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_assets' ) );
	}

	/**
	 * Register the secret-generator script
	 *
	 * @param string $hook_suffix Current admin page.
	 * @return void
	 */
	public static function enqueue_assets( $hook_suffix ) {
		if ( 'tools_page_cross-site-sso' !== $hook_suffix ) {
			return;
		}

		wp_register_script( 'ls-sso-admin', false, array(), LS_SSO_VERSION, true );
		wp_enqueue_script( 'ls-sso-admin' );

		// Generates the secret in the browser.
		wp_add_inline_script(
			'ls-sso-admin',
			'( function () {
	var button = document.getElementById( "ls-sso-generate" );
	if ( ! button ) { return; }
	button.addEventListener( "click", function () {
		var bytes = new Uint8Array( 32 );
		window.crypto.getRandomValues( bytes );
		var hex = Array.prototype.map.call( bytes, function ( b ) {
			return b.toString( 16 ).padStart( 2, "0" );
		} ).join( "" );
		var field = document.getElementById( "ls-sso-secret-line" );
		field.value = "define( \'LS_SSO_SECRET\', \'" + hex + "\' );";
		document.getElementById( "ls-sso-generated" ).style.display = "";
		field.focus();
		field.select();
	} );
} )();'
		);
	}

	/**
	 * Tools submenu page.
	 *
	 * @return void
	 */
	public static function add_page() {
		add_management_page(
			__( 'Cross-Site SSO', 'cross-site-sso-for-openid-connect' ),
			__( 'Cross-Site SSO', 'cross-site-sso-for-openid-connect' ),
			'manage_options',
			'cross-site-sso-for-openid-connect',
			array( __CLASS__, 'render' )
		);
	}

	public static function config_notice() {
		if ( ! current_user_can( 'manage_options' ) || LS_SSO_Config::is_configured() ) {
			return;
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || ! in_array( $screen->id, array( 'plugins', 'tools_page_cross-site-sso' ), true ) ) {
			return;
		}

		echo '<div class="notice notice-error"><p><strong>';
		esc_html_e( 'Cross-Site SSO is inactive.', 'cross-site-sso-for-openid-connect' );
		echo '</strong> ';
		esc_html_e( 'Set the shared secret and peer sites under Tools > Cross-Site SSO, or define LS_SSO_SECRET and LS_SSO_PEERS in wp-config.php. Single sign-on and logout are all switched off until then.', 'cross-site-sso-for-openid-connect' );
		echo '</p></div>';
	}

	/**
	 * Status page.
	 *
	 * @return void
	 */
	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'cross-site-sso-for-openid-connect' ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'status';
		$tab = in_array( $tab, array( 'status', 'settings', 'activity' ), true ) ? $tab : 'status';
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Cross-Site SSO', 'cross-site-sso-for-openid-connect' ); ?></h1>
			<nav class="nav-tab-wrapper">
				<a href="<?php echo esc_url( admin_url( 'tools.php?page=cross-site-sso&tab=status' ) ); ?>"
				   class="nav-tab <?php echo 'status' === $tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Status', 'cross-site-sso-for-openid-connect' ); ?>
				</a>
				<a href="<?php echo esc_url( admin_url( 'tools.php?page=cross-site-sso&tab=settings' ) ); ?>"
				   class="nav-tab <?php echo 'settings' === $tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Settings', 'cross-site-sso-for-openid-connect' ); ?>
				</a>
				<a href="<?php echo esc_url( admin_url( 'tools.php?page=cross-site-sso&tab=activity' ) ); ?>"
				   class="nav-tab <?php echo 'activity' === $tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Activity', 'cross-site-sso-for-openid-connect' ); ?>
				</a>
			</nav>
			<?php
			if ( 'activity' === $tab ) {
				self::render_activity();
			} elseif ( 'settings' === $tab ) {
				self::render_settings();
			} else {
				self::render_status();
			}
			?>
		</div>
		<?php
	}

	/**
	 * Status tab.
	 *
	 * @return void
	 */
	protected static function render_status() {
		$peers = LS_SSO_Config::peers();
		$ran   = false;
		$results = array();

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_POST['ls_sso_test'] ) && check_admin_referer( 'ls_sso_test' ) ) {
			$ran     = true;
			$results = self::run_connectivity_test( $peers );
		}
		?>
			<h2><?php esc_html_e( 'Configuration', 'cross-site-sso-for-openid-connect' ); ?></h2>
			<table class="widefat striped" style="max-width:60em">
				<tbody>
					<?php
					self::row(
						__( 'Shared secret', 'cross-site-sso-for-openid-connect' ),
						LS_SSO_Config::secret()
							? sprintf(
								/* translators: 1: Configuration source (e.g., constant or file name), 2: Security fingerprint hash */
								__( 'Set via %1$s — fingerprint %2$s (must match on every site)', 'cross-site-sso-for-openid-connect' ),
								'constant' === LS_SSO_Config::source_of( 'LS_SSO_SECRET' ) ? 'wp-config.php' : __( 'the Settings tab', 'cross-site-sso-for-openid-connect' ),
								LS_SSO_Config::secret_fingerprint()
							)
							: __( 'Missing — set it on the Settings tab or in wp-config.php', 'cross-site-sso-for-openid-connect' ),
						(bool) LS_SSO_Config::secret()
					);
					self::row(
						__( 'This site', 'cross-site-sso-for-openid-connect' ),
						LS_SSO_Config::self_origin(),
						true
					);
					self::row(
						__( 'Peers', 'cross-site-sso-for-openid-connect' ),
						$peers ? implode( ', ', $peers ) : __( 'None configured', 'cross-site-sso-for-openid-connect' ),
						! empty( $peers )
					);
					self::row(
						__( 'Role on the network', 'cross-site-sso-for-openid-connect' ),
						LS_SSO_Config::is_store()
							? __( 'Store — serves order history', 'cross-site-sso-for-openid-connect' )
							: __( 'Satellite — reads order history', 'cross-site-sso-for-openid-connect' ),
						true
					);
					self::row(
						__( 'OpenID Connect Generic', 'cross-site-sso-for-openid-connect' ),
						class_exists( 'OpenID_Connect_Generic' )
							? __( 'Active', 'cross-site-sso-for-openid-connect' )
							: __( 'Not active — silent login and profile mapping are off', 'cross-site-sso-for-openid-connect' ),
						class_exists( 'OpenID_Connect_Generic' )
					);
					self::row(
						__( 'Silent SSO', 'cross-site-sso-for-openid-connect' ),
						LS_SSO_Config::silent_enabled()
							? sprintf( /* translators: %s: transport mode, either "js" or "redirect". */
                                      __( 'On (%s transport)', 'cross-site-sso-for-openid-connect' ), LS_SSO_Config::silent_mode() )
							: __( 'Off', 'cross-site-sso-for-openid-connect' ),
						LS_SSO_Config::silent_enabled()
					);
					self::row(
						__( 'Silent login refused for', 'cross-site-sso-for-openid-connect' ),
						LS_SSO_Config::blocked_silent_roles()
							? implode( ', ', LS_SSO_Config::blocked_silent_roles() )
							: __( 'No role — every role may be signed in silently', 'cross-site-sso-for-openid-connect' ),
						! empty( LS_SSO_Config::blocked_silent_roles() )
					);
					self::row(
						__( 'Synced meta keys', 'cross-site-sso-for-openid-connect' ),
						LS_SSO_Config::meta_keys()
							? implode( ', ', LS_SSO_Config::meta_keys() )
							: __( 'None — nothing is pushed between sites', 'cross-site-sso-for-openid-connect' ),
						true
					);
					?>
				</tbody>
			</table>

			<h2><?php esc_html_e( 'Connectivity', 'cross-site-sso-for-openid-connect' ); ?></h2>
			<p class="description">
				<?php esc_html_e( 'Sends a signed request to each peer. A 403 almost always means the shared secret differs between the two sites.', 'cross-site-sso-for-openid-connect' ); ?>
			</p>

			<form method="post">
				<?php wp_nonce_field( 'ls_sso_test' ); ?>
				<?php submit_button( __( 'Test peers', 'cross-site-sso-for-openid-connect' ), 'secondary', 'ls_sso_test', false ); ?>
			</form>

			<?php if ( $ran ) : ?>
				<table class="widefat striped" style="max-width:60em;margin-top:1em">
					<tbody>
					<?php foreach ( $results as $origin => $result ) : ?>
						<?php self::row( $origin, $result['message'], $result['ok'] ); ?>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Shared secret', 'cross-site-sso-for-openid-connect' ); ?></h2>
			<p class="description" style="max-width:60em">
				<?php esc_html_e( 'The secret lives in wp-config.php, not the database, so it stays out of backups and exports and cannot drift between sites. Generate one below and paste the line into every participating site.', 'cross-site-sso-for-openid-connect' ); ?>
			</p>
			<p>
				<button type="button" class="button" id="ls-sso-generate">
					<?php esc_html_e( 'Generate a secret', 'cross-site-sso-for-openid-connect' ); ?>
				</button>
			</p>
			<p id="ls-sso-generated" style="display:none">
				<label for="ls-sso-secret-line" class="screen-reader-text">
					<?php esc_html_e( 'Generated configuration line', 'cross-site-sso-for-openid-connect' ); ?>
				</label>
				<textarea id="ls-sso-secret-line" rows="2" readonly
					style="width:100%;max-width:60em;font-family:monospace"></textarea>
				<span class="description">
					<?php esc_html_e( 'Generated in your browser. It is never sent to this server, and is not stored anywhere until you paste it into wp-config.php.', 'cross-site-sso-for-openid-connect' ); ?>
				</span>
			</p>
		<?php
	}

	/**
	 * Settings tab.
	 *
	 * @return void
	 */
	protected static function render_settings() {
		$fields = array(
			'LS_SSO_SECRET'             => array(
				'label'  => __( 'Shared secret', 'cross-site-sso-for-openid-connect' ),
				'type'   => 'secret',
				'help'   => __( 'A 64-character hex string, identical on every participating site. Once saved it is never shown again — only its fingerprint, so you can confirm all sites match.', 'cross-site-sso-for-openid-connect' ),
			),
			'LS_SSO_PEERS'              => array(
				'label'  => __( 'Peer sites', 'cross-site-sso-for-openid-connect' ),
				'type'   => 'text',
				'help'   => __( 'Comma-separated origins of the OTHER sites, e.g. https://a.example.com,https://b.example.com', 'cross-site-sso-for-openid-connect' ),
			),
			'LS_SSO_STORE'              => array(
				'label'  => __( 'Store site', 'cross-site-sso-for-openid-connect' ),
				'type'   => 'text',
				'help'   => __( 'Origin of the site running WooCommerce. The same value on every site.', 'cross-site-sso-for-openid-connect' ),
			),
			'LS_SSO_ROLE_CLAIM'         => array(
				'label'  => __( 'Role claim', 'cross-site-sso-for-openid-connect' ),
				'type'   => 'text',
				'help'   => __( 'Optional. Namespaced claim carrying roles, e.g. https://example.com/roles — must be a domain you control. The provider Auth0 discards claims namespaced under auth0.com, webtask.io or webtask.run.', 'cross-site-sso-for-openid-connect' ),
			),
			'LS_SSO_META_KEYS'          => array(
				'label'  => __( 'Synced meta keys', 'cross-site-sso-for-openid-connect' ),
				'type'   => 'text',
				'help'   => __( 'Optional. Comma-separated user meta keys allowed to travel between sites. Leave empty to sync nothing.', 'cross-site-sso-for-openid-connect' ),
			),
			'LS_SSO_BLOCK_SILENT_ROLES' => array(
				'label'  => __( 'Never sign in silently', 'cross-site-sso-for-openid-connect' ),
				'type'   => 'text',
				'help'   => __( 'Comma-separated roles refused a silent session. Interactive login still works for them. Default: administrator.', 'cross-site-sso-for-openid-connect' ),
			),
		);

		$submitted = false;
		$changed   = array();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['ls_sso_save'] ) && check_admin_referer( 'ls_sso_save_settings' ) ) {
			$submitted = true;

			foreach ( $fields as $constant => $field ) {
				if ( defined( $constant ) || ! isset( $_POST[ $constant ] ) ) {
					continue;
				}

				$value = sanitize_text_field( wp_unslash( $_POST[ $constant ] ) );

				if ( 'secret' === $field['type'] ) {
					if ( '' === $value ) {
						continue;
					}
					if ( ! preg_match( '/\A[A-Za-z0-9+\/=_-]{32,255}\z/', $value ) ) {
						add_settings_error(
							'ls_sso',
							'bad_secret',
							__( 'The shared secret was NOT saved: it must be 32 to 255 characters, with no spaces or punctuation beyond + / = _ and -.', 'cross-site-sso-for-openid-connect' )
						);
						continue;
					}
				}

				if ( LS_SSO_Config::save( $constant, $value ) ) {
					$changed[] = $field['label'];
				}
			}
		}

		settings_errors( 'ls_sso' );

		if ( $submitted ) {
			if ( ! empty( $changed ) ) {
				echo '<div class="notice notice-success is-dismissible"><p>' .
					esc_html(
						sprintf(/* translators: %s: A comma-separated list of settings that were updated/saved (e.g., Client ID, Client Secret) */
							__( 'Updated: %s', 'cross-site-sso-for-openid-connect' ),
							implode( ', ', $changed )
						)
					) . '</p></div>';
			} elseif ( ! get_settings_errors( 'ls_sso' ) ) {
				echo '<div class="notice notice-warning is-dismissible"><p>' .
					esc_html__( 'Nothing changed. The shared secret field is intentionally blank on every page load — fill it in only when you want to replace the stored value.', 'cross-site-sso-for-openid-connect' ) .
					'</p></div>';
			}
		}
		?>
		<p class="description" style="max-width:60em;margin:1em 0">
			<?php esc_html_e( 'Values defined in wp-config.php always win and are shown here read-only. Use these fields when you cannot edit that file — some managed hosts allow plugin installation but no file access.', 'cross-site-sso-for-openid-connect' ); ?>
		</p>

		<form method="post">
			<?php wp_nonce_field( 'ls_sso_save_settings' ); ?>
			<table class="form-table" role="presentation">
				<tbody>
				<?php foreach ( $fields as $constant => $field ) : ?>
					<?php
					$locked = defined( $constant );
					$source = LS_SSO_Config::source_of( $constant );
					?>
					<tr>
						<th scope="row">
							<label for="<?php echo esc_attr( $constant ); ?>">
								<?php echo esc_html( $field['label'] ); ?>
							</label>
						</th>
						<td>
							<?php if ( $locked ) : ?>
								<p>
									<strong><?php esc_html_e( 'Set in wp-config.php', 'cross-site-sso-for-openid-connect' ); ?></strong>
									<?php if ( 'secret' !== $field['type'] ) : ?>
										— <code><?php echo esc_html( constant( $constant ) ); ?></code>
									<?php endif; ?>
								</p>
							<?php elseif ( 'secret' === $field['type'] ) : ?>
								<input type="password" class="regular-text" autocomplete="new-password"
									id="<?php echo esc_attr( $constant ); ?>"
									name="<?php echo esc_attr( $constant ); ?>" value=""
									placeholder="<?php echo esc_attr__( 'Leave blank to keep the current secret', 'cross-site-sso-for-openid-connect' ); ?>" />
							<?php else : ?>
								<input type="text" class="regular-text"
									id="<?php echo esc_attr( $constant ); ?>"
									name="<?php echo esc_attr( $constant ); ?>"
									value="<?php echo esc_attr( self::current_value( $constant ) ); ?>" />
							<?php endif; ?>

							<?php if ( 'secret' === $field['type'] ) : ?>
								<?php if ( LS_SSO_Config::secret() ) : ?>
									<p style="margin-top:.6em">
										<span style="color:#1f6f4a" aria-hidden="true">&#9679;</span>
										<strong><?php esc_html_e( 'A secret is stored.', 'cross-site-sso-for-openid-connect' ); ?></strong>
										<?php esc_html_e( 'Fingerprint:', 'cross-site-sso-for-openid-connect' ); ?>
										<code><?php echo esc_html( LS_SSO_Config::secret_fingerprint() ); ?></code>
										<br>
										<?php esc_html_e( 'This exact fingerprint must appear on every participating site. The field above stays blank by design — the secret is never displayed again.', 'cross-site-sso-for-openid-connect' ); ?>
									</p>
								<?php else : ?>
									<p style="margin-top:.6em">
										<span style="color:#a32020" aria-hidden="true">&#9679;</span>
										<strong><?php esc_html_e( 'No secret is stored yet.', 'cross-site-sso-for-openid-connect' ); ?></strong>
										<?php esc_html_e( 'Nothing works until one is set here or in wp-config.php.', 'cross-site-sso-for-openid-connect' ); ?>
									</p>
								<?php endif; ?>
							<?php endif; ?>

							<p class="description">
								<?php echo esc_html( $field['help'] ); ?>
								<?php if ( 'option' === $source ) : ?>
									<br><em><?php esc_html_e( 'Currently stored in the database. Moving it to wp-config.php keeps it out of backups and exports.', 'cross-site-sso-for-openid-connect' ); ?></em>
								<?php endif; ?>
							</p>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<?php submit_button( __( 'Save settings', 'cross-site-sso-for-openid-connect' ), 'primary', 'ls_sso_save' ); ?>
		</form>
		<?php
	}

	/**
	 * Current stored value.
	 *
	 * @param string $constant Constant name.
	 * @return string
	 */
	protected static function current_value( $constant ) {
		switch ( $constant ) {
			case 'LS_SSO_PEERS':
				return implode( ',', LS_SSO_Config::peers() );
			case 'LS_SSO_STORE':
				return LS_SSO_Config::store_origin();
			case 'LS_SSO_ROLE_CLAIM':
				return LS_SSO_Config::role_claim();
			case 'LS_SSO_META_KEYS':
				return implode( ',', LS_SSO_Config::meta_keys() );
			case 'LS_SSO_BLOCK_SILENT_ROLES':
				return implode( ',', LS_SSO_Config::blocked_silent_roles() );
		}
		return '';
	}

	/**
	 * Activity tab.
	 *
	 * @return void
	 */
	protected static function render_activity() {
		if ( ! LS_SSO_Logger::is_ready() ) {
			echo '<p>' . esc_html__( 'The activity table has not been created yet. Reload this page once the plugin has finished initializing.', 'cross-site-sso-for-openid-connect' ) . '</p>';
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended 
		$filters = array(
			'event'  => isset( $_GET['event'] ) ? sanitize_key( wp_unslash( $_GET['event'] ) ) : '',
			'status' => isset( $_GET['status'] ) ? sanitize_key( wp_unslash( $_GET['status'] ) ) : '',
			'page'   => isset( $_GET['paged'] ) ? absint( wp_unslash( $_GET['paged'] ) ) : 1,
		);
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		$result = LS_SSO_Logger::query( $filters );
		$events = LS_SSO_Logger::distinct( 'event' );
		?>
		<form method="get" style="margin:1em 0">
			<input type="hidden" name="page" value="cross-site-sso" />
			<input type="hidden" name="tab" value="activity" />
			<label for="ls-sso-filter-event" class="screen-reader-text">
				<?php esc_html_e( 'Filter by event', 'cross-site-sso-for-openid-connect' ); ?>
			</label>
			<select name="event" id="ls-sso-filter-event">
				<option value=""><?php esc_html_e( 'All events', 'cross-site-sso-for-openid-connect' ); ?></option>
				<?php foreach ( $events as $event ) : ?>
					<option value="<?php echo esc_attr( $event ); ?>" <?php selected( $filters['event'], $event ); ?>>
						<?php echo esc_html( $event ); ?>
					</option>
				<?php endforeach; ?>
			</select>
			<label for="ls-sso-filter-status" class="screen-reader-text">
				<?php esc_html_e( 'Filter by status', 'cross-site-sso-for-openid-connect' ); ?>
			</label>
			<select name="status" id="ls-sso-filter-status">
				<option value=""><?php esc_html_e( 'Any status', 'cross-site-sso-for-openid-connect' ); ?></option>
				<option value="success" <?php selected( $filters['status'], 'success' ); ?>>
					<?php esc_html_e( 'Success', 'cross-site-sso-for-openid-connect' ); ?>
				</option>
				<option value="failure" <?php selected( $filters['status'], 'failure' ); ?>>
					<?php esc_html_e( 'Failure', 'cross-site-sso-for-openid-connect' ); ?>
				</option>
			</select>
			<?php submit_button( __( 'Filter', 'cross-site-sso-for-openid-connect' ), 'secondary', '', false ); ?>
		</form>

		<table class="widefat striped">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Time (UTC)', 'cross-site-sso-for-openid-connect' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Event', 'cross-site-sso-for-openid-connect' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Direction', 'cross-site-sso-for-openid-connect' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Peer', 'cross-site-sso-for-openid-connect' ); ?></th>
					<th scope="col"><?php esc_html_e( 'User', 'cross-site-sso-for-openid-connect' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Status', 'cross-site-sso-for-openid-connect' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Detail', 'cross-site-sso-for-openid-connect' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php if ( empty( $result['rows'] ) ) : ?>
				<tr><td colspan="7"><?php esc_html_e( 'No activity recorded.', 'cross-site-sso-for-openid-connect' ); ?></td></tr>
			<?php else : ?>
				<?php foreach ( $result['rows'] as $row ) : ?>
					<tr>
						<td><?php echo esc_html( $row['logged_at'] ); ?></td>
						<td><code><?php echo esc_html( $row['event'] ); ?></code></td>
						<td><?php echo esc_html( $row['direction'] ); ?></td>
						<td><?php echo esc_html( $row['peer'] ); ?></td>
						<td>
							<?php echo (int) $row['user_id'] ? esc_html( (string) (int) $row['user_id'] ) : '&mdash;'; ?>
						</td>
						<td>
							<span style="color:<?php echo 'failure' === $row['status'] ? '#a32020' : '#1f6f4a'; ?>">
								<?php echo esc_html( $row['status'] ); ?>
							</span>
						</td>
						<td><?php echo esc_html( (string) $row['detail'] ); ?></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>

		<?php if ( $result['pages'] > 1 ) : ?>
			<div class="tablenav"><div class="tablenav-pages">
				<?php
				echo wp_kses_post(
					paginate_links(
						array(
							'base'      => add_query_arg( 'paged', '%#%' ),
							'format'    => '',
							'current'   => max( 1, (int) $filters['page'] ),
							'total'     => (int) $result['pages'],
							'prev_text' => '&laquo;',
							'next_text' => '&raquo;',
						)
					)
				);
				?>
			</div></div>
		<?php endif; ?>

		<p class="description">
			<?php
			printf(/* translators: %d: The number of days logs are kept before being purged. */
				esc_html__( 'Entries older than %d days are deleted automatically.', 'cross-site-sso-for-openid-connect' ),
				(int) apply_filters( 'ls_sso_log_retention_days', LS_SSO_Logger::RETENTION_DAYS )
			);
			?>
		</p>
		<?php
	}

	/**
	 * Check each peer with a harmless signed request.
	 *
	 * @param array $peers Peer origins.
	 * @return array<string,array{ok:bool,message:string}>
	 */
	protected static function run_connectivity_test( array $peers ) {
		$out = array();

		foreach ( $peers as $origin ) {
			// A subject that matches nobody: the peer answers 200 with
			// reason "unknown_subject", proving the signature verified without
			// changing any data.
			$result = LS_SSO_Http::post(
				$origin,
				'/cross-site-sso-for-openid-connect/v1/usermeta',
				array(
					'subject' => 'ls-sso-connectivity-check',
					'meta'    => new stdClass(),
				),
				10
			);

			if ( is_wp_error( $result ) ) {
				$out[ $origin ] = array(
					'ok'      => false,
					'message' => self::explain_failure( $result ),
				);
				continue;
			}

			$out[ $origin ] = array(
				'ok'      => true,
				'message' => __( 'Signed request accepted — this peer shares your secret.', 'cross-site-sso-for-openid-connect' ),
			);
		}

		return $out;
	}

	/**
	 * Peer failure.
	 *
	 * The status codes:
	 *
	 *   404 — no route. 
	 *   503 — the plugin is there but has no secret or not configured yet.
	 *   403 — the request was signed and rejected. 
	 *
	 * @param WP_Error $error The failure.
	 * @return string
	 */
	protected static function explain_failure( WP_Error $error ) {
		$code = $error->get_error_code();

		if ( 'ls_sso_http_404' === $code ) {
			return __( 'Not found (404). The plugin is not installed or not activated on that site. Your secret was never checked, so this says nothing about whether the secrets match.', 'cross-site-sso-for-openid-connect' );
		}

		if ( 'ls_sso_http_503' === $code ) {
			return __( 'Unconfigured (503). The plugin is installed on that site but has no shared secret or peer list yet, configure and test again.', 'cross-site-sso-for-openid-connect' );
		}

		if ( 'ls_sso_http_403' === $code ) {
			return __( 'Rejected (403). That site received the signed request and refused it since the shared secret differs. Please compare the fingerprint on sites, they must be identical.', 'cross-site-sso-for-openid-connect' );
		}

		if ( 'ls_sso_http_401' === $code ) {
			return __( 'Unauthorized (401). There is something blocking the request, such as a HTTP basic auth or firewall.', 'cross-site-sso-for-openid-connect' );
		}

		if ( 'ls_sso_bad_body' === $code ) {
			return __( 'No JSON response, a caching layer is probably intercepting the REST route.', 'cross-site-sso-for-openid-connect' );
		}

		return $error->get_error_message();
	}

	/**
	 * Status row.
	 *
	 * @param string $label 
	 * @param string $value
	 * @param bool   $ok
	 * @return void
	 */
	protected static function row( $label, $value, $ok ) {
		?>
		<tr>
			<th scope="row" style="width:14em"><?php echo esc_html( $label ); ?></th>
			<td>
				<span aria-hidden="true" style="color:<?php echo $ok ? '#1f6f4a' : '#a32020'; ?>">&#9679;</span>
				<span class="screen-reader-text">
					<?php echo esc_html( $ok ? __( 'OK:', 'cross-site-sso-for-openid-connect' ) : __( 'Problem:', 'cross-site-sso-for-openid-connect' ) ); ?>
				</span>
				<?php echo esc_html( $value ); ?>
			</td>
		</tr>
		<?php
	}
}
