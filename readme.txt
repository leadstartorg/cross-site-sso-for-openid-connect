=== Cross-Site SSO for OpenID Connect ===
Contributors: leadstartorg
Tags: sso, openid connect, single sign-on, oidc, woocommerce
Requires at least: 5.9
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

The plugin provides a single sign-on, logout and signed cross-site connection for separate WordPress installs sharing one OpenID Connect provider.

== Description ==

The plugin is an addon to the **OpenID Connect Generic** plugin which authenticates a user on each site. 

**Single sign-on.** The plugin performs an OpenID Connect authorization against your provider. If the provider session exists, the visitor is signed in with no click and no password prompt. 

**Single logout.** If you logout on a site you are logged out of them all. This happens through a signed top-level redirect chain that visits each configured site in turn and
ends at your provider's end-session endpoint. 

**Order history.** The sites without WooCommerce can display a signed-in customer's order history with the `[cross_site_orders]` shortcode. 

= Design notes =

This plugin deliberately does not replicate users, passwords, or orders between
sites. Your identity provider is the source of truth for identity; the site with WooCommerce is the source of truth for orders. 

= Roles and sign-on =

By default, silent authentication is disabled for administrators to prevent the exploitation of hijacked provider sessions; however, administrative access to the plugin remains fully available. If your organization requires administrative roles to be included in Single Sign-On (SSO), you can modify this behavior using the LS_SSO_BLOCK_SILENT_ROLES constant (configured as a comma-separated list of role slugs, or left empty to permit all roles). Alternatively, you can utilize the ls_sso_block_silent_roles filter.

= Requirements =

* The [OpenID Connect Generic](https://wordpress.org/plugins/daggerhart-openid-connect-generic/) plugin, active and configured, on every participating site.
* An OpenID Connect provider (Auth0, Keycloak, Okta, Entra ID and others).
* HTTPS on every site.
* WooCommerce, on the store site only if you want order data.

== Installation ==

1. Install and configure **OpenID Connect Generic** on every site first, and
   confirm that signing in works on each one individually.
2. Install and activate this plugin on every site.
3. Generate one shared secret, to be used by all sites:
   `php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"`
   The plugin's settings screen also has a **Generate** button that produces one
   in your browser without sending it to any server.
4. Configure each site, either in `wp-config.php` (preferred) or under
   **Tools > Cross-Site SSO > Settings** if you cannot edit that file.
   `LS_SSO_PEERS` lists the *other* sites, so it differs per site, the secret and
   the store are identical on all sites:

   `define( 'LS_SSO_SECRET', 'your-64-character-hex-secret' );`
   `define( 'LS_SSO_PEERS',  'https://second-site.com,https://third-site.com' );`
   `define( 'LS_SSO_STORE',  'https://store-site.com' );`

   Sites may mix the two methods as long as the secret matches.

5. Visit **Tools → Cross-Site SSO** and run **Test peers** on each site.
6. In OpenID Connect Generic, enable **Alternate Redirect URI**, then re-save
   Settings → Permalinks. Register each site's `/openid-connect-authorize` URL
   with your provider.

== Frequently Asked Questions ==

= Where should the shared secret live? =

In `wp-config.php`, if you can edit. A signing key in the options table is in every database backup and every export handed to a contractor, and is reachable by any vulnerability that discloses options.

If you cannot edit that file, many managed hosts allow plugin installation and no file access at all, set it under **Tools > Cross-Site SSO > Settings** instead. The option is stored with autoload off and is never displayed again after saving. A constant, when defined, always wins and the field becomes read-only.

The screen shows a short fingerprint of the secret, so you can confirm every site holds the same value. When the fingerprints match, this mean matching secrets; while a mismatch explains the 403 errors.

= What does the status codes that mean? =

The status code is the diagnosis, and these are unrelated:

* **404** — no REST route on that site, so the plugin is not installed or not activated.
* **503** — the plugin is installed but has no secret or not configured yet.
* **403** — the request was signed, received, but refused. 

You have to work through the sites in order: install and activate on sites, then configure and test.

= Can I mix wp-config.php constants and the Settings tab across sites? =

Yes, each site resolves each setting independently: the constant if one is defined, the stored option otherwise. A site with file access can use constants while another uses the Settings screen, as long as the secret matches, compare the fingerprints to confirm.

= Do all sites need the same plugin version? =

They interoperate across versions: the signing format, headers, REST routes and logout tickets have not changed since 1.0.0. When running the same version everywhere is still recommended, because newer versions add local behavior (for example, refusing silent sign-on for administrators) that only applies where installed.

= Can I install it in mu-plugins on some sites and as a normal plugin on others? =

Yes, per site. What you must not do is install it in **both** places on the **same** site: the classes then load twice from two paths, which is a fatal error. The plugin detects this, stops loading, and shows an admin notice naming the file that is actually running.

= Can I run this on a host with no SFTP access? =

Yes, every setting can be entered on the Settings tab. The plugin only needs to be installable and able to make outbound HTTPS requests.

= What role do new users get? =

Whatever **Settings > General > New User Default Role** says on that site normally `subscriber`. OpenID Connect Generic does not set a role when it creates the account, so `wp_insert_user()` falls back to that option., changing the setting is usually the whole answer, no code is needed.

In order to decide the role per user instead, use the `ls_sso_map_roles` filter. The plugin runs on every SSO login, including when no role claim is configured:

`add_filter( 'ls_sso_map_roles', function ( $roles, $incoming, $user ) {`
`    return in_array( 'staff', $incoming, true ) ? array( 'editor' ) : array( 'customer' );`
`}, 10, 3 );`

Administrators are never reassigned by this filter, so a misconfigured provider cannot demote a user.

If you map from a provider claim, note that **Auth0 silently drops custom claims
namespaced under an Auth0 domain** — `auth0.com`, `webtask.io` and `webtask.run`
are all rejected as namespaces. Please use a domain you control. A claim namespaced to `your-tenant.auth0.com` never
arrives, and role mapping then appears broken with no error.

= Does this require WooCommerce? =

No, WooCommerce is only needed for the optional order-history feature, and only
on the one site that runs the store.

= Does this work with WordPress Multisite? =

The plugin is built for the opposite case: separate installations with separate
databases. A multisite network already shares users, sessions and logout through
WordPress core, and does not need this plugin.

= What happens when a peer site is offline? =

All updates are queued and retried with backoff, using Action Scheduler when
available and WP-Cron otherwise. The order history requests uses a timeout and a
cached result, so a slow WooCommerce site never blocks a page for a visitor.

= Does SSO redirect every visitor, including search engines? =

No, crawlers are excluded, the check runs at most once per browser per 30
minutes, and by default the check is performed in the browser rather than as a
server-side redirect, so it cannot be captured by a page cache.

= What personal data does this store? =

The plugin stores no personal data of its own. The activity log records the
event type, the peer site, the route, a WordPress user ID, and success or
failure and never request bodies, meta values, tokens, or signatures. Rows are
deleted automatically after 30 days, filterable via `ls_sso_log_retention_days`. 

When uninstalling the plugin, it removes the log table entirely.

== Screenshots ==

No Screenshots at this time.

== Changelog ==

= 1.0.0 =
* Initial release: SSO, single logout, order history.
