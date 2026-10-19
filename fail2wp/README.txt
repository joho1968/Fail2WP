=== Fail2WP ===
Contributors: joho68, webbplatsen
Donate link: https://code.webbplatsen.net/wordpress/fail2wp/
Tags: fail2ban, authentication, security, admin, firewall
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.4.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

WordPress security plugin. Requires WordPress 6.2+ and PHP 7.4+.

== Description ==

* Adds security controls to WordPress.
* fail2ban integration is optional.

Security features:

* Disabling login with username (require e-mail address)
* Allow/Deny login from IP address, hostname (including wildcard support)
* Preventing user enumeration (?author=nnn)
* Less detailed error messages on login failures
* Minimum username length
* Blocking specific usernames from being used to register new users
* Requiring e-mail address matching for new user registrations
* Warning about new user role setting
* Blocking of portions or all of WordPress REST API
* Disabling of RSS and Atom feeds
* Removal of "Generator" information from HTML and feeds
* Detection of Cloudflare IP addresses for logging of actual IP addresses
* Blocking/Allowing logins from IP addresses, IP ranges, and/or hostnames
* Partially or fully disable XMLRPC access
* Monitoring administrator accounts for unexpected role/account changes

* fail2ban can dynamically block IP addresses after suspicious activity.

Other notes:

* Requires WordPress 6.2+ and PHP 7.4+.
* PHP compatibility checks: 7.4, 8.1, 8.2, 8.3, and 8.4.
* Uses `mb_` PHP functions when available.
* May write to the PHP error log when logging is enabled.
* Contains no JavaScript or tracking code.
* Optional IP blocking stores IP addresses and security-event timestamps. Administrator monitoring stores administrator IDs and login names.

Reverse proxy configuration:

* Available since 1.4.0.
* Setting: FAIL2WP_TRUSTED_PROXIES in wp-config.php, before wp-settings.php loads.
* Value: array of proxy IPv4/IPv6 addresses or CIDRs.

    define( 'FAIL2WP_TRUSTED_PROXIES', [ '192.0.2.10', '2001:db8:1234::/48' ] );

* Replace the examples with your actual proxy addresses.
* List directly connected proxy peers, identified by REMOTE_ADDR.
* Hostnames and wildcards: unsupported for this constant.
* Undefined or empty array: X-Real-IP ignored.
* Accepted header: one valid IP from a listed proxy.
* Missing or invalid header: peer address used.
* Proxy requirement: overwrite client-supplied X-Real-IP.
* Multiple proxy hops: final proxy supplies the verified visitor IP.
* X-Forwarded-For and address chains: unsupported.
* Proxy trust does not bypass login restrictions or IP bans.
* Scope: entire WordPress installation; excluded from settings exports.
* Server already supplies a verified REMOTE_ADDR: usually no constant needed.
* Cloudflare: enabled setting, matching source range, valid CF-Connecting-IP; takes precedence.
* Upgrade: configure trusted proxies before updating an existing X-Real-IP deployment.
* Verify client addresses and login access on staging.
* Login/bypass hostname wildcards: separate feature; forward-confirmed reverse DNS required.

== Installation ==

1. Upload the `fail2wp` folder to `/wp-content/plugins/`.
2. Activate Fail2WP from the Plugins menu.
3. Configure the basic settings.
4. For fail2ban integration, follow `FAIL2BAN.txt` or `FAIL2BAN.md`.

== Frequently Asked Questions ==

= Is the plugin locale aware =

* Uses WordPress localization functions.
* Default language: English.
* Swedish translation by the author.

= Are there any incompatibilities =

* No known incompatibilities.

== Changelog ==

= 1.4.0 =

* Fixed client-IP spoofing through X-Real-IP.
* Added FAIL2WP_TRUSTED_PROXIES for proxy IPs and CIDRs.
* Enforced Login IP rules before login processing.
* Extended REST blocks to child routes, trailing slashes, and case variants.
* Preserved REST discovery for authenticated and bypassed clients.
* Required forward-confirmed reverse DNS for hostname wildcards.
* Fixed hostname results on the first DNS lookup.
* Removed control characters from security log records.
* Restricted imports to registered settings; validated imported values.
* Escaped ignored import names.
* Fixed Cloudflare enablement and DNS-cache exports.
* Connected Login IP deny events to local ban accounting.
* Updated compatibility metadata for WordPress 7.1.
* Added security and WordPress regression checks.
* Documented fail2ban 1.0.x use with Fail2WP 1.3.0.
* Added explicit validation for checkbox values and role selections.
* Retained previous settings on invalid input; added validation notices.
* Preserved JSON settings during repeated sanitization.
* Removed duplicate translation calls from role renderers.
* Raised the minimum WordPress version to 6.2.
* Prepared IP-blocking table names with identifier placeholders.
* Rejected malformed settings exports before import.
* Escaped disabled-feed text and links; validated XML-RPC charset output.
* Removed a duplicate import nonce field.

= 1.3.0 =
* Added optional built-in IP blocking with configurable event threshold, observation window, and ban duration
* Added exact-IP sitewide 403 enforcement, cache-suppression headers, local block-page rendering, and Cloudflare client-IP handling
* Added active-ban management and exact-IP bypass entries in wp-admin
* Added import/export support for IP-blocking configuration and validated active-ban snapshots
* Added manual exact-IP ban creation and expanded trusted bypass entries to support IPs, CIDR ranges, hostnames, and hostname wildcards
* Added administrator baseline monitoring, immediate hook checks, hourly reconciliation, and syslog alerts
* Added a missing-object-cache notice; uncached ban checks use the database

= 1.2.6 =
* Fixed false REST block logs when REST blocking was disabled
* Fixed false REST namespace blocks with user-enumeration handling active
* Made blocked REST logs respect the "Log blocked requests" setting
* Verified with WordPress 6.9
* Updated internal version metadata

= 1.2.5 =
* Added Cloudflare IPv4/IPv6 range refresh in wp-admin; changes require Save Changes
* Muted disabled Cloudflare range controls; editing and refresh remain available
* Changed disabled feed requests to return `404` instead of redirecting to the home page
* Extended user enumeration blocking/logging to cover unauthenticated REST users endpoints
* Fixed the REST `users` route block so it also covers individual user endpoints
* Fixed REST route blocking so route-only rules are activated correctly
* Fixed REST handling so logged in and authenticated requests bypass REST blocking
* Fixed override IP handling for security/fail2ban alert messages
* Fixed IPv6 CIDR validation for login allow and deny lists
* Removed PHP 8.2 and PHP 8.3 dynamic property deprecations
* Fixed PHP 8.4 syslog signature deprecation while keeping PHP 7.4 compatibility
* Refreshed the bundled `php-cidr-match` library from current upstream
* Updated translation assets, including the Cloudflare refresh flow and Swedish admin strings
* Updated internal version metadata

= 1.2.4 =
* Verified with WordPress 6.8 and WordPress 6.9
* Removed PHP 7.2 compatibility (PHP 7.4 or above is now required)

= 1.2.3 =
* Verified with WordPress 6.7
* Verified with Plugin Check (PCP)
* Fixed issue when requiring REST API authentication and IPv4/IPv6 bypass was configured
* Fixed issue with uninitialized variable in XML-RPC handling
* Fixed a json_decode() warning without changing behavior
* Corrected some Swedish translations
* Corrected some checks for `uninstall.php` and made it more WP-CLI compatible

= 1.2.2 =
* Verified with WordPress 6.6
* Improved code for role notification settings (PR#2)
* Improved code for e-mail checking for new user registrations (PR#1)
* Thanks to philscott-rg and Edward Casbon

= 1.2.1 =
* Verified with WordPress 6.5.2
* Updated "About" information

= 1.2.0 =
* Verified with WordPress 6.2.2 and PHP 8.1.20
* Added support for allow/deny list for login (IP address, hostname with wildcard support)
* Added entry in fail2wp.conf example fail2ban configuration for allow/deny login
* Corrected typo in fail2wp.conf example fail2ban configuration, CHECK AGAINST YOURS!
* Added support for HTTP_X_REAL_IP (X-Real-IP) header to "decode" actual remote IP address
* Added support for partially or fully disabling XMLRPC
* Added entry in fail2wp.conf example fail2ban configuration for XMLRPC access attempts

= 1.1.2 =
* Verified with WordPress 5.8.3
* Fixes for various PHP warning messages

= 1.1.1 =
* Verified with WordPress 5.8

= 1.1.0 =
* Added minimum username length
* Added blocking of specific usernames (user registration)
* Added requiring e-mail address matching setting
* Added warning about new user role setting
* Added blocking of portions or all of WordPress REST API
* Added setting to disable RSS and Atom feeds
* Added setting to remove "Generator" information from HTML and feeds
* Minor corrections and general improvements

= 1.0.0 =
* Initial release

== Upgrade Notice ==

= 1.4.0 =

* Requires WordPress 6.2+.
* Before upgrading: set FAIL2WP_TRUSTED_PROXIES or supply a verified REMOTE_ADDR.
* Proxies must overwrite client-supplied X-Real-IP.
* Hostname wildcards require forward-confirmed reverse DNS.

= 1.3.0 =
* Configure IP blocking only after adding any trusted administrative IP addresses to the bypass list.

= 1.2.6 =
* Install the new version.

= 1.2.5 =
* Install the new version.

= 1.2.0 =
* Install the new version and walk through the settings.
* Check your fail2ban configuration against the supplied sample fail2wp.conf!

= 1.1.2 =
* Install the new version.

= 1.1.1 =
* Install the new version and walk through the settings.

= 1.1.0 =
* Install the new version and walk through the settings.

= 1.0.0 =
* Initial release

== Credits ==

The Fail2WP Plugin was written by Joaquim Homrighausen while converting caffeine into code.

Fail2WP is sponsored by [WebbPlatsen i Sverige AB](https://webbplatsen.se), Sweden.

Copyright 2020-2026 Joaquim Homrighausen; all rights reserved.

Commercial support and customizations for this plugin is available from WebbPlatsen i Sverige AB in Sweden.

If you find this plugin useful, the author is happy to receive a donation, good review, or just a kind word.

If there is something you feel to be missing from this plugin, or if you have found a problem with the code or a feature, please do not hesitate to reach out to support@webbplatsen.se.

This plugin can also be downloaded from [code.webbplatsen.net](https://code.webbplatsen.net/wordpress/fail2wp/) and [GitHub](https://github.com/joho1968/fail2wp)

More detailed documentation is available at [code.webbplatsen.net/documentation/fail2wp/](https://code.webbplatsen.net/documentation/fail2wp/)

Kudos to [Thomas Lutz](https://github.com/tholu).
