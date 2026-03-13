=== Fail2WP ===
Contributors: joho68, webbplatsen
Donate link: https://code.webbplatsen.net/wordpress/fail2wp/
Tags: fail2ban, authentication, security, admin, firewall
Requires at least: 5.4.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.2.5
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Security plugin for WordPress with support for fail2ban. Tested with WordPress 5.5+ and PHP 7.4-8.4

== Description ==

This WordPress plugin provides security functionality and integration with fail2ban.

It does not require fail2ban to function.

Basic security functionality includes:

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

The plugin also plays nicely with Fail2ban, which is an advanced way of blocking IP addresses dynamically upon suspicious behavior.

Other notes:

* This plugin **may** work with earlier versions of WordPress
* This plugin has been tested with **WordPress 5.5+ and 6.x** at the time of this writing
* This plugin has been tested with **PHP 7.4, 8.1, 8.2, and 8.3** at the time of this writing
* Local syntax/runtime compatibility checks have also been run on **PHP 8.4**
* This plugin optionally makes use of `mb_` PHP functions
* This plugin may create entries in your PHP error log (if active)
* This plugin contains no Javascript
* This plugin contains no tracking code and does not store any information about users

== Installation ==

This section describes how to install the plugin and get it working.

1. Upload the contents of the `fail2wp` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Configure the basic settings
4. To enable fail2ban integration, you will need to modify your fail2ban configuration. Please see `FAIL2BAN.txt` or `FAIL2BAN.md`.

== Frequently Asked Questions ==

= Is the plugin locale aware =

Fail2WP uses standard WordPress functionality to handle localization/locale. The native language localization of the plugin is English. It has been translated to Swedish by the author.

= Are there any incompatibilities =

This is a hard question to answer. There are no known incompatibilities.

== Changelog ==

= 1.2.5 =
* Added an admin-side helper to fetch current Cloudflare IPv4 and IPv6 ranges into the settings form without auto-saving
* Improved the Cloudflare tab UX so the ranges and refresh controls stay available but are visually muted when Cloudflare support is disabled
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
* Fixed PHP warning for json_decode() call, this did not impact functionality
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
