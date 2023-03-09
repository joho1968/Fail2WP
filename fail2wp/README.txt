=== Fail2WP ===
Contributors: joho68, webbplatsen
Donate link: https://code.webbplatsen.net/wordpress/fail2wp/
Tags: fail2ban, authentication, security, admin, firewall
Requires at least: 5.4.0
Tested up to: 6.1.1
Requires PHP: 7.2
Stable tag: 1.2.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Security plugin for WordPress with support for fail2ban. Tested with WordPress 5.5+ and PHP 7.4.

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
* This plugin has been tested with **WordPress 5.5+** at the time of this writing
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

= 1.2.0 =
* Verified with WordPress 6.1.1
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

Fail2WP is sponsored by [WebbPlatsen i Sverige AB](https://webbplatsen.se), Stockholm, Sweden.

Commercial support and customizations for this plugin is available from WebbPlatsen i Sverige AB in Stockholm, Sweden.

If you find this plugin useful, the author is happy to receive a donation, good review, or just a kind word.

If there is something you feel to be missing from this plugin, or if you have found a problem with the code or a feature, please do not hesitate to reach out to support@webbplatsen.se.

This plugin can also be downloaded from [code.webbplatsen.net](https://code.webbplatsen.net/wordpress/fail2wp/) and [GitHub](https://github.com/joho1968/fail2wp)

More detailed documentation is available at [code.webbplatsen.net/documentation/fail2wp/](https://code.webbplatsen.net/documentation/fail2wp/)

Kudos to [Thomas Lutz](https://github.com/tholu).
