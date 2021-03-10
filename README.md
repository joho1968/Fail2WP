[![Software License](https://img.shields.io/badge/License-GPL%20v2-green.svg?style=flat-square)](LICENSE) [![PHP 7.2\+](https://img.shields.io/badge/PHP-7.2-blue?style=flat-square)](https://php.net) [![WordPress 5](https://img.shields.io/badge/WordPress-5.7-orange?style=flat-square)](https://wordpress.org)

# Fail2WP

Security plugin for WordPress with support for Fail2ban and Cloudflare. Tested with WordPress 5.5+.

## Description

This WordPress plugin provides security functionality and integration with Fail2ban and Cloudflare.

The WordPress slug is `fail2wp`.

The plugin is also available on [wordpress.org](https://wordpress.org/plugins/fail2wp/)

Basic security functionality includes:

* Disabling login with username (require e-mail address)
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

The plugin also plays nicely with Fail2ban, which is an advanced way of blocking IP addresses dynamically upon suspicious behavior.

### Other notes

* This plugin `may` work with earlier versions of WordPress
* This plugin has been tested with `WordPress 5.5+` at the time of this writing
* This plugin optionally makes use of `mb_` PHP functions
* This plugin may create entries in your PHP error log (if active)
* This plugin contains no Javascript
* This plugin contains no tracking code and does not store any information about users

## Installation

This section describes how to install the plugin and get it working.

1. Upload the `fail2wp` folder to the `/wp-content/plugins/` directory (or install it from the 'Plugins' menu in WordPress)
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Configure the basic settings

## Frequently Asked Questions

### Is the plugin locale aware

Fail2WP uses standard WordPress functionality to handle localization/locale. The native language localization of the plugin is English. It has been translated to Swedish by the author.

All logging to system logs (i.e. `php.log` or `auth.log`) is done in English.

### Are there any incompatibilities

This is a hard question to answer. There are no known incompatibilities.

### How do I make this work with Fail2ban

1. Copy the file `fail2wp.conf` to `/etc/fail2ban/filter.d`
2. Create an entry in `/etc/fail2ban/jail.local` as per the instructions in `fail2wp.conf`
3. In the plugin configuration, enable logging of Unsuccessful logins and possibly other triggers
4. Re-start Fail2ban

## Changelog

### 1.1.0
* Added minimum username length
* Added blocking of specific usernames (user registration)
* Added requiring e-mail address matching setting
* Added warning about new user role setting
* Added blocking of portions or all of WordPress REST API
* Added setting to disable RSS and Atom feeds
* Added setting to remove "Generator" information from HTML and feeds
* Minor corrections and general improvements

### 1.0.0
* Initial release

## Upgrade Notice

### 1.1.0
* Install the new version and walk through the settings.

### 1.0.0
* Initial release

## License

Please see [LICENSE](LICENSE) for a full copy of GPLv2

Copyright (C) 2020 [Joaquim Homrighausen](https://github.com/joho1968); all rights reserved.

This file is part of Fail2WP. Fail2WP is free software.

You may redistribute it and/or modify it under the terms of the GNU General Public License version 2, as published by the Free Software Foundation.

Fail2WP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with the Fail2WP package. If not, write to:

```
The Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor
Boston, MA  02110-1301, USA.
```

## Credits

The Fail2WP WordPress Plugin was written by Joaquim Homrighausen while converting :coffee: into code.

Fail2WP is sponsored by [WebbPlatsen i Sverige AB](https://webbplatsen.se), Stockholm, :sweden:

Commercial support and customizations for this plugin is available from WebbPlatsen i Sverige AB in Stockholm, :sweden:

If you find this plugin useful, the author is happy to receive a donation, good review, or just a kind word.

If there is something you feel to be missing from this plugin, or if you have found a problem with the code or a feature, please do not hesitate to reach out to support@webbplatsen.se.

This plugin can also be downloaded from [code.webbplatsen.net](https://code.webbplatsen.net/wordpress/fail2wp/) and [WordPress.org](https://wordpress.org/plugins/fail2wp/)

More detailed documentation is available at [code.webbplatsen.net/documentation/fail2wp/](https://code.webbplatsen.net/documentation/fail2wp/)

Kudos to [Vincent Le Moign and Webalys](https://webalys.com) and [Thomas Lutz](https://github.com/tholu)

### External references

These links are not here for any sort of endorsement or marketing, they're purely for informational purposes.

* me; :monkey: https://joho.se and https://github.com/joho1968
* WebbPlatsen; https://webbplatsen.se and https://code.webbplatsen.net
