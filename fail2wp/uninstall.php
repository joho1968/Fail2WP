<?php
/**
 * Fail2WP is uninstalled.
 *
 * @link              https://code.webbplatsen.net/wordpress/fail2wp/
 * @since             1.0.0
 * @package           Fail2WP
 * @author            Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * uninstall.php
 * Copyright (C) 2021 Joaquim Homrighausen; all rights reserved.
 * Development sponsored by WebbPlatsen i Sverige AB, www.webbplatsen.se
 *
 * This file is part of Fail2WP. Fail2WP is free software.
 *
 * You may redistribute it and/or modify it under the terms of the
 * GNU General Public License version 2, as published by the Free Software
 * Foundation.
 *
 * Fail2WP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the Fail2WP package. If not, write to:
 *  The Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02110-1301, USA.
 */

// Don't load directly
defined( 'ABSPATH' ) || die( '-1' );
// If uninstall not called from WordPress, then exit
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}
// If action is not to uninstall, then exit
if ( empty( $_REQUEST['action'] ) || $_REQUEST['action'] !== 'delete-plugin' ) {
	exit;
}
// If it's not us, then exit
if ( empty( $_REQUEST['slug'] ) || $_REQUEST['slug'] !== 'fail2wp' ) {
	exit;
}
// If we shouldn't do this, then exit
if ( ! current_user_can( 'manage_options' ) || ! current_user_can( 'delete_plugins' ) ) {
	exit;
}

// Figure out if an uninstall should remove plugin settings
$remove_settings = get_option( 'fail2wp-remove-settings', '0' );

if ( $remove_settings == '1' ) {
	// Remove Fail2WP settings
    delete_option( 'fail2wp-site-label'           );
    delete_option( 'fail2wp-roles-notify'         );
    delete_option( 'fail2wp-roles-warn'           );
    delete_option( 'fail2wp-unknown-warn'         );
    delete_option( 'fail2wp-settings-remove'      );
    delete_option( 'fail2wp-also-log-php'         );
    delete_option( 'fail2wp-block-user-enum'      );
    delete_option( 'fail2wp-log-user-enum'        );
    delete_option( 'fail2wp-block-username-login' );
    delete_option( 'fail2wp-secure-login-message' );
    delete_option( 'fail2wp-cloudflare-check'     );
    delete_option( 'fail2wp-cloudflare-ipv4'      );
    delete_option( 'fail2wp-cloudflare-ipv6'      );
}
