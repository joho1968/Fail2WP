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
 * Copyright (C) 2021,2022,2023,2024 Joaquim Homrighausen; all rights reserved.
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

//  define( 'FAIL2WP_UNINSTALL_TRACE', true );

// Don't load directly
defined( 'ABSPATH' ) || die( '-1' );
// If uninstall not called from WordPress, then exit
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    if ( defined( 'FAIL2WP_UNINSTALL_TRACE' ) ) {
        error_log( 'fail2wp-uninstall: init, WP_UNINSTALL_PLUGIN not defined' );
    }
    die();
}

/**
 * We don't check these anymore.
 * https://developer.wordpress.org/plugins/plugin-basics/uninstall-methods/
 */

/*
// If action is not to uninstall, then exit
if ( empty( $_REQUEST['action'] ) || $_REQUEST['action'] !== 'delete-plugin' ) {
    if ( defined( 'FAIL2WP_UNINSTALL_TRACE' ) ) {
        error_log( 'fail2wp-uninstall: REQUEST["action"] is not delete-plugin' );
    }
    exit;
}
// If it's not us, then exit
if ( empty( $_REQUEST['slug'] ) || $_REQUEST['slug'] !== 'fail2wp' ) {
    if ( defined( 'FAIL2WP_UNINSTALL_TRACE' ) ) {
        error_log( 'fail2wp-uninstall: REQUEST["slug"] is not fail2wp' );
    }
    exit;
}
// If we shouldn't do this, then exit
if ( ! current_user_can( 'manage_options' ) || ! current_user_can( 'delete_plugins' ) ) {
    if ( defined( 'FAIL2WP_UNINSTALL_TRACE' ) ) {
        error_log( 'fail2wp-uninstall: User is not allowed to manage/uninstall plugins' );
    }
    exit;
}
*/

// Figure out if an uninstall should remove plugin settings
$remove_settings = get_option( 'fail2wp-settings-remove', '0' );

if ( $remove_settings == '1' ) {
    if ( defined( 'FAIL2WP_UNINSTALL_TRACE' ) ) {
        error_log( 'fail2wp-uninstall: uninstalling' );
    }
    define( 'FAIL2WP_WORDPRESS_PLUGIN', true );

    require_once dirname(__FILE__) . '/includes/fail2wp_misc.inc.php';

    fail2wp_misc_delete_all_settings();
} else {
    if ( defined( 'FAIL2WP_UNINSTALL_TRACE' ) ) {
        error_log( 'fail2wp-uninstall: $remove_settings = ' . var_export( $remove_settings, true ) );
    }
}
