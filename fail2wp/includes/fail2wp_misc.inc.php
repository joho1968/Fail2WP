<?php
/**
 * Fail2WP various functions
 *
 * @since      1.1.0
 * @package    Fail2WP
 * @subpackage fail2wp/includes
 * @author     Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * fail2wp_misc.inc.php
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

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    if ( defined( 'FAIL2WP_UNINSTALL_TRACE' ) ) {
        error_log( 'fail2wp-uninstall: (misc) WPINC not defined ' );
    }
    die;
}
if ( ! defined( 'ABSPATH' ) ) {
    if ( defined( 'FAIL2WP_UNINSTALL_TRACE' ) ) {
        error_log( 'fail2wp-uninstall: (misc) ABSPATH not defined ' );
    }
    die( '-1' );
}
if ( ! defined( 'FAIL2WP_WORDPRESS_PLUGIN' ) ) {
    if ( defined( 'FAIL2WP_UNINSTALL_TRACE' ) ) {
        error_log( 'fail2wp-uninstall: (misc) FAIL2WP_WORDPRESS_PLUGIN not defined ' );
    }
    die( '-1' );
}


/**
 * Remove all settings from WordPress database.
 *
 * This can, possibly, be used by more than one module.
 *
 * @since 1.1.0
 */
function fail2wp_misc_delete_all_settings() {
    if ( defined( 'FAIL2WP_UNINSTALL_TRACE' ) ) {
        error_log( 'fail2wp-uninstall: ' . __FUNCTION__ . ' start' );
    }
    delete_option( 'fail2wp-site-label'                );
    delete_option( 'fail2wp-prefix'                    );
    delete_option( 'fail2wp-roles-notify'              );
    delete_option( 'fail2wp-roles-warn'                );
    delete_option( 'fail2wp-unknown-warn'              );
    delete_option( 'fail2wp-reguser-warn'              );
    delete_option( 'fail2wp-reguser-warn-role'         );
    delete_option( 'fail2wp-reguser-force'             );
    delete_option( 'fail2wp-reguser-force-role'        );
    delete_option( 'fail2wp-reguser-username-length'   );
    delete_option( 'fail2wp-reguser-username-ban'      );
    delete_option( 'fail2wp-reguser-useremail-require' );

    delete_option( 'fail2wp-rest-filter-log-blocked'   );
    delete_option( 'fail2wp-rest-filter-block-all'     );
    delete_option( 'fail2wp-rest-filter-block-index'   );
    delete_option( 'fail2wp-rest-filter-block-ns'      );
    delete_option( 'fail2wp-rest-filter-block-routes'  );
    delete_option( 'fail2wp-rest-filter-require-authenticated' );
    delete_option( 'fail2wp-rest-filter-ipv4-bypass'   );
    delete_option( 'fail2wp-rest-filter-ipv6-bypass'   );

    delete_option( 'fail2wp-settings-dbversion'        );
    delete_option( 'fail2wp-settings-remove'           );
    delete_option( 'fail2wp-settings-remove-generator' );
    delete_option( 'fail2wp-settings-remove-feeds'     );

    delete_option( 'fail2wp-also-log-php'              );
    delete_option( 'fail2wp-block-user-enum'           );
    delete_option( 'fail2wp-log-user-enum'             );
    delete_option( 'fail2wp-block-username-login'      );
    delete_option( 'fail2wp-secure-login-message'      );

    delete_option( 'fail2wp-cloudflare-check'          );
    delete_option( 'fail2wp-cloudflare-ipv4'           );
    delete_option( 'fail2wp-cloudflare-ipv6'           );

    delete_option( 'fail2wp-allow-ipv4'                );
    delete_option( 'fail2wp-allow-ipv6'                );
    delete_option( 'fail2wp-deny-ipv4'                 );
    delete_option( 'fail2wp-deny-ipv6'                 );

    delete_option( 'fail2wp_loginip_enable'            );
    delete_option( 'fail2wp-loginip-dnscache'          );
    delete_option( 'fail2wp-loginip-allow'             );
    delete_option( 'fail2wp-loginip-deny'              );
    delete_option( 'fail2wp-loginip-testmode'          );
    delete_option( 'fail2wp-loginip-inform-fail2ban'   );

    delete_option( 'fail2wp-xmlrpc-disable'            );
    delete_option( 'fail2wp-xmlrpc-disable-pingback'   );
    delete_option( 'fail2wp-xmlrpc-disable-everything' );
    delete_option( 'fail2wp-xmlrpc-inform-fail2ban'    );

    delete_option( 'fail2wp-hostname-cache'            );
}
