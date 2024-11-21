<?php
/**
 * Fail2WP
 *
 * @link              https://code.webbplatsen.net/wordpress/fail2wp/
 * @since             1.0.0
 * @package           Fail2WP
 * @author            Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * @wordpress-plugin
 * Plugin Name:       Fail2WP
 * Plugin URI:        https://code.webbplatsen.net/wordpress/fail2wp/
 * Description:       Security plugin for WordPress with support for Fail2ban and Cloudflare
 * Version:           1.2.3
 * Author:            WebbPlatsen, Joaquim Homrighausen <joho@webbplatsen.se>
 * Author URI:        https://webbplatsen.se/
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       fail2wp
 * Domain Path:       /languages
 *
 * fail2wp.php
 * Copyright (C) 2020-2024 Joaquim Homrighausen; all rights reserved.
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
namespace fail2wp;

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}
if ( ! defined( 'ABSPATH' ) ) {
    die( '-1' );
}

define( 'FAIL2WP_WORDPRESS_PLUGIN',        true                    );
define( 'FAIL2WP_VERSION',                 '1.2.3'                 );
define( 'FAIL2WP_REV',                     1                       );
define( 'FAIL2WP_PLUGINNAME_HUMAN',        'Fail2WP'               );
define( 'FAIL2WP_PLUGINNAME_SLUG',         'fail2wp'               );
define( 'FAIL2WP_DEFAULT_PREFIX',          'fail2wp'               );
define( 'FAIL2WP_ALERT_SUCCESS',           1                       );
define( 'FAIL2WP_ALERT_FAILURE',           2                       );
define( 'FAIL2WP_ALERT_USER_ENUM',         3                       );
define( 'FAIL2WP_ALERT_REST_NOTAUTH',      4                       );
define( 'FAIL2WP_ALERT_REST_BLOCKED',      5                       );
define( 'FAIL2WP_ALERT_LOGINIP_BLOCKED',   6                       );
define( 'FAIL2WP_ALERT_XMLRPC_BLOCKED',    7                       );
define( 'FAIL2WP_DEFAULT_HTTP_PORT',       80                      );
define( 'FAIL2WP_DEFAULT_HTTPS_PORT',      443                     );
define( 'FAIL2WP_DB_VERSION',              2                       );
define( 'FAIL2WP_EXPORT_HEADER',           'fail2wp_export.begin.' );
define( 'FAIL2WP_EXPORT_FOOTER',           '.fail2wp_export.end'   );

define( 'VALIDATE_IPHOSTCIDR_INVALID',     -1 );
define( 'VALIDATE_IPHOSTCIDR_IPV4',        0 );
define( 'VALIDATE_IPHOSTCIDR_IPV4_CIDR',   1 );
define( 'VALIDATE_IPHOSTCIDR_IPV6',        2 );
define( 'VALIDATE_IPHOSTCIDR_IPV6_CIDR',   3 );
define( 'VALIDATE_IPHOSTCIDR_HOSTNAME',    4 );
define( 'VALIDATE_IPHOSTCIDR_HOSTNAME_WC', 5 );

define( 'FAIL2WP_DEBUG',                   false                   );
if ( defined( 'FAIL2WP_DEBUG' ) && FAIL2WP_DEBUG ) {
    define( 'FAIL2WP_REST_DEBUG',          false                   );
    define( 'FAIL2WP_GENERAL_DEBUG',       true                    );
    define( 'FAIL2WP_FLOW_DEBUG',          true                    );
    define( 'FAIL2WP_CACHE_DEBUG',         false                   );
    define( 'FAIL2WP_SETTINGS_DEBUG',      true                    );
    define( 'FAIL2WP_DUMP_SETTINGS',       true                    );
    define( 'FAIL2WP_XMLRPC_DEBUG',        false                   );
}


require_once plugin_dir_path( __FILE__ ) . 'includes/class-fail2wp-syslog.php';
// https://github.com/tholu/php-cidr-match
if ( ! class_exists( '\fail2wpCIDRmatch\CIDRmatch', false ) ) {
    require_once plugin_dir_path( __FILE__ ) . 'includes/class-fail2wp-cidr.php';
}


/**
 * "NULL" class for wp_xmlrpc_server_class filter
 *
 * @since 1.2.0
 */
class Fail2WP_Disable_XMLRPC {
    //No clones please.
    final public function __clone() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {fail2wp_disable_xmlrpc}' );
        }
    }
    //We are not a serial
    final public function __wakeup() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {fail2wp_disable_xmlrpc}' );
        }
    }
    //Start me up ...
    public function __construct() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {fail2wp_disable_xmlrpc}' );
        }
    }
    public function serve_request() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {fail2wp_disable_xmlrpc}' );
        }
        $error = new \IXR_Error( 405, 'XML-RPC services are disabled on this site.' );
        status_header( $error->code );
        // Mimic class-IXR-server output
        $charset = function_exists( 'get_option' ) ? get_option( 'blog_charset' ) : '';
        if ( ! empty( $charset ) ) {
            $xml_safe = '<?xml version="1.0" encoding="' . wp_kses_no_null( $charset ) . '"?>' . "\n";
        } else {
            $xml_safe = '<?xml version="1.0"?>' . "\n";
        }
        $length = strlen( $xml_safe );
        header( 'Connection: close' );
        if ( $charset ) {
            header( 'Content-Type: text/xml; charset=' . wp_kses_no_null( $charset ) );
        } else {
            header( 'Content-Type: text/xml' );
        }
        header( 'Date: ' . gmdate( 'r' ) );
        echo $xml_safe;
        echo wp_kses_no_null( $error->getXml() );

        // Instantiate our Fail2WP class so that we can possibly inform
        // fail2ban about the "failure" (if we should)

        $plugin = Fail2WP::getInstance( true );

        // Figure out "remote IP"
        $remote_real_ip = '';
        if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
            $remote_ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        } else {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': $_SERVER[REMOTE_ADDR] is empty?' );
            $remote_ip = '';
        }
        $remote_ip_cf = $plugin->fail2wp_do_cloudflare_lookup( $remote_ip );
        if ( $remote_ip == $remote_ip_cf ) {
            // Addresses are the same, not Cloudflare
            $remote_ip_cf = '';
            if ( isset( $_SERVER['HTTP_X_REAL_IP'] ) ) {
                // Proxy IP address information
                $remote_real_ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
            }
        }
        // Possibly log what we know
        $ip_message = '';
        if ( ! empty( $remote_ip_cf ) ) {
            $ip_message = ' {from Cloudflare: ' . $remote_ip_cf . '}';
        } elseif ( ! empty( $remote_real_ip ) ) {
            $ip_message = ' {from X-Real-IP: ' . $remote_real_ip  . '}';
        }
        $ip_message = $remote_ip . $ip_message;
        // Figure out actual remote IP
        if ( empty( $remote_ip_cf ) ) {
            if ( empty( $remote_real_ip ) ) {
                $remote_real_ip = $remote_ip;
            }
        } else {
            // Cloudflare
            $remote_real_ip = $remote_ip_cf;
        }

        if ( $plugin->fail2wp_xmlrpc_do_inform_fail2ban() ) {
            if ( defined( 'FAIL2WP_XMLRPC_DEBUG' ) && FAIL2WP_XMLRPC_DEBUG ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ' {fail2wp_disable_xmlrpc} We should inform fail2ban' );
            }
            $is_local_host = false;
            if ( ! empty( $_SERVER['SERVER_ADDR'] ) && $remote_real_ip == $_SERVER['SERVER_ADDR'] ) {
                $is_local_host = true;
            } elseif ( $remote_real_ip == '127.0.0.1' || $remote_real_ip == '0:0:0:0:0:0:0:1' || $remote_real_ip == '::1' ) {
                $is_local_host = true;
            }
            if ( $is_local_host == false ) {
                $alert_message = $plugin->fail2wp_make_alert_message( '', null, FAIL2WP_ALERT_XMLRPC_BLOCKED, false, $remote_real_ip );
                if ( ! empty( $alert_message ) ) {
                    $plugin->fail2wp_alert_send( $alert_message );
                }
            } else {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {fail2wp_disable_xmlrpc} Not informing fail2ban about XMLRPC access attempt from ' . $ip_message . ' (localhost)' );
            }

        } else {
            if ( defined( 'FAIL2WP_XMLRPC_DEBUG' ) && FAIL2WP_XMLRPC_DEBUG ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ' {fail2wp_disable_xmlrpc} We should not inform fail2ban' );
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {fail2wp_disable_xmlrpc} Not informing fail2ban about XMLRPC access attempt from ' . $ip_message );
            }
        }

        return( false );
    }
}


/**
 * Fail2WP class
 */
class Fail2WP {
    public static $instance = null;
    protected $fail2wp_mail_headers;                            // @since 1.1.0
    protected $fail2wp_have_mbstring;                           // @since 1.1.0

    protected $fail2wp_wp_roles = null;
    protected $fail2wp_wp_roles_enus = null;
    protected $fail2wp_settings_tab = '';
    protected $fail2wp_prefix;
    protected $fail2wp_roles_notify;
    protected $fail2wp_roles_warn;
    protected $fail2wp_unknown_warn;
    protected $fail2wp_settings_dbversion;                      // @since 1.1.0
    protected $fail2wp_settings_remove;
    protected $fail2wp_settings_remove_generator;               // @since 1.1.0
    protected $fail2wp_settings_remove_feeds;                   // @since 1.1.0
    protected $fail2wp_also_log_php;
    protected $fail2wp_block_user_enum;
    protected $fail2wp_block_username_login;
    protected $fail2wp_secure_login_message;
    protected $fail2wp_log_user_enum;
    protected $fail2wp_default_http_port;
    protected $fail2wp_default_https_port;
    protected $fail2wp_cloudflare_ipv4;
    protected $fail2wp_cloudflare_ipv6;

    protected $fail2wp_reguser_warn;                            // @since 1.1.0
    protected $fail2wp_reguser_warn_role;                       // @since 1.1.0
    protected $fail2wp_reguser_force;                           // @since 1.1.0
    protected $fail2wp_reguser_force_role;                      // @since 1.1.0
    protected $fail2wp_reguser_username_length;                 // @since 1.1.0
    protected $fail2wp_reguser_username_ban;                    // @since 1.1.0
    protected $fail2wp_reguser_useremail_require;               // @since 1.1.0

    protected $fail2wp_rest = null;                             // @since 1.1.0
    protected $fail2wp_rest_filter_log_blocked;                 // @since 1.1.0
    protected $fail2wp_rest_filter_block_all;                   // @since 1.1.0
    protected $fail2wp_rest_filter_block_index;                 // @since 1.1.0
    protected $fail2wp_rest_filter_block_ns;                    // @since 1.1.0
    protected $fail2wp_rest_filter_block_routes;                // @since 1.1.0
    protected $fail2wp_rest_filter_route_list;                  // @since 1.1.0
    protected $fail2wp_rest_filter_require_authenticated;       // @since 1.1.0
    protected $fail2wp_rest_filter_ipv4_bypass;                 // @since 1.1.0
    protected $fail2wp_rest_filter_ipv6_bypass;                 // @since 1.1.0

    protected $fail2wp_loginip_enable;                          // @since 1.2.0
    protected $fail2wp_loginip_testmode;                        // @since 1.2.0
    protected $fail2wp_loginip_inform_fail2ban;                 // @since 1.2.0
    protected $fail2wp_loginip_dnscache;                        // @since 1.2.0
    protected $fail2wp_loginip_allow;                           // @since 1.2.0
    protected $fail2wp_loginip_deny;                            // @since 1.2.0

    protected $fail2wp_xmlrpc_disable;                          // @since 1.2.0
    protected $fail2wp_xmlrpc_disable_pingback;                 // @since 1.2.0
    protected $fail2wp_xmlrpc_disable_everything;               // @since 1.2.0
    protected $fail2wp_xmlrpc_inform_fail2ban;                  // @since 1.2.0

    protected $fail2wp_cidrm;                                   // @since 1.2.0

    protected $fail2wp_hostname_cache;                          // @since 1.2.0
    protected $fail2wp_hostname_cache_updated;                  // @since 1.2.0

    final public static function getInstance( bool $is_for_xmlrpc = false ) {
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
            if ( self::$instance === null ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {instance==null}' );
            }
        }
        null === self::$instance AND self::$instance = new self( $is_for_xmlrpc );
        return( self::$instance );
    }
    /**
     * No clones please.
     *
     * @return void
     */
    final public function __clone() {
    }
    /**
     * We are not a serial
     *
     * @return void
     */
    final public function __wakeup() {
    }
    /**
     * Start me up ...
     */
    public function __construct( bool $is_for_xmlrpc = false ) {
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        // Setup default mail headers
        $this->fail2wp_mail_headers = array( 'Auto-Submitted: auto-replied',
                                             'X-Auto-Response-Suppress: All',
                                             'Precedence: auto_reply' );
        // We only need to query this once really
        $this->fail2wp_have_mbstring = extension_loaded( 'mbstring' );
        // Things we may be interested in for the REST API
        $this->fail2wp_rest_filter_route_list = array(
            'categories',
            'comments',
            'media',
            'pages',
            'posts',
            'search',
            'statuses',
            'tags',
            'taxonomies',
            'types',
            'users',
        );
        // Dump all of our settings, for development
        if ( defined( 'FAIL2WP_DUMP_SETTINGS' ) && FAIL2WP_DUMP_SETTINGS ) {
            global $wpdb;
            /*
            $settings = $wpdb->get_results(
                $wpdb->prepare( "SELECT * FROM {$wpdb->options} WHERE option_name LIKE 'fail2wp%'" ),
                ARRAY_A
            );
            */
            $settings = $wpdb->get_results( "SELECT * FROM {$wpdb->options} WHERE option_name LIKE 'fail2wp%'", ARRAY_A );
            if ( is_array( $settings ) ) {
                error_log( print_r( $settings, true ) );
            } else {
                error_log ( basename( __FILE__ ) . ': Unable to fetch settings' );
            }
        }
        // Fetch options and setup defaults
        // ..General
        $this->fail2wp_settings_dbversion = get_option( 'fail2wp-settings-dbversion', null );
        if ( $this->fail2wp_settings_dbversion === null ) {
            $this->fail2wp_settings_dbversion = FAIL2WP_DB_VERSION;
            update_option( 'fail2wp-settings-dbversion', $this->fail2wp_settings_dbversion );
        }
        $this->fail2wp_site_label = $this->fail2wp_get_site_label( false );
        $this->fail2wp_roles_notify = @ json_decode( get_option( 'fail2wp-roles-notify', null ), true, 2 );
        if ( ! is_array( $this->fail2wp_roles_notify ) ) {
            $this->fail2wp_roles_notify = array();
            update_option( 'fail2wp-roles-notify', wp_json_encode( $this->fail2wp_roles_notify ) );
        }
        $this->fail2wp_roles_warn = @ json_decode( get_option( 'fail2wp-roles-warn', null ), true, 2 );
        if ( ! is_array( $this->fail2wp_roles_warn ) ) {
            $this->fail2wp_roles_warn = array( 'administrator' );
            update_option( 'fail2wp-roles-warn', wp_json_encode( $this->fail2wp_roles_warn ) );
        }
        $this->fail2wp_unknown_warn = get_option( 'fail2wp-unknown-warn', null );
        if ( $this->fail2wp_unknown_warn || $this->fail2wp_unknown_warn === null ) {
            $this->fail2wp_unknown_warn = true;
        } else {
            $this->fail2wp_unknown_warn = false;
        }
        // ..New users @since 1.1.0
        $default_role = get_option( 'default_role', null );// Get WordPress' default role
        $this->fail2wp_reguser_warn = get_option( 'fail2wp-reguser-warn', null );
        if ( $this->fail2wp_reguser_warn === null ) {
            $this->fail2wp_reguser_warn = true;
        }
        $this->fail2wp_reguser_warn_role = get_option( 'fail2wp-reguser-warn-role', null );
        if ( $this->fail2wp_reguser_warn_role === null ) {
            $this->fail2wp_reguser_warn_role = ( ! empty( $default_role ) ? $default_role:'subscriber' );
        }
        $this->fail2wp_reguser_force = get_option( 'fail2wp-reguser-force', null );
        if ( $this->fail2wp_reguser_force === null ) {
            $this->fail2wp_reguser_force = true;
        }
        $this->fail2wp_reguser_force_role = get_option( 'fail2wp-reguser-force-role', null );
        if ( $this->fail2wp_reguser_force_role === null ) {
            $this->fail2wp_reguser_force_role = $this->fail2wp_reguser_warn_role;
        }
        if ( $this->fail2wp_reguser_force && $default_role != $this->fail2wp_reguser_force_role ) {
            // Set WordPress' default role
            update_option( 'default_role', $this->fail2wp_reguser_force_role );
            // Tell admin we've done this
            add_action( 'admin_notices',  [$this, 'fail2wp_admin_alert_new_user_role_forced'] );
            add_action( 'plugins_loaded', [$this, 'fail2wp_admin_alert_new_user_role_forced_email'] );
            $default_role = $this->fail2wp_reguser_force_role;
        }
        $users_can_register = get_option( 'users_can_register', null );
        if ( $is_for_xmlrpc == false && $this->fail2wp_reguser_warn ) {
            if ( $users_can_register ) {
                // Only trigger alarms if users_can_register is true
                if ( $default_role != $this->fail2wp_reguser_warn_role ) {
                    add_action( 'admin_notices', [$this, 'fail2wp_admin_alert_new_users_mismatch'] );
                } elseif ( $default_role == 'administrator' ) {
                    add_action( 'admin_notices', [$this, 'fail2wp_admin_alert_new_users_admin'] );
                } elseif ( $default_role == null ) {
                    add_action( 'admin_notices', [$this, 'fail2wp_admin_alert_new_users_null'] );
                }
            }
        }
        $this->fail2wp_reguser_username_length = get_option( 'fail2wp-reguser-username-length', null );
        if ( $this->fail2wp_reguser_username_length === null || $this->fail2wp_reguser_username_length > 200 ) {
            $this->fail2wp_reguser_username_length = 0;
            update_option( 'fail2wp-reguser-username-length', (int)$this->fail2wp_reguser_username_length );
        }
        $this->fail2wp_reguser_username_ban = @ json_decode( get_option ( 'fail2wp-reguser-username-ban', null ), true, 2 );
        if ( ! is_array( $this->fail2wp_reguser_username_ban ) ) {
            $this->fail2wp_reguser_username_ban = array( 'administrator', 'admin', 'sysadmin', 'siteadmin' );
            update_option( 'fail2wp-reguser-username-ban', wp_json_encode( $this->fail2wp_reguser_username_ban ) );
        }
        $this->fail2wp_reguser_useremail_require = @ json_decode( get_option ( 'fail2wp-reguser-useremail-require', null ), true, 2 );
        if ( ! is_array( $this->fail2wp_reguser_useremail_require ) ) {
            $this->fail2wp_reguser_useremail_require = array();
            update_option( 'fail2wp-reguser-useremail-require', wp_json_encode( $this->fail2wp_reguser_useremail_require ) );
        }
        // Possibly add new user registration details validation if new user
        // registrations are active and we have something to validate against.
        if ( $is_for_xmlrpc == false && $users_can_register &&
                    ( ! empty( $this->fail2wp_reguser_username_ban )
                      || ! empty( $this->fail2wp_reguser_useremail_require )
                      || $this->fail2wp_reguser_username_length > 1 ) ) {
            add_filter( 'registration_errors', [$this, 'fail2wp_admin_check_new_user'], 10, 3 );
        }
        // .. REST API @since 1.1.0
        $this->fail2wp_rest_filter_require_authenticated = get_option( 'fail2wp-rest-filter-require-authenticated', null );
        if ( ! $this->fail2wp_rest_filter_require_authenticated || $this->fail2wp_rest_filter_require_authenticated === null ) {
            $this->fail2wp_rest_filter_require_authenticated = false;
        } else {
            $this->fail2wp_rest_filter_require_authenticated = true;
        }
        if ( $is_for_xmlrpc == false && $this->fail2wp_rest_filter_require_authenticated ) {
            add_filter( 'rest_authentication_errors', [$this, 'fail2wp_rest_filter_authenticate'], 10, 1  );
        }
        $this->fail2wp_rest_filter_log_blocked = get_option( 'fail2wp-rest-filter-log-blocked', null );
        if ( ! $this->fail2wp_rest_filter_log_blocked || $this->fail2wp_rest_filter_log_blocked === null ) {
            $this->fail2wp_rest_filter_log_blocked = false;
        } else {
            $this->fail2wp_rest_filter_log_blocked = true;
        }
        $this->fail2wp_rest_filter_block_index = get_option( 'fail2wp-rest-filter-block-index', null );
        if ( ! $this->fail2wp_rest_filter_block_index || $this->fail2wp_rest_filter_block_index === null ) {
            $this->fail2wp_rest_filter_block_index = false;
        } else {
            $this->fail2wp_rest_filter_block_index = true;
        }
        $this->fail2wp_rest_filter_block_all = get_option( 'fail2wp-rest-filter-block-all', null );
        if ( ! $this->fail2wp_rest_filter_block_all || $this->fail2wp_rest_filter_block_all === null ) {
            $this->fail2wp_rest_filter_block_all = false;
        } else {
            $this->fail2wp_rest_filter_block_all = true;
        }
        $this->fail2wp_rest_filter_block_ns = @ json_decode( get_option( 'fail2wp-rest-filter-block-ns', null ), true, 2 );
        if ( ! is_array( $this->fail2wp_rest_filter_block_ns ) ) {
            $this->fail2wp_rest_filter_block_ns = array();
            update_option( 'fail2wp-rest-filter-block-ns', wp_json_encode( $this->fail2wp_rest_filter_block_ns ) );
        }
        $this->fail2wp_rest_filter_block_routes = @ json_decode( get_option( 'fail2wp-rest-filter-block-routes', null ), true, 2 );
        if ( ! is_array( $this->fail2wp_rest_filter_block_routes ) ) {
            $this->fail2wp_rest_filter_block_routes = array();
            update_option( 'fail2wp-rest-filter-block-routes', wp_json_encode( $this->fail2wp_rest_filter_block_routes ) );
        }
        $this->fail2wp_rest_filter_ipv4_bypass = @ json_decode( get_option( 'fail2wp-rest-filter-ipv4-bypass', null ), true, 2 );
        if ( ! is_array( $this->fail2wp_rest_filter_ipv4_bypass ) ) {
            $this->fail2wp_rest_filter_ipv4_bypass = array();
            update_option( 'fail2wp-rest-filter-ipv4-bypass', wp_json_encode( $this->fail2wp_rest_filter_ipv4_bypass ) );
        }
        $this->fail2wp_rest_filter_ipv6_bypass = @ json_decode( get_option( 'fail2wp-rest-filter-ipv6-bypass', null ), true, 2 );
        if ( ! is_array( $this->fail2wp_rest_filter_ipv6_bypass ) ) {
            $this->fail2wp_rest_filter_ipv6_bypass = array();
            update_option( 'fail2wp-rest-filter-ipv6-bypass', wp_json_encode( $this->fail2wp_rest_filter_ipv6_bypass ) );
        }
        // ..Logging
        $this->fail2wp_also_log_php = get_option( 'fail2wp-also-log-php', null );
        if ( ! $this->fail2wp_also_log_php || $this->fail2wp_also_log_php === null ) {
            $this->fail2wp_also_log_php = false;
        } else {
            $this->fail2wp_also_log_php = true;
        }
        $this->fail2wp_block_user_enum = get_option( 'fail2wp-block-user-enum', null );
        if ( $this->fail2wp_block_user_enum || $this->fail2wp_block_user_enum === null ) {
            $this->fail2wp_block_user_enum = true;
        } else {
            $this->fail2wp_block_user_enum = false;
        }
        $this->fail2wp_block_username_login = get_option( 'fail2wp-block-username-login', null );
        if ( $this->fail2wp_block_username_login === null || ! $this->fail2wp_block_username_login ) {
            $this->fail2wp_block_username_login = false;
        } else {
            $this->fail2wp_block_username_login = true;
        }
        $this->fail2wp_log_user_enum = get_option( 'fail2wp-log-user-enum', null );
        if ( $this->fail2wp_log_user_enum || $this->fail2wp_log_user_enum === null ) {
            $this->fail2wp_log_user_enum = true;
        } else {
            $this->fail2wp_log_user_enum = false;
        }
        // ..Failed login message
        $this->fail2wp_secure_login_message = get_option( 'fail2wp-secure-login-message', null );
        if ( $this->fail2wp_secure_login_message || $this->fail2wp_secure_login_message === null ) {
            $this->fail2wp_secure_login_message = true;
        } else {
            $this->fail2wp_secure_login_message = false;
        }
        // ..Cloudflare
        $this->fail2wp_cloudflare_check = get_option( 'fail2wp-cloudflare-check', null );
        if ( $this->fail2wp_cloudflare_check === null || ! $this->fail2wp_cloudflare_check ) {
            $this->fail2wp_cloudflare_check = false;
        } else {
            $this->fail2wp_cloudflare_check = true;
        }
        $this->fail2wp_cloudflare_ipv4 = @ json_decode( get_option( 'fail2wp-cloudflare-ipv4', null ), true, 2 );
        if ( ! is_array( $this->fail2wp_cloudflare_ipv4 ) ) {
            $this->fail2wp_cloudflare_ipv4 = array();
            update_option( 'fail2wp-cloudflare-ipv4', wp_json_encode( $this->fail2wp_cloudflare_ipv4 ) );
        }
        $this->fail2wp_cloudflare_ipv6 = @ json_decode( get_option( 'fail2wp-cloudflare-ipv6', null ), true, 2 );
        if ( ! is_array( $this->fail2wp_cloudflare_ipv6 ) ) {
            $this->fail2wp_cloudflare_ipv6 = array();
            update_option( 'fail2wp-cloudflare-ipv6', wp_json_encode( $this->fail2wp_cloudflare_ipv6 ) );
        }
        // ..Login IP checking @since 1.2.0
        $this->fail2wp_loginip_enable = get_option( 'fail2wp-loginip-enable', false );
        $this->fail2wp_loginip_testmode = get_option( 'fail2wp-loginip-testmode', true );
        $this->fail2wp_loginip_inform_fail2ban = get_option( 'fail2wp-loginip-inform-fail2ban', false );
        $this->fail2wp_loginip_dnscache = get_option( 'fail2wp-loginip-dnscache', -1 );
        if ( $this->fail2wp_loginip_dnscache < 0 ) {
            $this->fail2wp_loginip_dnscache = 60;
        } elseif ( $this->fail2wp_loginip_dnscache > 10080 ) {
            $this->fail2wp_loginip_dnscache = 10080;
        }
        // ..Allow (login) @since 1.2.0
        $this->fail2wp_loginip_allow = @ json_decode( get_option ( 'fail2wp-loginip-allow', null ), true, 2 );
        if ( ! is_array( $this->fail2wp_loginip_allow ) ) {
            $this->fail2wp_loginip_allow = array();
            update_option( 'fail2wp-loginip-allow', wp_json_encode( $this->fail2wp_loginip_allow ) );
        }
        // ..Deny (login) @since 1.2.0
        $this->fail2wp_loginip_deny = @ json_decode( get_option ( 'fail2wp-loginip-deny', null ), true, 2 );
        if ( ! is_array( $this->fail2wp_loginip_deny ) ) {
            $this->fail2wp_loginip_deny = array();
            update_option( 'fail2wp-loginip-deny', wp_json_encode( $this->fail2wp_loginip_deny ) );
        }
        // .. Block XMLRPC authenticated @since 1.2.0
        $this->fail2wp_xmlrpc_disable = get_option( 'fail2wp-xmlrpc-disable', false );
        // .. Block XMLRPC pingbacks @since 1.2.0
        $this->fail2wp_xmlrpc_disable_pingback = get_option( 'fail2wp-xmlrpc-disable-pingback', false );
        // .. Block all XMLRPC @since 1.2.0
        $this->fail2wp_xmlrpc_disable_everything = get_option( 'fail2wp-xmlrpc-disable-everything', false );
        // .. Inform fail2ban about XMLRPC "failures" @since 1.2.0
        $this->fail2wp_xmlrpc_inform_fail2ban = get_option( 'fail2wp-xmlrpc-inform-fail2ban', false );
        // ..Other options
        $this->fail2wp_settings_remove_generator = get_option( 'fail2wp-settings-remove-generator', null );
        if ( $this->fail2wp_settings_remove_generator === null || ! $this->fail2wp_settings_remove_generator ) {
            $this->fail2wp_settings_remove_generator = false;
        } else {
            $this->fail2wp_settings_remove_generator = true;
        }
        $this->fail2wp_settings_remove_feeds = get_option( 'fail2wp-settings-remove-feeds', null );
        if ( $this->fail2wp_settings_remove_feeds === null || ! $this->fail2wp_settings_remove_feeds ) {
            $this->fail2wp_settings_remove_feeds = false;
        } else {
            $this->fail2wp_settings_remove_feeds = true;
        }
        $this->fail2wp_settings_remove = get_option( 'fail2wp-settings-remove', null );
        if ( $this->fail2wp_settings_remove === null || ! $this->fail2wp_settings_remove ) {
            $this->fail2wp_settings_remove = false;
        } else {
            $this->fail2wp_settings_remove = true;
        }
        // .. REST filtering
        if ( $is_for_xmlrpc == false ) {
            if ( $this->fail2wp_rest_filter_block_all ) {
                remove_action( 'wp_head', 'rest_output_link_wp_head' );
            }
            if ( $this->fail2wp_rest_filter_block_all
                    || ! empty( $this->fail2wp_rest_filter_block_index )
                        || ! empty( $this->fail2wp_rest_filter_block_ns )
                            || ! empty( $this->fail2wp_rest_filer_block_routes ) ) {
                add_action( 'rest_api_init', [$this, 'fail2wp_rest_init'] );
            }
        }
        // ..Generator filtering
        if ( $is_for_xmlrpc == false && $this->fail2wp_settings_remove_generator ) {
            remove_action( 'wp_head', 'wp_generator' );
            add_filter( 'the_generator', [$this, 'fail2wp_the_generator'], 10, 2 );
        }
        // ..Feed filtering
        if ( $is_for_xmlrpc == false && $this->fail2wp_settings_remove_feeds ) {
            add_filter( 'feed_links_show_posts_feed',    [$this, 'fail2wp_noshow_feeds'], 10, 1 );
            add_filter( 'feed_links_show_comments_feed', [$this, 'fail2wp_noshow_feeds'], 10, 1 );
            remove_action( 'wp_head', 'rsd_link'                               );
            remove_action( 'wp_head', 'feed_links', 2                          );
            remove_action( 'wp_head', 'index_rel_link'                         );
            remove_action( 'wp_head', 'wlwmanifest_link'                       );
            remove_action( 'wp_head', 'feed_links_extra',                    3 );
            remove_action( 'wp_head', 'start_post_rel_link',             10, 0 );
            remove_action( 'wp_head', 'parent_post_rel_link',            10, 0 );
            remove_action( 'wp_head', 'adjacent_posts_rel_link',         10, 0 );
            remove_action( 'wp_head', 'wp_shortlink_wp_head',            10, 0 );
            remove_action( 'wp_head', 'adjacent_posts_rel_link_wp_head', 10, 0 );
            remove_action( 'wp_head', 'wp_oembed_add_discovery_links'          );
            add_action( 'do_feed',               [$this, 'fail2wp_remove_feeds'] );
            add_action( 'do_feed_rdf',           [$this, 'fail2wp_remove_feeds'] );
            add_action( 'do_feed_rss',           [$this, 'fail2wp_remove_feeds'] );
            add_action( 'do_feed_rss2',          [$this, 'fail2wp_remove_feeds'] );
            add_action( 'do_feed_atom',          [$this, 'fail2wp_remove_feeds'] );
            add_action( 'do_feed_rss2_comments', [$this, 'fail2wp_remove_feeds'] );
            add_action( 'do_feed_atom_comments', [$this, 'fail2wp_remove_feeds'] );
        }
        // ..Various settings
        $this->fail2wp_default_http_port = FAIL2WP_DEFAULT_HTTP_PORT;
        $this->fail2wp_default_https_port = FAIL2WP_DEFAULT_HTTPS_PORT;
        $this->fail2wp_prefix = get_option( 'fail2wp-prefix', null );
        if ( $this->fail2wp_prefix === null ) {
            $this->fail2wp_prefix = '';
        }
        // ..Login URL modification
        $this->fail2wp_login_url_modify = true;
        $this->fail2wp_login_url = 'access';
        $this->fail2wp_login_admin_url_modify = true;
        $this->fail2wp_login_admin_url = 'admin';

        // Our CIDR matcher
        $this->fail2wp_cidrm = new \fail2wpCIDRmatch\CIDRmatch();

        // Load (and possibly invalidate) our hostname cache @since 1.2.0
        $this->fail2wp_hostname_cache_updated = false;
        if ( $this->fail2wp_loginip_dnscache > 0 ) {
            // Only perform the fetch if cache is actually enabled
            $this->fail2wp_hostname_cache = @ json_decode( get_option ( 'fail2wp-hostname-cache', '' ), true, 3 );
            if ( ! is_array( $this->fail2wp_hostname_cache ) || empty( $this->fail2wp_hostname_cache['ts'] ) ) {
                if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': ' . var_export( $this->fail2wp_hostname_cache, true ) );
                }
                $this->fail2wp_hostname_cache = array();
                if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache is empty or invalid' );
                }
            } else {
                // Check for cache expiration
                if ( time() > $this->fail2wp_hostname_cache['ts'] ) {
                    // Cache has expired, clear it
                    $this->fail2wp_hostname_cache = array();
                    update_option( 'fail2wp-hostname-cache', wp_json_encode( $this->fail2wp_hostname_cache ) );
                    if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                        error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache has expired' );
                    }
                } else {
                    if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                        error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache expires in ' . ( $this->fail2wp_hostname_cache['ts'] - time() ) . 's' );
                    }

                }
            }
        } else {
            // Hostname lookup cache is disabled
            $this->fail2wp_hostname_cache = array();
            if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache is disabled' );
            }
        }

        // Validate selected configuration tab
        $this->fail2wp_settings_tab = ( isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : '' );
        if ( ! in_array( $this->fail2wp_settings_tab, ['loginip', 'newuser', 'logging', 'advanced', 'restapi', 'xmlrpc', 'cloudflare', 'importexport', 'about'] ) ) {
            $this->fail2wp_settings_tab = '';
        }
        // Add 'Settings' link in plugin list
        add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), [$this, 'fail2wp_settings_link'] );

        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
    }
    /**
     * Shut me down
     */
    public function __destruct() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        if ( $this->fail2wp_hostname_cache_updated ) {
            // Flush cache back to storage
            if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': ' . var_export( $this->fail2wp_hostname_cache, true ) );
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': ' . wp_json_encode( $this->fail2wp_hostname_cache ) );
            }
            if ( ! update_option( 'fail2wp-hostname-cache', wp_json_encode( $this->fail2wp_hostname_cache ) ) ) {
                if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache not flushed to DB (update_option() returned false)' );
                }
            } else {
                if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache flushed to DB' );
                }
            }
        }
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
    }
    /**
     * Simply return "fail2wp_xmlrpc_inform_fail2ban".
     *
     * fail2wp_xmlrpc_inform_fail2ban is protected, this is a public function
     * to allow reading its value.
     *
     * @return bool
     * @since 1.2.0
     */
    public function fail2wp_xmlrpc_do_inform_fail2ban() : bool {
        return( $this->fail2wp_xmlrpc_inform_fail2ban );
    }
    /**
     * Add link to Fail2WP settings in plugin list.
     *
     * @since 1.1.0
     */
    public function fail2wp_settings_link( array $links ) {
        $our_link = '<a href ="' . esc_url( admin_url() . 'options-general.php?page=' . 'fail2wp' ) . '">' .
                                   esc_html__( 'Settings', 'fail2wp' ) . '</a> ';
        array_unshift( $links, $our_link );
        return ( $links );
    }


    /**
     * Remove "generator" output.
     *
     * @since 1.1.0
     */
    public function fail2wp_the_generator( string $generator_type, string $type ) {
        return( '' );
    }


    /**
     * Remove feeds.
     *
     * Instead of a 404, we issue a WordPress redirect to the main page.
     *
     * @since 1.1.0
     */
    public function fail2wp_remove_feeds( $feed ) {
        wp_redirect( home_url(), 302 );
        exit();
        // One could have something like this too of course, but WordPress
        // doesn't seem to like this for some reason and will still display
        // the feed content.
        /*
        wp_die( __( 'This feed has been disabled, please visit', 'fail2wp' ) .
                ' <a href="' . home_url() . '">' .
                home_url() .
                '</a>',
                __( 'Feed disabled', 'fail2wp' ),
                array( 'link_url' => home_url(),
                       'link_text' => home_url(),
                       'code' => 'feed_disabled',
                       'response' => 404 ) );
        */

    }
    public function fail2wp_noshow_feeds( $noshow ) {
        return( false );
    }


    /**
     * Setup various REST handlers.
     *
     * We only do this on 'rest_api_init' so that we don't clutter chain.
     *
     * @since 1.1.0
     */
    public function fail2wp_rest_init( \WP_REST_Server $wp_rest ) {
        if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . ')' );
        }
        if ( $this->fail2wp_rest === null ){
            $this->fail2wp_rest = $wp_rest;
        }
        if ( $this->fail2wp_rest_filter_block_all ) {
            // Block everything
            $add_pre_dispatch_filter = true;
        } else {
            $add_pre_dispatch_filter = false;
            // Block selectively
            if ( $this->fail2wp_rest_filter_block_index ) {
                // Block REST API index calls
                add_filter( 'rest_index', [$this, 'fail2wp_rest_index'] );
                $add_pre_dispatch_filter = true;
            } elseif ( ! empty( $this->fail2wp_rest_filter_block_ns ) ) {
                // Check namespaces on requests
                $add_pre_dispatch_filter = true;
            }
        }
        if ( $add_pre_dispatch_filter ) {
            add_filter( 'rest_pre_dispatch', [$this, 'fail2wp_rest_pre_dispatch'], 10, 4 );
            if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): ' . 'Activating fail2wp_rest_pre_dispatch()' );
            }
        } else {
            if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): ' . 'Not activating fail2wp_rest_pre_dispatch()' );
            }
        }
    }
    /**
     * Require authentication for REST API calls.
     *
     * This effectively bypasses all other "block" settings.
     *
     * @since 1.1.0
     */
    public function fail2wp_rest_filter_authenticate( $result ) {
        // Pass along previous success or failure
        if ( $result || is_wp_error( $result ) ) {
            return( $result );
        }
        if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $remote_ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        } else {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': $_SERVER[REMOTE_ADDR] is empty?' );
            $remote_ip = '';
        }
        $remote_ip_cf = $this->fail2wp_do_cloudflare_lookup( $remote_ip );
        if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
            error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): ' .
                       'Remote address="' . $remote_ip_cf . '" ' . ( $remote_ip !== $remote_ip_cf ? '('  . $remote_ip . ') ' : '' ) .
                       'REST URL="'       . rest_url()              . '" ' .
                       'LoggedIn='        . ( is_user_logged_in() ? 'true':'false' ) );
        }
        if ( ! is_user_logged_in() ) {
            // Check bypass
            if ( $this->fail2wp_rest_check_ip_bypass( $remote_ip, $remote_ip_cf ) ) {
                return( $result );
            }
            if ( $this->fail2wp_rest_filter_log_blocked ) {
                // Possibly log this for Fail2ban
                $alert_message = $this->fail2wp_make_alert_message( '', null, FAIL2WP_ALERT_REST_NOTAUTH );
                if ( ! empty( $alert_message ) ) {
                    $this->fail2wp_alert_send( $alert_message );
                }
            }
            // This text is taken verbatim from WordPress and will thus be
            // translated in the same way.
            return new \WP_Error( 'rest_not_logged_in',
                                 __( 'You are not currently logged in.', 'default' ),
                                 array( 'status' => 401 )
                               );
        }
        return( $result );
    }
    /**
     * Block REST API index.
     *
     * This simply makes the REST API index request return an empty body.
     *
     * @since 1.1.0
     */
    public function fail2wp_rest_index( $response ) {
        if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
            error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): We are blocking REST API requests for index' );
        }
        if ( $response instanceof \WP_REST_Response ) {
            $response->data = array();
        }
        return( $response );
    }
    /**
     * Check if IP address is on REST API bypass list
     *
     * @since 1.2.3
     */
    protected function fail2wp_rest_check_ip_bypass( string $remote_ip, string $remote_ip_cf ) {
        $allowed_to_bypass = false;
        if ( ! empty( $this->fail2wp_rest_filter_ipv4_bypass ) || ! empty( $this->fail2wp_rest_filter_ipv6_bypass ) ) {
            // Setup CIDRmatch
            if ( ! empty( $this->fail2wp_rest_filter_ipv4_bypass ) && is_array( $this->fail2wp_rest_filter_ipv4_bypass ) ) {
                foreach( $this->fail2wp_rest_filter_ipv4_bypass as $bypass ) {
                    if ( ! empty( $bypass ) && $this->fail2wp_cidrm->match( $remote_ip_cf, $bypass ) ) {
                        $allowed_to_bypass = true;
                        break;
                    }
                }
            }
            if ( ! $allowed_to_bypass && ! empty( $this->fail2wp_rest_filter_ipv6_bypass ) && is_array( $this->fail2wp_rest_filter_ipv6_bypass ) ) {
                foreach( $this->fail2wp_rest_filter_ipv6_bypass as $bypass ) {
                    if ( ! empty( $bypass ) && $this->fail2wp_cidrm->match( $remote_ip_cf, $bypass ) ) {
                        $allowed_to_bypass = true;
                        break;
                    }
                }
            }
        }
        if ( $allowed_to_bypass ) {
            if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): IP address is allowed to bypass REST API blocks' );
            }
        }
        return( $allowed_to_bypass );
    }
    /**
     * Handle majority of REST API filtering.
     *
     * @since 1.1.0
     */
    public function fail2wp_rest_pre_dispatch( $result, \WP_REST_Server $rest_server, \WP_REST_Request $request ) {
        // Figure out who we're talking to
        if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $remote_ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        } else {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': $_SERVER[REMOTE_ADDR] is empty?' );
            $remote_ip = '';
        }
        $remote_ip_cf = $this->fail2wp_do_cloudflare_lookup( $remote_ip );
        if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
            error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): ' .
                       'Remote address="' . $remote_ip_cf . '" ' . ( $remote_ip !== $remote_ip_cf ? '('  . $remote_ip . ') ' : '' ) .
                       'REST URL="'       . rest_url()              . '" ' .
                       'Route="'          . $request->get_route()   . '"' );
        }
        if ( $this->fail2wp_rest_check_ip_bypass( $remote_ip, $remote_ip_cf ) ) {
            return( $result );
        }
        // Should we block all REST requests?
        if ( $this->fail2wp_rest_filter_block_all ) {
            if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): We are blocking all REST API requests' );
            }
            $alert_message = $this->fail2wp_make_alert_message( $remote_ip_cf, null, FAIL2WP_ALERT_REST_BLOCKED, true );
            if ( ! empty( $alert_message ) ) {
                $this->fail2wp_alert_send( $alert_message );
            }
            return new \WP_Error(
                'rest_no_route',
                // This text is taken verbatim from WordPress and will thus be
                // translated in the same way.
                __( 'No route was found matching the URL and request method.', 'default' ),
                array( 'status' => '404' )
            );
        }
        // Figure out what has been requested and where we live
        $namespaces = $this->fail2wp_get_rest_ns( $rest_server );
        $route = $request->get_route();
        $wp_route = '';
        $is_wp_route = false;
        if ( ! empty( $route ) ) {
            // "Normalize" route, remove leading /
            if ( $this->fail2wp_have_mbstring ) {
                $route = mb_substr( $route, 1 );
                $is_wp_route = ( mb_stripos( $route, 'wp/v2/' ) === 0 );
                if ( $is_wp_route ) {
                    $wp_route = mb_substr( $route, 6 );
                }
            } else {
                $route = substr( $route, 1 );
                $is_wp_route = ( stripos( $route, 'wp/v2/' ) === 0 );
                if ( $is_wp_route ) {
                    $wp_route = substr( $route, 6 );
                }
            }
        }
        // Figure out if we're blocking index requests and if this is one
        if ( in_array( $route, $namespaces ) ) {
            if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): We are blocking REST API requests for index' );
            }
            $alert_message = $this->fail2wp_make_alert_message( $remote_ip_cf, null, FAIL2WP_ALERT_REST_BLOCKED, true );
            if ( ! empty( $alert_message ) ) {
                $this->fail2wp_alert_send( $alert_message );
            }
            return new \WP_Error(
                'rest_no_route',
                // This text is taken verbatim from WordPress and will thus be
                // translated in the same way.
                __( 'No route was found matching the URL and request method.', 'default' ),
                array( 'status' => '404' )
            );
        }
        // Figure out if we're blocking this namespace. Request will be /...
        // Namespaces to block are stored without the leading slash.
        if ( ! empty( $this->fail2wp_rest_filter_block_ns ) ) {
            if ( in_array( $route, $this->fail2wp_rest_filter_block_ns ) ) {
                if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
                    error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): We are blocking REST API requests for NS "' . $route . '"' );
                }
                $alert_message = $this->fail2wp_make_alert_message( $remote_ip_cf, null, FAIL2WP_ALERT_REST_BLOCKED, true );
                if ( ! empty( $alert_message ) ) {
                    $this->fail2wp_alert_send( $alert_message );
                }
                return new \WP_Error(
                    'rest_no_route',
                    // This text is taken verbatim from WordPress and will thus be
                    // translated in the same way.
                    __( 'No route was found matching the URL and request method.', 'default' ),
                    array( 'status' => '404' )
                );
            }
        }
        // Figure out if we're blocking this WP REST API route. Request will be
        // /... Routes to block are stored without the leading slash.
        if ( $is_wp_route && ! empty( $this->fail2wp_rest_filter_block_routes ) ) {
            if ( in_array( $wp_route, $this->fail2wp_rest_filter_block_routes ) ) {
                if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
                    error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): We are blocking REST API requests for route "' . $route . '"' );
                }
                $alert_message = $this->fail2wp_make_alert_message( $remote_ip_cf, null, FAIL2WP_ALERT_REST_BLOCKED, true );
                if ( ! empty( $alert_message ) ) {
                    $this->fail2wp_alert_send( $alert_message );
                }
                return new \WP_Error(
                    'rest_no_route',
                    // This text is taken verbatim from WordPress and will thus be
                    // translated in the same way.
                    __( 'No route was found matching the URL and request method.', 'default' ),
                    array( 'status' => '404' )
                );
            }
        }
        // Carry on ...
        return( $result );
    }


    /**
     * Checks username and e-mail address prior to registration.
     *
     * Hooks 'registration_errors' and validates username and e-mail address
     * according to our settings.
     *
     * @since 1.1.0
     * @param WP_Error $errors.
     * @param string $sanitized_user_login.
     * @param string $user_email.
     * @return WP_Error With or without errors
     */
    public function fail2wp_admin_check_new_user( \WP_Error $errors, string $user_login, string $user_email ) {
        // apply_filters( 'registration_errors', $errors, $sanitized_user_login, $user_email );
        if ( ! is_object( $errors ) || ! is_a( $errors, 'WP_Error' ) ) {
            //Make sure we have what we need, otherwise just return it
            if ( is_object( $errors ) ) {
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): Unknown context "' . get_class( $errors ) . '"' );
            } else {
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): Unknown context "' . $errors . '"' );
            }
            return( $errors );
        }
        // error_log(print_r($errors, true));
        // Check for existing error message and possibly make it less revealing
        if ( $this->fail2wp_secure_login_message ) {
            if ( ! empty( $errors->errors['username_exists'] ) ) {
                $errors->remove( 'username_exists' );
                $errors->add( 'username_exists', esc_html__( 'Invalid username, please try again.', 'fail2wp' ) );
                return( $errors );
            } elseif ( ! empty( $errors->errors['email_exists'] ) ) {
                $errors->remove( 'email_exists' );
                $errors->add( 'email_exists', esc_html__( 'Invalid e-mail address, please try again.', 'fail2wp' ) );
                return( $errors );
            }
        }
        // Check usernames
        $have_error = false;
        if ( empty( $user_login ) || in_array( $user_login, $this->fail2wp_reguser_username_ban ) ) {
            $errors->add( 'fail2wp_username_ban', esc_html__( 'Invalid username, please try again.', 'fail2wp' ) );
            $have_error = true;
        } elseif ( $this->fail2wp_reguser_username_length > 1 ) {
            if ( $this->fail2wp_have_mbstring ) {
                if ( mb_strlen( $user_login ) < $this->fail2wp_reguser_username_length ) {
                    $have_error = true;
                }
            } elseif ( strlen( $user_login ) < $this->fail2wp_reguser_username_length ) {
                $have_error = true;
            }
            if ( $have_error ) {
                $errors->add( 'fail2wp_username_ban', esc_html__( 'Invalid username, please try again.', 'fail2wp' ) );
            }
        }
        // Check e-mail
        if ( ! $have_error && ! empty( $this->fail2wp_reguser_useremail_require ) ) {
            $invalid_email = true;
            if ( ! empty ( $user_email ) ) {
                $invalid_email = true;
                if ( $this->fail2wp_have_mbstring ) {
                    // mb_stripos
                    foreach( $this->fail2wp_reguser_useremail_require as $email_required ) {
                        if ( mb_stripos( $user_email, $email_required ) !== false ) {
                            $invalid_email = false;
                            break;
                        }
                    }// foreach
                } else {
                    // stripos
                    foreach( $this->fail2wp_reguser_useremail_require as $email_required ) {
                        if ( stripos( $user_email, $email_required ) !== false ) {
                            $invalid_email = false;
                            break;
                        }
                    }// foreach
                }
            }// !empty email
            if ( $invalid_email ) {
                error_log( FAIL2WP_PLUGINNAME_HUMAN . ': ' .
                           '"' . $user_email . '" is not an acceptable e-mail address' );
                $errors->add( 'fail2wp_username_ban', esc_html__( 'Invalid e-mail address, please try again.', 'fail2wp' ) );
            }
        }// e-mail

        return( $errors );
    }


    /*
     * Display admin alert about setting default user role.
     *
     * This will display an admin alert if we have overridden WordPress'
     * default new user role.
     *
     * @since 1.1.0
     */
    public function fail2wp_admin_alert_new_user_role_forced() {
        echo '<div class="notice notice-error"><br/>'.
             '<span class="dashicons dashicons-shield" style="font-size:24x;"></span>&nbsp;' .
             esc_html__( 'New user role default has been reset according to your', 'fail2wp' ) .
             '&nbsp;' .
             esc_html( FAIL2WP_PLUGINNAME_HUMAN ) .
             '&nbsp;' .
             esc_html__( 'settings', 'fail2wp' ) .
             '!' .
             '<br/><br/>';
        echo '</div>';
    }
    // Send the same alert via e-mail
    public function fail2wp_admin_alert_new_user_role_forced_email() {
        $admin_email = get_option( 'admin_email', null );
        if ( empty( $admin_email ) || $admin_email === null ) {
            error_log( FAIL2WP_PLUGINNAME_HUMAN . ': ' .
                       'No admin e-mail address from WordPress!' );
            return;
        }
        if ( ! empty($this->fail2wp_site_label ) ) {
            $from_site = $this->fail2wp_site_label;
        } else {
            $from_site = $this->fail2wp_get_site_label( true );
        }
        wp_mail( $admin_email,
                 __( 'Notification about new user role from', 'fail2wp' ) . ' ' . FAIL2WP_PLUGINNAME_HUMAN,
                 "\n" .
                 __( 'This is a notification from', 'fail2wp' ) . ' ' . FAIL2WP_PLUGINNAME_HUMAN .
                 "\n\n" .
                 __( 'The role for newly registered users has been reset to your configured setting.', 'fail2wp' ) .
                 "\n\n" .
                 __( 'This notification was sent from the site', 'fail2wp' ) .
                 ' ' . $from_site . "\n\n" .
                 __( 'You may access the admin interface to the site here', 'fail2wp' ) .
                 ': ' . admin_url() .
                 "\n"
                 ,
                 $this->fail2wp_mail_headers );
    }
    /**
     * Display admin alert about default user role.
     *
     * This will display an admin alert if the default new user role does not
     * match that configured in Fail2WP.
     *
     * @since 1.1.0
     */
    public function fail2wp_admin_alert_new_users_mismatch() {
        global $wp;

        echo '<div class="notice notice-error"><br/>'.
             '<span class="dashicons dashicons-shield" style="font-size:24x;"></span>&nbsp;' .
             esc_html__( 'User registration is enabled, but the new user role does not match', 'fail2wp' ) .
             '&nbsp;' .
             esc_html( FAIL2WP_PLUGINNAME_HUMAN ) .
             '!' .
             '<br/><br/>';
        if ( is_admin( ) && is_user_logged_in() && current_user_can( 'administrator' ) )  {
            // Include link to General settings, if we're not on that page already
            if ( ! empty( $_SERVER['REQUEST_URI' ] ) ) {
                $request_uri = home_url( add_query_arg( array(), $wp->request ) );
                /*esc_url( wp_unslash( $_SERVER['REQUEST_URI' ] ) );*/
            } else {
                $request_uri = '';
            }
            if ( basename( $request_uri ) != 'options-general.php' ) {
                $action = admin_url( 'options-general.php' );
                echo esc_html__( 'Go to', 'fail2wp' ) .
                     ' <a href="' . esc_attr( $action ) . '">' .
                     esc_html__( 'General settings', 'fail2wp' ) .
                     '</a> ' .
                     esc_html__( 'to check your membership and new user settings.', 'fail2wp' ).
                     '<br/><br/>';
            }
        }
        echo '</div>';
    }
    /*
     * Display admin alert about default user role.
     *
     * This will display an admin alert if the default new user role is set to
     * 'administrator'.
     *
     * @since 1.1.0
     */
    public function fail2wp_admin_alert_new_users_admin() {
        global $wp;

        echo '<div class="notice notice-error"><br/>'.
             '<span class="dashicons dashicons-shield" style="font-size:24x;"></span>&nbsp;' .
             esc_html__( 'User registration is enabled, and new users will be administrators', 'fail2wp' ) .
             '&nbsp;' .
             esc_html( FAIL2WP_PLUGINNAME_HUMAN ) .
             '!' .
             '<br/><br/>';
        if ( is_admin( ) && is_user_logged_in() && current_user_can( 'administrator' ) )  {
            // Include link to General settings, if we're not on that page already
            $request_uri = home_url( add_query_arg( array(), $wp->request ) );
            if ( basename( $request_uri ) != 'options-general.php' ) {
                $action = admin_url( 'options-general.php' );
                echo esc_html__( 'Go to', 'fail2wp' ) .
                     ' <a href="' . esc_attr( $action ) . '">' .
                     esc_html__( 'General settings', 'fail2wp' ) .
                     '</a> ' .
                     esc_html__( 'to check your membership and new user settings.', 'fail2wp' ).
                     '<br/><br/>';
            }
        }
        echo '</div>';
    }
    /*
     * Display admin alert about default user role.
     *
     * This will display an admin alert if the default new user role is not set
     *
     * @since 1.1.0
     */
    public function fail2wp_admin_alert_new_users_null() {
        echo '<div class="notice notice-error"><br/>'.
             '<span class="dashicons dashicons-shield" style="font-size:24x;"></span>&nbsp;' .
             esc_html__( 'User registration is enabled, but no role has been configured', 'fail2wp' ) .
             '&nbsp;' .
             esc_html( FAIL2WP_PLUGINNAME_HUMAN ) .
             '!' .
             '<br/><br/>';
        if ( is_admin( ) && is_user_logged_in() && current_user_can( 'administrator' ) )  {
            // Include link to General settings, if we're not on that page already
            $request_uri = home_url( add_query_arg( array(), $wp->request ) );
            if ( basename( $request_uri ) != 'options-general.php' ) {
                $action = admin_url( 'options-general.php' );
                echo esc_html__( 'Go to', 'fail2wp' ) .
                     ' <a href="' . esc_attr( $action ) . '">' .
                     esc_html__( 'General settings', 'fail2wp' ) .
                     '</a> ' .
                     esc_html__( 'to check your membership and new user settings.', 'fail2wp' ).
                     '<br/><br/>';
            }
        }
        echo '</div>';
    }
    /**
     * Fetch filemtime() of file and return it.
     *
     * Fetch filemtime() of $filename and return it, upon error, plugin_version
     * is returned instead. This could possibly simply return plugin_version in
     * production.
     *
     * @since  1.0.0
     * @param  string $filename The file for which we want filemtime()
     * @return string
     */
    protected function resource_mtime( $filename ) {
        $filetime = @ filemtime( $filename );
        if ( $filetime === false ) {
            $filetime = FAIL2WP_VERSION;
        }
        return ( $filetime );
    }


    /**
     * Fetch site label setting with default value.
     *
     * @since 1.1.0
     */
    protected function fail2wp_get_site_label( bool $auto_logic = false ) {
        $option_val = get_option( 'fail2wp-site-label', null );
        if ( $option_val === null ) {
            update_option( 'fail2wp-site-label', '' );
            $option_val = '';
        }
        if ( empty( $option_val ) && $auto_logic ) {
            $option_val = trim( get_bloginfo( 'name' ) );
            if ( empty( $option_val ) ) {
                if ( ! empty( $_SERVER['SERVER_NAME'] ) ) {
                    $option_val = sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) );
                } else {
                    $option_val = '';
                }
                if ( empty( $option_val ) ) {
                    if ( ! empty( $_SERVER['SERVER_ADDR'] ) ) {
                        $option_val = 'IP:' . sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) );
                    } else {
                        $option_val = '';
                    }
                }
            }
        }
        return( $option_val );
    }


    /**
     * Fetch WordPress roles.
     *
     * Fetch WordPress roles with WP names and human names, if possible. One could
     * argue that we can just fetch a list of role names from WP, but we may miss
     * roles with no names ... or not? :-)
     *
     * @since 1.0.0
     * @return array List of roles and their human names
     */
    protected function fail2wp_get_wp_roles() : array {
        if ( $this->fail2wp_wp_roles !== null ) {
            return( $this->fail2wp_wp_roles );
        }
        $wp_roles = wp_roles();
        if ( is_object( $wp_roles ) ) {
            // not sure why WP_Roles::get_roles_data() returns false
            // $roles = $wp_roles->get_roles_data();
            $roles = array_keys( $wp_roles->roles );
            $role_names = $role_names_en = $wp_roles->get_names();

        } else {
            $roles = false;
            $role_names = $role_names_en = array();
        }
        $return_roles = array();
        if ( is_array( $roles ) ) {
            foreach( $roles as $role_k => $role_v ) {
                if ( ! empty( $role_names_en[$role_v] ) ) {
                    $return_roles_en[$role_v] = $role_names_en[$role_v];
                } else {
                    $return_roles_en[$role_v] = __( 'Unknown role', 'fail2wp' ) . ' (' . $role_v . ')';
                }
                if ( ! empty( $role_names[$role_v] ) ) {
                    $return_roles[$role_v] = translate_user_role( $role_names[$role_v] );
                } else {
                    $return_roles[$role_v] = __( 'Unknown role', 'fail2wp' ) . ' (' . $role_v . ')';
                }
            }
        } else {
            error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): wp_roles() returned empty' );
        }
        $this->fail2wp_wp_roles = $return_roles;
        $this->fail2wp_wp_roles_enus = $return_roles_en;
        return( $return_roles );
    }


    /**
     * Setup WordPress admin menu.
     *
     * @since 1.0.0
     */
    public function fail2wp_menu() {
        if ( ! is_admin() || ! is_user_logged_in() || ! current_user_can( 'administrator' ) ) {
            return;
        }
        add_options_page(
            FAIL2WP_PLUGINNAME_HUMAN,
            FAIL2WP_PLUGINNAME_HUMAN,
            'administrator',
            FAIL2WP_PLUGINNAME_SLUG,
            [ $this, 'fail2wp_admin_page' ] );
    }


    /**
     * Setup WordPress admin options page.
     *
     * @since 1.0.0
     */
    public function fail2wp_admin_page() {
        if ( ! is_admin() || ! is_user_logged_in() || ! current_user_can( 'administrator' ) ) {
            return;
        }
        // Get ourselves a proper URL
        $action = admin_url( 'admin.php' ) . '?page=' . FAIL2WP_PLUGINNAME_SLUG;
        //
        $html = '';
        $tab_header ='<div class="wrap">';
        $tab_header .= '<h1><span class="dashicons dashicons-shield" style="font-size:30px"></span>&nbsp;&nbsp;' . FAIL2WP_PLUGINNAME_HUMAN . '</h1>';
        $tab_header .= '<p>' . esc_html__( 'Provides authentication security functions for WordPress, plays nicely with Fail2ban and Cloudflare', 'fail2wp' ) . '</p>';
        $tab_header .= '<nav class="nav-tab-wrapper">';
        $tab_header .= '<a href="' . $action . '" class="nav-tab' . ( empty( $this->fail2wp_settings_tab ) ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'Basic configuration', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . $action . '&tab=loginip" class="nav-tab' . ( $this->fail2wp_settings_tab === 'loginip' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'Login IP', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . $action . '&tab=newuser" class="nav-tab' . ( $this->fail2wp_settings_tab === 'newuser' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'New users', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . $action . '&tab=logging" class="nav-tab' . ( $this->fail2wp_settings_tab === 'logging' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'User logging', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . $action . '&tab=restapi" class="nav-tab' . ( $this->fail2wp_settings_tab === 'restapi' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'REST API', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . $action . '&tab=xmlrpc" class="nav-tab' . ( $this->fail2wp_settings_tab === 'xmlrpc' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'XMLRPC', 'fail2wp' ) .
                 '</a>';
         $tab_header .= '<a href="' . $action . '&tab=advanced" class="nav-tab' . ( $this->fail2wp_settings_tab === 'advanced' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'Advanced', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . $action . '&tab=cloudflare" class="nav-tab' . ( $this->fail2wp_settings_tab === 'cloudflare' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'Cloudflare', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . $action . '&tab=importexport" class="nav-tab' . ( $this->fail2wp_settings_tab === 'importexport' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'Import/Export', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . $action . '&tab=about" class="nav-tab' . ( $this->fail2wp_settings_tab === 'about' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'About', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '</nav>';
        if ( ! function_exists( 'openlog' ) || ! function_exists( 'closelog' ) || ! function_exists( 'syslog' ) ) {
            $tab_header .= '<div class="notice notice-error is-dismissible"><p><strong>'.
                           esc_html__( 'One or more of openlog(), closelog(), and/or syslog() seem to be missing on this system', 'fail2wp' ).
                           '</strong></p></div>';
        }
        ob_start();
        if ( $this->fail2wp_settings_tab == 'about' ) {
            $this->fail2wp_about_page();
            $html .= ob_get_contents();
            ob_end_clean();
        } elseif ( $this->fail2wp_settings_tab == 'importexport' ) {
            $html .= '<form method="post" action="' . esc_url( $action ) . '&tab=importexport">';
            $html .= wp_nonce_field( 'importexport', 'fail2wp_nonce' );
            $html .= '<div class="tab-content">';
            $html .= '<div class="fail2wp-config-header">';
            $do_import = false;

            if ( isset( $_POST['fail2wpimport']) && isset( $_POST['fail2wp_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['fail2wp_nonce'] ) ), 'importexport' ) ) {
                if ( ! empty( $_POST['fail2wp-import-settings'] ) ) {
                    // This construct is on purpose to be able to compare the filtered/unfiltered data
                    $xs = trim( $_POST['fail2wp-import-settings'] );
                    $_POST['fail2wp-import-settings'] = sanitize_text_field( $xs );
                    if ( $xs != $_POST['fail2wp-import-settings'] ) {
                        // Something was stripped
                        $tab_header .= '<div class="notice notice-error is-dismissible"><p><strong>'.
                                       esc_html__( 'Some data was filtered, please make sure you paste the content exactly as copied', 'fail2wp' ).
                                       '</strong></p></div>';
                    } elseif ( strpos( $xs, FAIL2WP_EXPORT_HEADER ) !== 0 || strpos( $xs, FAIL2WP_EXPORT_FOOTER) !== ( strlen( $xs ) - strlen( FAIL2WP_EXPORT_FOOTER ) ) ) {
                        // Header or footer check failed
                        $tab_header .= '<div class="notice notice-error is-dismissible"><p><strong>'.
                                       esc_html__( 'Please make sure you paste the content exactly as copied', 'fail2wp' ).
                                       '</strong></p></div>';
                    } else {
                        // Remove header/footer, convert, and decode before validating
                        $xs = @ json_decode( base64_decode( substr( $xs, strlen( FAIL2WP_EXPORT_HEADER ), strlen( $xs ) - ( strlen( FAIL2WP_EXPORT_HEADER ) + strlen( FAIL2WP_EXPORT_FOOTER ) ) ) ), true, 10 );
                        if ( ! is_array( $xs ) || empty( $xs['fail2wp_plugin_version'] ) ) {
                            // Decoding failed
                            $tab_header .= '<div class="notice notice-error is-dismissible"><p><strong>'.
                                           esc_html__( 'Please make sure you paste the content exactly as copied', 'fail2wp' ).
                                           '</strong></p></div>';
                        } elseif ( $xs['fail2wp_plugin_version'] !== FAIL2WP_VERSION ) {
                            // Version mismatch
                            $tab_header .= '<div class="notice notice-error is-dismissible"><p><strong>'.
                                           esc_html__( 'Plugin version mismatch. You can only import exported data from the same version as the one currently installed', 'fail2wp' ).
                                           '</strong></p></div>';
                        } else {
                            // Good to go
                            $do_import = true;
                        }
                    }
                }
                if ( $do_import ) {
                    // Variables are named fail2wp_this_and_that. Settings are named fail2wp-this-and-that.
                    // So we check if the variable exists in our context, and if so, update the setting.
                    // We do need to make exceptions for array settings, since we store them as json.
                    $warn_about_site_label = false;
                    $import_result = '';
                    foreach( $xs as $k => $v ) {
                        if ( ! property_exists( $this, $k ) ) {
                            $import_result .= '  ' . str_replace( '_', '-', $k ) . '<br/>';
                            continue;
                        }
                        // What we call our option in WP DB
                        $k_wp = str_replace( '_', '-', $k );
                        // Handle exceptions
                        switch( $k ) {
                            case 'fail2wp_loginip_allow':
                            case 'fail2wp_loginip_deny':
                            case 'fail2wp_cloudflare_ipv4':
                            case 'fail2wp_cloudflare_ipv6':
                            case 'fail2wp_reguser_username_ban':
                            case 'fail2wp_reguser_useremail_require':
                            case 'fail2wp_rest_filter_ipv4_bypass':
                            case 'fail2wp_rest_filter_ipv6_bypass':
                                // Some special treatment of these since WordPress
                                // calls the registered sanitization functions for
                                // update_option()
                                update_option( $k_wp, implode( "\n", $v ) );
                                break;
                            case 'fail2wp_roles_notify':
                            case 'fail2wp_roles_warn':
                            case 'fail2wp_rest_filter_block_ns':
                            case 'fail2wp_rest_filter_block_routes':
                                // Array elements (store as json)
                                $v_json = @ wp_json_encode( $v );
                                if ( ! $v_json ) {
                                    error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): Unable to encode import value for "' . $k . '"' );
                                    $import_result .= '  ' . $k_wp . '<br/>';
                                } else {
                                    update_option( $k_wp, $v );
                                }
                                break;
                            case 'fail2wp_plugin_version':
                                // Ignore
                                break;
                            default:
                                update_option( $k_wp, $v );
                                if ( $k == 'fail2wp_site_label' ) {
                                    if ( $v != $this->fail2wp_site_label ) {
                                        // Notify user that "Site label" option may need to be checked
                                        $warn_about_site_label = true;
                                    }
                                }
                                break;
                        }
                    }// foreach
                    // Possibly show warning/notices from import
                    if ( ! empty( $import_result ) ) {
                        $import_result = '<p>' .
                                         esc_html__( 'The following settings were ignored during the import', 'fail2wp' ) .
                                         ':<br/>' .
                                         $import_result .
                                         '</p>';
                        $html .= $import_result;
                    } else {
                        $html .= '<p>' .
                                 esc_html__( 'Settings were successfully imported', 'fail2wp' ) .
                                 '</p>';
                        if ( $warn_about_site_label ) {
                            $html .= '<p>' .
                                     esc_html__( 'The setting "Site label" may need manual correction', 'fail2wp' ) .
                                     '</p>';
                        }
                    }
                }
            }// import settings
            if ( ! $do_import ) {
                $html .= '<p>' . esc_html__( 'This tab can be used to import and export settings for the plugin.', 'fail2wp' ) . '</p>';
                $html .= '<table class="form-table" role="presentation">';
                $html .= '<tr><th scope="row">'.
                         '<label for="fail2wp-import-settings">' .
                         esc_html__( 'Import settings', 'fail2wp' ) .
                         '</label></th></td><td>' .
                         '<textarea name="fail2wp-import-settings" id="fail2wp-import-settings" rows="10" cols="30" class="large-text code" required>' .
                         '</textarea>' .
                         '<p class="description">' .
                         esc_html__( 'Paste settings in this field to import them', 'fail2wp' ) .
                         '</p>' .
                         '</td></tr>';
                $html .= '<tr><td></td><td>' .
                submit_button( esc_html__( 'Import settings', 'fail2wp'), 'primary', 'fail2wpimport' );
                $html .= ob_get_contents();
                $html .= '</td></tr>';
                $html .= '<tr><th scope="row">'.
                         '<label for="fail2wp-export-settings">' .
                         esc_html__( 'Export settings', 'fail2wp' ) .
                         '</label></th></td><td>' .
                         '<textarea name="fail2wp-export-settings" id="fail2wp-export-settings" rows="10" cols="30" class="large-text code" readonly>';
                $config_data = array(
                    'fail2wp_plugin_version'                => FAIL2WP_VERSION,
                    'fail2wp_site_label'                    => $this->fail2wp_site_label,
                    'fail2wp_prefix'                        => $this->fail2wp_prefix,
                    'fail2wp_roles_notify'                  => $this->fail2wp_roles_notify,
                    'fail2wp_roles_warn'                    => $this->fail2wp_roles_warn,
                    'fail2wp_unknown_warn'                  => $this->fail2wp_unknown_warn,
                    'fail2wp_settings_dbversion'            => $this->fail2wp_settings_dbversion,
                    'fail2wp_settings_remove'               => $this->fail2wp_settings_remove,
                    'fail2wp_settings_remove_generator'     => $this->fail2wp_settings_remove_generator,
                    'fail2wp_settings_remove_feeds'         => $this->fail2wp_settings_remove_feeds,
                    'fail2wp_also_log_php'                  => $this->fail2wp_also_log_php,
                    'fail2wp_block_user_enum'               => $this->fail2wp_block_user_enum,
                    'fail2wp_block_username_login'          => $this->fail2wp_block_username_login,
                    'fail2wp_secure_login_message'          => $this->fail2wp_secure_login_message,
                    'fail2wp_log_user_enum'                 => $this->fail2wp_log_user_enum,
                    'fail2wp_cloudflare_ipv4'               => $this->fail2wp_cloudflare_ipv4,
                    'fail2wp_cloudflare_ipv6'               => $this->fail2wp_cloudflare_ipv6,
                    'fail2wp_reguser_warn'                  => $this->fail2wp_reguser_warn,
                    'fail2wp_reguser_warn_role'             => $this->fail2wp_reguser_warn_role,
                    'fail2wp_reguser_force'                 => $this->fail2wp_reguser_force,
                    'fail2wp_reguser_force_role'            => $this->fail2wp_reguser_force_role,
                    'fail2wp_reguser_username_length'       => $this->fail2wp_reguser_username_length,
                    'fail2wp_reguser_username_ban'          => $this->fail2wp_reguser_username_ban,
                    'fail2wp_reguser_useremail_require'     => $this->fail2wp_reguser_useremail_require,
                    'fail2wp_rest_filter_log_blocked'       => $this->fail2wp_rest_filter_log_blocked,
                    'fail2wp_rest_filter_block_all'         => $this->fail2wp_rest_filter_block_all,
                    'fail2wp_rest_filter_block_index'       => $this->fail2wp_rest_filter_block_index,
                    'fail2wp_rest_filter_block_ns'          => $this->fail2wp_rest_filter_block_ns,
                    'fail2wp_rest_filter_block_routes'      => $this->fail2wp_rest_filter_block_routes,
                    'fail2wp_rest_filter_require_authenticated' => $this->fail2wp_rest_filter_require_authenticated,
                    'fail2wp_rest_filter_ipv4_bypass'       => $this->fail2wp_rest_filter_ipv4_bypass,
                    'fail2wp_rest_filter_ipv6_bypass'       => $this->fail2wp_rest_filter_ipv6_bypass,
                    'fail2wp_loginip_enable'                => $this->fail2wp_loginip_enable,
                    'fail2wp_loginip_testmode'              => $this->fail2wp_loginip_testmode,
                    'fail2wp_loginip_inform_fail2ban'       => $this->fail2wp_loginip_inform_fail2ban,
                    'fail2wp-loginip-dnscache'              => $this->fail2wp_loginip_dnscache,
                    'fail2wp_loginip_allow'                 => $this->fail2wp_loginip_allow,
                    'fail2wp_loginip_deny'                  => $this->fail2wp_loginip_deny,
                    'fail2wp_xmlrpc_disable'                => $this->fail2wp_xmlrpc_disable,
                    'fail2wp_xmlrpc_disable_pingback'       => $this->fail2wp_xmlrpc_disable_pingback,
                    'fail2wp_xmlrpc_disable_everything'     => $this->fail2wp_xmlrpc_disable_everything,
                    'fail2wp_xmlrpc_inform_fail2ban'        => $this->fail2wp_xmlrpc_inform_fail2ban,
                );
                /* Not included:
                    'fail2wp_default_http_port'             => $this->fail2wp_default_http_port,
                    'fail2wp_default_https_port'            => $this->fail2wp_default_https_port,
                */
                $json_data = @ wp_json_encode( $config_data, 10 );
                if ( $json_data == false ) {
                    $json_data = '';
                    // Could not encode data
                    $tab_header .= '<div class="notice notice-error is-dismissible"><p><strong>'.
                                   esc_html__( 'Unable to create data for export', 'fail2wp' ).
                                   '</strong></p></div>';
                }
                if ( ! empty( $json_data ) ) {
                    $html .= esc_attr( 'fail2wp_export.begin.' . base64_encode( $json_data ) . '.fail2wp_export.end' );
                }
                $html .= '</textarea>' .
                         '<p class="description">' .
                         esc_html__( 'Copy the text in this field to export your settings to another site', 'fail2wp' ) .
                         '</p>' .
                         '</td></tr>';
                $html .= '</table>';
                ob_end_clean();
            }
            $html .= '</div>';
            $html .= '</div>';
            $html .= '</form>';
        } else {
            $html .= '<form method="post" action="options.php">';
            $html .= '<div class="tab-content">';
            $html .= '<div class="fail2wp-config-header">';
            switch( $this->fail2wp_settings_tab ) {
                default:
                    settings_fields( 'fail2wp-settings' );
                    do_settings_sections( 'fail2wp-settings' );
                    break;
                case 'loginip':
                    settings_fields( 'fail2wp_settings_loginip' );
                    do_settings_sections( 'fail2wp_settings_loginip' );
                    break;
                case 'newuser':
                    settings_fields( 'fail2wp_settings_newuser' );
                    do_settings_sections( 'fail2wp_settings_newuser' );
                    break;
                case 'logging':
                    $html .= '<p>' .
                             esc_html__( "This is logged to the system's authentication log, which allows Fail2ban to dynamically block offending IP addresses.", 'fail2wp' ) .
                             ' '.
                             esc_html__( 'Configuration of the Fail2ban system daemon, or similar, must be done outside of WordPress for this to have any effect.', 'fail2wp' ) .
                             '</p>';
                    settings_fields( 'fail2wp_settings_notify' );
                    do_settings_sections( 'fail2wp_settings_notify' );
                    break;
                case 'restapi':
                    settings_fields( 'fail2wp_settings_restapi' );
                    do_settings_sections( 'fail2wp_settings_restapi' );
                    break;
                case 'xmlrpc':
                    settings_fields( 'fail2wp_settings_xmlrpc' );
                    do_settings_sections( 'fail2wp_settings_xmlrpc' );
                    break;
                case 'advanced':
                    settings_fields( 'fail2wp_settings_advanced' );
                    do_settings_sections( 'fail2wp_settings_advanced' );
                    break;
                case 'cloudflare':
                    settings_fields( 'fail2wp_settings_cloudflare' );
                    do_settings_sections( 'fail2wp_settings_cloudflare' );
                    break;
            }// switchfail2ban
            submit_button();
            $html .= ob_get_contents();
            ob_end_clean();
            $html .= '</div>';
            $html .= '</div>'; // tab-content
            $html .= '</form>';
        }
        $html .= '</div>'; // wrap
        //
        echo $tab_header . $html;
    }


    /**
     * Display about/support.
     *
     * @since  1.0.0
     */
    public function fail2wp_about_page() {
        echo '<div class="tab-content">';
        echo '<div class="fail2wp-config-header">'.
             '<p>'  . esc_html__( 'Thank you for installing', 'fail2wp' ) .' Fail2WP ' . esc_html( FAIL2WP_VERSION ) . '!' . '</p>'.
             '<p>'  . esc_html__( 'This plugin provides security functions and integration between WordPress and', 'fail2wp' ) . ' <a href="https://www.fail2ban.org" class="fail2wp-ext-link" target="_blank"> Fail2ban</a>.</p>'.
             '</div>';
        echo '<div class="fail2wp-config-section">'.
             '<p>'  . '<img class="fail2wp-wps-logo" alt="" src="' . esc_html( plugin_dir_url( __FILE__ ) ) . 'img/webbplatsen_logo.png" />' .
                      esc_html__( 'Commercial support and customizations for this plugin is available from', 'fail2wp' ) .
                      ' <a class="fail2wp-ext-link" href="https://webbplatsen.se" target="_blank">WebbPlatsen i Sverige AB</a> '.
                      esc_html__('(Sweden). We speak Swedish and English', 'fail2wp' ) . ' :-)' .
                      '<br/><br/>' .
                      esc_html__( 'The plugin is written by Joaquim Homrighausen and sponsored by WebbPlatsen i Sverige AB.', 'fail2wp' ) .
             '</p>' .
             '<p>'  . esc_html__( 'If you find this plugin useful, the author is happy to receive a donation, good review, or just a kind word.', 'fail2wp' ) . ' ' .
                      esc_html__( 'If there is something you feel to be missing from this plugin, or if you have found a problem with the code or a feature, please do not hesitate to reach out to', 'fail2wp' ) .
                                  ' <a class="fail2wp-ext-link" href="mailto:support@webbplatsen.se">support@webbplatsen.se</a>' . ' '.
             '</p>' .
             '<p>'  .
                      esc_html__( 'There is more documentation available at', 'fail2wp' ) . ' ' .
                                  '<a class="fail2wp-ext-link" target="_blank" href="https://code.webbplatsen.net/documentation/fail2wp/">'.
                                  'code.webbplatsen.net/documentation/fail2wp/</a>' .
             '</p>' .
             '<p style="margin-top:20px;">' .
                 '<h3>' . esc_html__( 'Other plugins', 'fail2wp' ) . '</h3>' .
                 '<p class="fail2wp-row">' .
                     '<a href="https://wordpress.org/plugins/cloudbridge-mattermost" target="_blank" class="fail2wp-ext-link">Cloudbridge Mattermost</a>' .
                     '<br/>' .
                     esc_html__( 'Plugin that provides integration with Mattermost, including notifications and OAuth2 authentication', 'fail2wp' ) . '.' .
                 '</p>' .
                 '<p class="fail2wp-row">' .
                     '<a href="https://wordpress.org/plugins/cloudbridge-2fa" target="_blank" class="fail2wp-ext-link">Cloudbridge 2FA</a>' .
                     '<br/>' .
                     esc_html__( 'Plugin that provides uncomplicated 2FA protection', 'fail2wp' ) . '.' .
                 '</p>' .
                 '<p class="fail2wp-row">' .
                     '<a href="https://wordpress.org/plugins/easymap" target="_blank" class="fail2wp-ext-link">EasyMap</a>' .
                     '<br/>' .
                     esc_html__( 'Plugin that provides uncomplicated map functionality', 'fail2wp' ) . '.' .
                '</p>' .
             '</p>' .
             '</div>';
        echo '</div>';
    }


    /**
     * Display settings.
     *
     * @since  1.0.0
     */
    public function fail2wp_settings() {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        add_settings_section( 'fail2wp-settings', '', false, 'fail2wp-settings' );
          add_settings_field( 'fail2wp-site-label', esc_html__( 'Site label', 'fail2wp' ), [$this, 'fail2wp_setting_site_label'], 'fail2wp-settings', 'fail2wp-settings', ['label_for' => 'fail2wp-site-label'] );
          add_settings_field( 'fail2wp-block-user-enum', esc_html__( 'Block user enum', 'fail2wp' ), [$this, 'fail2wp_setting_block_enums'], 'fail2wp-settings', 'fail2wp-settings', ['label_for' => 'fail2wp-block-user-enum'] );
          add_settings_field( 'fail2wp-block-username-login', esc_html__( 'Block username login', 'fail2wp' ), [$this, 'fail2wp_setting_block_username_login'], 'fail2wp-settings', 'fail2wp-settings', ['label_for' => 'fail2wp-block-username-login'] );
          add_settings_field( 'fail2wp-secure-login-message', esc_html__( 'Secure login messages', 'fail2wp' ), [$this, 'fail2wp_setting_secure_login_messages'], 'fail2wp-settings', 'fail2wp-settings', ['label_for' => 'fail2wp-secure-login-message'] );

        add_settings_section( 'fail2wp_section_other', esc_html__( 'Other settings', 'fail2wp' ), false, 'fail2wp-settings' );
          add_settings_field( 'fail2wp-settings-remove-generator', esc_html__( 'Remove generator info', 'fail2wp' ), [$this, 'fail2wp_setting_remove_generator'], 'fail2wp-settings', 'fail2wp_section_other', ['label_for' => 'fail2wp-settings-remove-generator'] );
          add_settings_field( 'fail2wp-settings-remove-feeds', esc_html__( 'Remove feeds', 'fail2wp' ), [$this, 'fail2wp_setting_remove_feeds'], 'fail2wp-settings', 'fail2wp_section_other', ['label_for' => 'fail2wp-settings-remove-feeds'] );
          add_settings_field( 'fail2wp-settings-remove', esc_html__( 'Remove settings', 'fail2wp' ), [$this, 'fail2wp_setting_remove'], 'fail2wp-settings', 'fail2wp_section_other', ['label_for' => 'fail2wp-settings-remove'] );
        add_settings_section( 'fail2wp_section_loginip',
                              '',
                              [$this, 'fail2wp_settings_loginip_callback'],
                              'fail2wp_settings_loginip' );
          add_settings_field( 'fail2wp-loginip-enable',
                              esc_html__( 'Login IP check enabled', 'fail2wp' ),
                              [$this, 'fail2wp_setting_loginip_enable'],
                              'fail2wp_settings_loginip',
                              'fail2wp_section_loginip',
                              ['label_for' => 'fail2wp-loginip-enable'] );
          add_settings_field( 'fail2wp-loginip-testmode',
                              esc_html__( 'Login IP check testmode', 'fail2wp' ),
                              [$this, 'fail2wp_setting_loginip_testmode'],
                              'fail2wp_settings_loginip',
                              'fail2wp_section_loginip',
                              ['label_for' => 'fail2wp-loginip-testmode'] );
          add_settings_field( 'fail2wp-loginip-inform-fail2ban',
                              esc_html__( 'Notify fail2ban', 'fail2wp' ),
                              [$this, 'fail2wp_setting_loginip_inform_fail2ban'],
                              'fail2wp_settings_loginip',
                              'fail2wp_section_loginip',
                              ['label_for' => 'fail2wp-loginip-inform-fail2ban'] );
          add_settings_field( 'fail2wp-loginip-dnscache',
                              esc_html__( 'Cache DNS lookups', 'fail2wp' ),
                              [$this, 'fail2wp_setting_loginip_dnscache'],
                              'fail2wp_settings_loginip',
                              'fail2wp_section_loginip',
                              ['label_for' => 'fail2wp-loginip-dnscache'] );
          add_settings_field( 'fail2wp-loginip-allow',
                              esc_html__( 'Allow list', 'fail2wp' ),
                              [$this, 'fail2wp_settings_loginip_allow'],
                              'fail2wp_settings_loginip',
                              'fail2wp_section_loginip',
                              ['label_for' => 'fail2wp-loginip-allow'] );
          add_settings_field( 'fail2wp-loginip-deny',
                              esc_html__( 'Deny list', 'fail2wp' ),
                              [$this, 'fail2wp_settings_loginip_deny'],
                              'fail2wp_settings_loginip',
                              'fail2wp_section_loginip',
                              ['label_for' => 'fail2wp-loginip-deny'] );
        add_settings_section( 'fail2wp_section_newuser', '', false, 'fail2wp_settings_newuser' );
          add_settings_field( 'fail2wp-reguser-warn', esc_html__( 'Membership warnings', 'fail2wp' ), [$this, 'fail2wp_setting_reguser_warn'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-warn'] );
          add_settings_field( 'fail2wp-reguser-warn-role', esc_html__( 'Check for role', 'fail2wp' ), [$this, 'fail2wp_setting_reguser_warn_role'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-warn-role'] );
          add_settings_field( 'fail2wp-reguser-force', esc_html__( 'Force role', 'fail2wp' ), [$this, 'fail2wp_setting_reguser_force'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-force'] );
          add_settings_field( 'fail2wp-reguser-force-role', esc_html__( 'Role to force', 'fail2wp' ), [$this, 'fail2wp_setting_reguser_force_role'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-force-role'] );
          add_settings_field( 'fail2wp-reguser-username-length', esc_html__( 'Minimum username length', 'fail2wp' ), [$this, 'fail2wp_settings_reguser_username_length'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-username-length'] );
          add_settings_field( 'fail2wp-reguser-username-ban', esc_html__( 'Banned usernames', 'fail2wp' ), [$this, 'fail2wp_settings_reguser_username_ban'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-username-ban'] );
          add_settings_field( 'fail2wp-reguser-useremail-require', esc_html__( 'E-mail must match', 'fail2wp' ), [$this, 'fail2wp_settings_reguser_useremail_require'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-useremail-require'] );

        add_settings_section( 'fail2wp_settings_notify', '', false, 'fail2wp_settings_notify' );
          add_settings_field( 'fail2wp-roles-notify', esc_html__( 'Successful login', 'fail2wp' ), [$this, 'fail2wp_setting_roles_notify'], 'fail2wp_settings_notify', 'fail2wp_settings_notify', ['label_for' => 'fail2wp-roles-notify'] );
          add_settings_field( 'fail2wp-roles-warn', esc_html__( 'Unsuccessful login', 'fail2wp' ), [$this, 'fail2wp_setting_roles_warn'], 'fail2wp_settings_notify', 'fail2wp_settings_notify', ['label_for' => 'fail2wp-roles-warn'] );
          add_settings_field( 'fail2wp-unknown-warn', '', [$this, 'fail2wp_setting_unknown_notify'], 'fail2wp_settings_notify', 'fail2wp_settings_notify', ['label_for' => 'fail2wp-unknown-warn'] );
          add_settings_field( 'fail2wp-log-user-enum', esc_html__( 'Log user enum', 'fail2wp' ), [$this, 'fail2wp_setting_log_enums'], 'fail2wp_settings_notify', 'fail2wp_settings_notify', ['label_for' => 'fail2wp-log-user-enum'] );

        add_settings_section( 'fail2wp_section_restapi', '', [$this, 'fail2wp_settings_restapi_callback'], 'fail2wp_settings_restapi' );
          add_settings_field( 'fail2wp-rest-filter-require-authenticated', esc_html__( 'Require authentication', 'fail2wp' ), [$this, 'fail2wp_setting_rest_filter_require_authenticated'], 'fail2wp_settings_restapi', 'fail2wp_section_restapi', ['label_for' => 'fail2wp-rest-filter-require-authenticated'] );
          add_settings_field( 'fail2wp-rest-filter-log-blocked', esc_html__( 'Log blocked requests', 'fail2wp' ), [$this, 'fail2wp_setting_rest_filter_log_blocked'], 'fail2wp_settings_restapi', 'fail2wp_section_restapi', ['label_for' => 'fail2wp-rest-filter-log-blocked'] );
          add_settings_field( 'fail2wp-rest-filter-block-index', esc_html__( 'Block index requests', 'fail2wp' ), [$this, 'fail2wp_setting_rest_filter_block_index'], 'fail2wp_settings_restapi', 'fail2wp_section_restapi', ['label_for' => 'fail2wp-rest-filter-block-index'] );
          add_settings_field( 'fail2wp-rest-filter-block-all', esc_html__( 'Block all requests', 'fail2wp' ), [$this, 'fail2wp_setting_rest_filter_block_all'], 'fail2wp_settings_restapi', 'fail2wp_section_restapi', ['label_for' => 'fail2wp-rest-filter-block-all'] );
          add_settings_field( 'fail2wp-rest-filter-block-ns', esc_html__( 'Block specific namespaces', 'fail2wp' ),   [$this, 'fail2wp_setting_rest_filter_block_ns'],  'fail2wp_settings_restapi', 'fail2wp_section_restapi', ['label_for' => 'fail2wp-rest-filter-block-ns'] );
          add_settings_field( 'fail2wp-rest-filter-block-routes', esc_html__( 'Block specific routes', 'fail2wp' ),   [$this, 'fail2wp_setting_rest_filter_block_routes'],  'fail2wp_settings_restapi', 'fail2wp_section_restapi', ['label_for' => 'fail2wp-rest-filter-block-routes'] );
          add_settings_field( 'fail2wp-rest-filter-ipv4-bypass', esc_html__( 'Bypass blocks for IPv4', 'fail2wp' ), [$this, 'fail2wp_settings_rest_filter_bypass_ipv4'], 'fail2wp_settings_restapi', 'fail2wp_section_restapi', ['label_for' => 'fail2wp-rest-filter-ipv4-bypass'] );
          add_settings_field( 'fail2wp-rest-filter-ipv6-bypass', esc_html__( 'Bypass blocks for IPv6', 'fail2wp' ), [$this, 'fail2wp_settings_rest_filter_bypass_ipv6'], 'fail2wp_settings_restapi', 'fail2wp_section_restapi', ['label_for' => 'fail2wp-rest-filter-ipv6-bypass'] );

        add_settings_section( 'fail2wp_section_xmlrpc', '', [$this, 'fail2wp_settings_xmlrpc_callback'], 'fail2wp_settings_xmlrpc' );
          add_settings_field( 'fail2wp-xmlrpc-disable',
                              esc_html__( 'Disable XMLRPC auth', 'fail2wp' ),
                              [$this, 'fail2wp_setting_xmlrpc_disable'],
                              'fail2wp_settings_xmlrpc',
                              'fail2wp_section_xmlrpc',
                              ['label_for' => 'fail2wp-xmlrpc-disable'] );
          add_settings_field( 'fail2wp-xmlrpc-disable-pingback',
                              esc_html__( 'Disable XMLRPC pingbacks', 'fail2wp' ),
                              [$this, 'fail2wp_setting_xmlrpc_disable_pingback'],
                              'fail2wp_settings_xmlrpc',
                              'fail2wp_section_xmlrpc',
                              ['label_for' => 'fail2wp-xmlrpc-disable-pingback'] );
          add_settings_field( 'fail2wp-xmlrpc-disable-everything',
                              esc_html__( 'Disable XMLRPC completely', 'fail2wp' ),
                              [$this, 'fail2wp_setting_xmlrpc_disable_everything'],
                              'fail2wp_settings_xmlrpc',
                              'fail2wp_section_xmlrpc',
                              ['label_for' => 'fail2wp-xmlrpc-disable-everything'] );
          add_settings_field( 'fail2wp-xmlrpc-inform-fail2ban',
                              esc_html__( 'Notify fail2ban', 'fail2wp' ),
                              [$this, 'fail2wp_setting_xmlrpc_inform_fail2ban'],
                              'fail2wp_settings_xmlrpc',
                              'fail2wp_section_xmlrpc',
                              ['label_for' => 'fail2wp-xmlrpc-inform-fail2ban'] );

        add_settings_section( 'fail2wp_settings_advanced', '', [$this, 'fail2wp_settings_advanced_callback'], 'fail2wp_settings_advanced' );
          add_settings_field( 'fail2wp-prefix', esc_html__( 'Logging prefix', 'fail2wp' ), [$this, 'fail2wp_settings_prefix'], 'fail2wp_settings_advanced', 'fail2wp_settings_advanced', ['label_for' => 'fail2wp-prefix'] );
          add_settings_field( 'fail2wp-also-log-php', esc_html__( 'Also log to PHP log', 'fail2wp' ), [$this, 'fail2wp_setting_also_log_php'], 'fail2wp_settings_advanced', 'fail2wp_settings_advanced', ['label_for' => 'fail2wp-also-log-php'] );

        add_settings_section( 'fail2wp_settings_cloudflare', '', [$this, 'fail2wp_settings_cloudflare_callback'], 'fail2wp_settings_cloudflare' );
          add_settings_field( 'fail2wp-cloudflare-check', esc_html__( 'Check for Cloudflare IP', 'fail2wp' ), [$this, 'fail2wp_setting_cloudflare_check'], 'fail2wp_settings_cloudflare', 'fail2wp_settings_cloudflare', ['label_for' => 'fail2wp-cloudflare-check'] );
          add_settings_field( 'fail2wp-cloudflare-ipv4', esc_html__( 'Cloudflare IPv4', 'fail2wp' ), [$this, 'fail2wp_settings_cloudflare_ipv4'], 'fail2wp_settings_cloudflare', 'fail2wp_settings_cloudflare', ['label_for' => 'fail2wp-cloudflare-ipv4'] );
          add_settings_field( 'fail2wp-cloudflare-ipv6', esc_html__( 'Cloudflare IPv6', 'fail2wp' ), [$this, 'fail2wp_settings_cloudflare_ipv6'], 'fail2wp_settings_cloudflare', 'fail2wp_settings_cloudflare', ['label_for' => 'fail2wp-cloudflare-ipv6'] );

        register_setting( 'fail2wp-settings', 'fail2wp-site-label', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_site_label']] );
        register_setting( 'fail2wp-settings', 'fail2wp-block-user-enum' );
        register_setting( 'fail2wp-settings', 'fail2wp-block-username-login' );
        register_setting( 'fail2wp-settings', 'fail2wp-block-username-login' );
        register_setting( 'fail2wp-settings', 'fail2wp-secure-login-message' );
        register_setting( 'fail2wp-settings', 'fail2wp-settings-remove-generator' );
        register_setting( 'fail2wp-settings', 'fail2wp-settings-remove-feeds' );
        register_setting( 'fail2wp-settings', 'fail2wp-settings-remove' );

        register_setting( 'fail2wp_settings_loginip', 'fail2wp-loginip-enable' );
        register_setting( 'fail2wp_settings_loginip', 'fail2wp-loginip-testmode' );
        register_setting( 'fail2wp_settings_loginip', 'fail2wp-loginip-inform-fail2ban' );
        register_setting( 'fail2wp_settings_loginip', 'fail2wp-loginip-dnscache', ['type' => 'number', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_dnscache']] );
        register_setting( 'fail2wp_settings_loginip', 'fail2wp-loginip-allow', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_textarea_setting']]  );
        register_setting( 'fail2wp_settings_loginip', 'fail2wp-loginip-deny', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_textarea_setting']]  );

        register_setting( 'fail2wp_settings_xmlrpc', 'fail2wp-xmlrpc-disable' );
        register_setting( 'fail2wp_settings_xmlrpc', 'fail2wp-xmlrpc-disable-pingback' );
        register_setting( 'fail2wp_settings_xmlrpc', 'fail2wp-xmlrpc-disable-everything' );
        register_setting( 'fail2wp_settings_xmlrpc', 'fail2wp-xmlrpc-inform-fail2ban' );

        register_setting( 'fail2wp_settings_newuser', 'fail2wp-reguser-warn' );
        register_setting( 'fail2wp_settings_newuser', 'fail2wp-reguser-warn-role' );
        register_setting( 'fail2wp_settings_newuser', 'fail2wp-reguser-force' );
        register_setting( 'fail2wp_settings_newuser', 'fail2wp-reguser-force-role' );
        register_setting( 'fail2wp_settings_newuser', 'fail2wp-reguser-username-length', ['type' => 'number', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_username_length']] );
        register_setting( 'fail2wp_settings_newuser', 'fail2wp-reguser-username-ban', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_textarea_setting']] );
        register_setting( 'fail2wp_settings_newuser', 'fail2wp-reguser-useremail-require', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_textarea_setting']] );

        register_setting( 'fail2wp_settings_notify', 'fail2wp-roles-notify', ['type' => 'array', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_roles']] );
        register_setting( 'fail2wp_settings_notify', 'fail2wp-roles-warn', ['type' => 'array', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_roles']] );
        register_setting( 'fail2wp_settings_notify', 'fail2wp-unknown-warn' );
        register_setting( 'fail2wp_settings_notify', 'fail2wp-log-user-enum' );

        register_setting( 'fail2wp_settings_restapi', 'fail2wp-rest-filter-require-authenticated' );
        register_setting( 'fail2wp_settings_restapi', 'fail2wp-rest-filter-log-blocked' );
        register_setting( 'fail2wp_settings_restapi', 'fail2wp-rest-filter-block-index' );
        register_setting( 'fail2wp_settings_restapi', 'fail2wp-rest-filter-block-all' );
        register_setting( 'fail2wp_settings_restapi', 'fail2wp-rest-filter-block-ns', ['type' => 'array', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_block_ns']] );
        register_setting( 'fail2wp_settings_restapi', 'fail2wp-rest-filter-block-routes', ['type' => 'array', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_block_routes']] );
        register_setting( 'fail2wp_settings_restapi', 'fail2wp-rest-filter-ipv4-bypass', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_textarea_setting']] );
        register_setting( 'fail2wp_settings_restapi', 'fail2wp-rest-filter-ipv6-bypass', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_textarea_setting']] );

        register_setting( 'fail2wp_settings_advanced', 'fail2wp-prefix', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_advanced']] );
        register_setting( 'fail2wp_settings_advanced', 'fail2wp-also-log-php' );

        register_setting( 'fail2wp_settings_cloudflare', 'fail2wp-cloudflare-check' );
        register_setting( 'fail2wp_settings_cloudflare', 'fail2wp-cloudflare-ipv4', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_textarea_setting']] );
        register_setting( 'fail2wp_settings_cloudflare', 'fail2wp-cloudflare-ipv6', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_textarea_setting']] );
    }


    /**
     * Sanitize input.
     *
     * Basic cleaning/checking of user input. Not much to do really.
     *
     * @since  1.0.0
     */
    public function fail2wp_setting_sanitize_site_label( $input ) {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        if ( $this->fail2wp_have_mbstring ) {
            return( mb_substr( sanitize_text_field( $input ), 0, 200 ) );
        }
        return( substr( sanitize_text_field( $input ), 0, 200 ) );
    }
    public function fail2wp_setting_sanitize_roles( $input ) {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        $available_roles = $this->fail2wp_get_wp_roles();
        $return_val = array();
        if ( is_array( $input ) ) {
            $roles_array = array_keys( $available_roles );
            foreach( $input as $role ) {
                if ( in_array( $role, $roles_array ) ) {
                    // We know $role is clean since it matches
                    $return_val[] = $role;
                }
            }
        }
        return( wp_json_encode( $return_val ) );
    }
    public function fail2wp_setting_sanitize_block_ns( $input ) {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        $namespaces = $this->fail2wp_get_rest_ns();
        $return_val = array();
        if ( is_array( $input ) ) {
            foreach( $input as $block_ns ) {
                if ( in_array( $block_ns, $namespaces ) ) {
                    // We know $bock_ns is clean since it matches
                    $return_val[] = $block_ns;
                }
            }
        }
        return( wp_json_encode( $return_val ) );
    }
    public function fail2wp_setting_sanitize_block_routes( $input ) {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        $return_val = array();
        if ( is_array( $input ) ) {
            foreach( $input as $block_route ) {
                if ( in_array( $block_route, $this->fail2wp_rest_filter_route_list ) ) {
                    // We know $block_route is clean since it matches
                    $return_val[] = $block_route;
                }
            }
        }
        return( wp_json_encode( $return_val ) );
    }
    public function fail2wp_setting_sanitize_advanced( $input ) {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        if ( $this->fail2wp_have_mbstring ) {
            return( mb_substr( sanitize_text_field( $input ), 0, 200 ) );
        }
        return( substr( sanitize_text_field( $input ), 0, 200 ) );
    }
    public function fail2wp_setting_sanitize_textarea_setting( $input ) {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        $output = array();
        $original_input = sanitize_textarea_field( $input );
        if ( ( $this->fail2wp_have_mbstring && mb_strlen( $original_input ) == 0 ) || strlen( $original_input ) == 0 ) {
            // empty string
            $input = @ wp_json_encode( $output );
            return( $input );
        }
        // Sanitize and split "string" on "EOL"
        if ( $this->fail2wp_have_mbstring ) {
            // This works, but there's an easier way
            // $output = mb_split( '([\, \n\t\v\r])+', sanitize_textarea_field( $input ) );
            $the_lines = mb_split( '([\, \s])+', mb_strtolower( $original_input ) );
            if ( ! is_array( $the_lines ) ) {
                if ( defined( 'FAIL2WP_GENERAL_DEBUG' ) && FAIL2WP_GENERAL_DEBUG ) {
                    error_log( __FILE__ . ' (' . __FUNCTION__ . '): mb_split() ' . var_export( $the_lines, true) );
                }
                $output = array( 0 => mb_strtolower( $original_input ) );
            } else {
                foreach( $the_lines as $the_line ) {
                    $output[] = trim( mb_substr( $the_line, 0, 200 ) );
                }
            }
        } else {
            $the_lines = preg_split( '/[\s,]+/', strtolower( $original_input ) );
            if ( ! is_array( $the_lines ) ) {
                if ( defined( 'FAIL2WP_GENERAL_DEBUG' ) && FAIL2WP_GENERAL_DEBUG ) {
                    error_log( __FILE__ . ' (' . __FUNCTION__ . '): preg_split() ' . var_export( $the_lines, true) );
                }
                $output = array( 0 => strtolower( $original_input ) );
            } else {
                foreach( $the_lines as $the_line ) {
                    $output[] = trim( substr( $the_line, 0, 200 ) );
                }
            }
        }
        $input = @ wp_json_encode( $output );
        return( $input );
    }
    public function fail2wp_setting_sanitize_username_length( $input ) {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        // We really should strip everything but numbers here, but ...
        $input = (int) sanitize_text_field( $input );
        if ( $input < 0 ) {
            $input = 0;
        } elseif ( $input > 200 ) {
            $input = 200;
        }
        return( $input );
    }
    public function fail2wp_setting_sanitize_dnscache( $input ) {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        // We really should strip everything but numbers here, but ...
        $input = (int) sanitize_text_field( $input );
        if ( $input < 0 ) {
            $input = 0;
        } elseif ( $input > 10080 ) {
            $input = 10080;
        }
        if ( $input === 0 && $this->fail2wp_loginip_dnscache !== 0 ) {
            if ( defined( 'FAIL2WP_SETTINGS_DEBUG' ) && FAIL2WP_SETTINGS_DEBUG ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache time changed from ' . $this->fail2wp_loginip_dnscache . ' to ' . $input );
            }
            // Cache setting has changed from non-zero to zero, clear cache
            $this->fail2wp_hostname_cache = array();
            update_option( 'fail2wp-hostname-cache', wp_json_encode( $this->fail2wp_hostname_cache ) );
        }
        return( $input );
    }
    /**
     * Output input fields.
     *
     * @since 1.0.0
     */
    public function fail2wp_setting_site_label() {
        $placeholder = $this->fail2wp_get_site_label( true );
        echo '<input type="text" size="60" maxlength="200" id="fail2wp-site-label" name="fail2wp-site-label" value="' . esc_attr( $this->fail2wp_site_label ). '"';
        if ( empty( $this->fail2wp_site_label ) && ! empty( $placeholder ) ) {
            echo ' placeholder="' . esc_attr( $placeholder ) . '"';
        }
        echo ' />';
        echo '<p class="description">' . esc_html__( 'The site name to use for logging, defaults to your site name if left empty', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_setting_roles_notify($args) {
        $available_roles = $this->fail2wp_get_wp_roles();
        foreach( $available_roles as $k => $v ) {
            echo '<div class="fail2wp-role-option">';
            echo '<label for="fail2wp-roles-notify[]">';
            echo '<input type="checkbox" name="fail2wp-roles-notify[]" id="fail2wp-roles-notify[]" value="' . esc_attr( $k ) . '" ' . ( in_array( $k, $this->fail2wp_roles_notify ) ? 'checked="checked" ':'' ) . '/>';
            echo esc_html__( $v, 'default' ) . '</label> ';
            echo '</div>';
        }
    }
    public function fail2wp_setting_roles_warn() {
        $available_roles = $this->fail2wp_get_wp_roles();
        foreach( $available_roles as $k => $v ) {
            echo '<div class="fail2wp-role-option">';
            echo '<label for="fail2wp-roles-warn[]">';
            echo '<input type="checkbox" name="fail2wp-roles-warn[]" id="fail2wp-roles-warn[]" value="' . esc_attr( $k ) . '" ' . ( in_array( $k, $this->fail2wp_roles_warn ) ? 'checked="checked" ':'' ) . '/>';
            echo esc_html__( $v, 'default' ) . '</label> ';
            echo '</div>';
        }
    }
    public function fail2wp_setting_unknown_notify() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-unknown-warn">';
        echo '<input type="checkbox" name="fail2wp-unknown-warn" id="fail2wp-unknown-warn" value="1" ' . ( checked( $this->fail2wp_unknown_warn, 1, false ) ) . '/>';
        echo esc_html__( 'Unknown users', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_log_enums() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-log-user-enum">';
        echo '<input type="checkbox" name="fail2wp-log-user-enum" id="fail2wp-log-user-enum" value="1" ' . ( checked( $this->fail2wp_log_user_enum, 1, false ) ) . '/>';
        echo esc_html__( 'User enumeration attempts (i.e. your.site/...?author=nnn)', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    // @since 1.2.0
    public function fail2wp_settings_loginip_callback() {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        echo '<p>'.
             esc_html__( 'These settings allows you to allow or block logins from IP addresses.', 'fail2wp' ).
             '</p><p>' .
             esc_html__( 'You may enter single IPv4 and IPv6 addresses, addresses in CIDR notation, and/or fully qualified hostnames.', 'fail2wp' ).
             ' ' .
             esc_html__( 'Hostnames will be resolved to IP addresses. If you have enabled checking for Cloudflare IPs, it will be taken into consideration.', 'fail2wp' ) .
             ' ' .
             esc_html__( 'You may also use wildcard*.hostna??.com, in which case a reverse name lookup is performed based on the visitor\'s IP address.', 'fail2wp' ) .
             '</p>';
        if ( $this->fail2wp_loginip_enable ) {
            echo '<p><span  style="color:#ff0000;">' .
                 esc_html__( 'Please make sure your IP address or hostname is on the allow list', 'fail2wp' ) .
                 '.</span> ';
            // Remote IP
            if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
                $remote_ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
            } else {
                $remote_ip = '(empty)';
            }
            echo esc_html__( 'Indicated remote IP address', 'fail2wp' ) . ': <b>' . esc_html( $remote_ip ) . '</b>. ';
            // Cloudflare
            $remote_ip_cf = $this->fail2wp_do_cloudflare_lookup( $remote_ip );
            if ( $remote_ip != $remote_ip_cf ) {
                echo esc_html__( 'Indicated Cloudflare IP address', 'fail2wp' ) . ': <b>' . esc_html( $remote_ip_cf ) . '</b>. ';
            }
            // Possibly remote IP, if proxied
            if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
                echo esc_html__( 'Indicated proxy addresses', 'fail2wp' ) . ' (X-Real-IP): <b>' . esc_html( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) ) ) . '</b>. ';
            }
            echo '</p>';
        }
    }
    public function fail2wp_setting_loginip_enable() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-loginip-enable">';
        echo '<input type="checkbox" name="fail2wp-loginip-enable" id="fail2wp-loginip-enable" value="1" ' . ( checked( $this->fail2wp_loginip_enable, 1, false ) ) . '/>';
        echo ' ' . esc_html__( 'enable IP address access control for logins', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_loginip_testmode() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-loginip-testmode">';
        echo '<input type="checkbox" name="fail2wp-loginip-testmode" id="fail2wp-loginip-testmode" value="1" ' . ( checked( $this->fail2wp_loginip_testmode, 1, false ) ) . '/>';
        echo ' ' . esc_html__( 'enable test mode. This will log failures to the PHP error log, but not actually block the login', 'fail2wp' ) . '.</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_loginip_inform_fail2ban() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-loginip-inform-fail2ban">';
        echo '<input type="checkbox" name="fail2wp-loginip-inform-fail2ban" id="fail2wp-loginip-inform-fail2ban" value="1" ' . ( checked( $this->fail2wp_loginip_inform_fail2ban, 1, false ) ) . '/>';
        echo ' ' .
             esc_html__( 'notify fail2ban about failed login attempts based on IP login rules, automatically disabled if test mode is enabled', 'fail2wp' ) . '.</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_loginip_dnscache() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-loginip-dnscache">';
        echo '<input type="number" min="0" max="10080" id="fail2wp-loginip-dnscache" name="fail2wp-loginip-dnscache" size="6" minlength="0" maxlength="5" value="' . esc_attr( (int)$this->fail2wp_loginip_dnscache ) . '" />';
        echo ' ' . esc_html__( 'minutes (0-10080)', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_settings_loginip_allow() {
        echo '<textarea rows="8" cols="30" id="fail2wp-loginip-allow" name="fail2wp-loginip-allow" class="large-text code">';
        echo esc_html( implode( "\n", $this->fail2wp_loginip_allow ) );
        echo '</textarea>';
        echo '<p class="description">' .
                 '<p>' . esc_html__( 'IPs matching these addresses will be allowed to login', 'fail2wp' ) . '.</p>' .
                 '<p style="font-weight:bold;">' . esc_html__( 'If this list is used, and the remote IP address does not match an entry here, the login will be denied', 'fail2wp' ) . '!</p>' .
                 '</p>';
    }
    public function fail2wp_settings_loginip_deny() {
        echo '<textarea rows="8" cols="30" id="fail2wp-loginip-deny" name="fail2wp-loginip-deny" class="large-text code">';
        echo esc_html( implode( "\n", $this->fail2wp_loginip_deny ) );
        echo '</textarea>';
        echo '<p class="description">' . esc_html__( 'IPs matching these addresses will be prevented from logging in', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_settings_xmlrpc_callback() {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        echo '<p>' .
             esc_html__( 'These settings will disable and/or monitor XMLRPC calls to this site', 'fail2wp' ) . '. ' .
             '</p>';
        echo '<p>' .
             esc_html__( 'Please make sure you understand how these settings can impact the operation of WordPress and other plugins before making changes to them', 'fail2wp' ) . '.' .
             '</p>';
        echo '<p>' .
             esc_html__( 'If an authenticated XMLRPC call fails due to an unknown username or invalid password, it will be handled by Fail2WP as a failed user login attempt', 'fail2wp' ) . '. ' .
             esc_html__( 'Please see "', 'fail2wp' ) . '<b>' . esc_html__( 'User logging', 'fail2wp' ) . '</b>" ' . esc_html__( 'to configure applicable options', 'fail2wp' ) . '.' .
             '</p>';
        echo '<p>' .
             esc_html__( 'If XMLRPC pingbacks are disabled, the following XMLRPC methods are removed', 'fail2wp' ) . ': ' .
             '<b>' . esc_html  ( 'pingback.ping, pingback.extensions.getPingbacks, demo.sayHello, demo.addTwoNumbers.' ) . '</b>' .
             '</p>';
    }
    public function fail2wp_setting_xmlrpc_disable() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-xmlrpc-disable">';
        echo '<input type="checkbox" name="fail2wp-xmlrpc-disable" id="fail2wp-xmlrpc-disable" value="1" ' . ( checked( $this->fail2wp_xmlrpc_disable, 1, false ) ) . '/>';
        echo ' ' . esc_html__( 'disable authenticated XMLRPC calls', 'fail2wp' ) . '. ' .
             esc_html__( 'This will not notify fail2ban', 'fail2wp' ) . '.</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_xmlrpc_disable_pingback() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-xmlrpc-disable-pingback">';
        echo '<input type="checkbox" name="fail2wp-xmlrpc-disable-pingback" id="fail2wp-xmlrpc-disable-pingback" value="1" ' . ( checked( $this->fail2wp_xmlrpc_disable_pingback, 1, false ) ) . '/>';
        echo ' ' . esc_html__( 'disable XMLRPC pingbacks', 'fail2wp' ) . '. ' .
             esc_html__( 'This will not notify fail2ban', 'fail2wp' ) . '.</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_xmlrpc_disable_everything() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-xmlrpc-disable-everything">';
        echo '<input type="checkbox" name="fail2wp-xmlrpc-disable-everything" id="fail2wp-xmlrpc-disable-everything" value="1" ' . ( checked( $this->fail2wp_xmlrpc_disable_everything, 1, false ) ) . '/>';
        echo ' ' . esc_html__( 'disable XMLRPC completely', 'fail2wp' ) . '.</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_xmlrpc_inform_fail2ban() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-xmlrpc-inform-fail2ban">';
        echo '<input type="checkbox" name="fail2wp-xmlrpc-inform-fail2ban" id="fail2wp-xmlrpc-inform-fail2ban" value="1" ' . ( checked( $this->fail2wp_xmlrpc_inform_fail2ban, 1, false ) ) . '/>';
        echo ' ' . esc_html__( 'notify fail2ban about failed XMLRPC activity when completely disabled', 'fail2wp' ) . '.</label> ';
        echo '</div>';
    }
    // @since 1.1.0
    public function fail2wp_setting_reguser_warn() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-reguser-warn">';
        echo '<input type="checkbox" name="fail2wp-reguser-warn" id="fail2wp-reguser-warn" value="1" ' . ( checked( $this->fail2wp_reguser_warn, 1, false ) ) . '/>';
        echo esc_html__( 'Warn about odd membership/registration settings', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_reguser_warn_role() {
        $option_val = $this->fail2wp_reguser_warn_role;
        $available_roles = $this->fail2wp_get_wp_roles();
        echo '<div class="fail2wp-role-option">';
        if ( is_array( $available_roles ) ) {
            echo '<select name="fail2wp-reguser-warn-role" id="fail2wp-reguser-warn-role">';
            foreach( $available_roles as $k => $v ) {
                echo '<option value="' . esc_attr( $k ) . '"';
                if ( $k == $option_val ) {
                    echo ' selected="selected"';
                }
                echo ' />' . esc_html__( $v, 'default' ) . '</option>';
            }
            echo '</select>';
            echo '<p class="description">' .
                 esc_html__( 'Check WordPress setting against the value configured here', 'fail2wp' ) .
                 '</p>';

        } else {
            echo esc_html__( 'No available roles (?)', 'fail2wp' );
        }
        echo '</div>';
    }
    public function fail2wp_setting_reguser_force() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-reguser-force">';
        echo '<input type="checkbox" name="fail2wp-reguser-force" id="fail2wp-reguser-force" value="1" ' . ( checked( $this->fail2wp_reguser_force, 1, false ) ) . '/>';
        echo esc_html__( 'Force new user registration settings to a role', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_reguser_force_role() {
        $option_val = $this->fail2wp_reguser_force_role;
        $available_roles = $this->fail2wp_get_wp_roles();
        echo '<div class="fail2wp-role-option">';
        if ( is_array( $available_roles ) ) {
            echo '<select name="fail2wp-reguser-force-role" id="fail2wp-reguser-force-role">';
            foreach( $available_roles as $k => $v ) {
                echo '<option value="' . esc_attr( $k ) . '"';
                if ( $k == $option_val ) {
                    echo ' selected="selected"';
                }
                echo ' />' . esc_html__( $v, 'default' ) . '</option>';
            }
            echo '</select>';
            echo '<p class="description">' .
                 esc_html__( 'Force WordPress setting to the value configured here', 'fail2wp' ) .
                 '</p>';
        } else {
            echo esc_html__( 'No available roles (?)', 'fail2wp' );
        }
        echo '</div>';
    }
    public function fail2wp_settings_reguser_username_length() {
        echo '<input id="fail2wp-reguser-username-length" name="fail2wp-reguser-username-length" size="4" maxlength="4" value="' . esc_attr( (int)$this->fail2wp_reguser_username_length ) . '" />';
        echo '<p class="description">' . esc_html__( 'Minimum length of usernames, 2-200 characters, 0 ignores the setting', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_settings_reguser_username_ban() {
        echo '<textarea rows="10" cols="30" id="fail2wp-reguser-username-ban" name="fail2wp-reguser-username-ban" class="text code">';
        echo esc_html( implode( "\n", $this->fail2wp_reguser_username_ban ) );
        echo '</textarea>';
        echo '<p class="description">' . esc_html__( 'These usernames will be blocked for new user registrations', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_settings_reguser_useremail_require() {
        echo '<textarea rows="10" cols="30" id="fail2wp-reguser-useremail-require" name="fail2wp-reguser-useremail-require" class="text code">';
        echo esc_html( implode( "\n", $this->fail2wp_reguser_useremail_require ) );
        echo '</textarea>';
        echo '<p class="description">' . esc_html__( 'E-mail address must match at least one of these for new users', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_setting_remove_generator() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-settings-remove-generator">';
        echo '<input type="checkbox" name="fail2wp-settings-remove-generator" id="fail2wp-settings-remove-generator" value="1" ' . ( checked( $this->fail2wp_settings_remove_generator, 1, false ) ) . '/>';
        echo esc_html__( 'Remove "Generator" output in HTML, RSS, etc.', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_remove_feeds() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-settings-remove-feeds">';
        echo '<input type="checkbox" name="fail2wp-settings-remove-feeds" id="fail2wp-settings-remove-feeds" value="1" ' . ( checked( $this->fail2wp_settings_remove_feeds, 1, false ) ) . '/>';
        echo esc_html__( 'Remove RSS and Atom feeds', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    // @since 1.0.0
    public function fail2wp_setting_remove() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-settings-remove">';
        echo '<input type="checkbox" name="fail2wp-settings-remove" id="fail2wp-settings-remove" value="1" ' . ( checked( $this->fail2wp_settings_remove, 1, false ) ) . '/>';
        echo esc_html__( 'Remove all plugin settings and data when plugin is uninstalled', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_block_enums() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-block-user-enum">';
        echo '<input type="checkbox" name="fail2wp-block-user-enum" id="fail2wp-block-user-enum" value="1" ' . ( checked( $this->fail2wp_block_user_enum, 1, false ) ) . '/>';
        echo esc_html__( 'Block user enumeration attempts (i.e. your.site/...?author=nnn)', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_block_username_login() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-block-username-login">';
        echo '<input type="checkbox" name="fail2wp-block-username-login" id="fail2wp-block-username-login" value="1" ' . ( checked( $this->fail2wp_block_username_login, 1, false ) ) . '/>';
        echo esc_html__( 'Require users to login with their e-mail address', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_secure_login_messages() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-secure-login-message">';
        echo '<input type="checkbox" name="fail2wp-secure-login-message" id="fail2wp-secure-login-message" value="1" ' . ( checked( $this->fail2wp_secure_login_message, 1, false ) ) . '/>';
        echo esc_html__( 'Change login failure messages to contain less detail', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_settings_restapi_callback() {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        echo '<p>' .
             esc_html__( 'Please make sure you understand how these settings can impact the operation of WordPress and other plugins before making changes to them.', 'fail2wp' ) .
             '</p>';
        $rest_url = get_rest_url();
        echo '<p>' .
             esc_html__( 'The REST API URL of this site is', 'fail2wp' ) .
             ': <strong>' . esc_html( $rest_url ) . '</strong>' .
             '</p>';
        // Possibly output notice about blocking settings
        if ( $this->fail2wp_rest_filter_require_authenticated ) {
            echo '<p><strong><span class="dashicons dashicons-warning"></span>&nbsp;' . esc_html__( 'NOTE', 'fail2wp' ) . ':</strong> ' .
                 esc_html__( 'If "Require authentication" is enabled, no REST API calls will be blocked for logged in users and/or authenticated requests!', 'fail2wp' ) .
                 '</p>';
        }
    }
    public function fail2wp_settings_advanced_callback() {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        echo '<p>' .
             esc_html__( 'Please make sure you understand how these settings can impact the operation of the plugin before making changes to them.', 'fail2wp' ) .
             '</p>';
    }
    public function fail2wp_settings_cloudflare_callback() {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return;
        }
        echo '<p>'.
             esc_html__( 'These settings allows the plugin to better interact with Cloudflare.', 'fail2wp' ).
             ' ' .
             esc_html__( 'If your site is not published via Cloudflare, you can safely ignore these settings.', 'fail2wp' ).
             '<br/><br/>' .
             esc_html__( 'For an updated list of Cloudflare IPs, please use this link', 'fail2wp' ) .
             ': '.
             '<a href="https://www.cloudflare.com/ips/" target="_blank">'.
             'www.cloudflare.com/ips' .
             '</a>'.
             '</p>';
    }
    // @since 1.1.0
    public function fail2wp_setting_rest_filter_require_authenticated() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-rest-filter-require-authenticated">';
        echo '<input type="checkbox" name="fail2wp-rest-filter-require-authenticated" id="fail2wp-rest-filter-require-authenticated" value="1" ' . ( checked( $this->fail2wp_rest_filter_require_authenticated, 1, false ) ) . '/>';
        echo esc_html__( 'Require that users be logged in and/or that all REST API calls are authenticated, this is typically safe to do.', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_rest_filter_block_index() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-rest-filter-block-index">';
        echo '<input type="checkbox" name="fail2wp-rest-filter-block-index" id="fail2wp-rest-filter-block-index" value="1" ' . ( checked( $this->fail2wp_rest_filter_block_index, 1, false ) ) . '/>';
        echo esc_html__( 'Blocks all REST API index calls made to this site, this is typically safe to do.', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_rest_filter_log_blocked() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-rest-filter-log-blocked">';
        echo '<input type="checkbox" name="fail2wp-rest-filter-log-blocked" id="fail2wp-rest-filter-log-blocked" value="1" ' . ( checked( $this->fail2wp_rest_filter_log_blocked, 1, false ) ) . '/>';
        echo esc_html__( 'Log all blocked REST API calls for Fail2ban processing.', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_rest_filter_block_all() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-rest-filter-block-all">';
        echo '<input type="checkbox" name="fail2wp-rest-filter-block-all" id="fail2wp-rest-filter-block-all" value="1" ' . ( checked( $this->fail2wp_rest_filter_block_all, 1, false ) ) . '/>';
        echo esc_html__( 'Blocks all REST API calls made to this site, this is typically not safe to do.', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_rest_filter_block_ns() {
        $rest_ns = $this->fail2wp_get_rest_ns();
        if ( ! is_array( $rest_ns ) || empty( $rest_ns ) ) {
            echo '<div class="fail2wp-role-option">';
            echo esc_html__( 'WordPress did not return any available namespaces', 'fail2wp' );
            echo '</div>';
            return;
        }
        foreach( $rest_ns as $namespace ) {
            echo '<div class="fail2wp-role-option">';
            echo '<label for="fail2wp-rest-filter-block-ns[]">';
            echo '<input type="checkbox" name="fail2wp-rest-filter-block-ns[]" id="fail2wp-rest-filter-block-ns[]" value="' . esc_attr( $namespace ) . '" ' . ( in_array( $namespace, $this->fail2wp_rest_filter_block_ns ) ? 'checked="checked" ':'' ) . '/>';
            echo esc_html( $namespace ) . '</label> ';
            echo '</div>';
        }
    }
    public function fail2wp_setting_rest_filter_block_routes() {
        foreach( $this->fail2wp_rest_filter_route_list as $route ) {
            echo '<div class="fail2wp-role-option">';
            echo '<label for="fail2wp-rest-filter-block-routes[]">';
            echo '<input type="checkbox" name="fail2wp-rest-filter-block-routes[]" id="fail2wp-rest-filter-block-routes[]" value="' . esc_attr( $route ) . '" ' . ( in_array( $route, $this->fail2wp_rest_filter_block_routes ) ? 'checked="checked" ':'' ) . '/>';
            echo esc_html( $route ) . '</label> ';
            echo '</div>';
        }
    }
    public function fail2wp_settings_rest_filter_bypass_ipv4() {
        echo '<textarea rows="8" cols="30" id="fail2wp-rest-filter-ipv4-bypass" name="fail2wp-rest-filter-ipv4-bypass" class="large-text code">';
        echo esc_html( implode( "\n", $this->fail2wp_rest_filter_ipv4_bypass ) );
        echo '</textarea>';
        echo '<p class="description">' . esc_html__( 'IPs matching these addresses will be allowed to make any REST API call', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_settings_rest_filter_bypass_ipv6() {
        echo '<textarea rows="8" cols="30" id="fail2wp-rest-filter-ipv6-bypass" name="fail2wp-rest-filter-ipv6-bypass" class="large-text code">';
        echo esc_html( implode( "\n", $this->fail2wp_rest_filter_ipv6_bypass ) );
        echo '</textarea>';
        echo '<p class="description">' . esc_html__( 'IPs matching these addresses will be allowed to make any REST API call', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_settings_prefix() {
        echo '<input type="text" size="60" maxlength="200" id="fail2wp-prefix" name="fail2wp-prefix" value="' . esc_attr( $this->fail2wp_prefix ). '" />';
        echo '<p class="description">' . esc_html__( 'The logging prefix, this should normally be left empty', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_setting_also_log_php() {
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-also-log-php">';
        echo '<input type="checkbox" name="fail2wp-also-log-php" id="fail2wp-also-log-php" value="1" ' . ( checked( $this->fail2wp_also_log_php, 1, false ) ) . '/>';
        echo esc_html__( 'Log the same information to PHP log using error_log()', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_cloudflare_check() {
        $option_val = $this->fail2wp_cloudflare_check;
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-cloudflare-check">';
        echo '<input type="checkbox" name="fail2wp-cloudflare-check" id="fail2wp-cloudflare-check" value="1" ' . ( checked( $this->fail2wp_cloudflare_check, 1, false ) ) . '/>';
        echo esc_html__( 'Attempt to unmask real IP when Cloudflare IP is detected', 'fail2wp' ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_settings_cloudflare_ipv4() {
        echo '<textarea rows="10" cols="30" id="fail2wp-cloudflare-ipv4" name="fail2wp-cloudflare-ipv4" class="large-text code">';
        echo esc_html( implode( "\n", $this->fail2wp_cloudflare_ipv4 ) );
        echo '</textarea>';
        echo '<p class="description">' . esc_html__( 'IPs matching these addresses will be considerd to be coming from Cloudflare', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_settings_cloudflare_ipv6() {
        echo '<textarea rows="10" cols="30" id="fail2wp-cloudflare-ipv6" name="fail2wp-cloudflare-ipv6" class="large-text code">';
        echo esc_html( implode( "\n", $this->fail2wp_cloudflare_ipv6 ) );
        echo '</textarea>';
        echo '<p class="description">' . esc_html__( 'IPs matching these addresses will be considerd to be coming from Cloudflare', 'fail2wp' ) . '</p>';
    }


    /**
     * Send alert to syslog
     *
     * @since  1.0.0
     * @param  string $alert_message The error message.
     */
    public function fail2wp_alert_send( string $alert_message ) {
        // Logging prefix (i.e. "this is us")
        $prefix = $this->fail2wp_prefix;
        if ( empty( $prefix ) ) {
            $prefix = FAIL2WP_DEFAULT_PREFIX;
        }
        // Site label
        if ( empty( $this->fail2wp_site_label ) ) {
            $this->fail2wp_site_label = $this->fail2wp_get_site_label( true );
        }
        if ( empty( $this->fail2wp_site_label ) ) {
            $prefix .= '(unknown.site)';
        } else {
            $prefix .= '(' . $this->fail2wp_site_label . ')';
        }
        // Go through syslog mechanism
        if ( defined( 'LOG_AUTHPRIV' ) ) {
            $log_facility = LOG_AUTHPRIV;
        } elseif ( defined( 'LOG_AUTH' ) ) {
            $log_facility = LOG_AUTH;
        } elseif ( defined( 'LOG_USER' ) ) {
            $log_facility = LOG_USER;
        } else {
            $log_facility = 0;
        }
        $log = new \fail2wp\SysLog( $prefix, $log_facility );
        if ( is_object( $log )  ) {
            if ( defined( 'LOG_ERR' ) ) {
                $log_type = LOG_ERR;
            } elseif ( defined( 'LOG_WARNING' ) ) {
                $log_type = LOG_WARNING;
            } elseif ( defined( 'LOG_NOTICE' ) ) {
                $log_type = LOG_NOTICE;
            } else {
                $log_type = 0;
            }
            $log->log_message( $alert_message, $log_type );
            $syslog_ok = true;
        } else {
            $syslog_ok = false;
            error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): Unable to initialize syslog interface' );
        }
        // Possibly log to PHP log as well
        if ( $this->fail2wp_also_log_php ) {
            error_log( $prefix . ': ' . $alert_message );
        }
    }


    /**
     * Get string for message containing user information.
     *
     * Formats the contents of WP_User $user object into a suitable string.
     *
     * @since 1.1.0
     * @param object $user WP_User
     * @return string String with "user display" suitable for the notification
     */
    protected function fail2wp_get_message_user_display( \WP_User $user ) : string {
        $name = trim( $user->display_name );
        if ( empty( $name ) ) {
            $name = trim( $user->user_firstname );
            $name .= ( empty( $name ) ? '': ' ') . trim( $user->user_lastname );
        }
        $user_login = trim( $user->user_login );
        if ( $name != $user_login ) {
            $name = ( empty( $name ) ? '`' . $user_login . '`' : $name . ' (`' . $user_login . '`)' );
        } else {
            $name = '`' . $name . '`';
        }
        return( $name );

    }


    /**
     * Possibly process Cloudflare address.
     *
     * If the passed IP address matches one of the configured Cloudflare addresses,
     * the function attempts to fetch the actual IP address from Cloudflare
     * headers.
     *
     * @since 1.0.0
     * @param string $remote_ip Remote IP address
     * @return string The actual IP address
     */
    public function fail2wp_do_cloudflare_lookup( string $remote_ip ) {
        if ( $this->fail2wp_cloudflare_check ) {
            // Possibly check for Cloudflare
            $is_cloudflare = false;
            if ( ! empty( $this->fail2wp_cloudflare_ipv4 ) && is_array( $this->fail2wp_cloudflare_ipv4 ) ) {
                foreach( $this->fail2wp_cloudflare_ipv4 as $cf ) {
                    if ( ! empty( $cf ) && $this->fail2wp_cidrm->match( $remote_ip, $cf ) ) {
                        $is_cloudflare = true;
                        break;
                    }
                }
            }
            if ( ! $is_cloudflare && ! empty( $this->fail2wp_cloudflare_ipv6 ) && is_array( $this->fail2wp_cloudflare_ipv6 ) ) {
                foreach( $this->fail2wp_cloudflare_ipv6 as $cf ) {
                    if ( ! empty( $cf ) && $this->fail2wp_cidrm->match( $remote_ip, $cf ) ) {
                        $is_cloudflare = true;
                        break;
                    }
                }
            }
            if ( $is_cloudflare && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
                $remote_ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
            }
        }
        return( $remote_ip );
    }


    /**
     * Build context based alert message.
     *
     * @since 1.0.0
     * @param string $username Username as entered when logging in.
     * @param mixed $context Either WP_User or WP_Error.
     * @param int $alert_type Type of notification.
     * @param bool $username_is_ip_address If $username contains already handled IP address
     * @return mixed String with alert message or false on error.
     */
    public function fail2wp_make_alert_message( string $username, $context, int $alert_type, bool $username_is_ip_address = false, string $override_ip = '' ) {
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        $remote_ip = '';
        if ( empty( $overripde_ip ) ) {
            if ( $username_is_ip_address ) {
                // Username string contains IP address (some REST API requests)
                $remote_ip = $username;
            } elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
                // Fetch remote IP if set
                $remote_addr = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
                $remote_ip = $this->fail2wp_do_cloudflare_lookup( $remote_addr );
                if ( $remote_ip == $remote_addr ) {
                    // Not a Cloudflare address, check for proxy address (X-Real-IP)
                    if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
                        $remote_ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
                    }
                }
            }
        } else {
            $remote_ip = $override_ip;
        }
        if ( ! empty( $remote_ip ) ) {
            $remote_ip = ' from' . ' ' . $remote_ip;
        } else {
            $remote_ip = ' from' . ' ' . '?.?.?.?';
        }
        // Fetch local (our) port if set
        if ( ! empty( $_SERVER['SERVER_PORT'] ) ) {
            $our_port = (int) sanitize_text_field( wp_unslash( $_SERVER['SERVER_PORT'] ) );
        } else {
            if ( ! empty( $_SERVER['HTTPS'] ) ) {
                $our_port = $this->fail2wp_default_https_port;
            } else {
                $our_port = $this->fail2wp_default_http_port;
            }
        }
        $our_port = ' port ' . $our_port;
        // Figure out path to take
        switch( $alert_type ) {
            default: // Notification
                if ( ! is_a( $context, 'WP_User' ) ) {
                    if ( is_object( $context ) ) {
                        error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): Unknown context "' . get_class( $context ) . '" for alert_type (' . $alert_type . ')' );
                    } else {
                        error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): Unknown context "' . $context . '" for alert_type (' . $alert_type . ')' );
                    }
                    return( false );
                }
                $name = $this->fail2wp_get_message_user_display( $context );
                $alert_message = 'Successful login for ' . $context->user_login . $remote_ip . $our_port;
                break;
            case FAIL2WP_ALERT_FAILURE:
                if ( ! is_object( $context ) || ! is_a( $context, 'WP_Error' ) ) {
                    if ( is_object( $context ) ) {
                        error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): Unknown context "' . get_class( $context ) . '" for alert_type (' . $alert_type . ')' );
                    } else {
                        error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): Unknown context "' . $context . '" for alert_type (' . $alert_type . ')' );
                    }
                    return( false );
                }
                $alert_code = key( $context->errors );
                switch( $alert_code ) {
                    case 'empty_username':
                        $alert_message = 'Invalid user' . ' ' . '(empty)' . $remote_ip . $our_port;
                        break;
                    case 'invalid_username':
                        $alert_message = 'Invalid user' . ' ' . $username . $remote_ip . $our_port;
                        break;
                    case 'invalid_email':
                        $alert_message = 'Invalid email' . ' ' . $username . $remote_ip . $our_port;
                        break;
                    case 'incorrect_password':
                        $alert_message = 'Authentication failure for' . ' ' . $username . $remote_ip . $our_port;
                        break;
                    case 'invalidcombo':
                        $alert_message = 'Invalid credentials' . ' ' . $username . $remote_ip . $our_port;
                        break;
                    default:
                        $alert_message = 'Unknown error' . ' "' . $alert_code . '" during login from' . $remote_ip . $our_port;
                        break;
                } // switch
                break;
            case FAIL2WP_ALERT_USER_ENUM:
                $alert_message = 'User enumeration request' . $remote_ip . $our_port;
                break;
            case FAIL2WP_ALERT_REST_NOTAUTH:
                $alert_message = 'Unauthenticated REST API request' . $remote_ip . $our_port;
                break;
            case FAIL2WP_ALERT_REST_BLOCKED:
                $alert_message = 'Blocked REST API request' . $remote_ip . $our_port;
                break;
            case FAIL2WP_ALERT_LOGINIP_BLOCKED:
                $alert_message = 'Blocked login attempt' . $remote_ip . $our_port;
                break;
            case FAIL2WP_ALERT_XMLRPC_BLOCKED:
                $alert_message = 'XMLRPC access attempted' . $remote_ip . $our_port;
                break;
        } // switch
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
        return( $alert_message );
    }


    /**
     * See if a user's roles/caps have been configured for notifications.
     *
     * Compares all configured notification roles/caps with that of the roles/
     * caps of a user. If found, returns true, otherwise false.
     *
     * @since 1.0.0
     * @param array $roles WordPress roles/caps of user in question.
     * @param string $notify_rules JSON string with configured roles.
     * @return boolean true=Notify, false=Don't notify
     */
    protected function fail2wp_role_is_active( array $roles, array $notify_roles ) : bool {
        // Lookup our selected notification roles. We could walk the other way
        // too, but we're likely to have less configured roles/caps than what
        // is available. So maybe this will save an iteration or two :-)
        foreach( $notify_roles as $role ) {
            if ( array_key_exists( $role, $roles ) && $roles[$role] ) {
                return( true );
            }
        }
        return( false );
    }


    /**
     * Create human readable role names from two lists.
     *
     * Extracts the human readable role names from a merged version of roles we
     * know about and roles present for a user.
     *
     * @since 1.1.0
     * @param array $roles WordPress roles/caps of user in question.
     * @param string $notify_rules JSON string with configured roles.
     * @return string List of translated role names like ' [Administratör,Prenumerant]'
     */
    protected function fail2wp_roles_merge( array $roles, string $notify_roles ) : string {
        $notify_array = @ json_decode( $notify_roles, true, 2 );
        if ( ! is_array( $notify_array ) || empty( $notify_array ) ) {
            return( false );
        }
        $new_roles = array();
        // Lookup our selected notification roles. We could walk the other way
        // too, but we're likely to have less configured roles/caps than what
        // is available. So maybe this will save an iteration or two :-)
        foreach( $notify_array as $role ) {
            if ( array_key_exists( $role, $roles ) && $roles[$role] ) {
                $new_roles[] = $role;
            }
        }
        // Do some i18n
        $wp_roles = $this->fail2wp_get_wp_roles();
        for ( $c = 0; $c < count( $new_roles ); $c++ ) {
            if ( ! empty( $wp_roles[ $new_roles[$c] ] ) ) {
                $new_roles[$c] = $wp_roles[ $new_roles[$c] ];
            }
        }
        return( ' [' . implode( ',', $new_roles ) . ']' );
    }


    /**
     * Get REST API namespaces from WordPress.
     *
     * @since 1.1.0
     * @param object $rest_server WP_REST_Server object to use or null
     * @return array List of known namespaces
     */
    protected function fail2wp_get_rest_ns( $rest_server = null ) {
        if ( $rest_server === null ) {
            if ( $this->fail2wp_rest === null ) {
                if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
                    error_log( basename( __FILE__ ) . ' (' . __FUNCTION__ . '): Getting WP_REST_Server instance' );
                }
                $this->fail2wp_rest = rest_get_server();
            }
            return( $this->fail2wp_rest->get_namespaces() );
        }
        return( $rest_server->get_namespaces() );
    }


    /**
     * Send alert when user with configured role(s) login.
     *
     * Send notification ("success") when a user with a role matching the
     * configured notification roles logs in.
     *
     * @since 1.0.0
     * @param string $username The username as entered when logging in.
     * @param object $user, WP_User
     */
    public function fail2wp_alert_login( string $username, object $user ) {
        if ( ! is_a( $user, 'WP_User' ) ) {
            error_log( basename( __FILE__ ) . ' (' . __FUNCTION__ . '): No user information?' );
            if ( is_object( $user ) ) {
                error_log( get_class( $user ) );
            } else {
                error_log( print_r( $user, true ) );
            }
            return;
        }
        // Fetch user's roles/caps from WordPress for currently logged in user
        $role_caps = $user->get_role_caps();
        // Possibly notify
        if ( $this->fail2wp_role_is_active( $role_caps, $this->fail2wp_roles_notify ) ) {
            $alert_message = $this->fail2wp_make_alert_message( $username, $user, FAIL2WP_ALERT_SUCCESS );
            if ( ! empty( $alert_message ) ) {
                $this->fail2wp_alert_send( $alert_message );
            }
        }
    }


    /**
     * Send alert of login failure.
     *
     * @since 1.0.0
     * @param string $username The username as entered when logging in.
     * @param object $error, WP_Error
     */
    public function fail2wp_alert_failed_login( string $username, object $error ) {
        if ( ! is_a( $error, 'WP_Error' ) ) {
            error_log( basename( __FILE__ ) . ' (' . __FUNCTION__ . '): No error information?' );
            if ( is_object( $error ) ) {
                error_log( get_class( $error ) );
            } else {
                error_log( print_r( $error, true ) );
            }
            return;
        }
        $error_code = key( $error->errors );
        if ( ( $error_code == 'invalid_username' || $error_code == 'invalid_email' || $error_code == 'empty_username' ) && empty( $this->fail2wp_unknown_warn ) ) {
            // We're configured to not notify about unknown users
            return;
        } elseif ( $error_code == 'incorrect_password' ) {
            // We can get user info for this, so let's see if we should notify
            $failed_user = new \WP_User( 0, $username );
            $role_caps = $failed_user->get_role_caps();
            if ( is_array( $role_caps ) ) {
                if ( ! $this->fail2wp_role_is_active( $role_caps, $this->fail2wp_roles_warn ) ) {
                    // We're not configured to notify for this user role/cap, bail
                    return;
                }
            }
        }
        $alert_message = $this->fail2wp_make_alert_message( $username, $error, FAIL2WP_ALERT_FAILURE );
        if ( ! empty( $alert_message ) ) {
            $this->fail2wp_alert_send( $alert_message );
        }
    }


    /**
     * Disable XMLRPC Pingbacks
     *
     * @since 1.2.0
     */
    public function fail2wp_xmlrpc_disable_pingback( $methods ) {
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        unset( $methods['pingback.ping'] );
        unset( $methods['pingback.extensions.getPingbacks'] );
        unset( $methods['demo.sayHello'] );
        unset( $methods['demo.addTwoNumbers'] );
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
        return( $methods );
    }


    /**
     * Disable XMLRPC.
     *
     * @since 1.2.0
     */
    public function fail2wp_xmlrpc_disabled() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
        return( false );
    }


    /**
     * Handle authentication settings.
     *
     * @since 1.0.0
     */
    public function fail2wp_auth_check( $user, string $username, string $password ) {
        if ( empty( $username ) || empty( $password ) ) {
            return( $user );
        }
        $wp_error = $user;
        if ( $this->fail2wp_have_mbstring ) {
            if ( mb_substr_count( $username, '@' ) !== 1 || mb_strpos( $username, '@' ) === 0) {
                $wp_error = new \WP_Error( 'invalid_username', __('Please specify your e-mail address to login', 'fail2wp') );
            }
        } else {
            if ( substr_count( $username, '@' ) !== 1 || strpos( $username, '@' ) === 0) {
                $wp_error = new \WP_Error( 'invalid_username', __('Please specify your e-mail address to login', 'fail2wp') );
            }
        }
        return( $wp_error );
    }


    /**
     * Possibly replace username/e-mail label for login screen.
     *
     * Activated by fail2wp_login_text().
     *
     * @since 1.0.0
     */
    public function fail2wp_gettext( string $xlat_in, string $text_in, string $domain) {
        if ( $domain === 'default' ) {
            switch( $text_in ) {
                case 'Username or Email Address';
                    $text_out = __( 'E-mail address', 'fail2wp' );
                    break;
                default:
                    $text_out = $xlat_in;
                    break;
            }
        } else {
            $text_out = $xlat_in;
        }
        return( $text_out );
    }


    /**
     * Activate some gettext filtering on login page.
     *
     * This is done via a login_head action so that we don't process every single
     * gettext() call.
     *
     * @since 1.0.0
     *
     */
    public function fail2wp_login_text() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }

        add_filter( 'gettext', [$this, 'fail2wp_gettext'], 10, 3 );

        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
    }


    /**
     * Lookup IP address, return hostname(s).
     *
     * Lookup IP address, either from cache (if enabled and found), or directly.
     * This function assumes that the passed string is actually an IP address
     * andwill not do any further parameter validation.
     *
     * @since 1.2.0
     * @param string $ip_address
     * @return mixed Hostname(s) or empty if not found
     */
    protected function fail2wp_reverse_hostname_lookup( string $ip_address ) {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        $lookup_result = false;
        if ( $this->fail2wp_loginip_dnscache > 0 && $this->fail2wp_loginip_dnscache < 10080 ) {
            if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache lookup for "' . $ip_address . '"' );
            }
            if ( ! empty( $this->fail2wp_hostname_cache[$ip_address] ) ) {
                if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache lookup match' );
                }
                if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
                }
                return( $this->fail2wp_hostname_cache[$ip_address] );
            }
            if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache lookup no match' );
            }
        }
        // No match, perform DNS lookup
        $dns = gethostbyaddr( $ip_address );
        if ( ! empty( $dns ) ) {
            $addr_list = array( 0 => $dns );
            if ( empty( $this->fail2wp_hostname_cache['ts'] ) ) {
                $this->fail2wp_hostname_cache['ts'] = time() + ( $this->fail2wp_loginip_dnscache * 60 );
                if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache timer set to ' . $this->fail2wp_hostname_cache['ts'] );
                }
            }
            $this->fail2wp_hostname_cache_updated = true;
            $this->fail2wp_hostname_cache[$ip_address] = $addr_list;
            $lookup_result = $addr_list;
            if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache entry added (' . implode( ',', $addr_list ) . ')' );
            }
        } else {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': DNS-lookup failed for "' . $ip_address . '"' );
        }
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
    }


    /**
     * Lookup hostname, return IP address.
     *
     * Lookup hostname, either from cache (if enabled and found), or directly.
     * This function assumes that the passed string is actually a hostname and
     * will not do any further parameter validation.
     *
     * FALSE or array can be returned
     *
     * @since 1.2.0
     * @param string $hostname
     * @return mixed IP address or empty if not found
     */
    protected function fail2wp_hostname_lookup( string $hostname ) {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        $lookup_result = false;
        if ( $this->fail2wp_loginip_dnscache > 0 && $this->fail2wp_loginip_dnscache < 10080 ) {
            if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache lookup for "' . $hostname . '"' );
            }
            if ( ! empty( $this->fail2wp_hostname_cache[$hostname] ) ) {
                if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache lookup match' );
                }
                return( $this->fail2wp_hostname_cache[$hostname] );
            }
            if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache lookup no match' );
            }
        } else {
            if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': DNS cache is disabled' );
            }
        }
        // No match, perform DNS lookup
        $dns = dns_get_record( $hostname, DNS_A|DNS_AAAA );
        if ( is_array( $dns ) ) {
            $addr_list = array();
            foreach( $dns as $d ) {
                if ( ! empty( $d['class'] ) && $d['class'] == 'IN' ) {
                    if ( ! empty( $d['type'] ) ) {
                        if ( $d['type'] == 'A' && ! empty( $d['ip'] ) ) {
                           $addr_list[] = $d['ip'];
                        } elseif ( $d['type'] == 'AAAA' && ! empty( $d['ipv6'] ) ) {
                           $addr_list[] = $d['ipv6'];
                        }
                    }
                }
            }
            if ( is_array( $addr_list ) ) {
                if ( empty( $this->fail2wp_hostname_cache['ts'] ) ) {
                    $this->fail2wp_hostname_cache['ts'] = time() + ( $this->fail2wp_loginip_dnscache * 60 );
                    if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                        error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache timer set to ' . $this->fail2wp_hostname_cache['ts'] );
                    }
                }
                $this->fail2wp_hostname_cache_updated = true;
                $this->fail2wp_hostname_cache[$hostname] = $addr_list;
                $lookup_result = $addr_list;
                if ( defined( 'FAIL2WP_CACHE_DEBUG' ) && FAIL2WP_CACHE_DEBUG ) {
                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Cache entry added (' . implode( ',', $addr_list ) . ')' );
                }
            }
        } else {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': DNS-lookup failed for "' . $hostname . '"' );
        }
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
        return( $lookup_result );
    }


    /**
     * Determine if string contains wildcard characters.
     *
     * Checks string for * and ? characters, in which case TRUE is returned.
     *
     * @since 1.2.0
     * @param string $hostname Hostname string, possibly containing wildcards
     * @return bool
     */
    protected function fail2wp_hostname_has_wildcard( string $hostname ) : bool {
        return ( strpos( $hostname, '*' ) !== false || strpos( $hostname, '?' ) !== false );
    }


    /**
     * Check if $match_str matches $hostname.
     *
     * This function should be used, when/if $match_str may contain the wildcard
     * characters * and/or ?, to check for a match in a hostname.
     *
     * @since 1.2.0
     * @param string $hostname Hostname
     * @param string $match_str String to match, including * and ? wildcards
     * @return bool
     */
    protected function fail2wp_hostname_match_wildcard( string $hostname, string $match_str ) : bool {
        $match_str = str_replace( array( '\*', '\?' ), array( '.*', '.' ), preg_quote( $match_str, '/' ) );
        return ( preg_match('/^' . $match_str . '$/u', $hostname ) );
    }


    /**
     * Precondition access list.
     *
     * Step through an allow/deny list and classify each entry, and possibly
     * resolving hostnames.
     *
     * @since 1.2.0
     * @param bool $is_allow If true, use allow list, otherwise use deny list
     * @return array Array with address type, and (possibly) resolved hostname
     *
     * TODO: This could potentially be improved so that it's done when the
     * list(s) are saved, since the result of the parsing of the list(s) is
     * static. OTOH, it's safe to assume that there'll be reasonably few
     * entries on these lists, and there are many other things in a WordPress
     * plugin and WordPress itself that could be optimized rather than saving
     * a millisecond or two here.
     */
    protected function fail2wp_precond_access_list( bool $is_allow ) : array {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        $access_list = array();
        if ( $is_allow ) {
            $the_list = $this->fail2wp_loginip_allow;
        } else {
            $the_list = $this->fail2wp_loginip_deny;
        }
        foreach( $the_list as $entry ) {
            $entry_type = 9999;

            // Check for CIDR notation, address/mask
            $split = explode( '/', $entry );
            if ( ! is_array( $split) || count( $split ) !== 2 ) {
                // Not CIDR, check for IP address
                if ( filter_var( $entry, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
                    // IPv4
                    $entry_type = VALIDATE_IPHOSTCIDR_IPV4;
                } elseif ( filter_var( $entry, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
                    // IPv6
                    $entry_type = VALIDATE_IPHOSTCIDR_IPV6 ;
                } elseif ( filter_var( $entry, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME ) ) {
                    // Not IPv4 nor IPv6, check for hostname
                    // PHP will allow a trailing dot (.), but we do not
                    if ( $entry[strlen( $entry ) - 1] == '.' ) {
                        $entry_type = VALIDATE_IPHOSTCIDR_INVALID;
                    } elseif ( strpos( $entry, '.' ) === false && $entry !== 'localhost' ) {
                        // PHP apparently allows "123" and "hostname"
                        $entry_type = VALIDATE_IPHOSTCIDR_INVALID;
                    } else {
                        // All good, it's a hostname (or domain name)
                        $entry_type = VALIDATE_IPHOSTCIDR_HOSTNAME;
                    }
                } elseif ( ! $this->fail2wp_hostname_has_wildcard( $entry ) ) {
                    // Not IPv4, not IPv6, and not hostname/domain name nor wildcard
                    $entry_type = VALIDATE_IPHOSTCIDR_INVALID;
                } else {
                    // Hostname definition with wildcard characters ? and/or *
                    $entry_type = VALIDATE_IPHOSTCIDR_HOSTNAME_WC;
                }
                // CIDR?
            } elseif ( filter_var( $split[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
                // .. CIDR, check IP address part for IPv4
                // .. CIDR, we only allow two digits in mask for IPv4
                if ( ! preg_match( '/^\d{1,2}$/', $split[1] ) ) {
                    // Something else here, invalid
                    $entry_type = VALIDATE_IPHOSTCIDR_INVALID;
                } elseif ( (int)$split[1] <= 32 ) {
                    $entry_type = VALIDATE_IPHOSTCIDR_IPV4_CIDR;
                } else {
                    $entry_type = VALIDATE_IPHOSTCIDR_INVALID;
                }
            } elseif ( filter_var( $split[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
                // .. CIDR, check IP address part for IPv6
                // .. CIDR, we only allow three digits in mask for IPv6
                if ( ! preg_match( '/^\d{1,3}$/', $split[1] ) ) {
                    // Something else here, invalid
                    $entry_type = VALIDATE_IPHOSTCIDR_INVALID;
                } elseif ( (int)$split[1] = 128 ) {
                    $entry_type = VALIDATE_IPHOSTCIDR_IPV6_CIDR;
                } else {
                    $entry_type = VALIDATE_IPHOSTCIDR_INVALID;
                }
            }
            // Final call. We could possibly use VALIDATE_IPHOSTCIDR_INVALID as
            // the default value and skip some assignments above, but we'll
            // leave that for another day.
            if ( $entry_type == 9999 || $entry_type == VALIDATE_IPHOSTCIDR_INVALID ) {
                // Invalid entry
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Unable to interpret "' . $entry . '", skipped' );
            } else {
                // Valid entry
                $access_list[] = array( 'type' => $entry_type, 'data' => $entry );
            }
        }// foreach
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
        return( $access_list );
    }


    /**
     * Check IP before login.
     *
     * Checks remote IP against allow/deny list and possibly terminates WordPress.
     *
     * @since 1.2.0
     *
     */
    public function fail2wp_login_ip_check() {
        global $error;

        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }

        $deny_login = false;

        // Figure out "remote IP"
        $remote_real_ip = '';
        if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $remote_ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        } else {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': $_SERVER[REMOTE_ADDR] is empty?' );
            $remote_ip = '';
        }
        $remote_ip_cf = $this->fail2wp_do_cloudflare_lookup( $remote_ip );
        if ( $remote_ip == $remote_ip_cf ) {
            // Addresses are the same, not Cloudflare
            $remote_ip_cf = '';
            if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
                // Proxy IP address information
                $remote_real_ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
            }
        }
        // Possibly log what we know
        if ( $this->fail2wp_loginip_testmode ) {
            $ip_message = '';
            if ( ! empty( $remote_ip_cf ) ) {
                $ip_message = ' {from Cloudflare: ' . $remote_ip_cf . '}';
            } elseif ( ! empty( $remote_real_ip ) ) {
                $ip_message = ' {from X-Real-IP: ' . $remote_real_ip  . '}';
            }
            $ip_message = 'Remote IP is ' . $remote_ip . $ip_message;
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': ' . $ip_message );
        }
        // Figure out actual remote IP
        if ( empty( $remote_ip_cf ) ) {
            if ( empty( $remote_real_ip ) ) {
                $remote_real_ip = $remote_ip;
            }
        } else {
            // Cloudflare
            $remote_real_ip = $remote_ip_cf;
        }
        // Check "Allow list"
        if ( ! empty( $this->fail2wp_loginip_allow ) ) {
            if ( $this->fail2wp_loginip_testmode ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Login IP allow list is "' . implode( ',', $this->fail2wp_loginip_allow ) . '"' );
            }
            $access_list = $this->fail2wp_precond_access_list( true );
            if ( ! empty( $access_list ) ) {
                foreach( $access_list as $alr ) {
                    switch( $alr['type'] ) {
                        case VALIDATE_IPHOSTCIDR_INVALID:
                            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {allow} "' . $alr['data'] . '" is invalid' );
                            break;
                        case VALIDATE_IPHOSTCIDR_IPV4:
                        case VALIDATE_IPHOSTCIDR_IPV6:
                            if ( $alr['data'] == $remote_real_ip ) {
                                //Direct match with allow list
                                if ( $this->fail2wp_loginip_testmode ) {
                                    $error = esc_html( '{fail2wp}' ) . ' ' . esc_html__( 'Login attempt would have been allowed', 'fail2wp' );
                                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {allow} Remote address matches allow list, "' . $remote_real_ip . '"' );
                                }
                                return( true );
                            }
                            break;
                        case VALIDATE_IPHOSTCIDR_IPV4_CIDR:
                        case VALIDATE_IPHOSTCIDR_IPV6_CIDR:
                            if ( $this->fail2wp_cidrm->match( $remote_real_ip, $alr['data'] ) ) {
                                //Match with CIDR
                                if ( $this->fail2wp_loginip_testmode ) {
                                    $error = esc_html( '{fail2wp}' ) . ' ' . esc_html__( 'Login attempt would have been allowed', 'fail2wp' );
                                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {allow} Remote address matches allow list (CIDR), "' . $remote_real_ip . '"' );
                                }
                                return( true );
                            }
                            break;
                        case VALIDATE_IPHOSTCIDR_HOSTNAME:
                            $dns_lookup = $this->fail2wp_hostname_lookup( $alr['data'] );
                            if ( ! empty( $dns_lookup ) ) {
                                foreach( $dns_lookup as $lookup ) {
                                    // Check remote IP against 1-nn IP resolved
                                    // IP addresses
                                    if ( $remote_real_ip == $lookup ) {
                                        if ( $this->fail2wp_loginip_testmode ) {
                                            $error = esc_html( '{fail2wp}' ) . ' ' . esc_html__( 'Login attempt would have been allowed', 'fail2wp' );
                                            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {allow} Remote address matches hostname, "' . $alr['data'] . '" ("' . $lookup . '")' );
                                        }
                                        return( true );
                                    }
                                }// foreach
                            }
                            break;
                        case VALIDATE_IPHOSTCIDR_HOSTNAME_WC:
                            $dns_lookup = $this->fail2wp_reverse_hostname_lookup( $remote_real_ip );
                            if ( ! empty( $dns_lookup ) ) {
                                foreach( $dns_lookup as $lookup ) {
                                    // Check remote hostname against wildcard strings
                                    if ( $this->fail2wp_hostname_match_wildcard( $lookup, $alr['data'] ) ) {
                                        if ( $this->fail2wp_loginip_testmode ) {
                                            $error = esc_html( '{fail2wp}' ) . ' ' . esc_html__( 'Login attempt would have been allowed', 'fail2wp' );
                                            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {allow} Remote hostname ("' . $lookup . '") matches string "' . $alr['data'] . '"' );
                                        }
                                        return( true );
                                    }
                                }// foreach
                            }
                            break;
                    }// switch
                }// foreach
                // Allow list is not empty, but no match was made, deny access
                if ( $this->fail2wp_loginip_testmode ) {
                    $error = esc_html( '{fail2wp}' ) . ' ' . esc_html__( 'Login attempt would have been denied', 'fail2wp' );
                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {allow} Allow list is not empty, but no matches could be found, login denied' );
                    if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
                        error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit, wpdie}' );
                    }
                    return( false );
                } else {
                    if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
                        error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit, wpdie}' );
                    }
                    // If testmode is *not* enabled, we possibly notify fail2ban and "die"
                    if ($this->fail2wp_loginip_inform_fail2ban) {
                        $alert_message = $this->fail2wp_make_alert_message( '', null, FAIL2WP_ALERT_LOGINIP_BLOCKED, false, $remote_real_ip );
                        if ( ! empty( $alert_message ) ) {
                            $this->fail2wp_alert_send( $alert_message );
                        }
                    }
                    wp_die( esc_html__('Logins are temporarily disabled', 'fail2wp'),
                            esc_html__('Logins are temporarily disabled', 'fail2wp'),
                            array( 'response'  => 503,
                                   'link_url'  => esc_url( get_site_url() ),
                                   'link_text' => esc_html__('Go to site', 'fail2wp') . ' ' . esc_html( get_site_url() ), )
                            );
                }
            }
        }
        // Check "Deny list"
        if ( ! empty( $this->fail2wp_loginip_deny ) ) {
            $block_login = false;
            if ( $this->fail2wp_loginip_testmode ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': Login IP deny list is "' . implode( ',', $this->fail2wp_loginip_deny ) . '"' );
            }
            $access_list = $this->fail2wp_precond_access_list( false );
            if ( ! empty( $access_list ) ) {
                foreach( $access_list as $alr ) {
                    switch( $alr['type'] ) {
                        case VALIDATE_IPHOSTCIDR_INVALID:
                            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {deny} "' . $alr['data'] . '" is invalid' );
                            break;
                        case VALIDATE_IPHOSTCIDR_IPV4:
                        case VALIDATE_IPHOSTCIDR_IPV6:
                            if ( $alr['data'] == $remote_real_ip ) {
                                //Direct match with allow list
                                if ( $this->fail2wp_loginip_testmode ) {
                                    $error = esc_html( '{fail2wp}' ) . ' ' . esc_html__( 'Login attempt would have been denied', 'fail2wp' );
                                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {deny} Remote address matches deny list, "' . $remote_real_ip . '"' );
                                }
                                $block_login = true;
                                break 2;
                            }
                            break;
                        case VALIDATE_IPHOSTCIDR_IPV4_CIDR:
                        case VALIDATE_IPHOSTCIDR_IPV6_CIDR:
                            if ( $this->fail2wp_cidrm->match( $remote_real_ip, $alr['data'] ) ) {
                                //Match with CIDR
                                if ( $this->fail2wp_loginip_testmode ) {
                                    $error = esc_html( '{fail2wp}' ) . ' ' . esc_html__( 'Login attempt would have been denied', 'fail2wp' );
                                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {deny} Remote address matches deny list (CIDR), "' . $remote_real_ip . '"' );
                                }
                                $block_login = true;
                                break 2;
                            }
                            break;
                        case VALIDATE_IPHOSTCIDR_HOSTNAME:
                            $dns_lookup = $this->fail2wp_hostname_lookup( $alr['data'] );
                            if ( ! empty( $dns_lookup ) ) {
                                foreach( $dns_lookup as $lookup ) {
                                    // Check remote IP against 1-nn IP resolved
                                    // IP addresses
                                    if ( $remote_real_ip == $lookup ) {
                                        if ( $this->fail2wp_loginip_testmode ) {
                                            $error = esc_html( '{fail2wp}' ) . ' ' . esc_html__( 'Login attempt would have been denied', 'fail2wp' );
                                            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {deny} Remote address matches hostname, "' . $alr['data'] . '" ("' . $lookup . '")' );
                                        }
                                        $block_login = true;
                                        break 2;
                                    }
                                }// foreach
                            }
                            break;
                        case VALIDATE_IPHOSTCIDR_HOSTNAME_WC:
                            $dns_lookup = $this->fail2wp_reverse_hostname_lookup( $remote_real_ip );
                            if ( ! empty( $dns_lookup ) ) {
                                foreach( $dns_lookup as $lookup ) {
                                    // Check remote hostname against wildcard strings
                                    if ( $this->fail2wp_hostname_match_wildcard( $lookup, $alr['data'] ) ) {
                                        if ( $this->fail2wp_loginip_testmode ) {
                                            $error = esc_html( '{fail2wp}' ) . ' ' . esc_html__( 'Login attempt would have been denied', 'fail2wp' );
                                            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {deny} Remote hostname ("' . $lookup . '") matches string "' . $alr['data'] . '"' );
                                        }
                                        $block_login = true;
                                        break 2;
                                    }
                                }// foreach
                            }
                            break;
                    }// switch
                }// foreach
            }
            if ( $block_login ) {
                // If testmode is *not* enabled, we possibly notify fail2ban and "die"
                if ( ! $this->fail2wp_loginip_testmode ) {
                    if ($this->fail2wp_loginip_inform_fail2ban) {
                        $alert_message = $this->fail2wp_make_alert_message( '', null, FAIL2WP_ALERT_LOGINIP_BLOCKED, false, $remote_real_ip );
                        if ( ! empty( $alert_message ) ) {
                            $this->fail2wp_alert_send( $alert_message );
                        }
                    }
                    wp_die( esc_html__('Logins are temporarily disabled', 'fail2wp'),
                            esc_html__('Logins are temporarily disabled', 'fail2wp'),
                            array( 'response'  => 503,
                                   'link_url'  => esc_url( get_site_url() ),
                                   'link_text' => esc_html__('Go to site', 'fail2wp') . ' ' . esc_html( get_site_url() ), )
                            );
                }
            } else {
                if ( $this->fail2wp_loginip_testmode ) {
                    $error = esc_html( '{fail2wp}' ) . ' ' . esc_html__( 'Login attempt would have been allowed', 'fail2wp' );
                }
            }
        } else {
            if ( $this->fail2wp_loginip_testmode && empty( $error ) ) {
                $error = esc_html( '{fail2wp}' ) . ' ' . esc_html__( 'Login attempt would have been allowed', 'fail2wp' );
            }
        }
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
    }

    /**
     * Add hooks we're watching when WordPress is fully loaded.
     *
     * @since 1.0.0
     */
    public function fail2wp_xmlrpc_set_class( $classname ) {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . '' );
        }
        return('fail2wp\Fail2WP_Disable_XMLRPC');
    }

    public function fail2wp_wp_loaded() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        add_action( 'wp_login',           [$this, 'fail2wp_alert_login'],         10, 2 );
        add_action( 'wp_login_failed',    [$this, 'fail2wp_alert_failed_login'],  10, 2 );
        add_filter( 'login_errors',       [$this, 'fail2wp_login_errors'],        10, 1 );
        //add_filter( 'lostpassword_post',  [$this, 'fail2wp_lostpassword_errors'], 10, 2 );
        if ( $this->fail2wp_block_username_login ) {
            add_filter( 'authenticate',   [$this, 'fail2wp_auth_check'], 99999, 3 );
            add_action( 'login_head',     [$this, 'fail2wp_login_text'] );
        }
        // IP access checking @since 1.2.0
        if ( $this->fail2wp_loginip_enable ) {
            add_action( 'login_head', [$this, 'fail2wp_login_ip_check'] );
        }
        // XMLRPC handling @since 1.2.0
        // We only do this if we're actually in an XMLRPC request
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            if ( $this->fail2wp_xmlrpc_disable_everything ) {
                // Everything XMLRPC is disabled, replace request handler
                if ( defined( 'FAIL2WP_XMLRPC_DEBUG' ) && FAIL2WP_XMLRPC_DEBUG ) {
                    error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': XMLRPC is completely disabled, replacing request handler' );
                }
                add_filter( 'wp_xmlrpc_server_class', [$this, 'fail2wp_xmlrpc_set_class'], 10, 1 );
            } else {
                // Check for other XMLRPC things that should be disabled
                if ( $this->fail2wp_xmlrpc_disable ) {
                    // AUthenticated XMLRPC calls
                    if ( defined( 'FAIL2WP_XMLRPC_DEBUG' ) && FAIL2WP_XMLRPC_DEBUG ) {
                        error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': XMLRPC authenticated calls are disabled, adding filter' );
                    }
                    add_filter( 'xmlrpc_enabled', [$this, 'fail2wp_xmlrpc_disabled'] );
                    $have_disabled_xmlrpc = true;
                }
                if ( $this->fail2wp_xmlrpc_disable_pingback ) {
                    if ( defined( 'FAIL2WP_XMLRPC_DEBUG' ) && FAIL2WP_XMLRPC_DEBUG ) {
                        error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': XMLRPC pingbacks are disabled, adding filter' );
                    }
                    add_filter( 'xmlrpc_methods', [$this, 'fail2wp_xmlrpc_disable_pingback'] );
                    $have_disabled_xmlrpc = true;
                }
            }
        }
        if ( defined( 'FAIL2WP_XMLRPC_DEBUG' ) && FAIL2WP_XMLRPC_DEBUG ) {
            if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': XMLRPC_REQUEST = true' );
            } else {
                error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': XMLRPC_REQUEST = false' );
            }
        }
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
    }
    /**
     * Add hooks we're watching when WordPress is fully loaded.
     *
     * Not needed at the moment
     *
     * @since 1.0.0
     */
    /*
    public function fail2wp_plugins_loaded() {
    }
    */
    /**
     * Process things when everything else is ready and we know what the request is.
     *
     * Not needed at the moment
     *
     * @since 1.0.0
     */
    /*
    public function fail2wp_wp_main() {
    }
    */
    /**
     * Pre-get posts hook.
     *
     * Not needed at the moment
     *
     * @since 1.0.0
     */
    /*
    public function fail2wp_pgp( \WP_Query $wpq ) {
    }
    */


    /**
     * Inspect request for things we need to check for early.
     *
     * @since 1.0.0
     */
    public function fail2wp_parse_request( \WP $wp ) {
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': XMLRPC_REQUEST = true' );
        }
        // Check for user enumeration
        if ( isset( $wp->query_vars['author'] ) ) {
            // See if we should block it
            if ( $this->fail2wp_block_user_enum ) {
                // And if so, we unset it to pretend it was never there
                unset( $wp->query_vars['author'] );
            }
            // See if we should log it
            if ( $this->fail2wp_log_user_enum ) {
                $alert_message = $this->fail2wp_make_alert_message( '', '', FAIL2WP_ALERT_USER_ENUM );
                if ( ! empty( $alert_message ) ) {
                    $this->fail2wp_alert_send( $alert_message );
                }
            }
        }
    }


    /**
     * Possibly modify login errors in-transit.
     *
     * @since 1.0.0
     */
    public function fail2wp_login_errors( $error ) {
        global $errors;

        if ( $errors === null ) {
            return;
        }
        $e_c = $errors->get_error_codes();
        if ( ! empty( $e_c[0] ) ) {
            if ( ! empty( $_REQUEST['action'] ) &&  $_REQUEST['action'] == 'lostpassword' ) {
                // Handle lost password form errors here
                switch( $e_c[0] ) {
                    case 'invalid_username':
                    case 'invalid_email':
                    case 'invalidcombo':
                    case 'empty_username':
                        if ( $this->fail2wp_secure_login_message ) {
                            $error = esc_html__( 'Invalid login credentials, please try again.', 'fail2wp' );
                        }
                        $wp_error = new \WP_Error( $e_c[0], $error );
                        if ( ! empty( $this->fail2wp_unknown_warn ) ) {
                            // We're configured to notify about unknown users
                            if ( ! empty( $_REQUEST['user_login'] ) ) {
                                $username = sanitize_user( wp_unslash( $_REQUEST['user_login'] ), false );
                                if ( $this->fail2wp_have_mbstring ) {
                                    $username = mb_ereg_replace( ' ', '', $username );
                                } else {
                                    $username = str_replace( ' ', '', $username );
                                }
                            } else {
                                $username = '';
                            }
                            $alert_message = $this->fail2wp_make_alert_message( $username, $wp_error, FAIL2WP_ALERT_FAILURE );
                            if ( ! empty( $alert_message ) ) {
                                $this->fail2wp_alert_send( $alert_message );
                            }
                        }
                        break;
                }// switch

            return( $error );
            }
            // "Normal" login form errors
            switch( $e_c[0] ) {
                case 'invalid_username':
                case 'incorrect_password':
                case 'invalid_email':
                case 'empty_username':
                case 'invalidcombo':
                    if ( $this->fail2wp_secure_login_message ) {
                        $error = esc_html__( 'Invalid login credentials, please try again.', 'fail2wp' );
                        // Possibly include link to password recovery if we're not already there
                        $lost_password_url = wp_lostpassword_url();
                        if ( ! empty( $lost_password_url ) ) {
                            $error .= '<br/><a href=" ' . esc_url( $lost_password_url ) . '">' . esc_html__( 'Lost password', 'fail2wp' ) . '</a>';
                        }
                    }
                    break;
            }// switch
        }
        return( $error );
    }


    /**
     * Lost password errors
     * NOT HOOKED ATM
     */
    /*
    public function fail2wp_lostpassword_errors( \WP_Error $errors, $user_data ) {
        return( $errors );
    }
    */
    /**
     * Activation of plugin.
     *
     * We don't really need to do anything at activation of the plugin
     *
     * @since 1.0.0
     */
    /*
    public function fail2wp_activate_plugin() {
    }
    */
    /**
     * Deactivation of plugin.
     *
     * We don't really need to do anything at activation of the plugin
     *
     * @since 1.0.0
     */
    /*
    public function fail2wp_deactivate_plugin() {
    }
    */


    /**
     * Setup language support.
     *
     * @since 1.0.0
     */
    public function setup_locale() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        if ( ! load_plugin_textdomain( 'fail2wp',
                                       false,
                                       dirname( plugin_basename( __FILE__ ) ) . '/languages' ) ) {
            /**
             * We don't consider this to be a "real" error since 1.1.0
             */
            // error_log( 'Unable to load language file (' . dirname( plugin_basename( __FILE__ ) ) . '/languages' . ')' );
        }
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
    }


    /**
     * Setup CSS (admin).
     *
	 * @since 1.0.0
     */
    public function fail2wp_setup_css() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }

        wp_enqueue_style( 'fail2wp', plugin_dir_url( __FILE__ ) . 'css/fail2wp.css', array(), $this->resource_mtime( dirname(__FILE__).'/css/fail2wp.css' ), 'all' );

        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
    }


    /**
     * Run plugin.
     *
     * Basically "enqueues" WordPress actions and lets WordPress do its thing.
     *
     * @since 1.0.0
     */
    public function run() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        // Plugin activation, not needed for this plugin atm :-)
        // register_activation_hook( __FILE__, [$this, 'fail2wp_activate_plugin'] );

        // Setup i18n. We use the 'init' action rather than 'plugins_loaded' as per
        // https://developer.wordpress.org/reference/functions/load_plugin_textdomain/#user-contributed-notes
        add_action( 'init',  [$this, 'setup_locale'] );

        // Admin setup
        if ( is_admin() ) {
            add_action( 'admin_enqueue_scripts', [$this, 'fail2wp_setup_css'] );
            add_action( 'admin_menu',            [$this, 'fail2wp_menu']      );
            add_action( 'admin_init',            [$this, 'fail2wp_settings']  );
        }
        // Other setup
        add_action( 'wp_loaded',                 [$this, 'fail2wp_wp_loaded'] );
        /*
        add_action( 'plugins_loaded',            [$this, 'fail2wp_plugins_loaded'], 9999 );
        */
        add_action( 'parse_request',             [$this, 'fail2wp_parse_request'] );

        // add_action( 'wp',                  [$this, 'fail2wp_wp_main']              );
        // add_action( 'pre_get_posts',       [$this, 'fail2wp_pgp']                  );
        // Plugin deactivation, not needed atm :-)
        // register_deactivation_hook( __FILE__, [$this, 'fail2wp_deactivate_plugin'] );
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
    }

}// Fail2WP


/**
 * Run plugin
 *
 * @since 1.0.0
 */
function run_fail2wp() {
    if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
        error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
    }
    $plugin = Fail2WP::getInstance();
    $plugin->run();
    if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
        error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
    }
}

if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
    error_log( '=====' . basename( __FILE__ ) . ' ' . __FUNCTION__ . ': {start ' . time() . '}' );
}
if ( defined( 'FAIL2WP_XMLRPC_DEBUG' ) && FAIL2WP_XMLRPC_DEBUG ) {
    if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
        error_log( basename(__FILE__) . ' ' . __LINE__ . ': XMLRPC_REQUEST = true' );
    } else {
        error_log( basename(__FILE__) . ' ' . __LINE__ . ': XMLRPC_REQUEST = false' );
    }
}

run_fail2wp();

if ( defined( 'FAIL2WP_XMLRPC_DEBUG' ) && FAIL2WP_XMLRPC_DEBUG ) {
    if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
        error_log( basename(__FILE__) . ' ' . __LINE__ . ': XMLRPC_REQUEST = true' );
    } else {
        error_log( basename(__FILE__) . ' ' . __LINE__ . ': XMLRPC_REQUEST = false' );
    }
}
if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
    error_log( '=====' . basename( __FILE__ ) . ' ' . __FUNCTION__ . ': {stop ' . time() . '}' );
}
