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
 * Version:           1.4.0
 * Requires at least: 6.2
 * Requires PHP:      7.4
 * Author:            WebbPlatsen, Joaquim Homrighausen <joho@webbplatsen.se>
 * Author URI:        https://webbplatsen.se/
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       fail2wp
 * Domain Path:       /languages
 *
 * fail2wp.php
 * Copyright (C) 2020-2026 Joaquim Homrighausen; all rights reserved.
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
define( 'FAIL2WP_VERSION',                 '1.4.0'                 );
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
define( 'FAIL2WP_ALERT_IP_BLOCK_CREATED',  8                       );
define( 'FAIL2WP_ALERT_IP_BLOCK_HIT',      9                       );
define( 'FAIL2WP_DEFAULT_HTTP_PORT',       80                      );
define( 'FAIL2WP_DEFAULT_HTTPS_PORT',      443                     );
define( 'FAIL2WP_DB_VERSION',              2                       );
define( 'FAIL2WP_EXPORT_HEADER',           'fail2wp_export.begin.' );
define( 'FAIL2WP_EXPORT_FOOTER',           '.fail2wp_export.end'   );
define( 'FAIL2WP_CLOUDFLARE_IPS_V4_URL',   'https://www.cloudflare.com/ips-v4/' );
define( 'FAIL2WP_CLOUDFLARE_IPS_V6_URL',   'https://www.cloudflare.com/ips-v6/' );

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
require_once plugin_dir_path( __FILE__ ) . 'includes/trait-fail2wp-settings.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/class-fail2wp-ip-blocking-storage.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/class-fail2wp-admin-user-monitor.php';
// https://github.com/tholu/php-cidr-match
if ( ! class_exists( '\fail2wpCIDRmatch\CIDRmatch', false ) ) {
    require_once plugin_dir_path( __FILE__ ) . 'includes/class-fail2wp-cidr.php';
}
require_once plugin_dir_path( __FILE__ ) . 'includes/class-fail2wp-cidr-matcher.php';


/**
 * Disabled XML-RPC request handler.
 *
 * @since 1.2.0
 */
class Fail2WP_Disable_XMLRPC {
    // Log clone calls.
    final public function __clone() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {fail2wp_disable_xmlrpc}' );
        }
    }
    // Log unserialize calls.
    final public function __wakeup() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {fail2wp_disable_xmlrpc}' );
        }
    }
    // Initialize XML-RPC handler.
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
        if ( ! is_string( $charset ) || ( $charset !== '' && ! preg_match( '/^[A-Za-z][A-Za-z0-9._-]*$/D', $charset ) ) ) {
            $charset = 'UTF-8';
        }
        header( 'Connection: close' );
        if ( $charset ) {
            header( 'Content-Type: text/xml; charset=' . $charset );
        } else {
            header( 'Content-Type: text/xml' );
        }
        header( 'Date: ' . gmdate( 'r' ) );
        if ( $charset !== '' ) {
            echo '<?xml version="1.0" encoding="' . esc_attr( $charset ) . '"?>' . "\n";
        } else {
            echo '<?xml version="1.0"?>' . "\n";
        }
        echo $error->getXml(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core IXR fault; fixed code and message.

        // Load XML-RPC logging settings.

        $plugin = Fail2WP::getInstance( true );

        // Figure out "remote IP"
        $remote_real_ip = '';
        if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
            $remote_ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        } else {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': $_SERVER[REMOTE_ADDR] is empty?' );
            $remote_ip = '';
        }
        $remote_ip_cf = $plugin->fail2wp_get_client_ip();
        if ( $remote_ip == $remote_ip_cf ) {
            // Addresses are the same, not Cloudflare
            $remote_ip_cf = '';
            $remote_real_ip = $remote_ip;
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
                    $plugin->fail2wp_record_ip_blocking_event( $remote_real_ip );
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
    use Fail2WP_Settings;

    public static $instance = null;
    protected $fail2wp_mail_headers;                            // @since 1.1.0
    protected $fail2wp_have_mbstring;                           // @since 1.1.0

    protected $fail2wp_wp_roles = null;
    protected $fail2wp_wp_roles_enus = null;
    protected $fail2wp_settings_rejected_options = [];          // @since 1.4.0
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
    protected $fail2wp_site_label;
    protected $fail2wp_cloudflare_check;
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

    protected $fail2wp_ip_blocking_enable;                      // @since 1.3.0
    protected $fail2wp_ip_blocking_threshold;                   // @since 1.3.0
    protected $fail2wp_ip_blocking_window;                      // @since 1.3.0
    protected $fail2wp_ip_blocking_duration;                    // @since 1.3.0
    protected $fail2wp_ip_blocking_bypass;                      // @since 1.3.0

    protected $fail2wp_admin_monitor_enable;                    // @since 1.3.0

    protected $fail2wp_cidrm;                                   // @since 1.2.0
    protected $fail2wp_login_url_modify;
    protected $fail2wp_login_url;
    protected $fail2wp_login_admin_url_modify;
    protected $fail2wp_login_admin_url;

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
     * Log clone calls.
     *
     * @return void
     */
    final public function __clone() {
    }
    /**
     * Log unserialize calls.
     *
     * @return void
     */
    final public function __wakeup() {
    }
    /**
     * Initialize plugin settings.
     */
    public function __construct( bool $is_for_xmlrpc = false ) {
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        // Setup default mail headers
        $this->fail2wp_mail_headers = array( 'Auto-Submitted: auto-replied',
                                             'X-Auto-Response-Suppress: All',
                                             'Precedence: auto_reply' );
        // Cache extension availability.
        $this->fail2wp_have_mbstring = extension_loaded( 'mbstring' );
        // Configurable WordPress REST routes.
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
        // Validate enabled registration rules.
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
        // ..IP blocking @since 1.3.0
        $this->fail2wp_ip_blocking_enable = (bool) get_option( 'fail2wp-ip-blocking-enable', false );
        $this->fail2wp_ip_blocking_threshold = (int) get_option( 'fail2wp-ip-blocking-threshold', 5 );
        $this->fail2wp_ip_blocking_window = (int) get_option( 'fail2wp-ip-blocking-window', 600 );
        $this->fail2wp_ip_blocking_duration = (int) get_option( 'fail2wp-ip-blocking-duration', 3600 );
        $this->fail2wp_ip_blocking_bypass = @ json_decode( get_option( 'fail2wp-ip-blocking-bypass', '[]' ), true, 2 );
        if ( ! is_array( $this->fail2wp_ip_blocking_bypass ) ) {
            $this->fail2wp_ip_blocking_bypass = array();
        }
        // ..Administrator-account monitor @since 1.3.0
        $this->fail2wp_admin_monitor_enable = (bool) get_option( 'fail2wp-admin-monitor-enable', false );
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
                            || ! empty( $this->fail2wp_rest_filter_block_routes )
                                || $this->fail2wp_block_user_enum
                                    || $this->fail2wp_log_user_enum ) {
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
            add_action( 'do_feed',               [$this, 'fail2wp_remove_feeds'], 1 );
            add_action( 'do_feed_rdf',           [$this, 'fail2wp_remove_feeds'], 1 );
            add_action( 'do_feed_rss',           [$this, 'fail2wp_remove_feeds'], 1 );
            add_action( 'do_feed_rss2',          [$this, 'fail2wp_remove_feeds'], 1 );
            add_action( 'do_feed_atom',          [$this, 'fail2wp_remove_feeds'], 1 );
            add_action( 'do_feed_rss2_comments', [$this, 'fail2wp_remove_feeds'], 1 );
            add_action( 'do_feed_atom_comments', [$this, 'fail2wp_remove_feeds'], 1 );
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
        $this->fail2wp_cidrm = new Fail2WP_Cidr_Matcher();

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
        if ( ! in_array( $this->fail2wp_settings_tab, ['loginip', 'ipblocking', 'newuser', 'adminmonitor', 'logging', 'advanced', 'restapi', 'xmlrpc', 'cloudflare', 'importexport', 'about'] ) ) {
            $this->fail2wp_settings_tab = '';
        }
        // Add 'Settings' link in plugin list
        add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), [$this, 'fail2wp_settings_link'] );

        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
    }
    /**
     * Persist updated hostname cache.
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
     * Return the XML-RPC logging setting.
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
     * Return HTTP 404 for disabled feeds.
     *
     * @since 1.1.0
     */
    protected function fail2wp_die_feed_disabled() {
        wp_die(
            esc_html__( 'This feed has been disabled, please visit', 'fail2wp' ) .
            ' <a href="' . esc_url( home_url() ) . '">' .
            esc_html( home_url() ) .
            '</a>',
            esc_html__( 'Feed disabled', 'fail2wp' ),
            array(
                'link_url'  => esc_url( home_url() ),
                'link_text' => esc_html( home_url() ),
                'code'      => 'feed_disabled',
                'response'  => 404,
            )
        );
    }
    public function fail2wp_remove_feeds( $feed ) {
        $this->fail2wp_die_feed_disabled();
    }
    public function fail2wp_noshow_feeds( $noshow ) {
        return( false );
    }


    /**
     * Register REST filtering hooks.
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
            } elseif ( ! empty( $this->fail2wp_rest_filter_block_ns )
                       || ! empty( $this->fail2wp_rest_filter_block_routes )
                       || $this->fail2wp_block_user_enum
                       || $this->fail2wp_log_user_enum ) {
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
     * Require REST authentication unless the client IP is bypassed.
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
        $remote_ip_cf = $this->fail2wp_get_client_ip();
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
                    $this->fail2wp_record_ip_blocking_event();
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
     * Clear anonymous REST discovery unless the client IP is bypassed.
     *
     * @since 1.1.0
     */
    public function fail2wp_rest_index( $response ) {
        if ( is_user_logged_in() || $this->fail2wp_rest_check_ip_bypass( '', $this->fail2wp_get_client_ip() ) ) {
            return( $response );
        }
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
     * Match REST user collection and child routes.
     *
     * @since 1.2.5
     */
    protected function fail2wp_rest_is_users_route( string $wp_route ) : bool {
        if ( strcasecmp( $wp_route, 'users' ) === 0 ) {
            return( true );
        }
        if ( $this->fail2wp_have_mbstring ) {
            return( mb_stripos( $wp_route, 'users/' ) === 0 );
        }
        return( stripos( $wp_route, 'users/' ) === 0 );
    }

    /**
     * Optionally log blocked REST API requests for Fail2ban.
     *
     * @since 1.2.6
     */
    protected function fail2wp_rest_alert_blocked_request( string $remote_ip ) {
        if ( ! $this->fail2wp_rest_filter_log_blocked ) {
            return;
        }
        $alert_message = $this->fail2wp_make_alert_message( $remote_ip, null, FAIL2WP_ALERT_REST_BLOCKED, true );
        if ( ! empty( $alert_message ) ) {
            $this->fail2wp_alert_send( $alert_message );
            $this->fail2wp_record_ip_blocking_event();
        }
    }
    /**
     * Handle majority of REST API filtering.
     *
     * @since 1.1.0
     */
    public function fail2wp_rest_pre_dispatch( $result, \WP_REST_Server $rest_server, \WP_REST_Request $request ) {
        // Preserve authenticated REST workflows.
        if ( is_user_logged_in() ) {
            return( $result );
        }
        // Figure out who we're talking to
        if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $remote_ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        } else {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': $_SERVER[REMOTE_ADDR] is empty?' );
            $remote_ip = '';
        }
        $remote_ip_cf = $this->fail2wp_get_client_ip();
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
            $this->fail2wp_rest_alert_blocked_request( $remote_ip_cf );
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
        $route = '/' . trim( $request->get_route(), '/' );
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
        if ( $is_wp_route && $this->fail2wp_rest_is_users_route( $wp_route ) ) {
            if ( $this->fail2wp_log_user_enum ) {
                $alert_message = $this->fail2wp_make_alert_message( $remote_ip_cf, null, FAIL2WP_ALERT_USER_ENUM, true );
                if ( ! empty( $alert_message ) ) {
                    $this->fail2wp_alert_send( $alert_message );
                    $this->fail2wp_record_ip_blocking_event();
                }
            }
            if ( $this->fail2wp_block_user_enum ) {
                return new \WP_Error(
                    'rest_no_route',
                    __( 'No route was found matching the URL and request method.', 'default' ),
                    array( 'status' => '404' )
                );
            }
        }
        // Figure out if we're blocking index requests and if this is one
        if ( $this->fail2wp_rest_filter_block_index && in_array( strtolower( $route ), array_map( 'strtolower', $namespaces ), true ) ) {
            if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): We are blocking REST API requests for index' );
            }
            $this->fail2wp_rest_alert_blocked_request( $remote_ip_cf );
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
            $namespace_block_match = false;
            foreach ( $this->fail2wp_rest_filter_block_ns as $namespace ) {
                if ( strcasecmp( $route, $namespace ) === 0 || stripos( $route, $namespace . '/' ) === 0 ) {
                    $namespace_block_match = true;
                    break;
                }
            }
            if ( $namespace_block_match ) {
                if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
                    error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): We are blocking REST API requests for NS "' . $route . '"' );
                }
                $this->fail2wp_rest_alert_blocked_request( $remote_ip_cf );
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
            $route_block_match = false;
            foreach ( $this->fail2wp_rest_filter_block_routes as $blocked_route ) {
                if ( strcasecmp( $wp_route, $blocked_route ) === 0 || stripos( $wp_route, $blocked_route . '/' ) === 0 ) {
                    $route_block_match = true;
                    break;
                }
            }
            if ( $route_block_match ) {
                if ( defined( 'FAIL2WP_REST_DEBUG' ) && FAIL2WP_REST_DEBUG ) {
                    error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): We are blocking REST API requests for route "' . $route . '"' );
                }
                $this->fail2wp_rest_alert_blocked_request( $remote_ip_cf );
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
     * Validate registration username and email settings.
     *
     * @since 1.1.0
     * @param \WP_Error $errors.
     * @param string $sanitized_user_login.
     * @param string $user_email.
     * @return \WP_Error With or without errors
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
     * Report a forced default registration role.
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
     * Report a default registration role mismatch.
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
        global $wp;

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
     * Return file modification time; fall back to the plugin version.
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
     * Return WordPress role identifiers and display names.
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
        $tab_notice = '';
        if ( $this->fail2wp_settings_tab == 'cloudflare' ) {
            $tab_notice = $this->fail2wp_handle_cloudflare_refresh();
        } elseif ( $this->fail2wp_settings_tab == 'ipblocking' ) {
            $tab_notice = $this->fail2wp_handle_ip_blocking_actions();
        } elseif ( $this->fail2wp_settings_tab == 'adminmonitor' ) {
            $tab_notice = $this->fail2wp_handle_admin_monitor_actions();
        }
        //
        $html = '';
        $tab_header ='<div class="wrap">';
        $tab_header .= '<h1><span class="dashicons dashicons-shield" style="font-size:30px"></span>&nbsp;&nbsp;' . esc_html( FAIL2WP_PLUGINNAME_HUMAN ) . '</h1>';
        $tab_header .= '<p>' . esc_html__( 'Provides authentication security functions for WordPress, plays nicely with Fail2ban and Cloudflare', 'fail2wp' ) . '</p>';
        $tab_header .= '<nav class="nav-tab-wrapper">';
        $tab_header .= '<a href="' . esc_url( $action ) . '" class="nav-tab' . ( empty( $this->fail2wp_settings_tab ) ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'Basic configuration', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . esc_url( $action . '&tab=loginip' ) . '" class="nav-tab' . ( $this->fail2wp_settings_tab === 'loginip' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'Login IP', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . esc_url( $action . '&tab=ipblocking' ) . '" class="nav-tab' . ( $this->fail2wp_settings_tab === 'ipblocking' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'IP blocking', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . esc_url( $action . '&tab=newuser' ) . '" class="nav-tab' . ( $this->fail2wp_settings_tab === 'newuser' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'New users', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . esc_url( $action . '&tab=adminmonitor' ) . '" class="nav-tab' . ( $this->fail2wp_settings_tab === 'adminmonitor' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'Admin monitor', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . esc_url( $action . '&tab=logging' ) . '" class="nav-tab' . ( $this->fail2wp_settings_tab === 'logging' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'User logging', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . esc_url( $action . '&tab=restapi' ) . '" class="nav-tab' . ( $this->fail2wp_settings_tab === 'restapi' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'REST API', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . esc_url( $action . '&tab=xmlrpc' ) . '" class="nav-tab' . ( $this->fail2wp_settings_tab === 'xmlrpc' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'XMLRPC', 'fail2wp' ) .
                 '</a>';
         $tab_header .= '<a href="' . esc_url( $action . '&tab=advanced' ) . '" class="nav-tab' . ( $this->fail2wp_settings_tab === 'advanced' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'Advanced', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . esc_url( $action . '&tab=cloudflare' ) . '" class="nav-tab' . ( $this->fail2wp_settings_tab === 'cloudflare' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'Cloudflare', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . esc_url( $action . '&tab=importexport' ) . '" class="nav-tab' . ( $this->fail2wp_settings_tab === 'importexport' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'Import/Export', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '<a href="' . esc_url( $action . '&tab=about' ) . '" class="nav-tab' . ( $this->fail2wp_settings_tab === 'about' ? ' nav-tab-active':'' ) . '">'.
                 esc_html__( 'About', 'fail2wp' ) .
                 '</a>';
        $tab_header .= '</nav>';
        if ( ! function_exists( 'openlog' ) || ! function_exists( 'closelog' ) || ! function_exists( 'syslog' ) ) {
            $tab_header .= '<div class="notice notice-error is-dismissible"><p><strong>'.
                           esc_html__( 'One or more of openlog(), closelog(), and/or syslog() seem to be missing on this system', 'fail2wp' ).
                           '</strong></p></div>';
        }
        $tab_header .= $tab_notice;
        ob_start();
        if ( $this->fail2wp_settings_tab == 'about' ) {
            $this->fail2wp_about_page();
            $html .= ob_get_contents();
            ob_end_clean();
        } elseif ( $this->fail2wp_settings_tab == 'importexport' ) {
            $html .= '<form method="post" action="' . esc_url( $action ) . '&tab=importexport">';
            $html .= wp_nonce_field( 'importexport', 'fail2wp_nonce', true, false );
            $html .= '<div class="tab-content">';
            $html .= '<div class="fail2wp-config-header">';
            $do_import = false;

            if ( isset( $_POST['fail2wpimport'], $_POST['fail2wp_nonce'] ) && is_string( $_POST['fail2wp_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['fail2wp_nonce'] ) ), 'importexport' ) ) {
                if ( isset( $_POST['fail2wp-import-settings'] ) && is_string( $_POST['fail2wp-import-settings'] ) ) {
                    // Preserve encoded data; validate the envelope and decoded payload below.
                    $xs = trim( wp_unslash( $_POST['fail2wp-import-settings'] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Strict envelope, base64, JSON, and setting validation follow.
                    if ( $xs !== sanitize_text_field( $xs ) ) {
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
                        $payload = base64_decode( substr( $xs, strlen( FAIL2WP_EXPORT_HEADER ), strlen( $xs ) - ( strlen( FAIL2WP_EXPORT_HEADER ) + strlen( FAIL2WP_EXPORT_FOOTER ) ) ), true );
                        $xs = $payload === false ? null : json_decode( $payload, true, 10 );
                        if ( ! is_array( $xs ) || empty( $xs['fail2wp_plugin_version'] ) || ! is_string( $xs['fail2wp_plugin_version'] ) ) {
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
                } else {
                    $tab_header .= $this->fail2wp_admin_notice( __( 'Please make sure you paste the content exactly as copied', 'fail2wp' ), 'error' );
                }
                if ( $do_import ) {
                    // Map exported property names to registered option names.
                    $warn_about_site_label = false;
                    $import_result = '';
                    foreach( $xs as $k => $v ) {
                        if ( $k === 'fail2wp_ip_blocking_active_bans' ) {
                            if ( ! is_array( $v ) || ! Fail2WP_IP_Blocking_Storage::replace_active_bans( $v ) ) {
                                $import_result .= '  ' . str_replace( '_', '-', $k ) . '<br/>';
                            }
                            continue;
                        }
                        if ( $k === 'fail2wp_plugin_version' || $k === 'fail2wp_settings_dbversion' ) {
                            continue;
                        }
                        // Restrict imports to settings; escape rejected names.
                        $k_wp = str_replace( '_', '-', $k );
                        $registered_settings = get_registered_settings();
                        if ( ! property_exists( $this, str_replace( '-', '_', $k ) ) || ! isset( $registered_settings[$k_wp] ) ) {
                            $import_result .= '  ' . esc_html( $k_wp ) . '<br/>';
                            continue;
                        }
                        $array_settings = array( 'fail2wp_loginip_allow', 'fail2wp_loginip_deny', 'fail2wp_cloudflare_ipv4', 'fail2wp_cloudflare_ipv6', 'fail2wp_reguser_username_ban', 'fail2wp_reguser_useremail_require', 'fail2wp_rest_filter_ipv4_bypass', 'fail2wp_rest_filter_ipv6_bypass', 'fail2wp_ip_blocking_bypass', 'fail2wp_roles_notify', 'fail2wp_roles_warn', 'fail2wp_rest_filter_block_ns', 'fail2wp_rest_filter_block_routes' );
                        if ( in_array( $k, $array_settings, true ) ) {
                            if ( ! is_array( $v ) || count( array_filter( $v, 'is_string' ) ) !== count( $v ) ) {
                                $import_result .= '  ' . esc_html( $k_wp ) . '<br/>';
                                continue;
                            }
                        } elseif ( ! is_scalar( $v ) ) {
                            $import_result .= '  ' . esc_html( $k_wp ) . '<br/>';
                            continue;
                        }
                        // Stored option name.
                        $k_wp = str_replace( '_', '-', $k );
                        unset( $this->fail2wp_settings_rejected_options[$k_wp] );
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
                            case 'fail2wp_ip_blocking_bypass':
                                // Pass list text through the registered sanitizer.
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
                                    $import_result .= '  ' . esc_html( $k_wp ) . '<br/>';
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
                        if ( isset( $this->fail2wp_settings_rejected_options[$k_wp] ) ) {
                            $import_result .= '  ' . esc_html( $k_wp ) . '<br/>';
                            $html .= $this->fail2wp_admin_notice( $this->fail2wp_settings_rejected_options[$k_wp], 'error' );
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
                $html .= '<p>' . esc_html__( 'This tab can be used to import and export plugin settings and active IP-blocking bans.', 'fail2wp' ) . '</p>';
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
                    'fail2wp_cloudflare_check'              => $this->fail2wp_cloudflare_check,
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
                    'fail2wp_loginip_dnscache'              => $this->fail2wp_loginip_dnscache,
                    'fail2wp_loginip_allow'                 => $this->fail2wp_loginip_allow,
                    'fail2wp_loginip_deny'                  => $this->fail2wp_loginip_deny,
                    'fail2wp_xmlrpc_disable'                => $this->fail2wp_xmlrpc_disable,
                    'fail2wp_xmlrpc_disable_pingback'       => $this->fail2wp_xmlrpc_disable_pingback,
                    'fail2wp_xmlrpc_disable_everything'     => $this->fail2wp_xmlrpc_disable_everything,
                    'fail2wp_xmlrpc_inform_fail2ban'        => $this->fail2wp_xmlrpc_inform_fail2ban,
                    'fail2wp_ip_blocking_enable'            => $this->fail2wp_ip_blocking_enable,
                    'fail2wp_ip_blocking_threshold'         => $this->fail2wp_ip_blocking_threshold,
                    'fail2wp_ip_blocking_window'            => $this->fail2wp_ip_blocking_window,
                    'fail2wp_ip_blocking_duration'          => $this->fail2wp_ip_blocking_duration,
                    'fail2wp_ip_blocking_bypass'            => $this->fail2wp_ip_blocking_bypass,
                    'fail2wp_ip_blocking_active_bans'       => Fail2WP_IP_Blocking_Storage::get_active_bans(),
                    'fail2wp_admin_monitor_enable'          => $this->fail2wp_admin_monitor_enable,
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
                         esc_html__( 'Copy the text in this field to export your settings and active IP-blocking bans to another site', 'fail2wp' ) .
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
                case 'ipblocking':
                    settings_fields( 'fail2wp_settings_ipblocking' );
                    settings_errors( 'fail2wp-ip-blocking-bypass' );
                    do_settings_sections( 'fail2wp_settings_ipblocking' );
                    $this->fail2wp_ip_blocking_active_bans();
                    break;
                case 'newuser':
                    settings_fields( 'fail2wp_settings_newuser' );
                    do_settings_sections( 'fail2wp_settings_newuser' );
                    break;
                case 'adminmonitor':
                    settings_fields( 'fail2wp_settings_adminmonitor' );
                    do_settings_sections( 'fail2wp_settings_adminmonitor' );
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
        echo $tab_header . $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Values escaped during assembly; includes core Settings API markup.
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
             '<p>'  . '<img class="fail2wp-wps-logo" alt="" src="' . esc_url( plugin_dir_url( __FILE__ ) . 'img/webbplatsen_logo.png' ) . '" />' .
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
     * Sanitize the site label.
     *
     * @since  1.0.0
     */
    public function fail2wp_setting_sanitize_site_label( $input ) : string {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return( '' );
        }
        if ( $this->fail2wp_have_mbstring ) {
            return( mb_substr( sanitize_text_field( $input ), 0, 200 ) );
        }
        return( substr( sanitize_text_field( $input ), 0, 200 ) );
    }
    /**
     * Reject invalid input; retain the stored or effective default value.
     *
     * @since 1.4.0
     */
    protected function fail2wp_setting_reject_input( string $message, bool $report_error = true ) {
        $hook_prefix = 'sanitize_option_';
        $hook = current_filter();
        if ( strpos( $hook, $hook_prefix ) !== 0 ) {
            return( null );
        }
        $option = substr( $hook, strlen( $hook_prefix ) );
        $property = str_replace( '-', '_', $option );
        if ( ! property_exists( $this, $property ) ) {
            return( null );
        }
        if ( $report_error ) {
            $this->fail2wp_settings_rejected_options[$option] = $message;
            $error_code = $option . '_invalid_value';
            $reported = false;
            foreach ( get_settings_errors( $option ) as $error ) {
                if ( $error['code'] === $error_code ) {
                    $reported = true;
                    break;
                }
            }
            if ( ! $reported ) {
                add_settings_error( $option, $error_code, $message, 'error' );
            }
        }
        $fallback = $this->{$property};
        if ( is_array( $fallback ) ) {
            $fallback = wp_json_encode( $fallback );
        }
        return( get_option( $option, $fallback ) );
    }

    /**
     * Normalize checkbox values to 0 or 1.
     *
     * @since 1.4.0
     */
    public function fail2wp_setting_sanitize_boolean( $input ) : int {
        if ( ! is_admin() || ! is_user_logged_in() || ! current_user_can( 'administrator' ) ) {
            return( (int)(bool) $this->fail2wp_setting_reject_input( '', false ) );
        }
        if ( in_array( $input, [ true, 1, '1' ], true ) ) {
            return( 1 );
        }
        if ( in_array( $input, [ false, 0, '0', '', null ], true ) ) {
            return( 0 );
        }
        return( (int)(bool) $this->fail2wp_setting_reject_input( __( 'Invalid on/off value. Previous setting retained.', 'fail2wp' ) ) );
    }

    /**
     * Accept registered role identifiers; reject invalid selections.
     *
     * @since 1.4.0
     */
    public function fail2wp_setting_sanitize_role( $input ) : string {
        if ( ! is_admin() || ! is_user_logged_in() || ! current_user_can( 'administrator' ) ) {
            return( (string) $this->fail2wp_setting_reject_input( '', false ) );
        }
        if ( is_string( $input ) && array_key_exists( $input, $this->fail2wp_get_wp_roles() ) ) {
            return( $input );
        }
        return( (string) $this->fail2wp_setting_reject_input( __( 'Invalid role selection. Previous setting retained.', 'fail2wp' ) ) );
    }

    public function fail2wp_setting_sanitize_roles( $input ) : string {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return( (string) $this->fail2wp_setting_reject_input( '', false ) );
        }
        if ( $input === null || $input === '' ) {
            $input = [];
        } elseif ( is_string( $input ) ) {
            $input = json_decode( $input, true, 2 );
        }
        $available_roles = $this->fail2wp_get_wp_roles();
        $valid = is_array( $input );
        if ( $valid ) {
            foreach ( $input as $role ) {
                if ( ! is_string( $role ) || ! array_key_exists( $role, $available_roles ) ) {
                    $valid = false;
                    break;
                }
            }
        }
        if ( ! $valid ) {
            return( (string) $this->fail2wp_setting_reject_input( __( 'Invalid role selection. Previous setting retained.', 'fail2wp' ) ) );
        }
        return( wp_json_encode( array_values( array_unique( $input ) ) ) );
    }
    public function fail2wp_setting_sanitize_block_ns( $input ) : string {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return( '' );
        }
        $namespaces = $this->fail2wp_get_rest_ns();
        $return_val = array();
        if ( is_string( $input ) ) {
            $input = json_decode( $input, true, 2 );
        }
        if ( is_array( $input ) ) {
            foreach( $input as $block_ns ) {
                if ( in_array( $block_ns, $namespaces ) ) {
                    // Registered namespace match.
                    $return_val[] = $block_ns;
                }
            }
        }
        return( wp_json_encode( $return_val ) );
    }
    public function fail2wp_setting_sanitize_block_routes( $input ) : string {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return( '' );
        }
        $return_val = array();
        if ( is_string( $input ) ) {
            $input = json_decode( $input, true, 2 );
        }
        if ( is_array( $input ) ) {
            foreach( $input as $block_route ) {
                if ( in_array( $block_route, $this->fail2wp_rest_filter_route_list ) ) {
                    // Registered route match.
                    $return_val[] = $block_route;
                }
            }
        }
        return( wp_json_encode( $return_val ) );
    }
    public function fail2wp_setting_sanitize_advanced( $input ) : string {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return( '' );
        }
        if ( $this->fail2wp_have_mbstring ) {
            return( mb_substr( sanitize_text_field( $input ), 0, 200 ) );
        }
        return( substr( sanitize_text_field( $input ), 0, 200 ) );
    }
    public function fail2wp_setting_sanitize_textarea_setting( $input ) : string {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return( '' );
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
    protected function fail2wp_sanitize_textarea_setting_to_array( string $input ) : array {
        $sanitized = $this->fail2wp_setting_sanitize_textarea_setting( $input );
        $decoded = @ json_decode( $sanitized, true, 2 );
        if ( ! is_array( $decoded ) ) {
            return( array() );
        }
        $output = array();
        foreach( $decoded as $entry ) {
            if ( ! empty( $entry ) ) {
                $output[] = $entry;
            }
        }
        return( $output );
    }
    public function fail2wp_setting_sanitize_username_length( $input ) : string {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return( '' );
        }
        // Apply numeric bounds.
        $input = (int) sanitize_text_field( $input );
        if ( $input < 0 ) {
            $input = 0;
        } elseif ( $input > 200 ) {
            $input = 200;
        }
        return( $input );
    }
    public function fail2wp_setting_sanitize_dnscache( $input ) : int {
        if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
            return( 10080 );
        }
        // Apply numeric bounds.
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
    public function fail2wp_setting_sanitize_ip_blocking_threshold( $input ) : int {
        if ( ! is_admin() || ! is_user_logged_in() || ! current_user_can( 'administrator' ) ) {
            return( 5 );
        }
        return( max( 1, min( 1000, absint( $input ) ) ) );
    }
    public function fail2wp_setting_sanitize_ip_blocking_seconds( $input ) : int {
        if ( ! is_admin() || ! is_user_logged_in() || ! current_user_can( 'administrator' ) ) {
            return( 600 );
        }
        return( max( 60, min( 2592000, absint( $input ) ) ) );
    }
    protected function fail2wp_get_ip_blocking_bypass_entry_type( string $entry ) : int {
        if ( filter_var( $entry, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return( VALIDATE_IPHOSTCIDR_IPV4 );
        }
        if ( filter_var( $entry, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
            return( VALIDATE_IPHOSTCIDR_IPV6 );
        }
        $split = explode( '/', $entry );
        if ( count( $split ) === 2 ) {
            if ( filter_var( $split[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) && preg_match( '/^\d{1,2}$/', $split[1] ) && (int) $split[1] <= 32 ) {
                return( VALIDATE_IPHOSTCIDR_IPV4_CIDR );
            }
            if ( filter_var( $split[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) && preg_match( '/^\d{1,3}$/', $split[1] ) && (int) $split[1] <= 128 ) {
                return( VALIDATE_IPHOSTCIDR_IPV6_CIDR );
            }
            return( VALIDATE_IPHOSTCIDR_INVALID );
        }
        if ( filter_var( $entry, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME ) && substr( $entry, -1 ) !== '.' && ( strpos( $entry, '.' ) !== false || $entry === 'localhost' ) ) {
            return( VALIDATE_IPHOSTCIDR_HOSTNAME );
        }
        $hostname = str_replace( array( '*', '?' ), 'a', $entry );
        if ( $this->fail2wp_hostname_has_wildcard( $entry ) && substr_count( $entry, '.' ) >= 2 && preg_match( '/^[a-z0-9*?.-]+$/', $entry ) && filter_var( $hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME ) && substr( $entry, -1 ) !== '.' ) {
            return( VALIDATE_IPHOSTCIDR_HOSTNAME_WC );
        }
        return( VALIDATE_IPHOSTCIDR_INVALID );
    }
    public function fail2wp_setting_sanitize_ip_blocking_bypass( $input ) : string {
        if ( ! is_admin() || ! is_user_logged_in() || ! current_user_can( 'administrator' ) ) {
            return( wp_json_encode( array() ) );
        }
        $input = sanitize_textarea_field( $input );
        $entries = @ json_decode( $input, true, 2 );
        if ( ! is_array( $entries ) ) {
            $entries = preg_split( '/[\s,]+/', $input );
        }
        $output = array();
        $invalid_entries = array();
        if ( is_array( $entries ) ) {
            foreach ( $entries as $entry ) {
                $entry = strtolower( trim( $entry ) );
                if ( empty( $entry ) ) {
                    continue;
                }
                if ( $this->fail2wp_get_ip_blocking_bypass_entry_type( $entry ) !== VALIDATE_IPHOSTCIDR_INVALID ) {
                    $output[] = $entry;
                } else {
                    $invalid_entries[] = $entry;
                }
            }
        }
        if ( ! empty( $invalid_entries ) ) {
            static $reported_invalid_entries = array();
            $invalid_entries = array_unique( $invalid_entries );
            $error_key = implode( ',', $invalid_entries );
            if ( ! isset( $reported_invalid_entries[$error_key] ) ) {
                add_settings_error(
                    'fail2wp-ip-blocking-bypass',
                    'fail2wp_ip_blocking_bypass_invalid',
                    sprintf(
                        /* translators: %s: Invalid bypass entries, separated by commas. */
                        __( 'The following bypass entries were not saved because they are invalid: %s', 'fail2wp' ),
                        implode( ', ', $invalid_entries )
                    ),
                    'error'
                );
                $reported_invalid_entries[$error_key] = true;
            }
        }
        return( wp_json_encode( array_values( array_unique( $output ) ) ) );
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
            echo esc_html( $v ) . '</label> ';
            echo '</div>';
        }
    }
    public function fail2wp_setting_roles_warn() {
        $available_roles = $this->fail2wp_get_wp_roles();
        foreach( $available_roles as $k => $v ) {
            echo '<div class="fail2wp-role-option">';
            echo '<label for="fail2wp-roles-warn[]">';
            echo '<input type="checkbox" name="fail2wp-roles-warn[]" id="fail2wp-roles-warn[]" value="' . esc_attr( $k ) . '" ' . ( in_array( $k, $this->fail2wp_roles_warn ) ? 'checked="checked" ':'' ) . '/>';
            echo esc_html( $v ) . '</label> ';
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
        echo esc_html__( 'User enumeration attempts (i.e. your.site/...?author=nnn or /wp-json/wp/v2/users)', 'fail2wp' ) . '</label> ';
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
    public function fail2wp_settings_ip_blocking_callback() {
        if ( ! is_admin() || ! is_user_logged_in() || ! current_user_can( 'administrator' ) ) {
            return;
        }
        echo '<p>' . esc_html__( 'Temporarily blocks an exact client IP after it reaches the configured number of security events. Only events that Fail2WP is configured to log contribute to this counter.', 'fail2wp' ) . '</p>';
        echo '<p>' . esc_html__( 'Cloudflare client-IP unmasking is applied before counting and blocking. Login allow-list matches retain precedence on the login endpoint.', 'fail2wp' ) . '</p>';
        echo '<p>' . esc_html__( 'Bypass hostname and wildcard entries use DNS lookups. Prefer exact IP addresses or CIDR ranges when possible to avoid lookup latency.', 'fail2wp' ) . '</p>';
        if ( ! wp_using_ext_object_cache() ) {
            echo '<p><strong><span class="dashicons dashicons-warning"></span>&nbsp;' . esc_html__( 'NOTE', 'fail2wp' ) . ':</strong> ' . esc_html__( 'No persistent object cache is available. IP blocking still works, but each sitewide ban check may require a database lookup.', 'fail2wp' ) . '</p>';
        }
    }
    public function fail2wp_setting_ip_blocking_enable() {
        echo '<label for="fail2wp-ip-blocking-enable"><input type="checkbox" name="fail2wp-ip-blocking-enable" id="fail2wp-ip-blocking-enable" value="1" ' . checked( $this->fail2wp_ip_blocking_enable, 1, false ) . '/> ' . esc_html__( 'Enable temporary sitewide IP blocking', 'fail2wp' ) . '</label>';
    }
    public function fail2wp_setting_ip_blocking_threshold() {
        echo '<input type="number" min="1" max="1000" id="fail2wp-ip-blocking-threshold" name="fail2wp-ip-blocking-threshold" value="' . esc_attr( $this->fail2wp_ip_blocking_threshold ) . '" />';
        echo '<p class="description">' . esc_html__( 'Security events from one IP before a ban is created.', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_setting_ip_blocking_window() {
        echo '<input type="number" min="60" max="2592000" id="fail2wp-ip-blocking-window" name="fail2wp-ip-blocking-window" value="' . esc_attr( $this->fail2wp_ip_blocking_window ) . '" /> ' . esc_html__( 'seconds', 'fail2wp' );
        echo '<p class="description">' . esc_html__( 'Time period in which events are counted.', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_setting_ip_blocking_duration() {
        echo '<input type="number" min="60" max="2592000" id="fail2wp-ip-blocking-duration" name="fail2wp-ip-blocking-duration" value="' . esc_attr( $this->fail2wp_ip_blocking_duration ) . '" /> ' . esc_html__( 'seconds', 'fail2wp' );
        echo '<p class="description">' . esc_html__( 'How long a new or refreshed ban remains active.', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_setting_ip_blocking_bypass() {
        echo '<textarea rows="5" cols="30" id="fail2wp-ip-blocking-bypass" name="fail2wp-ip-blocking-bypass" class="large-text code">' . esc_html( implode( "\n", $this->fail2wp_ip_blocking_bypass ) ) . '</textarea>';
        echo '<p class="description">' . esc_html__( 'Exact IPv4/IPv6 addresses, CIDR ranges, hostnames, or hostname wildcards that must never be blocked. Enter one entry per line; for example, 192.0.2.15, 192.0.2.0/24, admin.example.com, or *.defsol.com.', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_settings_admin_monitor_callback() {
        if ( ! is_admin() || ! is_user_logged_in() || ! current_user_can( 'administrator' ) ) {
            return;
        }
        echo '<p>' . esc_html__( 'Monitors administrator-role accounts and reports unexpected changes. It is a detection feature and cannot guarantee prevention against a compromised administrator account or direct database changes.', 'fail2wp' ) . '</p>';
        echo '<p>' . esc_html__( 'Changes are checked immediately when WordPress user and role hooks run, then reconciled hourly through WP-Cron. Configure a real server cron or system timer for reliable scheduled checks on low-traffic sites.', 'fail2wp' ) . '</p>';
    }
    public function fail2wp_setting_admin_monitor_enable() {
        echo '<label for="fail2wp-admin-monitor-enable"><input type="checkbox" name="fail2wp-admin-monitor-enable" id="fail2wp-admin-monitor-enable" value="1" ' . checked( $this->fail2wp_admin_monitor_enable, 1, false ) . '/> ' . esc_html__( 'Monitor administrator accounts and log unexpected changes', 'fail2wp' ) . '</label>';
    }
    public function fail2wp_setting_admin_monitor_baseline() {
        $baseline = Fail2WP_Admin_User_Monitor::get_baseline();
        $current = Fail2WP_Admin_User_Monitor::get_current_snapshot();
        $changes = Fail2WP_Admin_User_Monitor::compare( $baseline, $current );
        $action = admin_url( 'admin.php?page=' . FAIL2WP_PLUGINNAME_SLUG . '&tab=adminmonitor' );
        if ( empty( $baseline ) ) {
            echo '<p>' . esc_html__( 'No administrator baseline has been recorded yet. Saving this setting enabled or reviewing the current accounts will establish one.', 'fail2wp' ) . '</p>';
        } elseif ( Fail2WP_Admin_User_Monitor::has_changes( $changes ) ) {
            echo '<p><strong>' . esc_html__( 'The current administrator accounts differ from the stored baseline.', 'fail2wp' ) . '</strong></p>';
        } else {
            echo '<p>' . esc_html__( 'The current administrator accounts match the stored baseline.', 'fail2wp' ) . '</p>';
        }
        echo '<p><code>' . esc_html( implode( ', ', array_values( $current ) ) ) . '</code></p>';
        wp_nonce_field( 'fail2wp_admin_monitor_actions', 'fail2wp_admin_monitor_nonce' );
        echo '<button type="submit" class="button button-secondary" name="fail2wp-admin-monitor-action" value="baseline" formaction="' . esc_url( $action ) . '" formmethod="post">' . esc_html__( 'Review and update baseline', 'fail2wp' ) . '</button>';
        echo '<p class="description">' . esc_html__( 'Use this only after intentionally creating, removing, or changing administrator accounts.', 'fail2wp' ) . '</p>';
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
                echo ' />' . esc_html( $v ) . '</option>';
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
                echo ' />' . esc_html( $v ) . '</option>';
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
        echo esc_html__( 'Block user enumeration attempts (i.e. your.site/...?author=nnn or /wp-json/wp/v2/users)', 'fail2wp' ) . '</label> ';
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
                 esc_html__( 'If "Require authentication" is enabled, unauthenticated REST API calls will be blocked while logged in and authenticated requests are allowed.', 'fail2wp' ) .
                 '</p>';
        } elseif ( $this->fail2wp_rest_filter_block_all || $this->fail2wp_rest_filter_block_index || ! empty( $this->fail2wp_rest_filter_block_ns ) || ! empty( $this->fail2wp_rest_filter_block_routes ) ) {
            echo '<p><strong><span class="dashicons dashicons-warning"></span>&nbsp;' . esc_html__( 'NOTE', 'fail2wp' ) . ':</strong> ' .
                 esc_html__( 'REST block settings only affect unauthenticated requests. Logged in and authenticated requests are allowed so that WordPress and plugins can continue to use the REST API.', 'fail2wp' ) .
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
             esc_html__( 'You can fetch the current Cloudflare IPv4 and IPv6 lists into the fields below before saving.', 'fail2wp' ) .
             '<br/>' .
             esc_html__( 'For an updated list of Cloudflare IPs, please use this link', 'fail2wp' ) .
             ': '.
             '<a href="https://www.cloudflare.com/ips/" target="_blank">'.
             'www.cloudflare.com/ips' .
             '</a>'.
             '</p>';
        if ( ! $this->fail2wp_cloudflare_check ) {
            echo '<p><strong><span class="dashicons dashicons-warning"></span>&nbsp;' . esc_html__( 'NOTE', 'fail2wp' ) . ':</strong> ' .
                 esc_html__( 'Cloudflare support is currently disabled. The ranges and refresh tool below remain available so you can prepare changes before enabling it.', 'fail2wp' ) .
                 '</p>';
        }
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
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-cloudflare-check">';
        echo '<input type="checkbox" name="fail2wp-cloudflare-check" id="fail2wp-cloudflare-check" value="1" ' . ( checked( $this->fail2wp_cloudflare_check, 1, false ) ) . '/>';
        echo esc_html__( 'Attempt to unmask real IP when Cloudflare IP is detected', 'fail2wp' ) . '</label> ';
        echo '<p class="description">' . esc_html__( 'The IPv4, IPv6, and refresh controls below are only used when this setting is enabled.', 'fail2wp' ) . '</p>';
        echo '</div>';
    }
    public function fail2wp_settings_cloudflare_ipv4() {
        $cloudflare_ranges_class = 'fail2wp-cloudflare-field' . ( $this->fail2wp_cloudflare_check ? '' : ' fail2wp-soft-disabled' );
        echo '<div class="' . esc_attr( $cloudflare_ranges_class ) . '">';
        echo '<textarea rows="10" cols="30" id="fail2wp-cloudflare-ipv4" name="fail2wp-cloudflare-ipv4" class="large-text code">';
        echo esc_html( implode( "\n", $this->fail2wp_cloudflare_ipv4 ) );
        echo '</textarea>';
        echo '<p class="description">' . esc_html__( 'IPs matching these addresses will be considerd to be coming from Cloudflare', 'fail2wp' ) . '</p>';
        echo '<p class="description">' . esc_html__( 'You can edit this list even when Cloudflare support is disabled.', 'fail2wp' ) . '</p>';
        echo '</div>';
    }
    public function fail2wp_settings_cloudflare_ipv6() {
        $cloudflare_ranges_class = 'fail2wp-cloudflare-field' . ( $this->fail2wp_cloudflare_check ? '' : ' fail2wp-soft-disabled' );
        echo '<div class="' . esc_attr( $cloudflare_ranges_class ) . '">';
        echo '<textarea rows="10" cols="30" id="fail2wp-cloudflare-ipv6" name="fail2wp-cloudflare-ipv6" class="large-text code">';
        echo esc_html( implode( "\n", $this->fail2wp_cloudflare_ipv6 ) );
        echo '</textarea>';
        echo '<p class="description">' . esc_html__( 'IPs matching these addresses will be considerd to be coming from Cloudflare', 'fail2wp' ) . '</p>';
        echo '<p class="description">' . esc_html__( 'You can edit this list even when Cloudflare support is disabled.', 'fail2wp' ) . '</p>';
        echo '</div>';
    }
    public function fail2wp_settings_cloudflare_refresh() {
        $action = admin_url( 'admin.php?page=' . FAIL2WP_PLUGINNAME_SLUG . '&tab=cloudflare' );
        $cloudflare_refresh_class = 'fail2wp-cloudflare-field' . ( $this->fail2wp_cloudflare_check ? '' : ' fail2wp-soft-disabled' );
        echo '<div class="' . esc_attr( $cloudflare_refresh_class ) . '">';
        wp_nonce_field( 'fail2wp_cloudflare_refresh', 'fail2wp_cloudflare_refresh_nonce' );
        submit_button(
            esc_html__( 'Fetch current Cloudflare IPs', 'fail2wp' ),
            'secondary',
            'fail2wp-cloudflare-refresh',
            false,
            [
                'id'             => 'fail2wp-cloudflare-refresh',
                'formaction'     => esc_url( $action ),
                'formmethod'     => 'post',
                'formnovalidate' => 'formnovalidate',
            ]
        );
        echo '<p class="description">' .
             esc_html__( 'Fetches the current Cloudflare IPv4 and IPv6 lists into the fields above. Use Save Changes to store any updates.', 'fail2wp' ) .
             '</p>';
        echo '<p class="description">' . esc_html__( 'This button stays available so you can refresh the ranges before enabling Cloudflare support.', 'fail2wp' ) . '</p>';
        echo '</div>';
    }
    protected function fail2wp_validate_cloudflare_cidr( string $cidr, bool $is_ipv6 ) : bool {
        $split = explode( '/', trim( $cidr ) );
        if ( ! is_array( $split ) || count( $split ) !== 2 ) {
            return( false );
        }
        if ( $is_ipv6 ) {
            if ( ! filter_var( $split[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
                return( false );
            }
            if ( ! preg_match( '/^\d{1,3}$/', $split[1] ) ) {
                return( false );
            }
            return( (int)$split[1] <= 128 );
        }
        if ( ! filter_var( $split[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return( false );
        }
        if ( ! preg_match( '/^\d{1,2}$/', $split[1] ) ) {
            return( false );
        }
        return( (int)$split[1] <= 32 );
    }
    protected function fail2wp_fetch_cloudflare_ranges( string $url, bool $is_ipv6 ) {
        $response = wp_safe_remote_get(
            $url,
            [
                'timeout'     => 10,
                'redirection' => 3,
            ]
        );
        if ( is_wp_error( $response ) ) {
            return( $response );
        }
        if ( wp_remote_retrieve_response_code( $response ) !== 200 ) {
            return( new \WP_Error( 'fail2wp_cloudflare_fetch_status', __( 'Unexpected response from Cloudflare IP list endpoint.', 'fail2wp' ) ) );
        }
        $body = trim( wp_remote_retrieve_body( $response ) );
        if ( empty( $body ) ) {
            return( new \WP_Error( 'fail2wp_cloudflare_fetch_empty', __( 'Cloudflare IP list endpoint returned an empty response.', 'fail2wp' ) ) );
        }
        $ranges = preg_split( '/\r\n|\r|\n/', strtolower( $body ) );
        if ( ! is_array( $ranges ) ) {
            return( new \WP_Error( 'fail2wp_cloudflare_fetch_parse', __( 'Unable to parse Cloudflare IP list response.', 'fail2wp' ) ) );
        }
        $output = array();
        foreach( $ranges as $range ) {
            $range = trim( $range );
            if ( empty( $range ) ) {
                continue;
            }
            if ( ! $this->fail2wp_validate_cloudflare_cidr( $range, $is_ipv6 ) ) {
                return( new \WP_Error( 'fail2wp_cloudflare_fetch_invalid', __( 'Cloudflare IP list response contained an invalid entry.', 'fail2wp' ) ) );
            }
            $output[] = $range;
        }
        if ( empty( $output ) ) {
            return( new \WP_Error( 'fail2wp_cloudflare_fetch_empty', __( 'Cloudflare IP list endpoint returned an empty response.', 'fail2wp' ) ) );
        }
        return( $output );
    }
    protected function fail2wp_admin_notice( string $message, string $type = 'info' ) : string {
        return(
            '<div class="notice notice-' . esc_attr( $type ) . ' is-dismissible"><p><strong>' .
            esc_html( $message ) .
            '</strong></p></div>'
        );
    }
    protected function fail2wp_handle_ip_blocking_actions() : string {
        if ( empty( $_POST['fail2wp-ip-blocking-action'] ) ) {
            return( '' );
        }
        if ( ! isset( $_POST['fail2wp_ip_blocking_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['fail2wp_ip_blocking_nonce'] ) ), 'fail2wp_ip_blocking_actions' ) ) {
            return( $this->fail2wp_admin_notice( __( 'Unable to verify the IP-blocking request.', 'fail2wp' ), 'error' ) );
        }
        $action = sanitize_text_field( wp_unslash( $_POST['fail2wp-ip-blocking-action'] ) );
        if ( $action === 'clear' ) {
            Fail2WP_IP_Blocking_Storage::clear_bans();
            return( $this->fail2wp_admin_notice( __( 'All IP blocks were cleared.', 'fail2wp' ), 'success' ) );
        }
        if ( $action === 'add' && ! empty( $_POST['fail2wp-ip-blocking-add-ip'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_POST['fail2wp-ip-blocking-add-ip'] ) );
            $duration = isset( $_POST['fail2wp-ip-blocking-add-duration'] ) ? absint( $_POST['fail2wp-ip-blocking-add-duration'] ) : $this->fail2wp_ip_blocking_duration;
            $duration = max( 60, min( 2592000, $duration ) );
            if ( Fail2WP_IP_Blocking_Storage::add_ban( $ip, $duration ) ) {
                return( $this->fail2wp_admin_notice( __( 'The IP address was blocked.', 'fail2wp' ), 'success' ) );
            }
        }
        if ( strpos( $action, 'remove:' ) === 0 ) {
            $ip = sanitize_text_field( substr( $action, 7 ) );
            if ( Fail2WP_IP_Blocking_Storage::remove_ban( $ip ) ) {
                return( $this->fail2wp_admin_notice( __( 'The IP block was cleared.', 'fail2wp' ), 'success' ) );
            }
        }
        return( $this->fail2wp_admin_notice( __( 'Unable to update the IP block.', 'fail2wp' ), 'error' ) );
    }
    protected function fail2wp_handle_admin_monitor_actions() : string {
        if ( empty( $_POST['fail2wp-admin-monitor-action'] ) ) {
            return( '' );
        }
        if ( ! isset( $_POST['fail2wp_admin_monitor_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['fail2wp_admin_monitor_nonce'] ) ), 'fail2wp_admin_monitor_actions' ) ) {
            return( $this->fail2wp_admin_notice( __( 'Unable to verify the administrator-monitor request.', 'fail2wp' ), 'error' ) );
        }
        if ( sanitize_text_field( wp_unslash( $_POST['fail2wp-admin-monitor-action'] ) ) === 'baseline' ) {
            $baseline = Fail2WP_Admin_User_Monitor::store_baseline();
            $message = sprintf(
                /* translators: %d: Number of administrator accounts. */
                __( 'Administrator baseline updated with %d account(s).', 'fail2wp' ),
                count( $baseline )
            );
            return( $this->fail2wp_admin_notice( $message, 'success' ) );
        }
        return( $this->fail2wp_admin_notice( __( 'Unable to update the administrator baseline.', 'fail2wp' ), 'error' ) );
    }
    protected function fail2wp_ip_blocking_active_bans() {
        $bans = Fail2WP_IP_Blocking_Storage::get_active_bans();
        $action = admin_url( 'admin.php?page=' . FAIL2WP_PLUGINNAME_SLUG . '&tab=ipblocking' );
        wp_nonce_field( 'fail2wp_ip_blocking_actions', 'fail2wp_ip_blocking_nonce' );
        echo '<section class="fail2wp-config-section fail2wp-manual-ban" aria-labelledby="fail2wp-manual-ban-heading">';
        echo '<h2 id="fail2wp-manual-ban-heading">' . esc_html__( 'Block an IP address manually', 'fail2wp' ) . '</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';
        echo '<tr><th scope="row"><label for="fail2wp-ip-blocking-add-ip">' . esc_html__( 'IP address', 'fail2wp' ) . '</label></th><td>';
        echo '<input type="text" class="regular-text code" id="fail2wp-ip-blocking-add-ip" name="fail2wp-ip-blocking-add-ip" inputmode="text" />';
        echo '<p class="description">' . esc_html__( 'Manual blocks accept exact IPv4 or IPv6 addresses only. Use the bypass list above for trusted CIDR ranges and hostnames.', 'fail2wp' ) . '</p></td></tr>';
        echo '<tr><th scope="row"><label for="fail2wp-ip-blocking-add-duration">' . esc_html__( 'Duration', 'fail2wp' ) . '</label></th><td>';
        echo '<input type="number" min="60" max="2592000" id="fail2wp-ip-blocking-add-duration" name="fail2wp-ip-blocking-add-duration" value="' . esc_attr( $this->fail2wp_ip_blocking_duration ) . '" /> ' . esc_html__( 'seconds', 'fail2wp' ) . '</td></tr>';
        echo '<tr><th scope="row"></th><td><button type="submit" class="button button-secondary" name="fail2wp-ip-blocking-action" value="add" formaction="' . esc_url( $action ) . '" formmethod="post">' . esc_html__( 'Block IP address', 'fail2wp' ) . '</button></td></tr>';
        echo '</tbody></table></section>';
        echo '<section class="fail2wp-config-section fail2wp-active-bans" aria-labelledby="fail2wp-active-bans-heading"><h2 id="fail2wp-active-bans-heading">' . esc_html__( 'Active IP blocks', 'fail2wp' ) . '</h2>';
        if ( empty( $bans ) ) {
            echo '<p>' . esc_html__( 'There are no active IP blocks.', 'fail2wp' ) . '</p></section>';
            return;
        }
        echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'IP address', 'fail2wp' ) . '</th><th>' . esc_html__( 'Hits', 'fail2wp' ) . '</th><th>' . esc_html__( 'Created', 'fail2wp' ) . '</th><th>' . esc_html__( 'Expires', 'fail2wp' ) . '</th><th>' . esc_html__( 'Action', 'fail2wp' ) . '</th></tr></thead><tbody>';
        foreach ( $bans as $ban ) {
            echo '<tr><td><code>' . esc_html( $ban['ip'] ) . '</code></td><td>' . esc_html( $ban['hit_count'] ) . '</td><td>' . esc_html( get_date_from_gmt( $ban['created_at'] ) ) . '</td><td>' . esc_html( get_date_from_gmt( $ban['expires_at'] ) ) . '</td><td>';
            echo '<button type="submit" class="button-link-delete" name="fail2wp-ip-blocking-action" value="remove:' . esc_attr( $ban['ip'] ) . '" formaction="' . esc_url( $action ) . '" formmethod="post">' . esc_html__( 'Clear', 'fail2wp' ) . '</button></td></tr>';
        }
        echo '</tbody></table>';
        echo '<p><button type="submit" class="button button-secondary" name="fail2wp-ip-blocking-action" value="clear" formaction="' . esc_url( $action ) . '" formmethod="post">' . esc_html__( 'Clear all IP blocks', 'fail2wp' ) . '</button></p></section>';
    }
    protected function fail2wp_apply_cloudflare_form_state_from_post() {
        $this->fail2wp_cloudflare_check = isset( $_POST['fail2wp-cloudflare-check'] );
        if ( isset( $_POST['fail2wp-cloudflare-ipv4'] ) ) {
            $this->fail2wp_cloudflare_ipv4 = $this->fail2wp_sanitize_textarea_setting_to_array( wp_unslash( $_POST['fail2wp-cloudflare-ipv4'] ) );
        }
        if ( isset( $_POST['fail2wp-cloudflare-ipv6'] ) ) {
            $this->fail2wp_cloudflare_ipv6 = $this->fail2wp_sanitize_textarea_setting_to_array( wp_unslash( $_POST['fail2wp-cloudflare-ipv6'] ) );
        }
    }
    protected function fail2wp_handle_cloudflare_refresh() : string {
        if ( ! isset( $_POST['fail2wp-cloudflare-refresh'] ) ) {
            return( '' );
        }
        if ( ! isset( $_POST['fail2wp_cloudflare_refresh_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['fail2wp_cloudflare_refresh_nonce'] ) ), 'fail2wp_cloudflare_refresh' ) ) {
            return( $this->fail2wp_admin_notice( __( 'Unable to verify the Cloudflare refresh request.', 'fail2wp' ), 'error' ) );
        }
        $this->fail2wp_apply_cloudflare_form_state_from_post();
        $current_ipv4 = $this->fail2wp_cloudflare_ipv4;
        $current_ipv6 = $this->fail2wp_cloudflare_ipv6;
        $fetched_ipv4 = $this->fail2wp_fetch_cloudflare_ranges( FAIL2WP_CLOUDFLARE_IPS_V4_URL, false );
        $fetched_ipv6 = $this->fail2wp_fetch_cloudflare_ranges( FAIL2WP_CLOUDFLARE_IPS_V6_URL, true );
        $have_error = false;
        $notices = '';
        $updated_ipv4 = false;
        $updated_ipv6 = false;
        if ( is_wp_error( $fetched_ipv4 ) ) {
            $have_error = true;
        } elseif ( $fetched_ipv4 !== $current_ipv4 ) {
            $this->fail2wp_cloudflare_ipv4 = $fetched_ipv4;
            $updated_ipv4 = true;
        }
        if ( is_wp_error( $fetched_ipv6 ) ) {
            $have_error = true;
        } elseif ( $fetched_ipv6 !== $current_ipv6 ) {
            $this->fail2wp_cloudflare_ipv6 = $fetched_ipv6;
            $updated_ipv6 = true;
        }
        if ( $updated_ipv4 && $updated_ipv6 ) {
            $notices .= $this->fail2wp_admin_notice( __( 'Cloudflare IPv4 and IPv6 ranges have been updated in the form. Use Save Changes to store the update.', 'fail2wp' ), 'success' );
        } elseif ( $updated_ipv4 ) {
            $notices .= $this->fail2wp_admin_notice( __( 'Cloudflare IPv4 ranges have been updated in the form. Use Save Changes to store the update.', 'fail2wp' ), 'success' );
        } elseif ( $updated_ipv6 ) {
            $notices .= $this->fail2wp_admin_notice( __( 'Cloudflare IPv6 ranges have been updated in the form. Use Save Changes to store the update.', 'fail2wp' ), 'success' );
        } elseif ( ! $have_error ) {
            $notices .= $this->fail2wp_admin_notice( __( 'No changes detected in Cloudflare IP ranges.', 'fail2wp' ), 'info' );
        }
        if ( $have_error ) {
            $notices .= $this->fail2wp_admin_notice( __( 'An error occurred while fetching Cloudflare IP ranges. No changes were made for the affected field.', 'fail2wp' ), 'error' );
        }
        return( $notices );
    }


    /**
     * Send alert to syslog
     *
     * @since  1.0.0
     * @param  string $alert_message The error message.
     */
    public function fail2wp_alert_send( string $alert_message ) {
        $alert_message = preg_replace( '/[\x00-\x1f\x7f]/', ' ', $alert_message );
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
        $prefix = preg_replace( '/[\x00-\x1f\x7f]/', ' ', $prefix );
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
     * Format user display and login names for notifications.
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
     * Read a valid Cloudflare client IP from a configured Cloudflare peer.
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
            if ( $is_cloudflare && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && is_string( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && filter_var( $_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP ) ) {
                $remote_ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
            }
        }
        return( $remote_ip );
    }

    /**
     * Resolve client IP; prefer Cloudflare, then explicitly trusted X-Real-IP.
     *
     * @since 1.3.0
     */
    public function fail2wp_get_client_ip() : string {
        if ( empty( $_SERVER['REMOTE_ADDR'] ) ) {
            return( '' );
        }
        $remote_ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        if ( ! filter_var( $remote_ip, FILTER_VALIDATE_IP ) ) {
            return( '' );
        }
        $client_ip = $this->fail2wp_do_cloudflare_lookup( $remote_ip );
        if ( $client_ip === $remote_ip && defined( 'FAIL2WP_TRUSTED_PROXIES' ) && is_array( FAIL2WP_TRUSTED_PROXIES ) ) {
            foreach ( FAIL2WP_TRUSTED_PROXIES as $proxy ) {
                if ( is_string( $proxy ) && $this->fail2wp_cidrm->match( $remote_ip, $proxy ) ) {
                    if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) && is_string( $_SERVER['HTTP_X_REAL_IP'] ) && filter_var( $_SERVER['HTTP_X_REAL_IP'], FILTER_VALIDATE_IP ) ) {
                        $client_ip = $_SERVER['HTTP_X_REAL_IP'];
                    }
                    break;
                }
            }
        }
        return( filter_var( $client_ip, FILTER_VALIDATE_IP ) ? $client_ip : '' );
    }

    protected function fail2wp_ip_blocking_is_bypassed( string $ip ) : bool {
        foreach ( $this->fail2wp_ip_blocking_bypass as $entry ) {
            switch ( $this->fail2wp_get_ip_blocking_bypass_entry_type( $entry ) ) {
                case VALIDATE_IPHOSTCIDR_IPV4:
                case VALIDATE_IPHOSTCIDR_IPV6:
                    if ( $ip === $entry ) {
                        return( true );
                    }
                    break;
                case VALIDATE_IPHOSTCIDR_IPV4_CIDR:
                case VALIDATE_IPHOSTCIDR_IPV6_CIDR:
                    if ( $this->fail2wp_cidrm->match( $ip, $entry ) ) {
                        return( true );
                    }
                    break;
                case VALIDATE_IPHOSTCIDR_HOSTNAME:
                    $lookup = $this->fail2wp_hostname_lookup( $entry );
                    if ( is_array( $lookup ) && in_array( $ip, $lookup, true ) ) {
                        return( true );
                    }
                    break;
                case VALIDATE_IPHOSTCIDR_HOSTNAME_WC:
                    $hostnames = $this->fail2wp_reverse_hostname_lookup( $ip );
                    if ( is_array( $hostnames ) ) {
                        foreach ( $hostnames as $hostname ) {
                            if ( $this->fail2wp_hostname_match_wildcard( $hostname, $entry ) ) {
                                return( true );
                            }
                        }
                    }
                    break;
            }
        }
        return( false );
    }

    protected function fail2wp_is_login_request() : bool {
        return( ! empty( $_SERVER['SCRIPT_NAME'] ) && basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) ) === 'wp-login.php' );
    }

    /**
     * Match the login allow list before local-ban enforcement.
     *
     * @since 1.3.0
     */
    protected function fail2wp_login_ip_is_allowlisted( string $ip ) : bool {
        if ( ! $this->fail2wp_loginip_enable || empty( $this->fail2wp_loginip_allow ) ) {
            return( false );
        }
        foreach ( $this->fail2wp_precond_access_list( true ) as $entry ) {
            switch ( $entry['type'] ) {
                case VALIDATE_IPHOSTCIDR_IPV4:
                case VALIDATE_IPHOSTCIDR_IPV6:
                    if ( $entry['data'] === $ip ) {
                        return( true );
                    }
                    break;
                case VALIDATE_IPHOSTCIDR_IPV4_CIDR:
                case VALIDATE_IPHOSTCIDR_IPV6_CIDR:
                    if ( $this->fail2wp_cidrm->match( $ip, $entry['data'] ) ) {
                        return( true );
                    }
                    break;
                case VALIDATE_IPHOSTCIDR_HOSTNAME:
                    if ( in_array( $ip, $this->fail2wp_hostname_lookup( $entry['data'] ), true ) ) {
                        return( true );
                    }
                    break;
                case VALIDATE_IPHOSTCIDR_HOSTNAME_WC:
                    foreach ( $this->fail2wp_reverse_hostname_lookup( $ip ) as $hostname ) {
                        if ( $this->fail2wp_hostname_match_wildcard( $hostname, $entry['data'] ) ) {
                            return( true );
                        }
                    }
                    break;
            }
        }
        return( false );
    }

    /**
     * Record a qualifying, already-loggable security event.
     *
     * @since 1.3.0
     */
    public function fail2wp_record_ip_blocking_event( string $ip = '' ) {
        if ( ! $this->fail2wp_ip_blocking_enable ) {
            return;
        }
        if ( empty( $ip ) ) {
            $ip = $this->fail2wp_get_client_ip();
        }
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) || $this->fail2wp_ip_blocking_is_bypassed( $ip ) ) {
            return;
        }
        $was_banned = Fail2WP_IP_Blocking_Storage::is_banned( $ip );
        $is_banned = Fail2WP_IP_Blocking_Storage::record_event(
            $ip,
            max( 1, $this->fail2wp_ip_blocking_threshold ),
            max( 60, $this->fail2wp_ip_blocking_window ),
            max( 60, $this->fail2wp_ip_blocking_duration )
        );
        Fail2WP_IP_Blocking_Storage::prune( max( 60, $this->fail2wp_ip_blocking_window ) );
        if ( $is_banned && ! $was_banned ) {
            $message = $this->fail2wp_make_alert_message( $ip, null, FAIL2WP_ALERT_IP_BLOCK_CREATED, true );
            if ( ! empty( $message ) ) {
                $this->fail2wp_alert_send( $message );
            }
        }
    }

    /**
     * Enforce local bans before WordPress routes public or admin requests.
     *
     * @since 1.3.0
     */
    public function fail2wp_ip_blocking_enforce() {
        if ( ! $this->fail2wp_ip_blocking_enable || php_sapi_name() === 'cli' ) {
            return;
        }
        $ip = $this->fail2wp_get_client_ip();
        if ( empty( $ip ) || $this->fail2wp_ip_blocking_is_bypassed( $ip ) ) {
            return;
        }
        if ( $this->fail2wp_is_login_request() && $this->fail2wp_login_ip_is_allowlisted( $ip ) ) {
            return;
        }
        if ( ! Fail2WP_IP_Blocking_Storage::is_banned( $ip ) ) {
            return;
        }
        $message = $this->fail2wp_make_alert_message( $ip, null, FAIL2WP_ALERT_IP_BLOCK_HIT, true );
        if ( ! empty( $message ) ) {
            $this->fail2wp_alert_send( $message );
        }
        status_header( 403 );
        nocache_headers();
        header( 'Content-Type: text/html; charset=utf-8' );
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>' . esc_html__( 'Access temporarily blocked', 'fail2wp' ) . '</title><style>body{margin:0;background:#f6f7f7;color:#1d2327;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.fail2wp-block{max-width:38rem;margin:10vh auto;padding:2rem;background:#fff;border-top:4px solid #b32d2e;box-shadow:0 1px 3px rgba(0,0,0,.12)}h1{margin-top:0;font-size:1.5rem}</style></head><body><main class="fail2wp-block"><h1>' . esc_html__( 'Access temporarily blocked', 'fail2wp' ) . '</h1><p>' . esc_html__( 'This address has been temporarily blocked because of repeated security events. Please try again later.', 'fail2wp' ) . '</p></main></body></html>';
        exit;
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
        // Keep untrusted login names within a single log record.
        $username = preg_replace( '/[\x00-\x1f\x7f]/', ' ', $username );
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        $remote_ip = '';
        if ( empty( $override_ip ) ) {
            if ( $username_is_ip_address ) {
                // Username string contains IP address (some REST API requests)
                $remote_ip = $username;
            } elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
                // Fetch remote IP if set
                $remote_ip = $this->fail2wp_get_client_ip();
            }
        } else {
            $remote_ip = $override_ip;
        }
        if ( ! filter_var( $remote_ip, FILTER_VALIDATE_IP ) ) {
            $remote_ip = '';
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
            case FAIL2WP_ALERT_IP_BLOCK_CREATED:
                $alert_message = 'Local IP block created' . $remote_ip . $our_port;
                break;
            case FAIL2WP_ALERT_IP_BLOCK_HIT:
                $alert_message = 'Blocked local IP request' . $remote_ip . $our_port;
                break;
        } // switch
        if ( defined( 'FAIL2WP_FLOW_DEBUG') && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {exit}' );
        }
        return( $alert_message );
    }


    /**
     * Check configured notification roles against user capabilities.
     *
     * @since 1.0.0
     * @param array $roles WordPress roles/caps of user in question.
     * @param array $notify_roles Configured roles.
     * @return boolean true=Notify, false=Don't notify
     */
    protected function fail2wp_role_is_active( array $roles, array $notify_roles ) : bool {
        // Match configured notification roles.
        foreach( $notify_roles as $role ) {
            if ( array_key_exists( $role, $roles ) && $roles[$role] ) {
                return( true );
            }
        }
        return( false );
    }


    /**
     * Return translated names for matching notification roles.
     *
     * @since 1.1.0
     * @param array $roles WordPress roles/caps of user in question.
     * @param string $notify_roles Configured roles as JSON.
     * @return string List of translated role names like ' [Administratör,Prenumerant]'
     */
    protected function fail2wp_roles_merge( array $roles, string $notify_roles ) : string {
        $notify_array = @ json_decode( $notify_roles, true, 2 );
        if ( ! is_array( $notify_array ) || empty( $notify_array ) ) {
            return( false );
        }
        $new_roles = array();
        // Match configured notification roles.
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
     * Log successful logins for configured roles.
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
            // Check notification roles for known users.
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
            $this->fail2wp_record_ip_blocking_event();
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
     * Replace the login username label when email login is required.
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
     * Enable login-label translation on login_head.
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
     * Return forward-confirmed reverse DNS names; reuse cached lookups.
     *
     * @since 1.2.0
     * @param string $ip_address
     * @return array Forward-confirmed hostnames.
     */
    protected function fail2wp_reverse_hostname_lookup( string $ip_address ) {
        if ( ! filter_var( $ip_address, FILTER_VALIDATE_IP ) ) {
            return( array() );
        }
        $use_cache = $this->fail2wp_loginip_dnscache > 0 && $this->fail2wp_loginip_dnscache <= 10080;
        if ( $use_cache && ! empty( $this->fail2wp_hostname_cache[$ip_address] ) ) {
            $hostnames = $this->fail2wp_hostname_cache[$ip_address];
        } else {
            $hostname = gethostbyaddr( $ip_address );
            $hostnames = ! empty( $hostname ) && ! filter_var( $hostname, FILTER_VALIDATE_IP ) ? array( $hostname ) : array();
        }
        $confirmed = array();
        foreach ( $hostnames as $hostname ) {
            // Forward-confirm PTR names, including cached entries.
            foreach ( $this->fail2wp_hostname_lookup( $hostname ) as $address ) {
                if ( inet_pton( $address ) === inet_pton( $ip_address ) ) {
                    $confirmed[] = $hostname;
                    break;
                }
            }
        }
        if ( $use_cache ) {
            if ( empty( $this->fail2wp_hostname_cache['ts'] ) ) {
                $this->fail2wp_hostname_cache['ts'] = time() + ( $this->fail2wp_loginip_dnscache * 60 );
            }
            $this->fail2wp_hostname_cache[$ip_address] = $confirmed;
            $this->fail2wp_hostname_cache_updated = true;
        }
        return( $confirmed );
    }


    /**
     * Return hostname A/AAAA addresses; empty array on lookup failure.
     *
     * @since 1.2.0
     * @param string $hostname
     * @return array A/AAAA addresses.
     */
    protected function fail2wp_hostname_lookup( string $hostname ) {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        $lookup_result = array();
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
     * Check for * or ? wildcard characters.
     *
     * @since 1.2.0
     * @param string $hostname Hostname string, possibly containing wildcards
     * @return bool
     */
    protected function fail2wp_hostname_has_wildcard( string $hostname ) : bool {
        return ( strpos( $hostname, '*' ) !== false || strpos( $hostname, '?' ) !== false );
    }


    /**
     * Match a hostname against a pattern containing * or ?.
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
     * Classify valid login allow/deny entries; skip invalid entries.
     *
     * @since 1.2.0
     * @param bool $is_allow If true, use allow list, otherwise use deny list
     * @return array Classified access-list entries.
     *
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
                    // Reject trailing dots.
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
                // IPv4 masks: at most two digits.
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
                // IPv6 masks: at most three digits.
                if ( ! preg_match( '/^\d{1,3}$/', $split[1] ) ) {
                    // Something else here, invalid
                    $entry_type = VALIDATE_IPHOSTCIDR_INVALID;
                } elseif ( (int)$split[1] <= 128 ) {
                    $entry_type = VALIDATE_IPHOSTCIDR_IPV6_CIDR;
                } else {
                    $entry_type = VALIDATE_IPHOSTCIDR_INVALID;
                }
            }
            // Skip invalid entries.
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
     * Enforce login IP allow/deny lists before login processing.
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
        $remote_ip_cf = $this->fail2wp_get_client_ip();
        if ( $remote_ip == $remote_ip_cf ) {
            // Addresses are the same, not Cloudflare
            $remote_ip_cf = '';
            $remote_real_ip = $remote_ip;
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
                    // Enforce the block and log when configured.
                    if ($this->fail2wp_loginip_inform_fail2ban) {
                        $alert_message = $this->fail2wp_make_alert_message( '', null, FAIL2WP_ALERT_LOGINIP_BLOCKED, false, $remote_real_ip );
                        if ( ! empty( $alert_message ) ) {
                            $this->fail2wp_alert_send( $alert_message );
                            $this->fail2wp_record_ip_blocking_event( $remote_real_ip );
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
                // Enforce the block and log when configured.
                if ( ! $this->fail2wp_loginip_testmode ) {
                    if ($this->fail2wp_loginip_inform_fail2ban) {
                        $alert_message = $this->fail2wp_make_alert_message( '', null, FAIL2WP_ALERT_LOGINIP_BLOCKED, false, $remote_real_ip );
                        if ( ! empty( $alert_message ) ) {
                            $this->fail2wp_alert_send( $alert_message );
                            $this->fail2wp_record_ip_blocking_event( $remote_real_ip );
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
            add_action( 'login_init', [$this, 'fail2wp_login_ip_check'] );
        }
        // XMLRPC handling @since 1.2.0
        // Apply XML-RPC rules only to XML-RPC requests.
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
     * Schedule hourly administrator reconciliation through traffic-driven WP-Cron.
     *
     * @since 1.3.0
     */
    protected function fail2wp_admin_monitor_schedule() {
        if ( ! wp_next_scheduled( 'fail2wp_admin_monitor_reconcile' ) ) {
            wp_schedule_event( time() + 300, 'hourly', 'fail2wp_admin_monitor_reconcile' );
        }
    }

    /**
     * Initialize monitoring after WordPress has loaded users and roles.
     *
     * @since 1.3.0
     */
    public function fail2wp_admin_monitor_initialize() {
        if ( ! $this->fail2wp_admin_monitor_enable ) {
            return;
        }
        $this->fail2wp_admin_monitor_schedule();
        if ( empty( Fail2WP_Admin_User_Monitor::get_baseline() ) ) {
            Fail2WP_Admin_User_Monitor::store_baseline();
        }
    }

    /**
     * Return a concise, English syslog summary of administrator differences.
     *
     * @since 1.3.0
     */
    protected function fail2wp_admin_monitor_format_changes( array $changes ) : string {
        $parts = array();
        if ( ! empty( $changes['added'] ) ) {
            $parts[] = 'added administrator account(s): ' . implode( ',', array_values( $changes['added'] ) );
        }
        if ( ! empty( $changes['removed'] ) ) {
            $parts[] = 'removed administrator account(s): ' . implode( ',', array_values( $changes['removed'] ) );
        }
        return( implode( '; ', $parts ) );
    }

    /**
     * Reconcile the stored baseline with current administrator-role accounts.
     *
     * @since 1.3.0
     */
    public function fail2wp_admin_monitor_reconcile() {
        if ( ! $this->fail2wp_admin_monitor_enable ) {
            return;
        }
        $baseline = Fail2WP_Admin_User_Monitor::get_baseline();
        if ( empty( $baseline ) ) {
            Fail2WP_Admin_User_Monitor::store_baseline();
            return;
        }
        $current = Fail2WP_Admin_User_Monitor::get_current_snapshot();
        $changes = Fail2WP_Admin_User_Monitor::compare( $baseline, $current );
        update_option( Fail2WP_Admin_User_Monitor::LAST_CHECK_OPTION, time(), false );
        if ( ! Fail2WP_Admin_User_Monitor::has_changes( $changes ) ) {
            delete_option( Fail2WP_Admin_User_Monitor::LAST_SIGNATURE_OPTION );
            return;
        }
        $signature = hash( 'sha256', wp_json_encode( $changes ) );
        if ( hash_equals( (string) get_option( Fail2WP_Admin_User_Monitor::LAST_SIGNATURE_OPTION, '' ), $signature ) ) {
            return;
        }
        update_option( Fail2WP_Admin_User_Monitor::LAST_SIGNATURE_OPTION, $signature, false );
        $message = 'Administrator account baseline changed: ' . $this->fail2wp_admin_monitor_format_changes( $changes );
        $this->fail2wp_alert_send( $message );
    }

    /**
     * Reconcile immediately after a WordPress user or role change hook.
     *
     * @since 1.3.0
     */
    public function fail2wp_admin_monitor_event( $user_id = 0 ) {
        $this->fail2wp_admin_monitor_reconcile();
    }
    /**
     * Unused wp_loaded hook placeholder.
     *
     * @since 1.0.0
     */
    /*
    public function fail2wp_plugins_loaded() {
    }
    */
    /**
     * Unused main-request hook placeholder.
     *
     * @since 1.0.0
     */
    /*
    public function fail2wp_wp_main() {
    }
    */
    /**
     * Unused pre_get_posts hook placeholder.
     *
     * @since 1.0.0
     */
    /*
    public function fail2wp_pgp( \WP_Query $wpq ) {
    }
    */


    /**
     * Enforce feed and author-enumeration settings.
     *
     * @since 1.0.0
     */
    public function fail2wp_parse_request( \WP $wp ) {
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': XMLRPC_REQUEST = true' );
        }
        if ( $this->fail2wp_settings_remove_feeds && ! empty( $wp->query_vars['feed'] ) ) {
            $this->fail2wp_die_feed_disabled();
        }
        // Check for user enumeration
        if ( isset( $wp->query_vars['author'] ) ) {
            // Apply author-enumeration blocking.
            if ( $this->fail2wp_block_user_enum ) {
                // Remove the author query.
                unset( $wp->query_vars['author'] );
            }
            // Log author-enumeration requests.
            if ( $this->fail2wp_log_user_enum ) {
                $alert_message = $this->fail2wp_make_alert_message( '', '', FAIL2WP_ALERT_USER_ENUM );
                if ( ! empty( $alert_message ) ) {
                    $this->fail2wp_alert_send( $alert_message );
                    $this->fail2wp_record_ip_blocking_event();
                }
            }
        }
    }


    /**
     * Apply configured login error messages.
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
     * Legacy activation placeholder.
     *
     * @since 1.0.0
     */
    /*
    public function fail2wp_activate_plugin() {
    }
    */
    /**
     * Unused deactivation placeholder.
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
             * Missing optional translations are nonfatal.
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
     * Register plugin hooks and initialize storage.
     *
     * @since 1.0.0
     */
    public function run() {
        if ( defined( 'FAIL2WP_FLOW_DEBUG' ) && FAIL2WP_FLOW_DEBUG ) {
            error_log( basename(__FILE__) . ' ' . __FUNCTION__ . ': {entry}' );
        }
        Fail2WP_IP_Blocking_Storage::maybe_install();

        // Load translations on init.
        // https://developer.wordpress.org/reference/functions/load_plugin_textdomain/#user-contributed-notes
        add_action( 'init',  [$this, 'setup_locale'] );
        add_action( 'init',  [$this, 'fail2wp_ip_blocking_enforce'], 0 );

        if ( $this->fail2wp_admin_monitor_enable ) {
            add_action( 'fail2wp_admin_monitor_reconcile', [$this, 'fail2wp_admin_monitor_reconcile'] );
            add_action( 'user_register', [$this, 'fail2wp_admin_monitor_event'], 20, 1 );
            add_action( 'set_user_role', [$this, 'fail2wp_admin_monitor_event'], 20, 3 );
            add_action( 'add_user_role', [$this, 'fail2wp_admin_monitor_event'], 20, 2 );
            add_action( 'remove_user_role', [$this, 'fail2wp_admin_monitor_event'], 20, 2 );
            add_action( 'profile_update', [$this, 'fail2wp_admin_monitor_event'], 20, 2 );
            add_action( 'deleted_user', [$this, 'fail2wp_admin_monitor_event'], 20, 3 );
            if ( did_action( 'init' ) ) {
                $this->fail2wp_admin_monitor_initialize();
            } else {
                add_action( 'init', [$this, 'fail2wp_admin_monitor_initialize'], 1 );
            }
        }

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
        // Unused deactivation hook.
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

/**
 * Install the IP-blocking storage schema when the plugin is activated.
 *
 * @since 1.3.0
 */
function fail2wp_activate_plugin() {
    Fail2WP_IP_Blocking_Storage::maybe_install();
}

register_activation_hook( __FILE__, __NAMESPACE__ . '\\fail2wp_activate_plugin' );

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
