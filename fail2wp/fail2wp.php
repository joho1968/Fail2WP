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
 * Description:       Security plugin for WordPress with support for fail2ban
 * Version:           1.0.0
 * Author:            WebbPlatsen, Joaquim Homrighausen <joho@webbplatsen.se>
 * Author URI:        https://webbplatsen.se/
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       playground
 * Domain Path:       /languages
 *
 * fail2wp.php
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
namespace fail2wp;


// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}
if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

define( 'FAIL2WP_VERSION',                 '1.0.0'           );
define( 'FAIL2WP_REV',                     1                 );
define( 'FAIL2WP_PLUGINNAME_HUMAN',        'Fail2WP'         );
define( 'FAIL2WP_PLUGINNAME_SLUG',         'fail2wp'         );
define( 'FAIL2WP_DEFAULT_PREFIX',          'fail2wp'         );
define( 'FAIL2WP_ALERT_SUCCESS',           1                 );
define( 'FAIL2WP_ALERT_FAILURE',           2                 );
define( 'FAIL2WP_ALERT_USER_ENUM',         3                 );
define( 'FAIL2WP_DEFAULT_HTTP_PORT',       80                );
define( 'FAIL2WP_DEFAULT_HTTPS_PORT',      443               );


require_once plugin_dir_path( __FILE__ ) . 'includes/class-fail2wp-syslog.php';
// https://github.com/tholu/php-cidr-match
if ( ! class_exists( 'CIDRmatch', false ) ) {
    require_once plugin_dir_path( __FILE__ ) . 'externals/php-cidr-match-0.2/CIDRmatch/CIDRmatch.php';
}


class Fail2WP {
	public static $instance = null;
	protected $plugin_name;
	protected $version;
    protected $fail2wp_wp_roles = null;
    protected $fail2wp_wp_roles_enus = null;
    protected $fail2wp_settings_tab = '';
	protected $fail2wp_prefix;
    protected $fail2wp_roles_notify;
    protected $fail2wp_roles_warn;
    protected $fail2wp_unknown_warn;
	protected $fail2wp_settings_remove;
    protected $fail2wp_also_log_php;
    protected $fail2wp_block_user_enum;
    protected $fail2wp_block_username_login;
    protected $fail2wp_secure_login_message;
    protected $fail2wp_log_user_enum;
    protected $fail2wp_default_http_port;
    protected $fail2wp_default_https_port;
    protected $fail2wp_cloudflare_ipv4;
    protected $fail2wp_cloudflare_ipv6;

	public static function getInstance( string $version = '', string $slug = '' )
	{
		null === self::$instance AND self::$instance = new self( $version, $slug );
		return self::$instance;
	}
	/**
	 * Start me up ...
	 */
	public function __construct( string $version = '', string $slug = '' ) {
        if ( empty( $version ) ) {
            if ( defined( 'FAIL2WP_VERSION' ) ) {
                $this->version = FAIL2WP_VERSION;
            } else {
                $this->version = '0.0.1';
            }
        } else {
            $this->version = $version;
        }
        if ( empty( $slug ) ) {
    		$this->plugin_name = FAIL2WP_PLUGINNAME_SLUG;
        } else {
    		$this->plugin_name = $slug;
        }
        // Fetch options and setup defaults
        $this->fail2wp_site_label = $this->fail2wp_get_option( 'fail2wp-site-label', true );
        $this->fail2wp_roles_notify = $this->fail2wp_get_option( 'fail2wp-roles-notify', true );
        $this->fail2wp_roles_warn = $this->fail2wp_get_option( 'fail2wp-roles-warn', true );
        $this->fail2wp_unknown_warn = $this->fail2wp_get_option( 'fail2wp-unknown-warn', true );

        $this->fail2wp_also_log_php = $this->fail2wp_get_option( 'fail2wp-also-log-php', false );
        $this->fail2wp_block_user_enum = $this->fail2wp_get_option( 'fail2wp-block-user-enum', false );
        $this->fail2wp_block_username_login = $this->fail2wp_get_option( 'fail2wp-block-username-login', false );
        $this->fail2wp_log_user_enum = $this->fail2wp_get_option( 'fail2wp-log-user-enum', false );
        $this->fail2wp_secure_login_message = $this->fail2wp_get_option( 'fail2wp-secure-login-message', false );
        $this->fail2wp_cloudflare_check = $this->fail2wp_get_option( 'fail2wp-cloudflare-check', false );
        $this->fail2wp_cloudflare_ipv4 = @ json_decode( $this->fail2wp_get_option( 'fail2wp-cloudflare-ipv4', '' ), true, 2 );
        if ( ! is_array( $this->fail2wp_cloudflare_ipv4 ) ) {
            $this->fail2wp_cloudflare_ipv4 = array();
        }
        $this->fail2wp_cloudflare_ipv6 = @ json_decode( $this->fail2wp_get_option( 'fail2wp-cloudflare-ipv6', '' ), true, 2 );
        if ( ! is_array( $this->fail2wp_cloudflare_ipv6 ) ) {
            $this->fail2wp_cloudflare_ipv4 = array();
        }
        $this->fail2wp_settings_remove = $this->fail2wp_get_option( 'fail2wp-settings-remove', false );
        $this->fail2wp_default_http_port = FAIL2WP_DEFAULT_HTTP_PORT;
        $this->fail2wp_default_https_port = FAIL2WP_DEFAULT_HTTPS_PORT;

        $this->fail2wp_settings_tab = ( ! empty( $_GET['tab'] ) ? $_GET['tab'] : '' );
        if ( ! in_array( $this->fail2wp_settings_tab, ['logging', 'advanced', 'cloudflare', 'about'] ) ) {
            $this->fail2wp_settings_tab = '';
        }
	}

    /**
     * Fetch filemtime() of filen and return it.
     *
     * Fetch filemtime() of $filename and return it, upon error, $this->version
     * is returned instead. This could possibly simply return $this->version in
     * production.
     *
	 * @since  1.0.0
     * @param  string $filename The file for which we want filemtime()
     * @return string
     */
    protected function resource_mtime( $filename ) {
        $filetime = @ filemtime( $filename );
        if ( $filetime === false ) {
            $filetime = $this->version;
        }
        return ( $filetime );
    }

    /**
     * Fetch setting with default value.
     *
     * @since 1.0.0
     */
    protected function fail2wp_get_option( string $option_name, bool $auto_logic = false ) {
        switch( $option_name ) {
            case 'fail2wp-site-label':
                $option_val = get_option( 'fail2wp-site-label', '' );
                if ( empty( $option_val ) && $auto_logic ) {
                    $option_val = trim( get_bloginfo( 'name' ) );
                    if ( empty( $option_val ) ) {
                        $option_val = trim( $_SERVER['SERVER_NAME'] );
                        if ( empty( $option_val ) ) {
                            $option_val = 'IP:' . $_SERVER['SERVER_ADDR'];
                        }
                    }
                }
                if ( $auto_logic ) {
                    $default_val = '(' . __( 'Unknown', $this->plugin_name ) . ')';
                } else {
                    $default_val = '';
                }
                break;
            case 'fail2wp-roles-notify':
            case 'fail2wp-roles-warn':
                // Default is in JSON format
                $default_val = ( $auto_logic ? '["administrator"]' : '' );
                break;
            case 'fail2wp-unknown-warn':
                $default_val = ( $auto_logic ? '0' : '' );
                break;
            default:
                $default_val = '';
                break;
        } // switch
        if ( $option_name != 'fail2wp-site-label' ) {
            $option_val = get_option ( $option_name, $default_val );
        }
        if ( empty( $option_val ) ) {
            $option_val = $default_val;
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
                    $return_roles_en[$role_v] = __( 'Unknown role', $this->plugin_name ) . ' (' . $role_v . ')';
                }
                if ( ! empty( $role_names[$role_v] ) ) {
                    $return_roles[$role_v] = translate_user_role( $role_names[$role_v] );
                } else {
                    $return_roles[$role_v] = __( 'Unknown role', $this->plugin_name ) . ' (' . $role_v . ')';
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
     * @since  1.0.0
     */
    public function fail2wp_menu() {
		if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
			return;
		}
		add_options_page( FAIL2WP_PLUGINNAME_HUMAN,
						  FAIL2WP_PLUGINNAME_HUMAN,
					      'administrator',
					      FAIL2WP_PLUGINNAME_SLUG,
					      [ $this, 'fail2wp_admin_page' ]
						);
    }
    /**
     * Setup WordPress admin options page.
     *
	 * @since  1.0.0
     */
    public function fail2wp_admin_page() {
		if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
			return;
		}
        // Get ourselves a proper URL
        $action = admin_url( 'admin.php' ) . '?page=' . FAIL2WP_PLUGINNAME_SLUG;
        //
        $html = '<div class="wrap">';
            $html .= '<h1><span class="dashicons dashicons-shield" style="font-size:30px"></span>&nbsp;&nbsp;' . FAIL2WP_PLUGINNAME_HUMAN . '</h1>';
            $html .= '<p>' . esc_html__( 'Provides authentication related logging and security functions for WordPress, suitable for use with Fail2ban', $this->plugin_name ) . '</p>';
            $html .= '<nav class="nav-tab-wrapper">';
            $html .= '<a href="' . $action . '" class="nav-tab' . ( empty( $this->fail2wp_settings_tab ) ? ' nav-tab-active':'' ) . '">'.
                     esc_html__( 'Basic configuration', $this->plugin_name ) .
                     '</a>';
            $html .= '<a href="' . $action . '&tab=logging" class="nav-tab' . ( $this->fail2wp_settings_tab === 'logging' ? ' nav-tab-active':'' ) . '">'.
                     esc_html__( 'Logging', $this->plugin_name ) .
                     '</a>';
            $html .= '<a href="' . $action . '&tab=advanced" class="nav-tab' . ( $this->fail2wp_settings_tab === 'advanced' ? ' nav-tab-active':'' ) . '">'.
                     esc_html__( 'Advanced', $this->plugin_name ) .
                     '</a>';
            $html .= '<a href="' . $action . '&tab=cloudflare" class="nav-tab' . ( $this->fail2wp_settings_tab === 'cloudflare' ? ' nav-tab-active':'' ) . '">'.
                     esc_html__( 'Cloudflare', $this->plugin_name ) .
                     '</a>';
            $html .= '<a href="' . $action . '&tab=about" class="nav-tab' . ( $this->fail2wp_settings_tab === 'about' ? ' nav-tab-active':'' ) . '">'.
                     esc_html__( 'About', $this->plugin_name ) .
                     '</a>';
            $html .= '</nav>';
            ob_start();
            if ( ! function_exists( 'openlog' ) || ! function_exists( 'closelog' ) || ! function_exists( 'syslog' ) ) {
                $html .= '<div class="notice notice-error is-dismissible"><p><strong>'.
                         esc_html__( 'One or more of openlog(), closelog(), and/or syslog() seem to be missing on this system', $this->plugin_name ).
                         '</strong></p></div>';
            }
            if ( $this->fail2wp_settings_tab == 'about' ) {
                $this->fail2wp_about_page();
                $html .= ob_get_contents();
                ob_end_clean();
            } else {
                $html .= '<form method="post" action="options.php">';
                $html .= '<div class="tab-content">';
                $html .= '<div class="fail2wp-config-header">';
                switch( $this->fail2wp_settings_tab ) {
                    default:
                        settings_fields( 'fail2wp-settings' );
                        do_settings_sections( 'fail2wp-settings' );
                        break;
                    case 'logging':
                        settings_fields( 'fail2wp_settings_notify' );
                        do_settings_sections( 'fail2wp_settings_notify' );
                        break;
                    case 'advanced':
                        settings_fields( 'fail2wp_settings_advanced' );
                        do_settings_sections( 'fail2wp_settings_advanced' );
                        break;
                    case 'cloudflare':
                        settings_fields( 'fail2wp_settings_cloudflare' );
                        do_settings_sections( 'fail2wp_settings_cloudflare' );
                        break;
                }// switch
                submit_button();
                $html .= ob_get_contents();
                ob_end_clean();
                $html .= '</form>';
            }
            $html .= '</div>';
            $html .= '</div>'; // tab-content
        $html .= '</div>'; // wrap
        //
		echo $html;
    }
    /**
     * Display about/support.
     *
	 * @since  1.0.0
     */
    public function fail2wp_about_page() {
        echo '<div class="tab-content">';
        echo '<div class="fail2wp-config-header">'.
             '<p>'  . esc_html__( 'Thank you for installing', $this->plugin_name ) .' Fail2WP!' . ' '.
                      esc_html__( 'This plugin provides security functions and integration between WordPress and', $this->plugin_name ) . ' <a href="https://www.fail2ban.org" class="fail2wp-ext-link" target="_blank"> Fail2ban</a>.</p>'.
             '</div>';
        echo '<div class="fail2wp-config-section">'.
             '<p>'  . '<img class="fail2wp-wps-logo" alt="" src="' . plugin_dir_url( __FILE__ ) . 'img/webbplatsen_logo.png" />' .
                      esc_html__( 'Commercial support and customizations for this plugin is available from', $this->plugin_name ) .
                      ' <a class="fail2wp-ext-link" href="https://webbplatsen.se" target="_blank">WebbPlatsen i Sverige AB</a> '.
                      esc_html__('in Stockholm, Sweden. We speak Swedish and English', $this->plugin_name ) . ' :-)' .
                      '<br/><br/>' .
                      esc_html__( 'The plugin is written by Joaquim Homrighausen and sponsored by WebbPlatsen i Sverige AB.', $this->plugin_name ) . '</p>' .
             '<p>'  . esc_html__( 'If you find this plugin useful, the author is happy to receive a donation, good review, or just a kind word.', $this->plugin_name ) . '</p>' .
             '<p>'  . esc_html__( 'If there is something you feel to be missing from this plugin, or if you have found a problem with the code or a feature, please do not hesitate to reach out to', $this->plugin_name ) .
                                  ' <a class="fail2wp-ext-link" href="mailto:support@webbplatsen.se">support@webbplatsen.se</a>' . '</p>';
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
          add_settings_field( 'fail2wp-site-label', esc_html__( 'Site label', $this->plugin_name ), [$this, 'fail2wp_setting_site_label'], 'fail2wp-settings', 'fail2wp-settings', ['label_for' => 'fail2wp-site-label'] );
          add_settings_field( 'fail2wp-block-user-enum', esc_html__( 'Block user enum', $this->plugin_name ), [$this, 'fail2wp_setting_block_enums'], 'fail2wp-settings', 'fail2wp-settings', ['label_for' => 'fail2wp-block-user-enum'] );
          add_settings_field( 'fail2wp-block-username-login', esc_html__( 'Block username login', $this->plugin_name ), [$this, 'fail2wp_setting_block_username_login'], 'fail2wp-settings', 'fail2wp-settings', ['label_for' => 'fail2wp-block-username-login'] );
          add_settings_field( 'fail2wp-secure-login-message', esc_html__( 'Secure login messages', $this->plugin_name ), [$this, 'fail2wp_setting_secure_login_messages'], 'fail2wp-settings', 'fail2wp-settings', ['label_for' => 'fail2wp-secure-login-message'] );
        add_settings_section( 'fail2wp_section_other', esc_html__( 'Other settings', $this->plugin_name ), false, 'fail2wp-settings' );
          add_settings_field( 'fail2wp-settings-remove', esc_html__( 'Remove settings', $this->plugin_name ), [$this, 'fail2wp_setting_remove'], 'fail2wp-settings', 'fail2wp_section_other', ['label_for' => 'fail2wp-settings-remove'] );

        add_settings_section( 'fail2wp_settings_notify', '', false, 'fail2wp_settings_notify' );
          add_settings_field( 'fail2wp-roles-notify', esc_html__( 'Successful login', $this->plugin_name ), [$this, 'fail2wp_setting_roles_notify'], 'fail2wp_settings_notify', 'fail2wp_settings_notify', ['label_for' => 'fail2wp-roles-notify'] );
          add_settings_field( 'fail2wp-roles-warn', esc_html__( 'Unsuccessful login', $this->plugin_name ), [$this, 'fail2wp_setting_roles_warn'], 'fail2wp_settings_notify', 'fail2wp_settings_notify', ['label_for' => 'fail2wp-roles-warn'] );
          add_settings_field( 'fail2wp-unknown-warn', '', [$this, 'fail2wp_setting_unknown_notify'], 'fail2wp_settings_notify', 'fail2wp_settings_notify', ['label_for' => 'fail2wp-unknown-warn'] );
          add_settings_field( 'fail2wp-log-user-enum', 'Log user enum', [$this, 'fail2wp_setting_log_enums'], 'fail2wp_settings_notify', 'fail2wp_settings_notify', ['label_for' => 'fail2wp-log-user-enum'] );

        add_settings_section( 'fail2wp_settings_advanced', '', [$this, 'fail2wp_settings_advanced_callback'], 'fail2wp_settings_advanced' );
          add_settings_field( 'fail2wp-prefix', esc_html__( 'Logging prefix', $this->plugin_name ), [$this, 'fail2wp_settings_prefix'], 'fail2wp_settings_advanced', 'fail2wp_settings_advanced', ['label_for' => 'fail2wp-prefix'] );
          add_settings_field( 'fail2wp-also-log-php', esc_html__( 'Also log to PHP log', $this->plugin_name ), [$this, 'fail2wp_setting_also_log_php'], 'fail2wp_settings_advanced', 'fail2wp_settings_advanced', ['label_for' => 'fail2wp-also-log-php'] );

        add_settings_section( 'fail2wp_settings_cloudflare', '', [$this, 'fail2wp_settings_cloudflare_callback'], 'fail2wp_settings_cloudflare' );
          add_settings_field( 'fail2wp-cloudflare-check', esc_html__( 'Check for Cloudflare IP', $this->plugin_name ), [$this, 'fail2wp_setting_cloudflare_check'], 'fail2wp_settings_cloudflare', 'fail2wp_settings_cloudflare', ['label_for' => 'fail2wp-cloudflare-check'] );
          add_settings_field( 'fail2wp-cloudflare-ipv4', esc_html__( 'Cloudflare IPv4', $this->plugin_name ), [$this, 'fail2wp_settings_cloudflare_ipv4'], 'fail2wp_settings_cloudflare', 'fail2wp_settings_cloudflare', ['label_for' => 'fail2wp-cloudflare-ipv4'] );
          add_settings_field( 'fail2wp-cloudflare-ipv6', esc_html__( 'Cloudflare IPv6', $this->plugin_name ), [$this, 'fail2wp_settings_cloudflare_ipv6'], 'fail2wp_settings_cloudflare', 'fail2wp_settings_cloudflare', ['label_for' => 'fail2wp-cloudflare-ipv6'] );

        register_setting( 'fail2wp-settings', 'fail2wp-site-label', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_site_label']] );
        register_setting( 'fail2wp-settings', 'fail2wp-block-user-enum' );
        register_setting( 'fail2wp-settings', 'fail2wp-block-username-login' );
        register_setting( 'fail2wp-settings', 'fail2wp-block-username-login' );
        register_setting( 'fail2wp-settings', 'fail2wp-secure-login-message' );

        register_setting( 'fail2wp_settings_notify', 'fail2wp-roles-notify', ['type' => 'array', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_roles']] );
        register_setting( 'fail2wp_settings_notify', 'fail2wp-roles-warn', ['type' => 'array', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_roles']] );
        register_setting( 'fail2wp_settings_notify', 'fail2wp-unknown-warn' );
        register_setting( 'fail2wp_settings_notify', 'fail2wp-log-user-enum' );

        register_setting( 'fail2wp_settings_advanced', 'fail2wp-prefix', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_advanced']] );
        register_setting( 'fail2wp_settings_advanced', 'fail2wp-also-log-php' );

        register_setting( 'fail2wp_settings_cloudflare', 'fail2wp-cloudflare-check' );
        register_setting( 'fail2wp_settings_cloudflare', 'fail2wp-cloudflare-ipv4', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_cloudflare_ip']] );
        register_setting( 'fail2wp_settings_cloudflare', 'fail2wp-cloudflare-ipv6', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_cloudflare_ip']] );
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
        if ( function_exists( 'mb_substr' ) ) {
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
        return( json_encode( $return_val ) );
    }
    public function fail2wp_setting_sanitize_advanced( $input ) {
		if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
			return;
		}
        if ( function_exists( 'mb_substr' ) ) {
            return( mb_substr( sanitize_text_field( $input ), 0, 200 ) );
        }
        return( substr( sanitize_text_field( $input ), 0, 200 ) );
    }
    public function fail2wp_setting_sanitize_cloudflare_ip( $input ) {
		if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
			return;
		}
        $input = explode( "\n", sanitize_textarea_field( $input ) );
        $output = array();
        foreach( $input as $one_line ) {
            $output[] = trim( $one_line );
        }
        $input = json_encode( $output );
        return( $input );
    }
    /**
     * Output input fields.
     *
	 * @since  1.0.0
     */
    public function fail2wp_setting_site_label() {
        $option_val = $this->fail2wp_get_option( 'fail2wp-site-label', false );
        echo '<input type="text" size="60" maxlength="200" id="fail2wp-site-label" name="fail2wp-site-label" value="' . esc_attr( $option_val ). '" />';
        echo '<p class="description">' . esc_html__( 'The site name to use for logging, defaults to your site name if left empty', $this->plugin_name ) . '</p>';
    }
    public function fail2wp_setting_roles_notify($args) {
        $option_val = $this->fail2wp_get_option( 'fail2wp-roles-notify', false );
        $available_roles = $this->fail2wp_get_wp_roles();
        if ( ! empty( $option_val ) ) {
            $checkboxes = @ json_decode( $option_val, true, 2 );
            if ( ! is_array( $checkboxes ) ) {
                $checkboxes = array();
            }
        } else {
            $checkboxes = array();
        }
        foreach( $available_roles as $k => $v ) {
            echo '<div class="fail2wp-role-option">';
            echo '<label for="fail2wp-roles-notify[]">';
            echo '<input type="checkbox" name="fail2wp-roles-notify[]" id="fail2wp-roles-notify[]" value="' . esc_attr( $k ) . '" ' . ( in_array( $k, $checkboxes ) ? 'checked="checked" ':'' ) . '/>';
            echo esc_html__( $v ) . '</label> ';
            echo '</div>';
        }
    }
    public function fail2wp_setting_roles_warn() {
        $option_val = $this->fail2wp_get_option( 'fail2wp-roles-warn', false );
        $available_roles = $this->fail2wp_get_wp_roles();
        if ( ! empty( $option_val ) ) {
            $checkboxes = @ json_decode( $option_val, true, 2 );
            if ( ! is_array( $checkboxes ) ) {
                $checkboxes = array();
            }
        } else {
            $checkboxes = array();
        }
        foreach( $available_roles as $k => $v ) {
            echo '<div class="fail2wp-role-option">';
            echo '<label for="fail2wp-roles-warn[]">';
            echo '<input type="checkbox" name="fail2wp-roles-warn[]" id="fail2wp-roles-warn[]" value="' . esc_attr( $k ) . '" ' . ( in_array( $k, $checkboxes ) ? 'checked="checked" ':'' ) . '/>';
            echo esc_html__( $v ) . '</label> ';
            echo '</div>';
        }
    }
    public function fail2wp_setting_unknown_notify() {
        $option_val = $this->fail2wp_get_option( 'fail2wp-unknown-warn', false );
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-unknown-warn">';
        echo '<input type="checkbox" name="fail2wp-unknown-warn" id="fail2wp-unknown-warn" value="1" ' . ( checked( $option_val, 1, false ) ) . '/>';
        echo esc_html__( 'Unknown users', $this->plugin_name ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_log_enums() {
        $option_val = $this->fail2wp_get_option( 'fail2wp-log-user-enum', false );
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-log-user-enum">';
        echo '<input type="checkbox" name="fail2wp-log-user-enum" id="fail2wp-log-user-enum" value="1" ' . ( checked( $option_val, 1, false ) ) . '/>';
        echo esc_html__( 'User enumeration attempts (i.e. your.site/...?author=nnn)', $this->plugin_name ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_remove() {
        $option_val = $this->fail2wp_get_option( 'fail2wp-settings-remove', false );
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-settings-remove">';
        echo '<input type="checkbox" name="fail2wp-settings-remove" id="fail2wp-settings-remove" value="1" ' . ( checked( $option_val, 1, false ) ) . '/>';
        echo esc_html__( 'Remove all plugin settings and data when plugin is uninstalled', $this->plugin_name ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_block_enums() {
        $option_val = $this->fail2wp_get_option( 'fail2wp-block-user-enum', false );
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-block-user-enum">';
        echo '<input type="checkbox" name="fail2wp-block-user-enum" id="fail2wp-block-user-enum" value="1" ' . ( checked( $option_val, 1, false ) ) . '/>';
        echo esc_html__( 'Block user enumeration attempts (i.e. your.site/...?author=nnn)', $this->plugin_name ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_block_username_login() {
        $option_val = $this->fail2wp_get_option( 'fail2wp-block-username-login', false );
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-block-username-login">';
        echo '<input type="checkbox" name="fail2wp-block-username-login" id="fail2wp-block-username-login" value="1" ' . ( checked( $option_val, 1, false ) ) . '/>';
        echo esc_html__( 'Require users to login with their e-mail address', $this->plugin_name ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_secure_login_messages() {
        $option_val = $this->fail2wp_get_option( 'fail2wp-secure-login-message', false );
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-secure-login-message">';
        echo '<input type="checkbox" name="fail2wp-secure-login-message" id="fail2wp-secure-login-message" value="1" ' . ( checked( $option_val, 1, false ) ) . '/>';
        echo esc_html__( 'Change login failure messages to contain less detail', $this->plugin_name ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_settings_advanced_callback() {
		if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
			return;
		}
        echo '<p>'.
             esc_html__( 'Please make sure you understand how these settings can impact the operation of the plugin before making changes to them.', $this->plugin_name ).
             '</p>';
    }
    public function fail2wp_settings_cloudflare_callback() {
		if ( ! is_admin( ) || ! is_user_logged_in() || ! current_user_can( 'administrator' ) )  {
			return;
		}
        echo '<p>'.
             esc_html__( 'These settings allows the plugin to better interact with Cloudflare.', $this->plugin_name ).
             ' ' .
             esc_html__( 'If your site is not published via Cloudflare, you can safely ignore these settings.', $this->plugin_name ).
             '<br/><br/>' .
             esc_html__( 'For an updated list of Cloudflare IPs, please use this link', $this->plugin_name ) .
             ': '.
             '<a href="https://www.cloudflare.com/ips/" target="_blank">'.
             'www.cloudflare.com/ips' .
             '</a>'.
             '</p>';
    }
    public function fail2wp_settings_prefix() {
        $option_val = $this->fail2wp_get_option( 'fail2wp-prefix', false );
        echo '<input type="text" size="60" maxlength="200" id="fail2wp-prefix" name="fail2wp-prefix" value="' . esc_attr( $option_val ). '" />';
        echo '<p class="description">' . esc_html__( 'The logging prefix, this should normally be left empty', $this->plugin_name ) . '</p>';
    }
    public function fail2wp_setting_also_log_php() {
        $option_val = $this->fail2wp_get_option( 'fail2wp-also-log-php', false );
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-also-log-php">';
        echo '<input type="checkbox" name="fail2wp-also-log-php" id="fail2wp-also-log-php" value="1" ' . ( checked( $option_val, 1, false ) ) . '/>';
        echo esc_html__( 'Log the same information to PHP log using error_log()', $this->plugin_name ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_setting_cloudflare_check() {
        $option_val = $this->fail2wp_get_option( 'fail2wp-cloudflare-check', false );
        echo '<div class="fail2wp-role-option">';
        echo '<label for="fail2wp-cloudflare-check">';
        echo '<input type="checkbox" name="fail2wp-cloudflare-check" id="fail2wp-cloudflare-check" value="1" ' . ( checked( $option_val, 1, false ) ) . '/>';
        echo esc_html__( 'Attempt to unmask real IP when Cloudflare IP is detected', $this->plugin_name ) . '</label> ';
        echo '</div>';
    }
    public function fail2wp_settings_cloudflare_ipv4() {
        $option_val = $this->fail2wp_get_option( 'fail2wp-cloudflare-ipv4', false );
        $ip_list = @ json_decode( $option_val, true, 2 );
        if ( ! is_array( $ip_list ) ) {
            $ip_list = array();
        }
        echo '<textarea rows="10" cols="30" id="fail2wp-cloudflare-ipv4" name="fail2wp-cloudflare-ipv4" class="large-text code">';
        echo implode( "\n", $ip_list );
        echo '</textarea>';
        echo '<p class="description">' . esc_html__( 'IPs matching these addresses will be considerd to be coming from Cloudflare', $this->plugin_name ) . '</p>';
    }
    public function fail2wp_settings_cloudflare_ipv6() {
        $option_val = $this->fail2wp_get_option( 'fail2wp-cloudflare-ipv6', false );
        $ip_list = @ json_decode( $option_val, true, 2 );
        if ( ! is_array( $ip_list ) ) {
            $ip_list = array();
        }
        echo '<textarea rows="10" cols="30" id="fail2wp-cloudflare-ipv6" name="fail2wp-cloudflare-ipv6" class="large-text code">';
        echo implode( "\n", $ip_list );
        echo '</textarea>';
        echo '<p class="description">' . esc_html__( 'IPs matching these addresses will be considerd to be coming from Cloudflare', $this->plugin_name ) . '</p>';
    }

    /**
     * Send alert to syslog
     *
     * @since  1.0.0
     * @param  string $alert_message The error message.
     */
    protected function fail2wp_alert_send( string $alert_message ) {
        // Logging prefix (i.e. "this is us")
        $prefix = $this->fail2wp_get_option( 'fail2wp-prefix', false );
        if ( empty( $prefix ) ) {
            $prefix = FAIL2WP_DEFAULT_PREFIX;
        }
        // Site label
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
            error_log( 'Unable to initialize syslog interface' );
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
     * Build context based alert message.
     *
     * @since 1.0.0
     * @param string $username Username as entered when logging in.
     * @param mixed $context Either WP_User or WP_Error.
     * @param int $alert_type Type of notification.
     * @return mixed String with alert message or false on error.
     */
    protected function fail2wp_make_alert_message( string $username, $context, int $alert_type ) {
        $alert_message = '';
        // Fetch remote IP if set
        $remote_ip = $_SERVER['REMOTE_ADDR'];
        if ( $this->fail2wp_cloudflare_check ) {
            // Setup CIDRmatch
            $cidrm = new \CIDRmatch\CIDRmatch();
            // Possibly check for Cloudflare
            $is_cloudflare = false;
            if ( ! empty( $this->fail2wp_cloudflare_ipv4 ) && is_array( $this->fail2wp_cloudflare_ipv4 ) ) {
                foreach( $this->fail2wp_cloudflare_ipv4 as $cf ) {
                    if ( ! empty( $cf ) && $cidrm->match( $remote_ip, $cf ) ) {
                        $is_cloudflare = true;
                        break;
                    }
                }
            }
            if ( ! $is_cloudflare && ! empty( $this->fail2wp_cloudflare_ipv6 ) && is_array( $this->fail2wp_cloudflare_ipv6 ) ) {
                foreach( $this->fail2wp_cloudflare_ipv6 as $cf ) {
                    if ( ! empty( $cf ) && $cidrm->match( $remote_ip, $cf ) ) {
                        $is_cloudflare = true;
                        break;
                    }
                }
            }
            if ( $is_cloudflare && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
                // error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): Cloudflare IP=' . $remote_ip . ', actual IP=' . $_SERVER['HTTP_CF_CONNECTING_IP'] );
                $remote_ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
            }
        }
        if ( ! empty( $remote_ip ) ) {
            $remote_ip = ' from' . ' ' . $remote_ip;
        } else {
            $remote_ip = ' from' . ' ' . '?.?.?.?';
        }
        // Fetch local (our) port if set
        if ( ! empty( $_SERVER['SERVER_PORT'] ) ) {
            $our_port = $_SERVER['SERVER_PORT'];
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
        } // switch
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
    protected function fail2wp_role_is_active( array $roles, string $notify_roles ) : bool {
        $notify_array = @ json_decode( $notify_roles, true, 2 );
        if ( ! is_array( $notify_array ) || empty( $notify_array ) ) {
            return( false );
        }
        // Lookup our selected notification roles. We could walk the other way
        // too, but we're likely to have less configured roles/caps than what
        // is available. So maybe this will save an iteration or two :-)
        foreach( $notify_array as $role ) {
            if ( in_array( $role, $roles ) && $roles[$role] ) {
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
            if ( in_array( $role, $roles ) && $roles[$role] ) {
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
     * Handle authentication settings.
     *
     * @since 1.0.0
     */
    public function fail2wp_auth_check( $user, string $username, string $password ) {
        if ( empty( $username ) || empty( $password ) ) {
            return( $user );
        }
        $wp_error = $user;
        if ( function_exists( 'mb_substr_count' ) && function_exists( 'mb_strpos' ) ) {
            if ( mb_substr_count( $username, '@' ) !== 1 || mb_strpos( $username, '@' ) === 0) {
                $wp_error = new \WP_Error( 'invalid_username', __('Please specify your e-mail address to login', $this->plugin_name) );
            }
        } else {
            if ( substr_count( $username, '@' ) !== 1 || strpos( $username, '@' ) === 0) {
                $wp_error = new \WP_Error( 'invalid_username', __('Please specify your e-mail address to login', $this->plugin_name) );
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
                    $text_out = __( 'E-mail address', $this->plugin_name );
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
        add_filter( 'gettext', [$this, 'fail2wp_gettext'], 10, 3 );
    }

    /**
     * Add hooks we're watching when WordPress is fully loaded.
     *
     * @since 1.0.0
     */
    public function fail2wp_wp_loaded() {
        add_action( 'wp_login',           [$this, 'fail2wp_alert_login'],         10, 2 );
        add_action( 'wp_login_failed',    [$this, 'fail2wp_alert_failed_login'],  10, 2 );
        add_filter( 'login_errors',       [$this, 'fail2wp_login_errors'],        10, 1 );
        //add_filter( 'lostpassword_post',  [$this, 'fail2wp_lostpassword_errors'], 10, 2 );

        if ( $this->fail2wp_block_username_login ) {
            add_filter( 'authenticate',   [$this, 'fail2wp_auth_check'], 99999, 3 );
            add_action( 'login_head',     [$this, 'fail2wp_login_text'] );
        }
    }

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
     * Pre-get posts hook, not needed at the moment
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
                            $error = esc_html__( 'Invalid login credentials, please try again.', $this->plugin_name );
                        }
                        $wp_error = new \WP_Error( $e_c[0], $error );
                        if ( ! empty( $this->fail2wp_unknown_warn ) ) {
                            // We're configured to notify about unknown users
                            if ( ! empty( $_REQUEST['user_login'] ) ) {
                                $username = sanitize_user( $_REQUEST['user_login'], false );
                                if ( function_exists( 'mb_ereg_replace' ) ) {
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
                        $error = esc_html__( 'Invalid login credentials, please try again.', $this->plugin_name );
                        // Possibly include link to password recovery if we're not already there
                        $lost_password_url = wp_lostpassword_url();
                        if ( ! empty( $lost_password_url ) ) {
                            $error .= '<br/><a href=" ' . esc_url( $lost_password_url ) . '">' . esc_html__( 'Lost password', $this->plugin_name ) . '</a>';
                        }
                    }
                    break;
            }// switch
        }
        return( $error );
    }

    /**
     * Lost password errors
     *
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
		if ( ! load_plugin_textdomain( $this->plugin_name,
                                       false,
                                       dirname( plugin_basename( __FILE__ ) ) . '/languages' ) ) {
            error_log( 'Unable to load language file (' . dirname( plugin_basename( __FILE__ ) ) . '/languages' . ')' );
        }
    }

    /**
     * Setup CSS (admin)
     *
	 * @since 1.0.0
     */
    public function fail2wp_setup_css() {
		wp_enqueue_style( $this->plugin_name, plugin_dir_url( __FILE__ ) . 'css/fail2wp.css', array(), $this->resource_mtime( dirname(__FILE__).'/css/fail2wp.css' ), 'all' );
    }

    /**
     * Run plugin.
     *
     * Basically "enqueues" WordPress actions and lets WordPress do its thing.
     *
     * @since 1.0.0
     */
    public function run() {
        // Plugin activation, not needed for this plugin atm :-)
        // register_activation_hook( __FILE__, [$this, 'fail2wp_activate_plugin'] );

        // Setup i18n. We use the 'init' action rather than 'plugins_loaded' as per
        // https://developer.wordpress.org/reference/functions/load_plugin_textdomain/#user-contributed-notes
		add_action( 'init',                  [$this, 'setup_locale']    );
        // Setup CSS
        if ( is_admin() ) {
    		add_action( 'admin_enqueue_scripts', [$this, 'fail2wp_setup_css']  );
        }
        // Setup
        add_action( 'admin_menu',          [$this, 'fail2wp_menu']                 );
		add_action( 'admin_init',          [$this, 'fail2wp_settings']             );
        add_action( 'wp_loaded',           [$this, 'fail2wp_wp_loaded']            );
        add_action( 'parse_request',       [$this, 'fail2wp_parse_request']        );
        // add_action( 'wp',                  [$this, 'fail2wp_wp_main']              );
        // add_action( 'pre_get_posts',       [$this, 'fail2wp_pgp']                  );

        // Plugin deactivation
        // register_deactivation_hook( __FILE__, [$this, 'fail2wp_deactivate_plugin'] );
    }

}// Fail2WP


/**
 * Run plugin
 *
 * @since 1.0.0
 */
function run_fail2wp() {
	$plugin = Fail2WP::getInstance( FAIL2WP_VERSION, FAIL2WP_PLUGINNAME_SLUG );
	$plugin->run();
}

run_fail2wp();
