<?php
/**
 * Fail2WP settings registration.
 *
 * @since      1.3.0
 * @package    Fail2WP
 * @subpackage fail2wp/includes
 * @author     Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * fail2wp_misc.inc.php
 * Copyright (C) 2021-2026 Joaquim Homrighausen; all rights reserved.
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

if ( ! defined( 'WPINC' ) ) {
    die;
}
if ( ! defined( 'ABSPATH' ) ) {
    die( '-1' );
}

trait Fail2WP_Settings {
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
        add_settings_section( 'fail2wp_section_ipblocking',
                              '',
                              [$this, 'fail2wp_settings_ip_blocking_callback'],
                              'fail2wp_settings_ipblocking' );
          add_settings_field( 'fail2wp-ip-blocking-enable',
                              esc_html__( 'Enable IP blocking', 'fail2wp' ),
                              [$this, 'fail2wp_setting_ip_blocking_enable'],
                              'fail2wp_settings_ipblocking',
                              'fail2wp_section_ipblocking',
                              ['label_for' => 'fail2wp-ip-blocking-enable'] );
          add_settings_field( 'fail2wp-ip-blocking-threshold',
                              esc_html__( 'Ban threshold', 'fail2wp' ),
                              [$this, 'fail2wp_setting_ip_blocking_threshold'],
                              'fail2wp_settings_ipblocking',
                              'fail2wp_section_ipblocking',
                              ['label_for' => 'fail2wp-ip-blocking-threshold'] );
          add_settings_field( 'fail2wp-ip-blocking-window',
                              esc_html__( 'Observation window', 'fail2wp' ),
                              [$this, 'fail2wp_setting_ip_blocking_window'],
                              'fail2wp_settings_ipblocking',
                              'fail2wp_section_ipblocking',
                              ['label_for' => 'fail2wp-ip-blocking-window'] );
          add_settings_field( 'fail2wp-ip-blocking-duration',
                              esc_html__( 'Ban duration', 'fail2wp' ),
                              [$this, 'fail2wp_setting_ip_blocking_duration'],
                              'fail2wp_settings_ipblocking',
                              'fail2wp_section_ipblocking',
                              ['label_for' => 'fail2wp-ip-blocking-duration'] );
          add_settings_field( 'fail2wp-ip-blocking-bypass',
                              esc_html__( 'Bypass addresses and ranges', 'fail2wp' ),
                              [$this, 'fail2wp_setting_ip_blocking_bypass'],
                              'fail2wp_settings_ipblocking',
                              'fail2wp_section_ipblocking',
                              ['label_for' => 'fail2wp-ip-blocking-bypass'] );
        add_settings_section( 'fail2wp_section_newuser', '', false, 'fail2wp_settings_newuser' );
          add_settings_field( 'fail2wp-reguser-warn', esc_html__( 'Membership warnings', 'fail2wp' ), [$this, 'fail2wp_setting_reguser_warn'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-warn'] );
          add_settings_field( 'fail2wp-reguser-warn-role', esc_html__( 'Check for role', 'fail2wp' ), [$this, 'fail2wp_setting_reguser_warn_role'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-warn-role'] );
          add_settings_field( 'fail2wp-reguser-force', esc_html__( 'Force role', 'fail2wp' ), [$this, 'fail2wp_setting_reguser_force'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-force'] );
          add_settings_field( 'fail2wp-reguser-force-role', esc_html__( 'Role to force', 'fail2wp' ), [$this, 'fail2wp_setting_reguser_force_role'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-force-role'] );
          add_settings_field( 'fail2wp-reguser-username-length', esc_html__( 'Minimum username length', 'fail2wp' ), [$this, 'fail2wp_settings_reguser_username_length'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-username-length'] );
          add_settings_field( 'fail2wp-reguser-username-ban', esc_html__( 'Banned usernames', 'fail2wp' ), [$this, 'fail2wp_settings_reguser_username_ban'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-username-ban'] );
          add_settings_field( 'fail2wp-reguser-useremail-require', esc_html__( 'E-mail must match', 'fail2wp' ), [$this, 'fail2wp_settings_reguser_useremail_require'], 'fail2wp_settings_newuser', 'fail2wp_section_newuser', ['label_for' => 'fail2wp-reguser-useremail-require'] );

        add_settings_section( 'fail2wp_section_adminmonitor', '', [$this, 'fail2wp_settings_admin_monitor_callback'], 'fail2wp_settings_adminmonitor' );
          add_settings_field( 'fail2wp-admin-monitor-enable', esc_html__( 'Enable administrator monitor', 'fail2wp' ), [$this, 'fail2wp_setting_admin_monitor_enable'], 'fail2wp_settings_adminmonitor', 'fail2wp_section_adminmonitor', ['label_for' => 'fail2wp-admin-monitor-enable'] );
          add_settings_field( 'fail2wp-admin-monitor-baseline', esc_html__( 'Administrator baseline', 'fail2wp' ), [$this, 'fail2wp_setting_admin_monitor_baseline'], 'fail2wp_settings_adminmonitor', 'fail2wp_section_adminmonitor', ['label_for' => 'fail2wp-admin-monitor-baseline'] );

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
          add_settings_field( 'fail2wp-cloudflare-refresh', esc_html__( 'Refresh Cloudflare IPs', 'fail2wp' ), [$this, 'fail2wp_settings_cloudflare_refresh'], 'fail2wp_settings_cloudflare', 'fail2wp_settings_cloudflare', ['label_for' => 'fail2wp-cloudflare-refresh'] );

        register_setting( 'fail2wp-settings', 'fail2wp-site-label', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_site_label']] );
        register_setting( 'fail2wp-settings', 'fail2wp-block-user-enum' );
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

        register_setting( 'fail2wp_settings_ipblocking', 'fail2wp-ip-blocking-enable' );
        register_setting( 'fail2wp_settings_ipblocking', 'fail2wp-ip-blocking-threshold', ['type' => 'number', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_ip_blocking_threshold']] );
        register_setting( 'fail2wp_settings_ipblocking', 'fail2wp-ip-blocking-window', ['type' => 'number', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_ip_blocking_seconds']] );
        register_setting( 'fail2wp_settings_ipblocking', 'fail2wp-ip-blocking-duration', ['type' => 'number', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_ip_blocking_seconds']] );
        register_setting( 'fail2wp_settings_ipblocking', 'fail2wp-ip-blocking-bypass', ['type' => 'string', 'sanitize_callback' => [$this, 'fail2wp_setting_sanitize_ip_blocking_bypass']] );

        register_setting( 'fail2wp_settings_adminmonitor', 'fail2wp-admin-monitor-enable' );

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


}
