<?php
/**
 * Exercise the workspace plugin against an installed WordPress core.
 * Run with WP-CLI: --skip-plugins --skip-themes eval-file <this file>
 * Changes use request-local option filters; no user or content is created.
 */
if ( PHP_SAPI !== 'cli' || ! defined( 'WP_CLI' ) || ! WP_CLI ) { exit; }
global $fail2wp_test_plugin, $fail2wp_test_count;
if ( class_exists( '\\fail2wp\\Fail2WP', false ) ) {
    WP_CLI::error( 'Run this check with --skip-plugins.' );
}
$fail2wp_test_options = [
    'fail2wp-reguser-force' => false,
    'fail2wp-admin-monitor-enable' => false,
    'fail2wp-ip-blocking-enable' => false,
    'fail2wp-loginip-enable' => true,
    'fail2wp-loginip-testmode' => false,
    'fail2wp-loginip-inform-fail2ban' => false,
    'fail2wp-loginip-allow' => '["192.0.2.42"]',
    'fail2wp-loginip-deny' => '[]',
    'fail2wp-log-user-enum' => false,
    'fail2wp-block-user-enum' => true,
    'fail2wp-rest-filter-log-blocked' => false,
    'fail2wp-rest-filter-block-all' => false,
    'fail2wp-rest-filter-block-index' => false,
    'fail2wp-rest-filter-block-ns' => '[]',
    'fail2wp-rest-filter-block-routes' => '["posts"]',
    'fail2wp-rest-filter-require-authenticated' => false,
    'fail2wp-rest-filter-ipv4-bypass' => '[]',
    'fail2wp-rest-filter-ipv6-bypass' => '[]',
    'fail2wp-cloudflare-check' => false,
    'fail2wp-settings-remove-feeds' => false,
];
// pre_option may return false only as "not handled", so force false values
// through option/default_option too, without changing stored configuration.
foreach ( $fail2wp_test_options as $fail2wp_test_name => $fail2wp_test_value ) {
    foreach ( [ 'pre_option_', 'option_', 'default_option_' ] as $fail2wp_test_prefix ) {
        add_filter( $fail2wp_test_prefix . $fail2wp_test_name, static function () use ( $fail2wp_test_value ) { return $fail2wp_test_value; } );
    }
}
require dirname( __DIR__ ) . '/fail2wp.php';
$fail2wp_test_plugin = \fail2wp\Fail2WP::getInstance();
$fail2wp_test_plugin->fail2wp_wp_loaded();
$fail2wp_test_count = 0;
function fail2wp_integration_check( $condition, $label ) {
    global $fail2wp_test_count;
    if ( ! $condition ) { WP_CLI::error( $label ); }
    $fail2wp_test_count++;
}
function fail2wp_integration_setting( $name, $value ) {
    global $fail2wp_test_plugin;
    $property = new ReflectionProperty( $fail2wp_test_plugin, $name );
    $property->setAccessible( true );
    $property->setValue( $fail2wp_test_plugin, $value );
}
$_SERVER['REMOTE_ADDR'] = '203.0.113.10';
$_SERVER['HTTP_X_REAL_IP'] = '192.0.2.42';
$_SERVER['SERVER_PORT'] = '7000';
wp_set_current_user( 0 );
fail2wp_integration_check( $fail2wp_test_plugin->fail2wp_get_client_ip() === '203.0.113.10', 'Spoofed X-Real-IP accepted' );
fail2wp_integration_check( has_action( 'login_init', [ $fail2wp_test_plugin, 'fail2wp_login_ip_check' ] ) !== false, 'Login gate registered too late' );
$fail2wp_test_die_filter = static function () {
    return static function ( $message, $title, $args ) { throw new RuntimeException( 'blocked:' . $args['response'] ); };
};
add_filter( 'wp_die_handler', $fail2wp_test_die_filter );
try { do_action( 'login_init' ); $fail2wp_test_blocked = false; }
catch ( RuntimeException $e ) { $fail2wp_test_blocked = $e->getMessage() === 'blocked:503'; }
remove_filter( 'wp_die_handler', $fail2wp_test_die_filter );
fail2wp_integration_check( $fail2wp_test_blocked, 'Login gate accepts spoofed allowlist address' );

$fail2wp_test_server = rest_get_server();
foreach ( [ '/wp/v2/posts', '/wp/v2/posts/', '/wp/v2/posts/1', '/wp/v2/users', '/wp/v2/users/', '/WP/v2/USERS' ] as $fail2wp_test_route ) {
    $fail2wp_test_response = rest_do_request( new WP_REST_Request( 'GET', $fail2wp_test_route ) );
    fail2wp_integration_check( $fail2wp_test_response->get_status() === 404, 'Unblocked public route: ' . $fail2wp_test_route );
}
$fail2wp_test_response = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2' ) );
fail2wp_integration_check( $fail2wp_test_response->get_status() === 200, 'Namespace falsely blocked with index rule disabled' );
fail2wp_integration_setting( 'fail2wp_rest_filter_block_ns', [ 'wp/v2' ] );
$fail2wp_test_response = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/types' ) );
fail2wp_integration_check( $fail2wp_test_response->get_status() === 404, 'Namespace children remain accessible' );
fail2wp_integration_setting( 'fail2wp_rest_filter_block_ns', [] );
fail2wp_integration_setting( 'fail2wp_rest_filter_block_all', true );
fail2wp_integration_setting( 'fail2wp_rest_filter_block_index', true );
add_filter( 'rest_index', [ $fail2wp_test_plugin, 'fail2wp_rest_index' ] );

// Use existing users in memory; do not create accounts or touch their roles.
foreach ( [ 'administrator', 'editor' ] as $fail2wp_test_role ) {
    $fail2wp_test_user = new WP_User();
    $fail2wp_test_user->ID = 987654;
    $fail2wp_test_user->caps = [ $fail2wp_test_role => true ];
    $fail2wp_test_user->get_role_caps();
    $GLOBALS['current_user'] = $fail2wp_test_user;
    foreach ( [ '/', '/wp/v2/posts', '/wp/v2/media', '/wp/v2/types' ] as $fail2wp_test_route ) {
        $fail2wp_test_response = rest_do_request( new WP_REST_Request( 'GET', $fail2wp_test_route ) );
        fail2wp_integration_check( $fail2wp_test_response->get_status() === 200, $fail2wp_test_role . ' REST workflow blocked: ' . $fail2wp_test_route );
        if ( $fail2wp_test_route === '/' ) {
            fail2wp_integration_check( ! empty( $fail2wp_test_response->get_data()['routes'] ), 'Authenticated REST discovery stripped' );
        }
    }
}
wp_set_current_user( 0 );

// Exercise the actual settings-page import path with a valid administrator
// nonce. Rejected entries must neither render HTML nor change cache options.
$fail2wp_test_user = new WP_User();
$fail2wp_test_user->ID = 987654;
$fail2wp_test_user->caps = [ 'administrator' => true ];
$fail2wp_test_user->get_role_caps();
$GLOBALS['current_user'] = $fail2wp_test_user;
set_current_screen( 'settings_page_fail2wp' );
$fail2wp_test_plugin->fail2wp_settings();
fail2wp_integration_setting( 'fail2wp_settings_tab', 'importexport' );
$fail2wp_test_payload = [
    'fail2wp_plugin_version' => FAIL2WP_VERSION,
    '<img src=x onerror=alert(1)>' => 'ignored',
    'fail2wp_hostname_cache' => [ 'poisoned' ],
    'fail2wp_loginip_allow' => [ [ 'nested' ] ],
];
$_POST = [
    'fail2wpimport' => '1', 'fail2wp_nonce' => wp_create_nonce( 'importexport' ),
    'fail2wp-import-settings' => FAIL2WP_EXPORT_HEADER . base64_encode( wp_json_encode( $fail2wp_test_payload ) ) . FAIL2WP_EXPORT_FOOTER,
];
$fail2wp_test_cache_before = get_option( 'fail2wp-hostname-cache' );
ob_start();
$fail2wp_test_plugin->fail2wp_admin_page();
$fail2wp_test_html = ob_get_clean();
fail2wp_integration_check( strpos( $fail2wp_test_html, '<img src=x' ) === false && strpos( $fail2wp_test_html, '&lt;img' ) !== false, 'Import names allow unescaped HTML' );
fail2wp_integration_check( get_option( 'fail2wp-hostname-cache' ) === $fail2wp_test_cache_before, 'Import writes runtime hostname cache' );
fail2wp_integration_check( get_option( 'fail2wp-loginip-allow' ) === '["192.0.2.42"]', 'Malformed import changes allowlist' );
$_POST = [];
require __DIR__ . '/settings-wordpress-checks.php';
require __DIR__ . '/storage-wordpress-checks.php';
require __DIR__ . '/release-wordpress-checks.php';
WP_CLI::success( 'WordPress ' . get_bloginfo( 'version' ) . ' / PHP ' . PHP_VERSION . ': ' . $fail2wp_test_count . ' integration checks passed.' );
