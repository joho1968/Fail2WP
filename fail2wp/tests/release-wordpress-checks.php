<?php
/**
 * Import, feed, XML-RPC, and settings markup checks.
 */
if ( PHP_SAPI !== 'cli' || ! defined( 'WP_CLI' ) || ! WP_CLI ) { exit; }

function fail2wp_release_wordpress_checks() {
    global $fail2wp_test_plugin;

    fail2wp_integration_setting( 'fail2wp_settings_tab', 'importexport' );
    $render = static function ( $input, $nonce = null ) use ( $fail2wp_test_plugin ) {
        $_POST = [
            'fail2wpimport' => '1',
            'fail2wp_nonce' => $nonce === null ? wp_create_nonce( 'importexport' ) : $nonce,
            'fail2wp-import-settings' => $input,
        ];
        $before = $_POST;
        ob_start();
        $fail2wp_test_plugin->fail2wp_admin_page();
        $html = ob_get_clean();
        fail2wp_integration_check( $_POST === $before, 'Import mutates POST input' );
        $_POST = [];
        return $html;
    };
    $encode = static function ( $payload ) {
        return FAIL2WP_EXPORT_HEADER . base64_encode( wp_json_encode( $payload ) ) . FAIL2WP_EXPORT_FOOTER;
    };
    $valid = $encode( [ 'fail2wp_plugin_version' => FAIL2WP_VERSION ] );
    foreach ( [
        [], [ $valid ], 123, '',
        'wrong.' . $valid, $valid . '.wrong',
        FAIL2WP_EXPORT_HEADER . '%%%' . substr( $valid, strlen( FAIL2WP_EXPORT_HEADER ) ),
        FAIL2WP_EXPORT_HEADER . base64_encode( '{broken' ) . FAIL2WP_EXPORT_FOOTER,
        $encode( [ 'fail2wp_plugin_version' => [ FAIL2WP_VERSION ] ] ),
    ] as $input ) {
        $html = $render( $input );
        fail2wp_integration_check( strpos( $html, 'notice-error' ) !== false, 'Malformed import has no error' );
        fail2wp_integration_check( strpos( $html, 'Settings were successfully imported' ) === false, 'Malformed import accepted' );
    }
    $html = $render( wp_slash( '  ' . $valid . '  ' ) );
    fail2wp_integration_check( strpos( $html, 'Settings were successfully imported' ) !== false, 'Valid import rejected' );
    $html = $render( $valid, [ 'invalid' ] );
    fail2wp_integration_check( strpos( $html, 'Settings were successfully imported' ) === false, 'Array nonce accepted' );

    $_POST = [];
    ob_start();
    $fail2wp_test_plugin->fail2wp_admin_page();
    $html = ob_get_clean();
    fail2wp_integration_check( substr_count( $html, 'name="fail2wp_nonce"' ) === 1, 'Import nonce duplicated' );
    fail2wp_integration_check( strpos( $html, 'name="fail2wp-import-settings"' ) !== false, 'Import field stripped' );
    fail2wp_integration_check( strpos( $html, 'name="fail2wp-export-settings"' ) !== false, 'Export field stripped' );
    $dom = new DOMDocument();
    @$dom->loadHTML( $html );
    $xpath = new DOMXPath( $dom );
    $tabs = $xpath->query( '//nav/a' );
    fail2wp_integration_check( $tabs->length === 12, 'Settings tab links missing' );
    foreach ( $tabs as $tab ) {
        fail2wp_integration_check( strpos( $tab->getAttribute( 'href' ), chr( 92 ) ) === false, 'Tab link contains a stray escape' );
        fail2wp_integration_check( strpos( $tab->getAttribute( 'class' ), 'nav-tab' ) === 0, 'Tab link markup corrupted' );
    }
    foreach ( [ 'adminmonitor', 'cloudflare', 'ipblocking' ] as $tab ) {
        fail2wp_integration_setting( 'fail2wp_settings_tab', $tab );
        ob_start();
        $fail2wp_test_plugin->fail2wp_admin_page();
        $html = ob_get_clean();
        $nonce_name = [ 'adminmonitor' => 'fail2wp_admin_monitor_nonce', 'cloudflare' => 'fail2wp_cloudflare_refresh_nonce', 'ipblocking' => 'fail2wp_ip_blocking_nonce' ][$tab];
        fail2wp_integration_check( substr_count( $html, 'name="' . $nonce_name . '"' ) === 1, 'Action nonce missing/duplicated: ' . $tab );
    }

    $home_filter = static function () { return 'https://example.test/?x=<svg onload=alert(1)>&y="quoted"'; };
    $translation_filter = static function ( $translated, $text, $domain ) {
        if ( $domain === 'fail2wp' && in_array( $text, [ 'This feed has been disabled, please visit', 'Feed disabled' ], true ) ) {
            return '<script>' . $text . '</script>';
        }
        return $translated;
    };
    $captured = null;
    $die_filter = static function () use ( &$captured ) {
        return static function ( $message, $title, $args ) use ( &$captured ) {
            $captured = [ $message, $title, $args ];
            throw new RuntimeException( 'feed-check' );
        };
    };
    add_filter( 'home_url', $home_filter );
    add_filter( 'gettext', $translation_filter, 10, 3 );
    add_filter( 'wp_die_handler', $die_filter );
    try {
        $fail2wp_test_plugin->fail2wp_remove_feeds( null );
    } catch ( RuntimeException $error ) {
        if ( $error->getMessage() !== 'feed-check' ) { throw $error; }
    } finally {
        remove_filter( 'home_url', $home_filter );
        remove_filter( 'gettext', $translation_filter, 10 );
        remove_filter( 'wp_die_handler', $die_filter );
    }
    fail2wp_integration_check( $captured !== null && $captured[2]['response'] === 404, 'Disabled feed response changed' );
    foreach ( [ $captured[0], $captured[1], $captured[2]['link_text'] ] as $value ) {
        fail2wp_integration_check( strpos( $value, '<script>' ) === false && strpos( $value, '<svg' ) === false, 'Feed output contains unescaped content' );
    }

    require_once ABSPATH . WPINC . '/class-IXR.php';
    fail2wp_integration_setting( 'fail2wp_xmlrpc_inform_fail2ban', false );
    $server = new \fail2wp\fail2wp_disable_xmlrpc();
    foreach ( [ 'UTF-8', 'ISO-8859-1', '', 'UTF-8"?><injected/>', "UTF-8\r\nX-Header: injected", [ 'UTF-8' ] ] as $charset ) {
        $charset_filter = static function () use ( $charset ) { return $charset; };
        add_filter( 'pre_option_blog_charset', $charset_filter );
        try {
            ob_start();
            $server->serve_request();
            $xml = ob_get_clean();
        } finally {
            remove_filter( 'pre_option_blog_charset', $charset_filter );
        }
        $parsed = simplexml_load_string( $xml );
        fail2wp_integration_check( $parsed !== false, 'XML-RPC fault is not valid XML' );
        fail2wp_integration_check( strpos( $xml, '<injected' ) === false && strpos( $xml, 'X-Header' ) === false, 'XML charset permits injection' );
        fail2wp_integration_check( (int) $parsed->fault->value->struct->member[0]->value->int === 405, 'XML-RPC fault code changed' );
        fail2wp_integration_check( (string) $parsed->fault->value->struct->member[1]->value->string === 'XML-RPC services are disabled on this site.', 'XML-RPC fault message changed' );
    }
    fail2wp_integration_setting( 'fail2wp_settings_tab', 'importexport' );
    $_POST = [];
}

fail2wp_release_wordpress_checks();
