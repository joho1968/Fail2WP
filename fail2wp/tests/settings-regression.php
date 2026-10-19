<?php
/**
 * Settings registration, sanitization, and role rendering regressions.
 * Run: php7.4 fail2wp/tests/settings-regression.php
 */
namespace {
    if ( PHP_SAPI !== 'cli' ) {
        exit;
    }
}

namespace {
    define( 'ABSPATH', dirname( __DIR__, 2 ) . '/' );
    define( 'WPINC', 'wp-includes' );

    class Test_WP_Roles {
        public $roles = [
            'administrator' => [],
            'subscriber' => [],
            'custom_role' => [],
        ];

        public function get_names() {
            return [
                'administrator' => 'Administrator',
                'subscriber' => 'Subscriber',
                'custom_role' => '<b>Custom role</b>',
            ];
        }
    }

    class Test_REST_Server {
        public function get_namespaces() {
            return [ 'wp/v2', 'vendor/v1' ];
        }
    }

    $GLOBALS['settings_registered'] = [];
    $GLOBALS['settings_errors'] = [];
    $GLOBALS['settings_options'] = [];
    $GLOBALS['settings_hook'] = '';
    $GLOBALS['settings_admin'] = true;
    $GLOBALS['settings_logged_in'] = true;
    $GLOBALS['settings_capable'] = true;
    $GLOBALS['translated_role_labels'] = [];

    function plugin_dir_path( $path ) {
        return dirname( __DIR__ ) . '/';
    }
    function register_activation_hook( $file, $callback ) {}
    function is_admin() {
        return $GLOBALS['settings_admin'];
    }
    function is_user_logged_in() {
        return $GLOBALS['settings_logged_in'];
    }
    function current_user_can( $capability ) {
        return $GLOBALS['settings_capable'];
    }
    function add_settings_section( $id, $title, $callback, $page ) {}
    function add_settings_field( $id, $title, $callback, $page, $section, $args = [] ) {}
    function register_setting( $group, $option, $args = [] ) {
        $GLOBALS['settings_registered'][$option] = $args;
    }
    function current_filter() {
        return $GLOBALS['settings_hook'];
    }
    function get_option( $option, $default = false ) {
        return array_key_exists( $option, $GLOBALS['settings_options'] )
            ? $GLOBALS['settings_options'][$option]
            : $default;
    }
    function get_settings_errors( $setting = '', $sanitize = false ) {
        return isset( $GLOBALS['settings_errors'][$setting] )
            ? $GLOBALS['settings_errors'][$setting]
            : [];
    }
    function add_settings_error( $setting, $code, $message, $type = 'error' ) {
        $GLOBALS['settings_errors'][$setting][] = [
            'code' => $code,
            'message' => $message,
            'type' => $type,
        ];
    }
    function wp_json_encode( $value, $flags = 0, $depth = 512 ) {
        return json_encode( $value, $flags, $depth );
    }
    function __( $text, $domain = '' ) {
        return $text;
    }
    function esc_html__( $text, $domain = '' ) {
        if ( in_array( $text, $GLOBALS['translated_role_labels'], true ) ) {
            return 'RETRANSLATED ROLE LABEL';
        }
        return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
    }
    function esc_html( $text ) {
        return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
    }
    function esc_attr( $text ) {
        return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
    }
    function wp_roles() {
        return new Test_WP_Roles();
    }
    function rest_get_server() {
        return new Test_REST_Server();
    }
    function translate_user_role( $role ) {
        $translated = 'Core translated: ' . $role;
        $GLOBALS['translated_role_labels'][] = $translated;
        return $translated;
    }

    $source = file_get_contents( dirname( __DIR__ ) . '/fail2wp.php' );
    $source = str_replace( "\nrun_fail2wp();\n", "\n", $source );
    eval( substr( $source, 5 ) );

    $reflection = new ReflectionClass( '\fail2wp\Fail2WP' );
    $plugin = $reflection->newInstanceWithoutConstructor();

    function setting( $name, $value ) {
        global $reflection, $plugin;
        $property = $reflection->getProperty( $name );
        $property->setAccessible( true );
        $property->setValue( $plugin, $value );
    }
    function setting_value( $name ) {
        global $reflection, $plugin;
        $property = $reflection->getProperty( $name );
        $property->setAccessible( true );
        return $property->getValue( $plugin );
    }
    function sanitize_setting( $option, $value ) {
        global $plugin;
        $GLOBALS['settings_hook'] = 'sanitize_option_' . $option;
        return call_user_func( $GLOBALS['settings_registered'][$option]['sanitize_callback'], $value );
    }
    $failures = [];
    $checks = 0;
    function check( $label, $condition ) {
        global $failures, $checks;
        $checks++;
        if ( ! $condition ) {
            $failures[] = $label;
        }
    }

    $plugin->fail2wp_settings();
    $boolean_settings = [];
    foreach ( $GLOBALS['settings_registered'] as $option => $args ) {
        if ( isset( $args['sanitize_callback'][1] ) && $args['sanitize_callback'][1] === 'fail2wp_setting_sanitize_boolean' ) {
            $boolean_settings[] = $option;
            check( $option . ' registered as boolean', isset( $args['type'] ) && $args['type'] === 'boolean' );
        }
    }
    check( '25 boolean settings registered', count( $boolean_settings ) === 25 );
    foreach ( [ 'fail2wp-roles-notify', 'fail2wp-roles-warn', 'fail2wp-rest-filter-block-ns', 'fail2wp-rest-filter-block-routes' ] as $option ) {
        check( $option . ' registered as string', isset( $GLOBALS['settings_registered'][$option]['type'] ) && $GLOBALS['settings_registered'][$option]['type'] === 'string' );
    }

    foreach ( $boolean_settings as $option ) {
        setting( str_replace( '-', '_', $option ), 1 );
        foreach ( [ true, 1, '1' ] as $value ) {
            check( $option . ' normalizes enabled value', sanitize_setting( $option, $value ) === 1 );
        }
        foreach ( [ false, 0, '0', '', null ] as $value ) {
            check( $option . ' normalizes unchecked value', sanitize_setting( $option, $value ) === 0 );
        }
        foreach ( [ 2, -1, 'yes', 'true', [], [ 1 ] ] as $value ) {
            $GLOBALS['settings_options'][$option] = 1;
            $before = count( $GLOBALS['settings_errors'][$option] ?? [] );
            check( $option . ' rejects invalid input and retains true', sanitize_setting( $option, $value ) === 1 );
            check( $option . ' reports invalid input once', count( $GLOBALS['settings_errors'][$option] ) === $before + ( $before === 0 ? 1 : 0 ) );
            $GLOBALS['settings_options'][$option] = 0;
            check( $option . ' retains stored false', sanitize_setting( $option, $value ) === 0 );
        }
        unset( $GLOBALS['settings_options'][$option], $GLOBALS['settings_errors'][$option] );
    }

    setting( 'fail2wp_wp_roles', null );
    setting( 'fail2wp_wp_roles_enus', null );
    setting( 'fail2wp_reguser_warn_role', 'subscriber' );
    setting( 'fail2wp_reguser_force_role', 'administrator' );
    foreach ( [ 'administrator', 'custom_role' ] as $role ) {
        check( 'role dropdown accepts registered role', sanitize_setting( 'fail2wp-reguser-warn-role', $role ) === $role );
    }
    foreach ( [ '', null, 'missing_role', [ 'administrator' ] ] as $value ) {
        $GLOBALS['settings_options']['fail2wp-reguser-warn-role'] = 'custom_role';
        check( 'role dropdown rejects invalid value and retains role', sanitize_setting( 'fail2wp-reguser-warn-role', $value ) === 'custom_role' );
    }
    check( 'role dropdown invalid errors deduplicate', count( $GLOBALS['settings_errors']['fail2wp-reguser-warn-role'] ?? [] ) === 1 );
    unset( $GLOBALS['settings_options']['fail2wp-reguser-warn-role'] );
    check( 'missing role option falls back to current default', sanitize_setting( 'fail2wp-reguser-force-role', [] ) === 'administrator' );

    foreach ( [ 'fail2wp-roles-notify', 'fail2wp-roles-warn' ] as $option ) {
        $encoded = sanitize_setting( $option, [ 'administrator', 'custom_role' ] );
        check( $option . ' accepts role array as JSON', $encoded === '["administrator","custom_role"]' );
        check( $option . ' accepts encoded JSON idempotently', sanitize_setting( $option, $encoded ) === $encoded );
        foreach ( [ [], null, '' ] as $empty ) {
            check( $option . ' clears on empty selection', sanitize_setting( $option, $empty ) === '[]' );
        }
        foreach ( [ [ 'administrator', 'unknown' ], [ [ 'administrator' ] ], '{bad json' ] as $invalid ) {
            $GLOBALS['settings_options'][$option] = '["custom_role"]';
            $before = count( $GLOBALS['settings_errors'][$option] ?? [] );
            check( $option . ' rejects malformed selection and retains old value', sanitize_setting( $option, $invalid ) === '["custom_role"]' );
            check( $option . ' reports malformed selection once', count( $GLOBALS['settings_errors'][$option] ) === $before + ( $before === 0 ? 1 : 0 ) );
        }
        unset( $GLOBALS['settings_options'][$option], $GLOBALS['settings_errors'][$option] );
    }

    setting( 'fail2wp_rest_filter_route_list', [ 'wp/v2/posts', 'vendor/v1/items' ] );
    foreach ( [
        'fail2wp-rest-filter-block-ns' => [ 'wp/v2', 'vendor/v1' ],
        'fail2wp-rest-filter-block-routes' => [ 'wp/v2/posts', 'vendor/v1/items' ],
    ] as $option => $values ) {
        $encoded = sanitize_setting( $option, $values );
        check( $option . ' accepts array as JSON', $encoded === wp_json_encode( $values ) );
        check( $option . ' JSON sanitizer is idempotent', sanitize_setting( $option, $encoded ) === $encoded );
    }

    setting( 'fail2wp_roles_notify', [ 'administrator' ] );
    setting( 'fail2wp_roles_warn', [ 'custom_role' ] );
    $renderer_methods = [
        'fail2wp_setting_roles_notify',
        'fail2wp_setting_roles_warn',
        'fail2wp_setting_reguser_warn_role',
        'fail2wp_setting_reguser_force_role',
    ];
    foreach ( $renderer_methods as $method ) {
        ob_start();
        if ( $method === 'fail2wp_setting_roles_notify' ) {
            $plugin->$method( [] );
        } else {
            $plugin->$method();
        }
        $output = ob_get_clean();
        check( $method . ' shows core translated role', strpos( $output, 'Core translated: Administrator' ) !== false );
        check( $method . ' shows custom role escaped', strpos( $output, '&lt;b&gt;Custom role&lt;/b&gt;' ) !== false );
        check( $method . ' does not retranslate role labels', strpos( $output, 'RETRANSLATED ROLE LABEL' ) === false );
        check( $method . ' escapes injected markup', strpos( $output, '<b>Custom role</b>' ) === false );
    }

    foreach ( [
        'fail2wp-block-user-enum' => 1,
        'fail2wp-cloudflare-check' => 0,
        'fail2wp-reguser-force-role' => 'subscriber',
    ] as $option => $fallback ) {
        unset( $GLOBALS['settings_options'][$option] );
        setting( str_replace( '-', '_', $option ), $fallback );
        $invalid = $option === 'fail2wp-block-user-enum' ? 'invalid' : [];
        $expected = $fallback;
        if ( is_bool( $expected ) || is_int( $expected ) ) {
            $expected = (int) (bool) $expected;
        }
        check( $option . ' preserves missing-option default on invalid input', sanitize_setting( $option, $invalid ) === $expected );
    }

    $GLOBALS['settings_capable'] = false;
    $GLOBALS['settings_options']['fail2wp-cloudflare-check'] = 1;
    $GLOBALS['settings_options']['fail2wp-reguser-force-role'] = 'custom_role';
    $GLOBALS['settings_options']['fail2wp-roles-notify'] = '["custom_role"]';
    check( 'non-administrator cannot change checkbox', sanitize_setting( 'fail2wp-cloudflare-check', 0 ) === 1 );
    check( 'non-administrator cannot change registration role', sanitize_setting( 'fail2wp-reguser-force-role', 'administrator' ) === 'custom_role' );
    check( 'non-administrator cannot change role list', sanitize_setting( 'fail2wp-roles-notify', [ 'administrator' ] ) === '["custom_role"]' );

    if ( $failures ) {
        fwrite( STDERR, implode( "\n", $failures ) . "\n" );
        exit( 1 );
    }
    echo "Settings regression checks passed ($checks checks)\n";
}
