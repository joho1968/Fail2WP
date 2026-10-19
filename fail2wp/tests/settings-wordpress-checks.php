<?php
/**
 * Settings checks loaded by wordpress-integration.php.
 */
if ( PHP_SAPI !== 'cli' || ! defined( 'WP_CLI' ) || ! WP_CLI || ! isset( $fail2wp_test_plugin ) ) {
    exit;
}

$fail2wp_registered = get_registered_settings();
$fail2wp_boolean_count = 0;
foreach ( $fail2wp_registered as $fail2wp_option => $fail2wp_metadata ) {
    if ( ( $fail2wp_metadata['sanitize_callback'] ?? null ) !== [ $fail2wp_test_plugin, 'fail2wp_setting_sanitize_boolean' ] ) {
        continue;
    }
    $fail2wp_boolean_count++;
    fail2wp_integration_check( $fail2wp_metadata['type'] === 'boolean', 'Missing boolean metadata: ' . $fail2wp_option );
    foreach ( [ true, 1, '1' ] as $fail2wp_input ) {
        fail2wp_integration_check( sanitize_option( $fail2wp_option, $fail2wp_input ) === 1, 'Valid enabled value rejected: ' . $fail2wp_option );
    }
    foreach ( [ false, 0, '0', '', null ] as $fail2wp_input ) {
        fail2wp_integration_check( sanitize_option( $fail2wp_option, $fail2wp_input ) === 0, 'Unchecked value rejected: ' . $fail2wp_option );
    }
    $fail2wp_property = new ReflectionProperty( $fail2wp_test_plugin, str_replace( '-', '_', $fail2wp_option ) );
    $fail2wp_property->setAccessible( true );
    $fail2wp_previous = (int) (bool) get_option( $fail2wp_option, $fail2wp_property->getValue( $fail2wp_test_plugin ) );
    fail2wp_integration_check( sanitize_option( $fail2wp_option, [ '1' ] ) === $fail2wp_previous, 'Malformed toggle replaced stored value: ' . $fail2wp_option );
}
fail2wp_integration_check( $fail2wp_boolean_count === 25, 'Unexpected checkbox registration count' );

foreach ( [ 'fail2wp-reguser-warn-role', 'fail2wp-reguser-force-role' ] as $fail2wp_option ) {
    $fail2wp_old_value_filter = static function () {
        return 'editor';
    };
    add_filter( 'pre_option_' . $fail2wp_option, $fail2wp_old_value_filter );
    fail2wp_integration_check( sanitize_option( $fail2wp_option, 'subscriber' ) === 'subscriber', 'Registered role rejected' );
    foreach ( [ 'not-a-role', '', [ 'administrator' ] ] as $fail2wp_input ) {
        fail2wp_integration_check( sanitize_option( $fail2wp_option, $fail2wp_input ) === 'editor', 'Invalid role changed previous setting' );
    }
    $fail2wp_errors = get_settings_errors( $fail2wp_option );
    fail2wp_integration_check( count( $fail2wp_errors ) === 1, 'Role rejection notice missing or duplicated' );
    remove_filter( 'pre_option_' . $fail2wp_option, $fail2wp_old_value_filter );
}

$fail2wp_json_cases = [
    'fail2wp-roles-notify' => [ 'editor' ],
    'fail2wp-roles-warn' => [ 'administrator' ],
    'fail2wp-rest-filter-block-ns' => [ 'wp/v2' ],
    'fail2wp-rest-filter-block-routes' => [ 'posts' ],
];
foreach ( $fail2wp_json_cases as $fail2wp_option => $fail2wp_value ) {
    fail2wp_integration_check( $fail2wp_registered[$fail2wp_option]['type'] === 'string', 'JSON option has array metadata' );
    $fail2wp_first = sanitize_option( $fail2wp_option, $fail2wp_value );
    fail2wp_integration_check( json_decode( $fail2wp_first, true ) === $fail2wp_value, 'JSON sanitizer changed valid input' );
    fail2wp_integration_check( sanitize_option( $fail2wp_option, $fail2wp_first ) === $fail2wp_first, 'Repeated sanitization cleared a valid list' );

    $fail2wp_temporary = 'fail2wp-settings-test-' . uniqid();
    register_setting( 'fail2wp-settings-test', $fail2wp_temporary, [
        'type' => 'string',
        'sanitize_callback' => $fail2wp_registered[$fail2wp_option]['sanitize_callback'],
    ] );
    try {
        fail2wp_integration_check( add_option( $fail2wp_temporary, $fail2wp_value ), 'Temporary option creation failed' );
        fail2wp_integration_check( get_option( $fail2wp_temporary ) === $fail2wp_first, 'First-save sanitization corrupted a JSON list' );
    } finally {
        delete_option( $fail2wp_temporary );
        unregister_setting( 'fail2wp-settings-test', $fail2wp_temporary );
    }
}

$fail2wp_roles_object = wp_roles();
$fail2wp_original_roles = $fail2wp_roles_object->roles;
$fail2wp_original_names = $fail2wp_roles_object->role_names;
$fail2wp_roles_object->roles['fail2wp_custom'] = [ 'name' => 'Custom role', 'capabilities' => [] ];
$fail2wp_roles_object->role_names['fail2wp_custom'] = 'Custom role';
$fail2wp_roles_object->roles['fail2wp_login_label'] = [ 'name' => 'Username or Email Address', 'capabilities' => [] ];
$fail2wp_roles_object->role_names['fail2wp_login_label'] = 'Username or Email Address';
$fail2wp_context_translations = 0;
$fail2wp_retranslations = 0;
$fail2wp_context_filter = static function ( $translated, $text, $context, $domain ) use ( &$fail2wp_context_translations ) {
    if ( $context === 'User role' && $domain === 'default' && in_array( $text, [ 'Administrator', 'Custom role' ], true ) ) {
        $fail2wp_context_translations++;
        return 'Translated <' . $text . '>';
    }
    return $translated;
};
$fail2wp_gettext_filter = static function ( $translated, $text, $domain ) use ( &$fail2wp_retranslations ) {
    if ( strpos( $text, 'Translated <' ) === 0 ) {
        $fail2wp_retranslations++;
        return 'Unexpected second translation';
    }
    return $translated;
};
add_filter( 'gettext_with_context', $fail2wp_context_filter, 10, 4 );
add_filter( 'gettext', $fail2wp_gettext_filter, 10, 3 );
$fail2wp_test_plugin->fail2wp_login_text();
fail2wp_integration_setting( 'fail2wp_wp_roles', null );
try {
    fail2wp_integration_check( __( 'Username or Email Address', 'default' ) === __( 'E-mail address', 'fail2wp' ), 'Login-label translation hook changed' );
    foreach ( [ 'fail2wp_setting_roles_notify', 'fail2wp_setting_roles_warn', 'fail2wp_setting_reguser_warn_role', 'fail2wp_setting_reguser_force_role' ] as $fail2wp_renderer ) {
        ob_start();
        if ( $fail2wp_renderer === 'fail2wp_setting_roles_notify' ) {
            $fail2wp_test_plugin->{$fail2wp_renderer}( [] );
        } else {
            $fail2wp_test_plugin->{$fail2wp_renderer}();
        }
        $fail2wp_markup = ob_get_clean();
        fail2wp_integration_check( strpos( $fail2wp_markup, 'Translated &lt;Administrator&gt;' ) !== false, 'Core role translation lost: ' . $fail2wp_renderer );
        fail2wp_integration_check( strpos( $fail2wp_markup, 'Translated &lt;Custom role&gt;' ) !== false, 'Custom role translation lost: ' . $fail2wp_renderer );
        fail2wp_integration_check( strpos( $fail2wp_markup, 'Translated <' ) === false, 'Role label output is unescaped' );
        fail2wp_integration_check( strpos( $fail2wp_markup, 'Username or Email Address' ) !== false, 'Login-label hook changed a role name' );
    }
    fail2wp_integration_check( $fail2wp_retranslations === 0, 'Role renderers translated labels twice' );
    fail2wp_integration_check( $fail2wp_context_translations === 2, 'Role helper bypassed core context or cache' );
    fail2wp_integration_check( sanitize_option( 'fail2wp-reguser-force-role', 'fail2wp_custom' ) === 'fail2wp_custom', 'Custom role selection rejected' );
} finally {
    remove_filter( 'gettext_with_context', $fail2wp_context_filter, 10 );
    remove_filter( 'gettext', $fail2wp_gettext_filter, 10 );
    remove_filter( 'gettext', [ $fail2wp_test_plugin, 'fail2wp_gettext' ], 10 );
    $fail2wp_roles_object->roles = $fail2wp_original_roles;
    $fail2wp_roles_object->role_names = $fail2wp_original_names;
    fail2wp_integration_setting( 'fail2wp_wp_roles', null );
}

$fail2wp_role_option = 'fail2wp-reguser-force-role';
$fail2wp_role_previous = static function () {
    return 'editor';
};
add_filter( 'pre_option_' . $fail2wp_role_option, $fail2wp_role_previous );
try {
    $_POST = [
        'fail2wpimport' => '1',
        'fail2wp_nonce' => wp_create_nonce( 'importexport' ),
        'fail2wp-import-settings' => FAIL2WP_EXPORT_HEADER . base64_encode( wp_json_encode( [
            'fail2wp_plugin_version' => FAIL2WP_VERSION,
            'fail2wp_reguser_force_role' => 'not-a-role',
        ] ) ) . FAIL2WP_EXPORT_FOOTER,
    ];
    ob_start();
    $fail2wp_test_plugin->fail2wp_admin_page();
    $fail2wp_markup = ob_get_clean();
    fail2wp_integration_check( get_option( $fail2wp_role_option ) === 'editor', 'Invalid imported role replaced stored selection' );
    fail2wp_integration_check( strpos( $fail2wp_markup, 'Invalid role selection. Previous setting retained.' ) !== false, 'Imported role error is not visible' );
    fail2wp_integration_check( strpos( $fail2wp_markup, 'Settings were successfully imported' ) === false, 'Rejected import reported success' );
} finally {
    remove_filter( 'pre_option_' . $fail2wp_role_option, $fail2wp_role_previous );
    $_POST = [];
}
