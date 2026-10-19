<?php
/**
 * Security boundary regressions, without a WordPress database.
 * Run: php7.4 fail2wp/tests/security-regression.php
 * Optional first argument: main plugin file to audit before a fix.
 */
namespace {
    if ( PHP_SAPI !== 'cli' ) { exit; }
}
namespace fail2wp {
    function gethostbyaddr( $ip ) {
        return $GLOBALS['test_ptr'];
    }
    function dns_get_record( $hostname, $type ) {
        return $GLOBALS['test_dns'];
    }
}
namespace {
    define( 'ABSPATH', dirname( __DIR__, 2 ) . '/' );
    define( 'WPINC', 'wp-includes' );
    define( 'FAIL2WP_TRUSTED_PROXIES', [ '192.0.2.0/24', '2001:db8:ffff::/48' ] );
    function plugin_dir_path( $path ) { return dirname( __DIR__ ) . '/'; }
    function register_activation_hook( $file, $callback ) {}
    function wp_unslash( $value ) { return stripslashes( $value ); }
    function sanitize_text_field( $value ) { return trim( strip_tags( $value ) ); }
    function __( $text, $domain = '' ) { return $text; }
    function esc_html__( $text, $domain = '' ) { return $text; }
    function esc_html( $text ) { return htmlspecialchars( $text, ENT_QUOTES ); }
    function esc_url( $url ) { return $url; }
    function get_site_url() { return 'http://example.test'; }
    function is_user_logged_in() { return $GLOBALS['test_authenticated']; }
    function rest_url() { return 'http://example.test/wp-json/'; }
    function is_wp_error( $value ) { return $value instanceof WP_Error; }
    function wp_die( $message, $title, $args ) { throw new RuntimeException( 'blocked:' . $args['response'] ); }
    function add_action( $hook, $callback, $priority = 10, $args = 1 ) { $GLOBALS['test_hooks'][$hook][] = $callback[1]; }
    function add_filter( $hook, $callback, $priority = 10, $args = 1 ) { add_action( $hook, $callback, $priority, $args ); }
    class WP_Error {
        public $errors = [];
        public $error_data = [];
        public function __construct( $code, $message, $data = null ) {
            $this->errors[$code] = [ $message ];
            $this->error_data[$code] = $data;
        }
    }
    class WP_REST_Server { public function get_namespaces() { return [ 'wp/v2', 'vendor/v1' ]; } }
    class WP_REST_Request {
        private $route;
        public function __construct( $route ) { $this->route = $route; }
        public function get_route() { return $this->route; }
    }
    class WP_REST_Response { public $data = [ 'routes' => [] ]; }

    // Load the shipped class bodies, omitting only the automatic site bootstrap.
    $source = file_get_contents( isset( $argv[1] ) ? $argv[1] : dirname( __DIR__ ) . '/fail2wp.php' );
    $source = str_replace( "\nrun_fail2wp();\n", "\n", $source );
    eval( substr( $source, 5 ) );
    $reflection = new ReflectionClass( '\\fail2wp\\Fail2WP' );
    $plugin = $reflection->newInstanceWithoutConstructor();
    function setting( $name, $value ) {
        global $reflection, $plugin;
        $property = $reflection->getProperty( $name );
        $property->setAccessible( true );
        $property->setValue( $plugin, $value );
    }
    function call_method( $name, ...$args ) {
        global $reflection, $plugin;
        $method = $reflection->getMethod( $name );
        $method->setAccessible( true );
        return $method->invokeArgs( $plugin, $args );
    }
    $failures = [];
    $checks = 0;
    function check( $label, $condition ) {
        global $failures, $checks;
        $checks++;
        if ( ! $condition ) { $failures[] = $label; }
    }
    foreach ( [
        'fail2wp_cidrm' => new \fail2wp\Fail2WP_Cidr_Matcher(),
        'fail2wp_cloudflare_check' => false,
        'fail2wp_cloudflare_ipv4' => [ '198.51.100.0/24' ],
        'fail2wp_cloudflare_ipv6' => [],
        'fail2wp_loginip_enable' => true,
        'fail2wp_loginip_testmode' => false,
        'fail2wp_loginip_inform_fail2ban' => false,
        'fail2wp_loginip_allow' => [], 'fail2wp_loginip_deny' => [],
        'fail2wp_loginip_dnscache' => 60, 'fail2wp_hostname_cache' => [],
        'fail2wp_hostname_cache_updated' => false,
        'fail2wp_rest_filter_block_all' => false, 'fail2wp_rest_filter_block_index' => false,
        'fail2wp_rest_filter_block_ns' => [], 'fail2wp_rest_filter_block_routes' => [],
        'fail2wp_rest_filter_ipv4_bypass' => [], 'fail2wp_rest_filter_ipv6_bypass' => [],
        'fail2wp_rest_filter_log_blocked' => false, 'fail2wp_log_user_enum' => false,
        'fail2wp_block_user_enum' => false, 'fail2wp_have_mbstring' => false,
        'fail2wp_ip_blocking_enable' => false,
        'fail2wp_default_http_port' => 80, 'fail2wp_default_https_port' => 443,
    ] as $name => $value ) { setting( $name, $value ); }
    $test_authenticated = false;
    $_SERVER = [ 'REMOTE_ADDR' => '203.0.113.10', 'HTTP_X_REAL_IP' => '203.0.113.99', 'SERVER_PORT' => '443' ];
    check( 'Untrusted X-Real-IP ignored', call_method( 'fail2wp_get_client_ip' ) === '203.0.113.10' );
    $message = $plugin->fail2wp_make_alert_message( '', null, FAIL2WP_ALERT_USER_ENUM );
    check( 'Security log uses verified client IP', strpos( $message, 'from 203.0.113.10 port' ) !== false );
    $_SERVER['REMOTE_ADDR'] = '192.0.2.5';
    check( 'Explicitly trusted proxy accepted', call_method( 'fail2wp_get_client_ip' ) === '203.0.113.99' );
    $_SERVER['HTTP_X_REAL_IP'] = 'bad from 203.0.113.99 port 443';
    check( 'Malformed trusted proxy header falls back to peer', call_method( 'fail2wp_get_client_ip' ) === '192.0.2.5' );
    $_SERVER['REMOTE_ADDR'] = '2001:db8:ffff::1';
    $_SERVER['HTTP_X_REAL_IP'] = '2001:db8::5';
    check( 'Trusted IPv6 proxy accepted', call_method( 'fail2wp_get_client_ip' ) === '2001:db8::5' );
    $_SERVER['REMOTE_ADDR'] = '198.51.100.5';
    $_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.7';
    setting( 'fail2wp_cloudflare_check', true );
    check( 'Configured Cloudflare peer accepted', call_method( 'fail2wp_get_client_ip' ) === '203.0.113.7' );
    $_SERVER['HTTP_CF_CONNECTING_IP'] = 'not-an-ip';
    check( 'Malformed Cloudflare header falls back to peer', call_method( 'fail2wp_get_client_ip' ) === '198.51.100.5' );
    $_SERVER['REMOTE_ADDR'] = '203.0.113.10';
    check( 'Cloudflare header from direct client ignored', call_method( 'fail2wp_get_client_ip' ) === '203.0.113.10' );

    $plugin->fail2wp_wp_loaded();
    check( 'Login IP gate runs before credential processing', in_array( 'fail2wp_login_ip_check', $test_hooks['login_init'] ?? [], true ) );
    setting( 'fail2wp_loginip_allow', [ '203.0.113.99' ] );
    $_SERVER['HTTP_X_REAL_IP'] = '203.0.113.99';
    try { $plugin->fail2wp_login_ip_check(); $blocked = false; }
    catch ( RuntimeException $e ) { $blocked = $e->getMessage() === 'blocked:503'; }
    check( 'Spoofed allowlisted address cannot access login', $blocked );

    setting( 'fail2wp_loginip_allow', [] );
    $server = new WP_REST_Server();
    foreach ( [ '/wp/v2/posts', '/wp/v2/posts/', '/wp/v2/posts/12', '/wp/v2/posts/12/revisions' ] as $route ) {
        setting( 'fail2wp_rest_filter_block_routes', [ 'posts' ] );
        check( 'Block configured route ' . $route, $plugin->fail2wp_rest_pre_dispatch( null, $server, new WP_REST_Request( $route ) ) instanceof WP_Error );
    }
    check( 'Similar route prefix remains available', $plugin->fail2wp_rest_pre_dispatch( null, $server, new WP_REST_Request( '/wp/v2/posts-extra' ) ) === null );
    setting( 'fail2wp_rest_filter_block_routes', [] );
    setting( 'fail2wp_rest_filter_block_ns', [ 'vendor/v1' ] );
    check( 'Namespace block covers children', $plugin->fail2wp_rest_pre_dispatch( null, $server, new WP_REST_Request( '/vendor/v1/items' ) ) instanceof WP_Error );
    setting( 'fail2wp_rest_filter_block_ns', [] );
    setting( 'fail2wp_block_user_enum', true );
    check( 'Trailing slash cannot evade user enumeration block', $plugin->fail2wp_rest_pre_dispatch( null, $server, new WP_REST_Request( '/wp/v2/users/' ) ) instanceof WP_Error );
    check( 'Case-insensitive core route cannot evade user block', $plugin->fail2wp_rest_pre_dispatch( null, $server, new WP_REST_Request( '/WP/v2/USERS' ) ) instanceof WP_Error );
    setting( 'fail2wp_block_user_enum', false );
    check( 'Namespace index accessible when rules disabled', $plugin->fail2wp_rest_pre_dispatch( null, $server, new WP_REST_Request( '/wp/v2' ) ) === null );
    setting( 'fail2wp_rest_filter_block_all', true );
    $test_authenticated = true;
    check( 'Authenticated editor bypasses broad REST rules', $plugin->fail2wp_rest_pre_dispatch( null, $server, new WP_REST_Request( '/wp/v2/posts/12/autosaves' ) ) === null );
    $response = new WP_REST_Response();
    $plugin->fail2wp_rest_index( $response );
    check( 'Authenticated REST discovery preserved', isset( $response->data['routes'] ) );
    $test_authenticated = false;

    $test_ptr = 'attacker.trusted.example';
    $test_dns = [ [ 'class' => 'IN', 'type' => 'A', 'ip' => '203.0.113.99' ] ];
    setting( 'fail2wp_hostname_cache', [ '203.0.113.10' => [ $test_ptr ] ] );
    check( 'Forged cached PTR requires forward confirmation', call_method( 'fail2wp_reverse_hostname_lookup', '203.0.113.10' ) === [] );
    $test_dns[0]['ip'] = '203.0.113.10';
    setting( 'fail2wp_hostname_cache', [] );
    check( 'Confirmed PTR returned on first lookup', call_method( 'fail2wp_reverse_hostname_lookup', '203.0.113.10' ) === [ $test_ptr ] );
    setting( 'fail2wp_hostname_cache_updated', false );

    $error = new WP_Error( 'invalid_username', '' );
    $message = $plugin->fail2wp_make_alert_message( "bad\nforged", $error, FAIL2WP_ALERT_FAILURE );
    check( 'Login names cannot create extra log lines', strpos( $message, "\n" ) === false );
    if ( $failures ) { fwrite( STDERR, implode( "\n", $failures ) . "\n" ); exit( 1 ); }
    echo "Security regression checks passed ($checks checks)\n";
}
