<?php
/**
 * Real-database storage checks. Included by wordpress-integration.php.
 */
if ( PHP_SAPI !== 'cli' || ! defined( 'WP_CLI' ) || ! WP_CLI ) { exit; }

function fail2wp_storage_wordpress_checks() {
    global $wpdb, $fail2wp_test_count;

    $original_db = $wpdb;
    $wpdb = clone $wpdb;
    $wpdb->prefix = 'fail2wp_test_' . bin2hex( random_bytes( 6 ) ) . '_';
    $event_table = \fail2wp\Fail2WP_IP_Blocking_Storage::get_event_table_name();
    $ban_table = \fail2wp\Fail2WP_IP_Blocking_Storage::get_ban_table_name();
    $options_table = $wpdb->prefix . 'options';
    $ips = [ '192.0.2.231', '2001:db8::f2:231', '2001:db8::f2:232' ];
    $version_option = \fail2wp\Fail2WP_IP_Blocking_Storage::DB_VERSION_OPTION;
    $force_install = static function () { return -1; };
    $retain_version = static function ( $new, $old ) { return $old; };
    $check = static function ( $condition, $label ) use ( &$fail2wp_test_count ) {
        if ( ! $condition ) {
            throw new RuntimeException( $label );
        }
        $fail2wp_test_count++;
    };
    add_filter( 'pre_option_' . $version_option, $force_install );
    add_filter( 'pre_update_option_' . $version_option, $retain_version, 10, 2 );

    try {
        $check( $wpdb->has_cap( 'identifier_placeholders' ), 'Identifier placeholders unavailable' );
        \fail2wp\Fail2WP_IP_Blocking_Storage::maybe_install();
        foreach ( [ $event_table, $ban_table ] as $table ) {
            $check( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) === $table, 'Storage schema missing' );
        }
        $check( ! \fail2wp\Fail2WP_IP_Blocking_Storage::record_event( $ips[0], 2, 600, 600 ), 'First event creates a ban' );
        $check( \fail2wp\Fail2WP_IP_Blocking_Storage::record_event( $ips[0], 2, 600, 600 ), 'Threshold event does not create a ban' );
        $check( (int) $wpdb->get_var( $wpdb->prepare( 'SELECT hit_count FROM %i WHERE ip = %s', $event_table, $ips[0] ) ) === 2, 'Event counter is incorrect' );
        $check( \fail2wp\Fail2WP_IP_Blocking_Storage::is_banned( $ips[0] ), 'Ban lookup fails' );
        $queries = $wpdb->num_queries;
        $check( \fail2wp\Fail2WP_IP_Blocking_Storage::is_banned( $ips[0] ) && $wpdb->num_queries === $queries, 'Positive cache misses' );
        $check( \fail2wp\Fail2WP_IP_Blocking_Storage::remove_ban( $ips[0] ), 'Unban fails' );
        $check( ! \fail2wp\Fail2WP_IP_Blocking_Storage::is_banned( $ips[0] ), 'Unban leaves cached block' );
        $queries = $wpdb->num_queries;
        $check( ! \fail2wp\Fail2WP_IP_Blocking_Storage::is_banned( $ips[0] ) && $wpdb->num_queries === $queries + 1, 'Missing ban is cached' );
        $check( \fail2wp\Fail2WP_IP_Blocking_Storage::add_ban( $ips[0], 600 ), 'Manual ban fails' );
        $check( \fail2wp\Fail2WP_IP_Blocking_Storage::is_banned( $ips[0] ), 'New ban hidden after a negative lookup' );
        $check( count( \fail2wp\Fail2WP_IP_Blocking_Storage::get_active_bans() ) === 1, 'Active-ban list is incorrect' );
        $check( \fail2wp\Fail2WP_IP_Blocking_Storage::add_ban( $ips[0], 1200 ), 'Ban refresh fails' );
        $check( wp_cache_get( 'ban_' . md5( $ips[0] ), \fail2wp\Fail2WP_IP_Blocking_Storage::CACHE_GROUP ) === false, 'Ban refresh retains cached expiry' );
        $check( \fail2wp\Fail2WP_IP_Blocking_Storage::is_banned( $ips[0] ), 'Refreshed ban missing' );

        $snapshot = [ [
            'ip' => $ips[1], 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 60 ),
            'expires_at' => gmdate( 'Y-m-d H:i:s', time() + 600 ), 'hit_count' => 7,
        ] ];
        $check( \fail2wp\Fail2WP_IP_Blocking_Storage::replace_active_bans( $snapshot ), 'Snapshot import fails' );
        $check( ! \fail2wp\Fail2WP_IP_Blocking_Storage::is_banned( $ips[0] ), 'Snapshot leaves old ban cached' );
        $check( \fail2wp\Fail2WP_IP_Blocking_Storage::is_banned( $ips[1] ), 'Snapshot IPv6 ban missing' );
        $bans = \fail2wp\Fail2WP_IP_Blocking_Storage::get_active_bans();
        $check( count( $bans ) === 1 && (int) $bans[0]['hit_count'] === 7, 'Snapshot fields changed' );
        $check( \fail2wp\Fail2WP_IP_Blocking_Storage::clear_bans(), 'Clear bans fails' );
        $check( ! \fail2wp\Fail2WP_IP_Blocking_Storage::is_banned( $ips[1] ), 'Clear bans leaves cached block' );

        $wpdb->query( $wpdb->prepare( 'UPDATE %i SET first_seen_at = %s WHERE ip = %s', $event_table, gmdate( 'Y-m-d H:i:s', time() - 1200 ), $ips[0] ) );
        $check( ! \fail2wp\Fail2WP_IP_Blocking_Storage::record_event( $ips[0], 2, 600, 600 ), 'Expired event window does not reset' );
        $check( (int) $wpdb->get_var( $wpdb->prepare( 'SELECT hit_count FROM %i WHERE ip = %s', $event_table, $ips[0] ) ) === 1, 'Reset counter is incorrect' );
        $check( \fail2wp\Fail2WP_IP_Blocking_Storage::add_ban( $ips[2], 600 ), 'Prune fixture ban fails' );
        $past = gmdate( 'Y-m-d H:i:s', time() - 1200 );
        $wpdb->query( $wpdb->prepare( 'UPDATE %i SET expires_at = %s WHERE ip = %s', $ban_table, $past, $ips[2] ) );
        $wpdb->query( $wpdb->prepare( 'UPDATE %i SET last_seen_at = %s', $event_table, $past ) );
        \fail2wp\Fail2WP_IP_Blocking_Storage::prune( 600 );
        $check( (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $ban_table ) ) === 0, 'Expired ban not pruned' );
        $check( (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $event_table ) ) === 0, 'Old counter not pruned' );
        $queries = $wpdb->num_queries;
        $check( ! \fail2wp\Fail2WP_IP_Blocking_Storage::add_ban( "192.0.2.1' OR 1=1", 600 ) && $wpdb->num_queries === $queries, 'Invalid IP reaches SQL' );

        remove_filter( 'pre_option_' . $version_option, $force_install );
        // Isolate uninstall's version-option deletion from site options.
        $wpdb->query( $wpdb->prepare( 'CREATE TABLE %i (option_name varchar(191) NOT NULL PRIMARY KEY, option_value longtext NOT NULL, autoload varchar(20) NOT NULL)', $options_table ) );
        $wpdb->insert( $options_table, [ 'option_name' => $version_option, 'option_value' => '1', 'autoload' => 'no' ] );
        $wpdb->options = $options_table;
        \fail2wp\Fail2WP_IP_Blocking_Storage::uninstall();
        $check( (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $options_table ) ) === 0, 'Uninstall retains schema version' );
        foreach ( [ $event_table, $ban_table ] as $table ) {
            $check( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) === null, 'Uninstall leaves table behind' );
        }
    } finally {
        foreach ( [ $event_table, $ban_table, $options_table ] as $table ) {
            $wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $table ) );
        }
        foreach ( $ips as $ip ) {
            wp_cache_delete( 'ban_' . md5( $ip ), \fail2wp\Fail2WP_IP_Blocking_Storage::CACHE_GROUP );
        }
        remove_filter( 'pre_option_' . $version_option, $force_install );
        remove_filter( 'pre_update_option_' . $version_option, $retain_version );
        $wpdb = $original_db;
    }
}

fail2wp_storage_wordpress_checks();
