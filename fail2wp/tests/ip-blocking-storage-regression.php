<?php
/**
 * Lightweight regression coverage for IP-blocking storage and cache handling.
 *
 * Run with: php7.4 tests/ip-blocking-storage-regression.php
 */
define( 'ABSPATH', dirname( __DIR__, 2 ) . '/' );
define( 'ARRAY_A', 'ARRAY_A' );

$cache = array();
function wp_cache_get( $key, $group ) {
    global $cache;
    return( isset( $cache[$group][$key] ) ? $cache[$group][$key] : false );
}
function wp_cache_set( $key, $value, $group, $expiration = 0 ) {
    global $cache;
    $cache[$group][$key] = $value;
    return( true );
}
function wp_cache_delete( $key, $group ) {
    global $cache;
    unset( $cache[$group][$key] );
    return( true );
}

class Fail2WP_Test_WPDB {
    public $prefix = 'wp_';
    public $events = array();
    public $bans = array();
    public $ban_lookup_queries = 0;

    public function prepare( $query ) {
        $arguments = func_get_args();
        array_shift( $arguments );
        foreach ( $arguments as $argument ) {
            $replacement = is_int( $argument ) ? (string) $argument : "'" . addslashes( $argument ) . "'";
            $query = preg_replace( '/%[sd]/', $replacement, $query, 1 );
        }
        return( $query );
    }
    public function query( $query ) {
        if ( strpos( $query, 'INSERT INTO wp_fail2wp_ip_block_events' ) !== false ) {
            preg_match( "/VALUES \('([^']+)'/", $query, $matches );
            $ip = $matches[1];
            if ( ! isset( $this->events[$ip] ) ) {
                $this->events[$ip] = 0;
            }
            $this->events[$ip]++;
            return( 1 );
        }
        if ( strpos( $query, 'INSERT INTO wp_fail2wp_ip_blocks' ) !== false ) {
            preg_match( "/VALUES \('([^']+)', '([^']+)', '([^']+)', (\d+)\)/", $query, $matches );
            $this->bans[$matches[1]] = array(
                'ip'         => $matches[1],
                'created_at' => $matches[2],
                'expires_at' => $matches[3],
                'hit_count'  => (int) $matches[4],
            );
            return( 1 );
        }
        if ( strpos( $query, 'DELETE FROM wp_fail2wp_ip_blocks WHERE ip' ) !== false ) {
            preg_match( "/ip = '([^']+)'/", $query, $matches );
            unset( $this->bans[$matches[1]] );
            return( 1 );
        }
        if ( trim( $query ) === 'DELETE FROM wp_fail2wp_ip_blocks' ) {
            $this->bans = array();
            return( 1 );
        }
        return( 1 );
    }
    public function get_var( $query ) {
        if ( strpos( $query, 'SELECT hit_count FROM wp_fail2wp_ip_block_events' ) !== false ) {
            preg_match( "/ip = '([^']+)'/", $query, $matches );
            return( isset( $this->events[$matches[1]] ) ? $this->events[$matches[1]] : null );
        }
        if ( strpos( $query, 'SELECT expires_at FROM wp_fail2wp_ip_blocks' ) !== false ) {
            $this->ban_lookup_queries++;
            preg_match( "/ip = '([^']+)'/", $query, $matches );
            return( isset( $this->bans[$matches[1]] ) ? $this->bans[$matches[1]]['expires_at'] : null );
        }
        return( null );
    }
    public function get_results( $query, $output ) {
        return( array_values( $this->bans ) );
    }
    public function get_col( $query ) {
        return( array_keys( $this->bans ) );
    }
}

global $wpdb;
$wpdb = new Fail2WP_Test_WPDB();

require_once dirname( __DIR__ ) . '/includes/class-fail2wp-ip-blocking-storage.php';

use fail2wp\Fail2WP_IP_Blocking_Storage;

$ip = '203.0.113.24';
if ( Fail2WP_IP_Blocking_Storage::record_event( 'not-an-ip', 2, 600, 600 ) ) {
    throw new RuntimeException( 'Invalid address was accepted.' );
}
if ( Fail2WP_IP_Blocking_Storage::record_event( $ip, 2, 600, 600 ) ) {
    throw new RuntimeException( 'The first event created a ban.' );
}
if ( ! Fail2WP_IP_Blocking_Storage::record_event( $ip, 2, 600, 600 ) ) {
    throw new RuntimeException( 'The threshold event did not create a ban.' );
}
if ( ! Fail2WP_IP_Blocking_Storage::is_banned( $ip ) ) {
    throw new RuntimeException( 'The active ban was not found.' );
}
$lookups = $wpdb->ban_lookup_queries;
if ( ! Fail2WP_IP_Blocking_Storage::is_banned( $ip ) || $wpdb->ban_lookup_queries !== $lookups ) {
    throw new RuntimeException( 'The positive ban cache was not used.' );
}
if ( count( Fail2WP_IP_Blocking_Storage::get_active_bans() ) !== 1 ) {
    throw new RuntimeException( 'The active-ban snapshot is incomplete.' );
}
if ( ! Fail2WP_IP_Blocking_Storage::remove_ban( $ip ) || Fail2WP_IP_Blocking_Storage::is_banned( $ip ) ) {
    throw new RuntimeException( 'Unban did not invalidate storage and cache.' );
}
if ( ! Fail2WP_IP_Blocking_Storage::add_ban( $ip, 600 ) || ! Fail2WP_IP_Blocking_Storage::is_banned( $ip ) ) {
    throw new RuntimeException( 'Manual exact-IP ban failed.' );
}
Fail2WP_IP_Blocking_Storage::clear_bans();
$snapshot = array(
    array(
        'ip'         => '2001:db8::7',
        'created_at' => gmdate( 'Y-m-d H:i:s', time() - 60 ),
        'expires_at' => gmdate( 'Y-m-d H:i:s', time() + 600 ),
        'hit_count'  => 4,
    ),
);
if ( ! Fail2WP_IP_Blocking_Storage::replace_active_bans( $snapshot ) || ! Fail2WP_IP_Blocking_Storage::is_banned( '2001:db8::7' ) ) {
    throw new RuntimeException( 'Active-ban snapshot import failed.' );
}
if ( Fail2WP_IP_Blocking_Storage::replace_active_bans( array( array( 'ip' => 'invalid' ) ) ) || ! Fail2WP_IP_Blocking_Storage::is_banned( '2001:db8::7' ) ) {
    throw new RuntimeException( 'Invalid snapshot changed active bans.' );
}
if ( Fail2WP_IP_Blocking_Storage::replace_active_bans( array( $snapshot[0], $snapshot[0] ) ) || ! Fail2WP_IP_Blocking_Storage::is_banned( '2001:db8::7' ) ) {
    throw new RuntimeException( 'Duplicate snapshot changed active bans.' );
}

echo "IP-blocking storage regression checks passed\n";
