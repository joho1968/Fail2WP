<?php
/**
 * Fail2WP IP blocking database storage.
 * This class owns the schema lifecycle and database-backed active-ban state.
 *
 * @since      1.3.0
 * @package    Fail2WP
 * @subpackage fail2wp/includes
 * @author     Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * class-fail2wp-ip-blocking-storage.php
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

if ( ! defined( 'ABSPATH' ) ) {
    die( '-1' );
}

class Fail2WP_IP_Blocking_Storage {
    const DB_VERSION_OPTION = 'fail2wp-ip-blocking-db-version';
    const DB_VERSION        = 1;
    const CACHE_GROUP       = 'fail2wp_ip_blocks';

    protected static function get_cache_key( string $ip ) : string {
        return( 'ban_' . md5( $ip ) );
    }

    public static function get_event_table_name() : string {
        global $wpdb;

        return( $wpdb->prefix . 'fail2wp_ip_block_events' );
    }

    public static function get_ban_table_name() : string {
        global $wpdb;

        return( $wpdb->prefix . 'fail2wp_ip_blocks' );
    }

    /**
     * Create or upgrade the storage schema when its version changes.
     *
     * @since 1.3.0
     */
    public static function maybe_install() {
        if ( (int) get_option( self::DB_VERSION_OPTION, 0 ) >= self::DB_VERSION ) {
            return;
        }

        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $charset_collate = $wpdb->get_charset_collate();
        $event_table = self::get_event_table_name();
        $ban_table = self::get_ban_table_name();

        $event_sql = "CREATE TABLE $event_table (
            ip varchar(45) NOT NULL,
            first_seen_at datetime NOT NULL,
            last_seen_at datetime NOT NULL,
            hit_count bigint(20) unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (ip),
            KEY last_seen_at (last_seen_at)
        ) $charset_collate;";

        $ban_sql = "CREATE TABLE $ban_table (
            ip varchar(45) NOT NULL,
            created_at datetime NOT NULL,
            expires_at datetime NOT NULL,
            hit_count bigint(20) unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (ip),
            KEY expires_at (expires_at)
        ) $charset_collate;";

        dbDelta( $event_sql );
        dbDelta( $ban_sql );

        update_option( self::DB_VERSION_OPTION, self::DB_VERSION, false );
    }

    /**
     * Delete expired bans and counters older than the supplied retention window.
     *
     * @since 1.3.0
     */
    public static function prune( int $counter_retention_seconds ) {
        if ( $counter_retention_seconds < 60 ) {
            return;
        }

        global $wpdb;

        $now = gmdate( 'Y-m-d H:i:s' );
        $counter_cutoff = gmdate( 'Y-m-d H:i:s', time() - $counter_retention_seconds );
        $ban_table = self::get_ban_table_name();
        $event_table = self::get_event_table_name();

        $wpdb->query( $wpdb->prepare( "DELETE FROM $ban_table WHERE expires_at <= %s", $now ) );
        $wpdb->query( $wpdb->prepare( "DELETE FROM $event_table WHERE last_seen_at <= %s", $counter_cutoff ) );
    }

    /**
     * Record an event and create or refresh an exact-IP ban at the threshold.
     *
     * @since 1.3.0
     */
    public static function record_event( string $ip, int $threshold, int $window_seconds, int $ban_seconds ) : bool {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) || $threshold < 1 || $window_seconds < 60 || $ban_seconds < 60 ) {
            return( false );
        }

        global $wpdb;

        $now = gmdate( 'Y-m-d H:i:s' );
        $window_start = gmdate( 'Y-m-d H:i:s', time() - $window_seconds );
        $event_table = self::get_event_table_name();
        $ban_table = self::get_ban_table_name();
        $sql = "INSERT INTO $event_table (ip, first_seen_at, last_seen_at, hit_count)
                VALUES (%s, %s, %s, 1)
                ON DUPLICATE KEY UPDATE
                hit_count = IF(first_seen_at < %s, 1, hit_count + 1),
                first_seen_at = IF(first_seen_at < %s, VALUES(first_seen_at), first_seen_at),
                last_seen_at = VALUES(last_seen_at)";
        $wpdb->query( $wpdb->prepare( $sql, $ip, $now, $now, $window_start, $window_start ) );
        $count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT hit_count FROM $event_table WHERE ip = %s", $ip ) );
        if ( $count < $threshold ) {
            return( false );
        }

        $expires_at = gmdate( 'Y-m-d H:i:s', time() + $ban_seconds );
        $ban_sql = "INSERT INTO $ban_table (ip, created_at, expires_at, hit_count)
                    VALUES (%s, %s, %s, %d)
                    ON DUPLICATE KEY UPDATE expires_at = VALUES(expires_at), hit_count = VALUES(hit_count)";
        $wpdb->query( $wpdb->prepare( $ban_sql, $ip, $now, $expires_at, $count ) );
        self::delete_cached_ban( $ip );
        return( true );
    }

    /**
     * Return whether an exact IP has an unexpired local ban.
     *
     * @since 1.3.0
     */
    public static function is_banned( string $ip ) : bool {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return( false );
        }

        $cache_key = self::get_cache_key( $ip );
        $cached = wp_cache_get( $cache_key, self::CACHE_GROUP );
        if ( $cached === true ) {
            return( true );
        }

        global $wpdb;

        $ban_table = self::get_ban_table_name();
        $now = gmdate( 'Y-m-d H:i:s' );
        $expires_at = $wpdb->get_var( $wpdb->prepare( "SELECT expires_at FROM $ban_table WHERE ip = %s AND expires_at > %s", $ip, $now ) );
        if ( empty( $expires_at ) ) {
            return( false );
        }

        $ttl = max( 1, strtotime( $expires_at . ' UTC' ) - time() );
        wp_cache_set( $cache_key, true, self::CACHE_GROUP, $ttl );
        return( true );
    }

    /**
     * Invalidate a cached ban after its database state changes.
     *
     * @since 1.3.0
     */
    protected static function delete_cached_ban( string $ip ) {
        wp_cache_delete( self::get_cache_key( $ip ), self::CACHE_GROUP );
    }

    /**
     * Return active bans for wp-admin management.
     *
     * @since 1.3.0
     */
    public static function get_active_bans() : array {
        global $wpdb;

        $ban_table = self::get_ban_table_name();
        $now = gmdate( 'Y-m-d H:i:s' );
        $bans = $wpdb->get_results(
            $wpdb->prepare( "SELECT ip, created_at, expires_at, hit_count FROM $ban_table WHERE expires_at > %s ORDER BY expires_at ASC, ip ASC", $now ),
            ARRAY_A
        );
        return( is_array( $bans ) ? $bans : array() );
    }

    /**
     * Remove one exact-IP ban.
     *
     * @since 1.3.0
     */
    public static function remove_ban( string $ip ) : bool {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return( false );
        }

        global $wpdb;

        $ban_table = self::get_ban_table_name();
        $deleted = $wpdb->query( $wpdb->prepare( "DELETE FROM $ban_table WHERE ip = %s", $ip ) );
        self::delete_cached_ban( $ip );
        return( $deleted !== false );
    }

    /**
     * Create or refresh one administrator-managed exact-IP ban.
     *
     * @since 1.3.0
     */
    public static function add_ban( string $ip, int $ban_seconds ) : bool {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) || $ban_seconds < 60 ) {
            return( false );
        }

        global $wpdb;

        $now = gmdate( 'Y-m-d H:i:s' );
        $expires_at = gmdate( 'Y-m-d H:i:s', time() + $ban_seconds );
        $ban_table = self::get_ban_table_name();
        $sql = "INSERT INTO $ban_table (ip, created_at, expires_at, hit_count)
                VALUES (%s, %s, %s, 0)
                ON DUPLICATE KEY UPDATE expires_at = VALUES(expires_at)";
        $result = $wpdb->query( $wpdb->prepare( $sql, $ip, $now, $expires_at ) );
        self::delete_cached_ban( $ip );
        return( $result !== false );
    }

    /**
     * Remove all active and expired bans.
     *
     * @since 1.3.0
     */
    public static function clear_bans() : bool {
        global $wpdb;

        $ban_table = self::get_ban_table_name();
        $ips = $wpdb->get_col( "SELECT ip FROM $ban_table" );
        $deleted = $wpdb->query( "DELETE FROM $ban_table" );
        if ( is_array( $ips ) ) {
            foreach ( $ips as $ip ) {
                self::delete_cached_ban( $ip );
            }
        }
        return( $deleted !== false );
    }

    /**
     * Replace active bans from an administrator-provided export snapshot.
     * Invalid, expired, and non-exact-IP entries are rejected before storage is
     * changed so a malformed import cannot clear an existing ban set.
     *
     * @since 1.3.0
     */
    public static function replace_active_bans( array $bans ) : bool {
        $normalized = array();
        $seen_ips = array();
        $now = time();
        foreach ( $bans as $ban ) {
            if ( ! is_array( $ban ) || empty( $ban['ip'] ) || empty( $ban['created_at'] ) || empty( $ban['expires_at'] ) ) {
                return( false );
            }
            $ip = (string) $ban['ip'];
            $created_at = strtotime( (string) $ban['created_at'] . ' UTC' );
            $expires_at = strtotime( (string) $ban['expires_at'] . ' UTC' );
            $hit_count = isset( $ban['hit_count'] ) ? (int) $ban['hit_count'] : 0;
            if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) || isset( $seen_ips[$ip] ) || $created_at === false || $expires_at === false || $expires_at <= $now || $created_at > $expires_at || $hit_count < 0 ) {
                return( false );
            }
            $seen_ips[$ip] = true;
            $normalized[] = array(
                'ip'         => $ip,
                'created_at' => gmdate( 'Y-m-d H:i:s', $created_at ),
                'expires_at' => gmdate( 'Y-m-d H:i:s', $expires_at ),
                'hit_count'  => $hit_count,
            );
        }

        if ( ! self::clear_bans() ) {
            return( false );
        }

        global $wpdb;

        $ban_table = self::get_ban_table_name();
        foreach ( $normalized as $ban ) {
            $sql = "INSERT INTO $ban_table (ip, created_at, expires_at, hit_count) VALUES (%s, %s, %s, %d)";
            if ( $wpdb->query( $wpdb->prepare( $sql, $ban['ip'], $ban['created_at'], $ban['expires_at'], $ban['hit_count'] ) ) === false ) {
                return( false );
            }
        }
        return( true );
    }

    /**
     * Remove IP-blocking data only during a full plugin data removal.
     *
     * @since 1.3.0
     */
    public static function uninstall() {
        global $wpdb;

        $wpdb->query( 'DROP TABLE IF EXISTS ' . self::get_event_table_name() );
        $wpdb->query( 'DROP TABLE IF EXISTS ' . self::get_ban_table_name() );
        delete_option( self::DB_VERSION_OPTION );
    }
}
