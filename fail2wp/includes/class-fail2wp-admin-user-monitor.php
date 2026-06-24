<?php
/**
 * Fail2WP administrator-account monitoring.
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

if ( ! defined( 'ABSPATH' ) ) {
    die( '-1' );
}

class Fail2WP_Admin_User_Monitor {
    const BASELINE_OPTION       = 'fail2wp-admin-monitor-baseline';
    const LAST_SIGNATURE_OPTION = 'fail2wp-admin-monitor-last-signature';
    const LAST_CHECK_OPTION     = 'fail2wp-admin-monitor-last-check';

    /**
     * Normalize user objects or exported snapshot rows to ID => login pairs.
     *
     * @since 1.3.0
     */
    public static function normalize_snapshot( array $users ) : array {
        $snapshot = array();
        foreach ( $users as $key => $user ) {
            if ( is_object( $user ) ) {
                $id = isset( $user->ID ) ? (int) $user->ID : 0;
                $login = isset( $user->user_login ) ? (string) $user->user_login : '';
            } elseif ( is_array( $user ) ) {
                $id = isset( $user['ID'] ) ? (int) $user['ID'] : (int) $key;
                $login = isset( $user['user_login'] ) ? (string) $user['user_login'] : '';
            } elseif ( is_string( $user ) ) {
                $id = (int) $key;
                $login = $user;
            } else {
                continue;
            }
            if ( $id > 0 && ! empty( $login ) ) {
                $snapshot[$id] = $login;
            }
        }
        ksort( $snapshot, SORT_NUMERIC );
        return( $snapshot );
    }

    /**
     * Get the current site's true administrator-role accounts.
     *
     * @since 1.3.0
     */
    public static function get_current_snapshot() : array {
        return( self::normalize_snapshot( get_users( array( 'role' => 'administrator', 'fields' => array( 'ID', 'user_login' ) ) ) ) );
    }

    /**
     * Get the stored baseline.
     *
     * @since 1.3.0
     */
    public static function get_baseline() : array {
        $baseline = @ json_decode( get_option( self::BASELINE_OPTION, '' ), true, 2 );
        if ( ! is_array( $baseline ) ) {
            return( array() );
        }
        return( self::normalize_snapshot( $baseline ) );
    }

    /**
     * Store the current administrator snapshot as the reviewed baseline.
     *
     * @since 1.3.0
     */
    public static function store_baseline() : array {
        $snapshot = self::get_current_snapshot();
        update_option( self::BASELINE_OPTION, wp_json_encode( $snapshot ), false );
        delete_option( self::LAST_SIGNATURE_OPTION );
        update_option( self::LAST_CHECK_OPTION, time(), false );
        return( $snapshot );
    }

    /**
     * Compare baseline and current administrator-role snapshots.
     *
     * @since 1.3.0
     */
    public static function compare( array $baseline, array $current ) : array {
        $added = array();
        $removed = array();
        foreach ( $current as $id => $login ) {
            if ( ! isset( $baseline[$id] ) ) {
                $added[$id] = $login;
            }
        }
        foreach ( $baseline as $id => $login ) {
            if ( ! isset( $current[$id] ) ) {
                $removed[$id] = $login;
            }
        }
        return( array( 'added' => $added, 'removed' => $removed ) );
    }

    /**
     * Return true when a comparison contains an administrator-role change.
     *
     * @since 1.3.0
     */
    public static function has_changes( array $changes ) : bool {
        return( ! empty( $changes['added'] ) || ! empty( $changes['removed'] ) );
    }
}
