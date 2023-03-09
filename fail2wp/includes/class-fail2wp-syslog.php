<?php
/**
 * Fail2WP syslog utility class
 *
 * @since      1.0.0
 * @package    Fail2WP
 * @subpackage fail2wp/includes
 * @author     Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * class-fail2wp-syslog.php
 * Copyright (C) 2021, 2022 Joaquim Homrighausen; all rights reserved.
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


// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}
if ( ! defined( 'ABSPATH' ) ) {
    die( '-1' );
}
if ( ! defined( 'FAIL2WP_VERSION' ) ) {
    die( '-1' );
}


class SysLog {
    protected $x_default_prefix = '';
    protected $x_default_facility = -1;
    private $x_openlog = false;
    private $x_last_facility = null;
    private $x_last_prefix = null;

    public function __construct( string $prefix = '', int $facility = -1 ) {
        $this->x_default_prefix = $prefix;
        $this->x_default_facility = $facility;
    }

    public function __destruct() {
        $this->log_close();
    }

    protected function log_open( string $prefix, int $facility ) {
        if ( $this->x_openlog ) {
            if ( $facility !== $this->x_last_facility || $prefix !== $this->x_last_prefix ) {
                // Open, but wrong facility, close
                $this->log_close();
            } else {
                // Already open, same facility
                return( true );
            }
        }
        if ( function_exists( 'openlog' ) ) {
            return( openlog( $prefix, 0 /*LOG_PID*/, $facility ) );
        }
        error_log( basename( __FILE__ ) . ' (' . __FUNCTION__ . '): openlog() does not seem to exist');
    }

    protected function log_close() {
        if ( $this->x_openlog ) {
            if ( function_exists( 'closelog' ) ) {
                closelog();
            } else {
                error_log( basename( __FILE__ ) . ' (' . __FUNCTION__ . '): closelog() does not seem to exist');
            }
            $this->x_openlog = false;
            $this->x_last_facility = null;
            $this->x_last_prefix = null;
        }
    }

    public function log_message( string $message, int $severity, string $prefix = '', int $facility = null ) {
        if ( empty( $prefix ) ) {
            $prefix = $this->x_default_prefix;
        }
        if ( $facility === null ) {
            $facility = $this->x_default_facility;
        }
        if ( ! $this->log_open( $prefix, $facility )) {
            error_log( basename( __FILE__ ) . ' (' . __FUNCTION__ . '): Unable to open log');
            return( false );
        }
        if ( function_exists( 'syslog' ) ) {
            return( syslog( $severity, $message ) );
        }
        error_log( basename( __FILE__ ) . ' (' . __FUNCTION__ . '): syslog() does not seem to exist');
    }
}// SysLog
