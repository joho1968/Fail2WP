<?php
/**
 * Fail2WP CIDR matcher adapter.
 * Wraps the bundled CIDR matcher.
 *
 * @since      1.3.0
 * @package    Fail2WP
 * @subpackage fail2wp/includes
 * @author     Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * class-fail2wp-cidr-matcher.php
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

class Fail2WP_Cidr_Matcher {
    protected $matcher;

    public function __construct() {
        $this->matcher = new \fail2wpCIDRmatch\CIDRmatch();
    }

    public function match( string $ip, string $cidr ) : bool {
        return( (bool) $this->matcher->match( $ip, $cidr ) );
    }
}
