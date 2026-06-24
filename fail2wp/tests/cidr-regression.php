<?php
/**
 * Compare the Fail2WP CIDR adapter with the bundled implementation.
 */
require_once dirname( __DIR__ ) . '/includes/class-fail2wp-cidr.php';
require_once dirname( __DIR__ ) . '/includes/class-fail2wp-cidr-matcher.php';

$legacy = new \fail2wpCIDRmatch\CIDRmatch();
$adapter = new \fail2wp\Fail2WP_Cidr_Matcher();
$cases = [
    [ '127.0.0.1', '127.0.0.0/8', true ],
    [ '192.168.1.25', '192.168.1.0/24', true ],
    [ '192.168.2.25', '192.168.1.0/24', false ],
    [ '192.168.1.25', '0.0.0.0/0', true ],
    [ '2001:db8::1', '2001:db8::/32', true ],
    [ '2001:db9::1', '2001:db8::/32', false ],
    [ '2001:db8::1', '::/0', true ],
    [ '192.168.1.25', '2001:db8::/32', false ],
    [ '2001:db8::1', '192.168.1.0/24', false ],
    [ '192.168.1.25', '192.168.1.0/33', false ],
    [ '2001:db8::1', '2001:db8::/129', false ],
    [ 'invalid', '192.168.1.0/24', false ],
];

foreach ( $cases as $case ) {
    $legacy_result = (bool) $legacy->match( $case[0], $case[1] );
    $adapter_result = $adapter->match( $case[0], $case[1] );
    if ( $legacy_result !== $case[2] || $adapter_result !== $legacy_result ) {
        fwrite( STDERR, 'CIDR regression failed for ' . $case[0] . ' in ' . $case[1] . "\n" );
        exit( 1 );
    }
}

echo "CIDR regression checks passed\n";
