<?php
/**
 * Regression coverage for administrator-monitor snapshot comparison.
 */
define( 'ABSPATH', dirname( __DIR__, 2 ) . '/' );

require_once dirname( __DIR__ ) . '/includes/class-fail2wp-admin-user-monitor.php';

use fail2wp\Fail2WP_Admin_User_Monitor;

$baseline = Fail2WP_Admin_User_Monitor::normalize_snapshot( array(
    (object) array( 'ID' => 2, 'user_login' => 'editorial-admin' ),
    (object) array( 'ID' => 1, 'user_login' => 'site-admin' ),
) );
if ( $baseline !== array( 1 => 'site-admin', 2 => 'editorial-admin' ) ) {
    throw new RuntimeException( 'Administrator snapshot normalization failed.' );
}
if ( Fail2WP_Admin_User_Monitor::normalize_snapshot( array( 1 => 'site-admin', 2 => 'editorial-admin' ) ) !== $baseline ) {
    throw new RuntimeException( 'Stored administrator snapshot normalization failed.' );
}
$current = array( 1 => 'site-admin', 3 => 'new-admin' );
$changes = Fail2WP_Admin_User_Monitor::compare( $baseline, $current );
if ( $changes['added'] !== array( 3 => 'new-admin' ) || $changes['removed'] !== array( 2 => 'editorial-admin' ) || ! Fail2WP_Admin_User_Monitor::has_changes( $changes ) ) {
    throw new RuntimeException( 'Administrator snapshot comparison failed.' );
}
if ( Fail2WP_Admin_User_Monitor::has_changes( Fail2WP_Admin_User_Monitor::compare( $baseline, $baseline ) ) ) {
    throw new RuntimeException( 'Equal administrator snapshots were reported as changed.' );
}

echo "Administrator-monitor regression checks passed\n";
