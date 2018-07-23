<?php

/*
Plugin Name: Auto Expire Passwords
Description: Force admin and super admins to change their passwords every 90 days.
Version: 1.0
Author: Miller Media LLC
Author URI: http://www.millermedia.io
Network: true

Adapted from http://github.com/telegraph/Expire-User-Passwords / https://wordpress.org/plugins/auto-expire-passwords/
to change reset period to 90 days and only for admins and super admins.
*/

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * If we're in the WordPress Admin, hook into profile update
 *
 * @return void
 */
function mm_aep_admin() {
	if ( is_admin() ) {
		add_action( 'user_profile_update_errors', 'mm_aep_profile_update', 11, 3 );
	}
}
add_action( 'init', 'mm_aep_admin' );

/**
 * When user successfully changes their password, set the timestamp in user meta.
 *
 * @param WP_Error $errors Errors, by ref.
 * @param bool $update Unknown, by ref.
 * @param object $user User object, by ref.
 *
 * @return void
 */
function mm_aep_profile_update( $errors, $update, $user ) {
	// Bail out if there are errors attached to the change password profile field,
	// or if the password is not being changed.
	if ( $errors->get_error_data( 'pass' ) || empty( $_POST['pass1'] ) || empty( $_POST['pass2'] ) ) {
		return;
	}

	// Store timestamp
	update_user_meta( $user->ID, 'mm_password_reset', time() );
}

/**
 * When user successfully resets their password, re-set the timestamp.
 *
 * @param object $user User object
 *
 * @return void
 */
function mm_aep_password_reset( $user ) {
	update_user_meta( $user->ID, 'mm_password_reset', time() );
}
add_action( 'password_reset', 'mm_aep_password_reset' );

/**
 * When the user logs in, check that their meta timestamp is still in the allowed range.
 * If it isn't, prevent log in.
 *
 * @param WP_Error|WP_User $user WP_User object if login was successful, otherwise WP_Error object.
 * @param string $username
 * @param string $password
 *
 * @return WP_Error|WP_User WP_User object if login was successful and had not expired, otherwise WP_Error object.
 */
function mm_aep_handle_log_in( $user ) {
	// Check if an error has already been set
	if ( is_wp_error( $user ) ) {
		return $user;
	}

	// Check we're dealing with a WP_User object
	if ( ! is_a( $user, 'WP_User' ) ) {
		return $user;
	}

	// Get the user id
	$user_id = $user->data->ID;

	// We only want to deal with admins or super-admins
	if ( ! in_array( 'administrator', (array) $user->roles ) && ! is_super_admin( $user_id ) ) {
	    return $user;
	}

	// find when the last reset was
	$lastReset = (int) get_user_meta( $user_id, 'mm_password_reset', true );

	// If no reset recorded, it's probably the user's first login attempt since this plugin was installed, so set the timestamp to now
	if ( empty( $lastReset ) ) {
		$lastReset = time();
		update_user_meta( $user_id, 'mm_password_reset', $lastReset );
		return $user;
	}

	// How long since they last reset?
	$diff = time() - $lastReset;

	// 60 (seconds) * 60 (minutes) * 24 (hours) * 90 (days) = 7,776,000
	$login_expiry = 7776000;

	// Check if more than 90 days
	if ( $diff >= $login_expiry ) {
		// Create a login error
		$user = new WP_Error( 'authentication_failed', sprintf( __( '<strong>ERROR</strong>: You must <a href="%s">reset your password</a>.', 'mm_aep' ), site_url( 'wp-login.php?action=lostpassword', 'login' ) ) );
	}

	return $user;
}
add_filter( 'authenticate', 'mm_aep_handle_log_in', 30, 1 );
