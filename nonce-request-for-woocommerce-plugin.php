<?php
/**
 *
 * This file is read by WordPress to generate the plugin information in the plugin
 * admin area. This file also includes all of the dependencies used by the plugin,
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin.
 *
 * @since             1.0.0
 * @package           Plugin_Name
 *
 * @wordpress-plugin
 * Plugin Name:       Nonce Request for Woocommerce Plugin
 * Description:       Generate WP nonce using woocommerce AUTH (tested on Woocommerce v.7.0.1)
 * Version:           1.0.0
 * Author:            Ecommerceado
 * Author URI:        https://www.facebook.com/ecommerceado
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       nonce-request-for-woocommerce-plugin
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Currently plugin version.
 */
define( 'PLUGIN_NAME_VERSION', '1.0.0' );

/**
 * Begins execution of the plugin.
 *
 * Since everything within the plugin is registered via hooks,
 * then kicking off the plugin from this point in the file does
 * not affect the page life cycle.
 *
 * @since    1.0.0
 */

defined('ABSPATH') or die();

class nonce_request_for_woocommerce_plugin {
    public function __construct() {
        $this->add_api_route();
    }

    function add_api_route() {
        // Getting Nonce with Woocommerce AUTH
        add_action( 'rest_api_init', function () {
            register_rest_route('nonce-request', '/get', array(
                'methods' => 'GET',
                'callback' => array($this, 'generate_nonce'),
                'permission_callback' => array($this, 'rest_auth')
            ));
        } );
    }

    function generate_nonce() {
        $nonce = wp_create_nonce( 'wc_store_api' );
        $results = array(
            'response'  => array(
                'nonce' => $nonce
            )
        );

        echo json_encode($results);
    }

    // validate woocommerce auth keys
    function rest_auth() {
        global $wpdb;
        
        // Woocommerce WC REST AUTH
        $wc_rest = new WC_REST_Authentication();

        $params = $wc_rest->get_oauth_parameters();

        $consumer_key   = $params['oauth_consumer_key'];
		$consumer_key   = wc_api_hash( sanitize_text_field( $consumer_key ) );

		$user           = $wpdb->get_row(
			$wpdb->prepare(
				"
			SELECT key_id, user_id, permissions, consumer_key, consumer_secret, nonces
			FROM {$wpdb->prefix}woocommerce_api_keys
			WHERE consumer_key = %s
		",
				$consumer_key
			)
		);

        // Perform OAuth validation.
		$signature = $this->check_oauth_signature( $user, $params );
        if ($signature) {
            return true;
        }

        return false;
    }

    // copied and modified source woocommerce v.7.0.1
    private function check_oauth_signature( $user, $params ) {
		$http_method  = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : ''; // WPCS: sanitization ok.
		$request_path = isset( $_SERVER['REQUEST_URI'] ) ? wp_parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ) : ''; // WPCS: sanitization ok.
		$wp_base      = get_home_url( null, '/', 'relative' );
		if ( substr( $request_path, 0, strlen( $wp_base ) ) === $wp_base ) {
			$request_path = substr( $request_path, strlen( $wp_base ) );
		}
		$base_request_uri = rawurlencode( get_home_url( null, $request_path, is_ssl() ? 'https' : 'http' ) );

		// Get the signature provided by the consumer and remove it from the parameters prior to checking the signature.
		$consumer_signature = rawurldecode( str_replace( ' ', '+', $params['oauth_signature'] ) );
		unset( $params['oauth_signature'] );

		// Sort parameters.
		if ( ! uksort( $params, 'strcmp' ) ) {
			return false;
		}

		// Normalize parameter key/values.
		$params         = $this->normalize_parameters( $params );
		$query_string   = implode( '%26', $this->join_with_equals_sign( $params ) ); // Join with ampersand.
		$string_to_sign = $http_method . '&' . $base_request_uri . '&' . $query_string;

		if ( 'HMAC-SHA1' !== $params['oauth_signature_method'] && 'HMAC-SHA256' !== $params['oauth_signature_method'] ) {
			return false;
		}

		$hash_algorithm = strtolower( str_replace( 'HMAC-', '', $params['oauth_signature_method'] ) );
		$secret         = $user->consumer_secret . '&';
		$signature      = base64_encode( hash_hmac( $hash_algorithm, $string_to_sign, $secret, true ) );

		if ( ! hash_equals( $signature, $consumer_signature ) ) { // @codingStandardsIgnoreLine
			return false;
		}

		return true;
	}

    private function join_with_equals_sign( $params, $query_params = array(), $key = '' ) {
		foreach ( $params as $param_key => $param_value ) {
			if ( $key ) {
				$param_key = $key . '%5B' . $param_key . '%5D'; // Handle multi-dimensional array.
			}

			if ( is_array( $param_value ) ) {
				$query_params = $this->join_with_equals_sign( $param_value, $query_params, $param_key );
			} else {
				$string         = $param_key . '=' . $param_value; // Join with equals sign.
				$query_params[] = wc_rest_urlencode_rfc3986( $string );
			}
		}

		return $query_params;
	}

    private function normalize_parameters( $parameters ) {
		$keys       = wc_rest_urlencode_rfc3986( array_keys( $parameters ) );
		$values     = wc_rest_urlencode_rfc3986( array_values( $parameters ) );
		$parameters = array_combine( $keys, $values );

		return $parameters;
	}
}

if (class_exists('nonce_request_for_woocommerce_plugin')) {
    $endpoint = new nonce_request_for_woocommerce_plugin();
}
?>