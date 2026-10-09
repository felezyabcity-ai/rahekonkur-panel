<?php
/**
 * Plugin Name: راه کنکور — پل پرتال (RKSP Bridge)
 * Description: لایه‌ی احراز هویت توکنی و CORS برای پرتال دانش‌آموز روی ساب‌دامین. افزونه‌ی rksp دست‌نخورده می‌ماند.
 * Version: 2.5.1
 * Author: راه کنکور
 * Requires PHP: 7.2
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

if ( ! defined( 'RKSPB_PANEL_ORIGIN' ) ) { define( 'RKSPB_PANEL_ORIGIN', 'https://panel.rahekonkur.ir' ); }
if ( ! defined( 'RKSPB_NS' ) )           { define( 'RKSPB_NS', 'rkspb/v1' ); }
if ( ! defined( 'RKSPB_META' ) )         { define( 'RKSPB_META', '_rkspb_tokens' ); }
if ( ! defined( 'RKSPB_TTL' ) )          { define( 'RKSPB_TTL', 60 * 60 * 24 * 30 ); }
if ( ! defined( 'RKSPB_MAX_DEVICES' ) )  { define( 'RKSPB_MAX_DEVICES', 8 ); }

/* ---------------------------------------------------------------- CORS -- */

if ( ! function_exists( 'rkspb_allowed_origins' ) ) {
	function rkspb_allowed_origins() {
		$list = array( RKSPB_PANEL_ORIGIN, home_url() );
		if ( defined( 'RKSPB_EXTRA_ORIGINS' ) && RKSPB_EXTRA_ORIGINS ) {
			$list = array_merge( $list, array_map( 'trim', explode( ',', RKSPB_EXTRA_ORIGINS ) ) );
		}
		$list = array_map( 'untrailingslashit', array_filter( $list ) );
		return array_values( array_unique( $list ) );
	}
}

if ( ! function_exists( 'rkspb_send_cors' ) ) {
	function rkspb_send_cors( $value ) {
		$origin = get_http_origin();
		if ( $origin && in_array( untrailingslashit( $origin ), rkspb_allowed_origins(), true ) ) {
			header( 'Access-Control-Allow-Origin: ' . esc_url_raw( $origin ) );
			header( 'Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS' );
			header( 'Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With, X-WP-Nonce, X-RKSP-Token' );
			header( 'Access-Control-Allow-Credentials: true' );
			header( 'Access-Control-Max-Age: 86400' );
			header( 'Vary: Origin' );
		}
		return $value;
	}
}

add_action( 'rest_api_init', function () {
	remove_filter( 'rest_pre_serve_request', 'rest_send_cors_headers' );
	add_filter( 'rest_pre_serve_request', 'rkspb_send_cors', 15 );
}, 15 );

/* --------------------------------------------------------------- TOKEN -- */

if ( ! function_exists( 'rkspb_bearer_token' ) ) {
	function rkspb_bearer_token() {
		$hdr = '';
		if ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$hdr = wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] );
		} elseif ( isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) {
			$hdr = wp_unslash( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] );
		} elseif ( function_exists( 'apache_request_headers' ) ) {
			$all = apache_request_headers();
			if ( is_array( $all ) ) {
				foreach ( $all as $k => $v ) {
					if ( 'authorization' === strtolower( $k ) ) { $hdr = $v; break; }
				}
			}
		}
		if ( ! $hdr && isset( $_SERVER['HTTP_X_RKSP_TOKEN'] ) ) {
			$hdr = 'Bearer ' . wp_unslash( $_SERVER['HTTP_X_RKSP_TOKEN'] );
		}
		if ( $hdr && preg_match( '/Bearer\s+(\S+)/i', $hdr, $m ) ) { return $m[1]; }
		return '';
	}
}

if ( ! function_exists( 'rkspb_issue_token' ) ) {
	function rkspb_issue_token( $user_id ) {
		$user_id = absint( $user_id );
		if ( ! $user_id ) { return ''; }
		$secret = wp_generate_password( 48, false, false );
		$tokens = get_user_meta( $user_id, RKSPB_META, true );
		if ( ! is_array( $tokens ) ) { $tokens = array(); }
		$now = time();
		foreach ( $tokens as $k => $t ) {
			if ( empty( $t['exp'] ) || $t['exp'] < $now ) { unset( $tokens[ $k ] ); }
		}
		$tokens   = array_values( $tokens );
		$tokens[] = array( 'h' => hash( 'sha256', $secret ), 'exp' => $now + RKSPB_TTL, 'iat' => $now );
		if ( count( $tokens ) > RKSPB_MAX_DEVICES ) {
			$tokens = array_slice( $tokens, -RKSPB_MAX_DEVICES );
		}
		update_user_meta( $user_id, RKSPB_META, $tokens );
		return $user_id . '.' . $secret;
	}
}

if ( ! function_exists( 'rkspb_resolve_token' ) ) {
	function rkspb_resolve_token( $token ) {
		if ( ! $token || false === strpos( $token, '.' ) ) { return 0; }
		list( $uid, $secret ) = explode( '.', $token, 2 );
		$uid = absint( $uid );
		if ( ! $uid || ! $secret ) { return 0; }
		$tokens = get_user_meta( $uid, RKSPB_META, true );
		if ( ! is_array( $tokens ) ) { return 0; }
		$h   = hash( 'sha256', $secret );
		$now = time();
		foreach ( $tokens as $t ) {
			if ( ! empty( $t['h'] ) && hash_equals( (string) $t['h'], $h ) && ! empty( $t['exp'] ) && $t['exp'] > $now ) {
				return $uid;
			}
		}
		return 0;
	}
}

if ( ! function_exists( 'rkspb_revoke_token' ) ) {
	function rkspb_revoke_token( $token ) {
		if ( ! $token || false === strpos( $token, '.' ) ) { return false; }
		list( $uid, $secret ) = explode( '.', $token, 2 );
		$uid    = absint( $uid );
		$tokens = get_user_meta( $uid, RKSPB_META, true );
		if ( ! is_array( $tokens ) ) { return false; }
		$h    = hash( 'sha256', $secret );
		$keep = array();
		foreach ( $tokens as $t ) {
			if ( empty( $t['h'] ) || ! hash_equals( (string) $t['h'], $h ) ) { $keep[] = $t; }
		}
		update_user_meta( $uid, RKSPB_META, $keep );
		return true;
	}
}

add_filter( 'determine_current_user', function ( $user_id ) {
	if ( $user_id ) { return $user_id; }
	$token = rkspb_bearer_token();
	if ( ! $token ) { return $user_id; }
	$uid = rkspb_resolve_token( $token );
	return $uid ? $uid : $user_id;
}, 20 );

add_filter( 'rest_authentication_errors', function ( $result ) {
	if ( is_wp_error( $result ) && 'rest_cookie_invalid_nonce' === $result->get_error_code() && rkspb_bearer_token() ) {
		return true;
	}
	return $result;
}, 99 );

/* -------------------------------------------------------------- HELPERS -- */

if ( ! function_exists( 'rkspb_plugin_version' ) ) {
	/**
	 * نسخه را از هدر خود فایل می‌خواند، نه از یک رشته‌ی دستی.
	 * قبلاً `ping` نسخه‌ی ثابت ۱.۴.۱ می‌داد در حالی که افزونه ۲.۲.۰ بود —
	 * یعنی ابزار اصلی عیب‌یابی، دروغ می‌گفت.
	 */
	function rkspb_plugin_version() {
		$v = get_option( 'rkspb_plugin_version_cache' );
		$h = get_file_data( __FILE__, array( 'Version' => 'Version' ) );
		$v = ! empty( $h['Version'] ) ? $h['Version'] : ( $v ? $v : '0' );
		update_option( 'rkspb_plugin_version_cache', $v, false );
		return $v;
	}
}

if ( ! function_exists( 'rkspb_latin_digits' ) ) {
	/** ارقام فارسی و عربی را لاتین می‌کند ولی بقیه‌ی متن را دست‌نخورده نگه می‌دارد. */
	function rkspb_latin_digits( $value ) {
		$fa = array( '۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹' );
		$ar = array( '٠', '١', '٢', '٣', '٤', '٥', '٦', '٧', '٨', '٩' );
		$en = array( '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' );
		$value = str_replace( $fa, $en, (string) $value );
		return str_replace( $ar, $en, $value );
	}
}

if ( ! function_exists( 'rkspb_extract_otp' ) ) {
	/**
	 * کد تأیید را از متن پیامک بیرون می‌کشد.
	 *
	 * مهم: نباید اول همه‌ی غیرعددها حذف شوند، وگرنه «۲ دقیقه» به کد می‌چسبد
	 * و عدد اشتباهی فرستاده می‌شود.
	 */
	function rkspb_extract_otp( $text ) {
		$text = rkspb_latin_digits( $text );
		if ( ! preg_match_all( '/\d+/', $text, $m ) ) { return ''; }
		$runs = $m[0];
		// اول دنبال کدهای ۵ و ۶ رقمی، بعد ۴ و ۷ و ۸ رقمی.
		foreach ( array( 5, 6, 4, 7, 8 ) as $len ) {
			foreach ( $runs as $run ) {
				if ( strlen( $run ) === $len ) { return $run; }
			}
		}
		return '';
	}
}

if ( ! function_exists( 'rkspb_normalize_digits' ) ) {
	function rkspb_normalize_digits( $value ) {
		$value = trim( (string) $value );
		$fa    = array( '۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹' );
		$ar    = array( '٠', '١', '٢', '٣', '٤', '٥', '٦', '٧', '٨', '٩' );
		$en    = array( '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' );
		$value = str_replace( $fa, $en, $value );
		$value = str_replace( $ar, $en, $value );
		return preg_replace( '/\D/', '', $value );
	}
}

if ( ! function_exists( 'rkspb_throttle_key' ) ) {
	function rkspb_throttle_key( $what, $who ) {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '0';
		return 'rkspb_th_' . md5( $what . '|' . $who . '|' . $ip );
	}
}

if ( ! function_exists( 'rkspb_throttle_check' ) ) {
	/**
	 * قفل پس از چند تلاش ناموفق.
	 *
	 * کد تأیید چهار تا شش رقم است؛ بدون این قفل، با چند هزار درخواست
	 * می‌شد واردِ حساب هر دانش‌آموزی شد. ورود با رمز هم همین‌طور.
	 *
	 * @return true|WP_Error
	 */
	function rkspb_throttle_check( $what, $who, $max = 5, $window = 900 ) {
		$key = rkspb_throttle_key( $what, $who );
		$n   = (int) get_transient( $key );
		if ( $n >= $max ) {
			return new WP_Error(
				'rkspb_throttled',
				'تلاش‌های ناموفق زیاد بوده. چند دقیقه صبر کنید و دوباره امتحان کنید.',
				array( 'status' => 429 )
			);
		}
		return true;
	}
}

if ( ! function_exists( 'rkspb_throttle_fail' ) ) {
	function rkspb_throttle_fail( $what, $who, $window = 900 ) {
		$key = rkspb_throttle_key( $what, $who );
		$n   = (int) get_transient( $key );
		set_transient( $key, $n + 1, $window );
	}
}

if ( ! function_exists( 'rkspb_throttle_clear' ) ) {
	function rkspb_throttle_clear( $what, $who ) {
		delete_transient( rkspb_throttle_key( $what, $who ) );
	}
}

if ( ! function_exists( 'rkspb_normalize_mobile' ) ) {
	function rkspb_normalize_mobile( $mobile ) {
		$mobile = rkspb_normalize_digits( $mobile );
		if ( 0 === strpos( $mobile, '0098' ) ) {
			$mobile = '0' . substr( $mobile, 4 );
		} elseif ( 0 === strpos( $mobile, '98' ) && 12 === strlen( $mobile ) ) {
			$mobile = '0' . substr( $mobile, 2 );
		} elseif ( 10 === strlen( $mobile ) && '9' === substr( $mobile, 0, 1 ) ) {
			$mobile = '0' . $mobile;
		}
		return $mobile;
	}
}

if ( ! function_exists( 'rkspb_mobile_meta_keys' ) ) {
	function rkspb_mobile_meta_keys() {
		return apply_filters( 'rkspb_mobile_meta_keys', array( 'rksp_mobile', 'mobile', 'billing_phone', 'digits_phone_no', 'phone' ) );
	}
}

if ( ! function_exists( 'rkspb_find_user_by_mobile' ) ) {
	function rkspb_find_user_by_mobile( $mobile ) {
		$mobile = rkspb_normalize_mobile( $mobile );
		if ( 11 !== strlen( $mobile ) ) { return null; }
		$user = get_user_by( 'login', $mobile );
		if ( $user ) { return $user; }
		foreach ( rkspb_mobile_meta_keys() as $key ) {
			$found = get_users( array( 'meta_key' => $key, 'meta_value' => $mobile, 'number' => 1 ) );
			if ( ! empty( $found ) ) { return $found[0]; }
		}
		return null;
	}
}

if ( ! function_exists( 'rkspb_user_mobile' ) ) {
	function rkspb_user_mobile( $user ) {
		foreach ( rkspb_mobile_meta_keys() as $key ) {
			$val = get_user_meta( $user->ID, $key, true );
			if ( $val ) { return rkspb_normalize_mobile( $val ); }
		}
		$login = rkspb_normalize_mobile( $user->user_login );
		return 11 === strlen( $login ) ? $login : '';
	}
}

if ( ! function_exists( 'rkspb_user_payload' ) ) {
	function rkspb_user_payload( $user ) {
		if ( ! $user instanceof WP_User ) { return null; }
		if ( in_array( 'rksp_student', (array) $user->roles, true ) ) {
			$role = 'student';
		} elseif ( in_array( 'rksp_mentor', (array) $user->roles, true ) ) {
			$role = 'mentor';
		} elseif ( in_array( 'rksp_sales_manager', (array) $user->roles, true ) ) {
			$role = 'sales_manager';
		} elseif ( in_array( 'rksp_mentor_manager', (array) $user->roles, true ) ) {
			$role = 'mentor_manager';
		} elseif ( in_array( 'rksp_sales', (array) $user->roles, true ) ) {
			$role = 'sales';
		} elseif ( user_can( $user, 'manage_options' ) ) {
			$role = 'admin';
		} else {
			$roles = (array) $user->roles;
			$role  = (string) reset( $roles );
		}

		$payload = array(
			'id'     => (int) $user->ID,
			'name'   => $user->display_name ? $user->display_name : $user->user_login,
			'mobile' => rkspb_user_mobile( $user ),
			'role'   => $role,
			'email'  => $user->user_email,
			'grade'  => (string) get_user_meta( $user->ID, 'rksp_grade', true ),
			'field'  => (string) get_user_meta( $user->ID, 'rksp_field', true ),
			'city'   => (string) get_user_meta( $user->ID, 'rksp_city', true ),
			'avatar' => get_avatar_url( $user->ID, array( 'size' => 96 ) ),
			'must_change_password' => (bool) get_user_meta( $user->ID, 'rkspb_force_pw', true ),
		);

		if ( 'mentor' === $role ) {
			global $wpdb;
			$table = $wpdb->prefix . 'rksp_mentors';
			if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table ) {
				$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$table}` WHERE user_id = %d LIMIT 1", $user->ID ), ARRAY_A );
				if ( $row ) {
					$payload['specialty']  = isset( $row['specialty'] ) ? (string) $row['specialty'] : '';
					$payload['experience'] = isset( $row['experience'] ) ? (string) $row['experience'] : '';
					$payload['mentor_id']  = isset( $row['id'] ) ? (int) $row['id'] : 0;
				}
			}
		}

		return $payload;
	}
}

if ( ! function_exists( 'rkspb_proxy' ) ) {
	/**
	 * Dispatch an internal request to the existing rksp REST routes,
	 * so the business logic stays in one place.
	 */
	function rkspb_proxy( $method, $route, $params ) {
		$req = new WP_REST_Request( strtoupper( $method ), $route );
		$req->set_header( 'Content-Type', 'application/json' );
		foreach ( (array) $params as $k => $v ) { $req->set_param( $k, $v ); }
		return rest_do_request( $req );
	}
}

if ( ! function_exists( 'rkspb_user_id_from_response' ) ) {
	function rkspb_user_id_from_response( $response ) {
		$uid = get_current_user_id();
		if ( $uid ) { return $uid; }
		if ( $response instanceof WP_REST_Response ) {
			$data = $response->get_data();
			if ( is_array( $data ) ) {
				foreach ( array( 'user_id', 'id', 'ID' ) as $key ) {
					if ( isset( $data[ $key ] ) && absint( $data[ $key ] ) ) { return absint( $data[ $key ] ); }
				}
				if ( isset( $data['user'] ) && is_array( $data['user'] ) ) {
					foreach ( array( 'id', 'ID', 'user_id' ) as $key ) {
						if ( isset( $data['user'][ $key ] ) && absint( $data['user'][ $key ] ) ) { return absint( $data['user'][ $key ] ); }
					}
				}
			}
		}
		return 0;
	}
}

if ( ! function_exists( 'rkspb_auth_success' ) ) {
	function rkspb_auth_success( $user_id, $extra = array() ) {
		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			return new WP_Error( 'rkspb_no_user', 'کاربر پیدا نشد.', array( 'status' => 404 ) );
		}
		$payload = array(
			'token'      => rkspb_issue_token( $user_id ),
			'expires_in' => RKSPB_TTL,
			'user'       => rkspb_user_payload( $user ),
		);
		return rest_ensure_response( array_merge( $payload, (array) $extra ) );
	}
}

/* --------------------------------------------------------------- ROUTES -- */

add_action( 'rest_api_init', function () {

	register_rest_route( RKSPB_NS, '/ping', array(
		'methods'             => 'GET',
		'permission_callback' => '__return_true',
		'callback'            => function () {
			return rest_ensure_response( array(
				'ok'      => true,
				'version' => rkspb_plugin_version(),
				'origins' => rkspb_allowed_origins(),
				'user'    => get_current_user_id() ? rkspb_user_payload( wp_get_current_user() ) : null,
			) );
		},
	) );

	register_rest_route( RKSPB_NS, '/login', array(
		'methods'             => 'POST',
		'permission_callback' => '__return_true',
		'callback'            => function ( WP_REST_Request $req ) {
			$mobile   = rkspb_normalize_mobile( $req->get_param( 'mobile' ) );
			$password = (string) $req->get_param( 'password' );
			if ( 11 !== strlen( $mobile ) || '' === $password ) {
				return new WP_Error( 'rkspb_bad_input', 'شماره موبایل یا رمز عبور وارد نشده است.', array( 'status' => 400 ) );
			}
			$gate = rkspb_throttle_check( 'login', $mobile, 8 );
			if ( is_wp_error( $gate ) ) { return $gate; }
			$user = rkspb_find_user_by_mobile( $mobile );
			if ( ! $user || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
				rkspb_throttle_fail( 'login', $mobile );
				return new WP_Error( 'rkspb_bad_credentials', 'شماره موبایل یا رمز عبور درست نیست.', array( 'status' => 401 ) );
			}
			rkspb_throttle_clear( 'login', $mobile );
			return rkspb_auth_success( $user->ID );
		},
	) );

	register_rest_route( RKSPB_NS, '/logout', array(
		'methods'             => 'POST',
		'permission_callback' => '__return_true',
		'callback'            => function () {
			rkspb_revoke_token( rkspb_bearer_token() );
			return rest_ensure_response( array( 'ok' => true ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/me', array(
		'methods'             => 'GET',
		'permission_callback' => function () { return is_user_logged_in(); },
		'callback'            => function () {
			return rest_ensure_response( array( 'user' => rkspb_user_payload( wp_get_current_user() ) ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/change-password', array(
		'methods'             => 'POST',
		'permission_callback' => function () { return is_user_logged_in(); },
		'callback'            => function ( WP_REST_Request $req ) {
			$user    = wp_get_current_user();
			$current = (string) $req->get_param( 'current_password' );
			$new     = (string) $req->get_param( 'new_password' );

			if ( '' === $current || ! wp_check_password( $current, $user->user_pass, $user->ID ) ) {
				return new WP_Error( 'rkspb_bad_current', 'رمز عبور فعلی درست نیست.', array( 'status' => 401 ) );
			}
			if ( strlen( $new ) < 8 ) {
				return new WP_Error( 'rkspb_weak', 'رمز جدید باید حداقل ۸ کاراکتر باشد.', array( 'status' => 400 ) );
			}
			if ( $new === $current ) {
				return new WP_Error( 'rkspb_same', 'رمز جدید با رمز فعلی یکی است.', array( 'status' => 400 ) );
			}
			if ( preg_match( '/^\d+$/', $new ) ) {
				return new WP_Error( 'rkspb_numeric', 'رمز فقط از عدد تشکیل نشود؛ حرف هم داشته باشد.', array( 'status' => 400 ) );
			}

			wp_set_password( $new, $user->ID );
			delete_user_meta( $user->ID, RKSPB_META );          // خروج از همه‌ی دستگاه‌های دیگر
			delete_user_meta( $user->ID, 'rkspb_force_pw' );    // دیگر اجباری نیست

			return rest_ensure_response( array(
				'ok'         => true,
				'token'      => rkspb_issue_token( $user->ID ),
				'expires_in' => RKSPB_TTL,
			) );
		},
	) );

	register_rest_route( RKSPB_NS, '/otp/request', array(
		'methods'             => 'POST',
		'permission_callback' => '__return_true',
		'callback'            => function ( WP_REST_Request $req ) {
			$mobile = rkspb_normalize_mobile( $req->get_param( 'mobile' ) );

			// اگر همین چند لحظه پیش کدی برای این شماره ساخته و فرستاده شده، کدِ تازه نساز.
			// فقط اعتبارش را تمدید کن و همان را معتبر نگه دار. جلوی «دو کد، دو پیامک،
			// فقط یکی معتبر» را می‌گیرد.
			$recent = rkspb_recent_otp( $mobile );
			if ( $recent ) {
				rkspb_extend_otp_expiry( $mobile );
				return rest_ensure_response( array(
					'ok'         => true,
					'mobile'     => $mobile,
					'sent'       => true,
					'throttled'  => true,
					'expires_in' => (int) RKSPB_OTP_TTL,
					'message'    => 'کد تایید پیامکی ارسال شد.',
				) );
			}

			$res    = rkspb_proxy( 'POST', '/rksp/v1/otp/request', array( 'mobile' => $mobile, 'phone' => $mobile ) );
			if ( is_wp_error( $res ) ) { return $res; }
			if ( $res->is_error() ) { return rest_ensure_response( $res ); }
			$up = (array) $res->get_data();
			return rest_ensure_response( array(
				'ok'             => true,
				'mobile'         => $mobile,
				'sent'           => ! empty( $up['sent'] ),
				'expires_in'     => isset( $up['expires_in'] ) ? (int) $up['expires_in'] : 120,
				'is_new_student' => ! empty( $up['is_new_student'] ),
				'upstream'       => $up,
			) );
		},
	) );

	register_rest_route( RKSPB_NS, '/otp/verify', array(
		'methods'             => 'POST',
		'permission_callback' => '__return_true',
		'callback'            => function ( WP_REST_Request $req ) {
			$mobile = rkspb_normalize_mobile( $req->get_param( 'mobile' ) );
			$code   = rkspb_normalize_digits( $req->get_param( 'code' ) );
			$gate   = rkspb_throttle_check( 'otp', $mobile );
			if ( is_wp_error( $gate ) ) { return $gate; }
			$res    = rkspb_proxy( 'POST', '/rksp/v1/otp/verify', array(
				'mobile' => $mobile,
				'phone'  => $mobile,
				'code'   => $code,
				'otp'    => $code,
			) );
			if ( is_wp_error( $res ) ) { return $res; }
			if ( $res->is_error() ) {
				rkspb_throttle_fail( 'otp', $mobile );
				return rest_ensure_response( $res );
			}
			rkspb_throttle_clear( 'otp', $mobile );
			$uid = rkspb_user_id_from_response( $res );
			if ( ! $uid ) {
				$user = rkspb_find_user_by_mobile( $mobile );
				$uid  = $user ? $user->ID : 0;
			}
			if ( ! $uid ) {
				// شماره تأیید شد ولی هنوز حساب ندارد: کلاینت باید مرحله‌ی ثبت‌نام را نشان بدهد.
				// تأیید را خودمان نگه می‌داریم تا کاربر مجبور نشود هر بار کد تازه بگیرد.
				rkspb_mark_verified( $mobile );
				return rest_ensure_response( array(
					'verified'       => true,
					'registered'     => false,
					'is_new_student' => true,
					'mobile'         => $mobile,
				) );
			}
			rkspb_mark_verified( $mobile );
			$out = rkspb_auth_success( $uid, array( 'verified' => true, 'registered' => true, 'is_new_student' => false ) );
			return $out;
		},
	) );

	register_rest_route( RKSPB_NS, '/register', array(
		'methods'             => 'POST',
		'permission_callback' => '__return_true',
		'callback'            => function ( WP_REST_Request $req ) {
			$params = (array) $req->get_json_params();
			if ( empty( $params ) ) { $params = (array) $req->get_body_params(); }
			$params['mobile'] = rkspb_normalize_mobile( isset( $params['mobile'] ) ? $params['mobile'] : '' );
			$params['phone']  = $params['mobile'];
			if ( 11 !== strlen( $params['mobile'] ) ) {
				return new WP_Error( 'rkspb_bad_mobile', 'شماره موبایل معتبر نیست.', array( 'status' => 400 ) );
			}
			if ( rkspb_find_user_by_mobile( $params['mobile'] ) ) {
				return new WP_Error( 'rkspb_exists', 'با این شماره قبلاً ثبت‌نام شده است. وارد شوید.', array( 'status' => 409 ) );
			}
			// افزونه‌ی اصلی برای ثبت‌نام، کد ملی و جنسیت و یک reg_token ده‌دقیقه‌ای می‌خواهد
			// که پرتال هیچ‌کدام را ندارد. به‌جای آن، خودمان حساب را می‌سازیم. تأییدِ شماره
			// را هم خودمان نگه داشته‌ایم، پس کاربر برای هر تلاش کد تازه نمی‌خواهد.
			if ( ! rkspb_is_verified( $params['mobile'] ) ) {
				return new WP_Error(
					'rkspb_not_verified',
					'ابتدا شماره‌ی موبایل را با کد پیامکی تأیید کنید.',
					array( 'status' => 403 )
				);
			}

			$made = rkspb_create_student( $params );
			if ( empty( $made['ok'] ) ) {
				$first = $made['errors'] ? reset( $made['errors'] ) : 'ثبت‌نام انجام نشد.';
				return new WP_Error( 'rkspb_register_failed', $first, array( 'status' => 400, 'errors' => $made['errors'] ) );
			}

			rkspb_clear_verified( $params['mobile'] );
			return rkspb_auth_success( (int) $made['user_id'], array( 'registered' => true ) );
		},
	) );
} );

/* ------------------------------------------------------- OTP VIA PATTERN -- */
/*
 * افزونه‌ی rksp کد تأیید را با ارسال ساده می‌فرستد و کلیدش هم پذیرفته نمی‌شود.
 * اینجا آن درخواست را می‌گیریم و به‌جایش از مسیر «الگو» می‌فرستیم، با همان
 * تنظیمات فراز که افزونه‌ی توزیع لید از قبل دارد و کار می‌کند.
 */

if ( ! defined( 'RKSPB_OTP_PATTERN' ) ) { define( 'RKSPB_OTP_PATTERN', 'Uy6wWEA28o' ); }
if ( ! defined( 'RKSPB_OTP_VAR' ) )     { define( 'RKSPB_OTP_VAR', 'code' ); }
if ( ! defined( 'RKSPB_PATTERN_URL' ) ) { define( 'RKSPB_PATTERN_URL', 'https://api.iranpayamak.com/ws/v1/sms/pattern' ); }

if ( ! function_exists( 'rkspb_ld_settings' ) ) {
	/** تنظیمات افزونه‌ی توزیع لید که از قبل کار می‌کند. */
	function rkspb_ld_settings() {
		$names = array( 'ldfs_settings', 'ld_farazsms_settings', 'ldfs_options', 'ld_farazsms', 'ldfs' );
		foreach ( $names as $name ) {
			$o = get_option( $name );
			if ( is_array( $o ) && ! empty( $o['api_key'] ) ) { return $o; }
		}
		global $wpdb;
		$rows = $wpdb->get_results(
			"SELECT option_value FROM {$wpdb->options}
			 WHERE option_value LIKE '%pattern_code%' AND option_value LIKE '%api_key%' LIMIT 5"
		);
		foreach ( (array) $rows as $row ) {
			$v = maybe_unserialize( $row->option_value );
			if ( is_array( $v ) && ! empty( $v['api_key'] ) ) { return $v; }
		}
		return array();
	}
}

if ( ! function_exists( 'rkspb_sms_settings' ) ) {
	/**
	 * تنظیمات مؤثر پیامک. ترتیب اولویت:
	 * ۱) چیزی که در صفحه‌ی تنظیمات پیامک پرتال وارد شده
	 * ۲) تنظیمات افزونه‌ی توزیع لید
	 * ۳) ثابت‌های wp-config
	 */
	function rkspb_sms_settings() {
		$own = get_option( 'rkspb_sms_settings', array() );
		if ( ! is_array( $own ) ) { $own = array(); }
		$ld  = rkspb_ld_settings();

		$pick = function ( $key, $fallbacks ) use ( $own, $ld ) {
			if ( ! empty( $own[ $key ] ) ) { return $own[ $key ]; }
			if ( ! empty( $ld[ $key ] ) )  { return $ld[ $key ]; }
			foreach ( (array) $fallbacks as $const ) {
				if ( defined( $const ) && constant( $const ) ) { return constant( $const ); }
			}
			return '';
		};

		return array(
			'api_key'     => $pick( 'api_key', array( 'RKSP_FARAZ_API_KEY' ) ),
			'line_number' => $pick( 'line_number', array( 'RKSP_FARAZ_LINE' ) ),
			'otp_pattern' => ! empty( $own['otp_pattern'] ) ? $own['otp_pattern'] : ( defined( 'RKSPB_OTP_PATTERN' ) ? RKSPB_OTP_PATTERN : '' ),
			'otp_var'     => ! empty( $own['otp_var'] ) ? $own['otp_var'] : ( defined( 'RKSPB_OTP_VAR' ) ? RKSPB_OTP_VAR : 'code' ),
			'auth_scheme' => ! empty( $own['auth_scheme'] ) ? $own['auth_scheme'] : 'auto',
			'source'      => array(
				'api_key'     => ! empty( $own['api_key'] ) ? 'پرتال' : ( ! empty( $ld['api_key'] ) ? 'توزیع لید' : 'wp-config' ),
				'line_number' => ! empty( $own['line_number'] ) ? 'پرتال' : ( ! empty( $ld['line_number'] ) ? 'توزیع لید' : 'wp-config' ),
			),
		);
	}
}

if ( ! function_exists( 'rkspb_faraz_settings' ) ) {
	function rkspb_faraz_settings() {
		return rkspb_sms_settings();
	}
}

if ( ! function_exists( 'rkspb_auth_variants' ) ) {
	function rkspb_auth_variants( $key ) {
		return array(
			// شکلی که افزونه‌ی توزیع لید استفاده می‌کند و اثبات‌شده کار می‌کند.
			'Api-Key'   => array( 'Api-Key' => $key, 'Accept' => 'application/json' ),
			'bare'      => array( 'Authorization' => $key ),
			'AccessKey' => array( 'Authorization' => 'AccessKey ' . $key ),
			'Bearer'    => array( 'Authorization' => 'Bearer ' . $key ),
			'apikey'    => array( 'apikey' => $key ),
		);
	}
}

if ( ! defined( 'RKSPB_OTP_TTL' ) ) { define( 'RKSPB_OTP_TTL', 300 ); }

if ( ! defined( 'RKSPB_OTP_THROTTLE' ) ) { define( 'RKSPB_OTP_THROTTLE', 90 ); }

if ( ! function_exists( 'rkspb_recent_otp' ) ) {
	/**
	 * آخرین کدی که برای این شماره ساخته شده، اگر تازه باشد، برمی‌گرداند.
	 *
	 * دلیلِ وجود این تابع: اگر کلاینت (یا کاربری که دوبار روی دکمه می‌زند) دو بار
	 * درخواست بدهد، افزونه‌ی اصلی دو کدِ متفاوت می‌سازد و دو پیامک می‌فرستد، ولی فقط
	 * کدِ آخر معتبر است. کاربر کدِ پیامکِ اول را وارد می‌کند و خطای «کد صحیح نیست»
	 * می‌گیرد. با این تابع، درخواست دومِ نزدیک‌به‌هم اصلاً به افزونه‌ی اصلی نمی‌رسد.
	 *
	 * @return array|null آرایه‌ی سطر، یا null اگر کد تازه‌ای وجود نداشته باشد.
	 */
	function rkspb_recent_otp( $mobile, $seconds = RKSPB_OTP_THROTTLE ) {
		global $wpdb;
		$table = $wpdb->prefix . 'rksp_otp';
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) { return null; }
		$seconds = max( 10, (int) $seconds );
		// created_at ممکن است به وقت UTC ذخیره شده باشد یا به وقت محلی؛ هر دو را می‌سنجیم.
		$row = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM `{$table}`
			 WHERE mobile = %s
			   AND (
			        ABS( TIMESTAMPDIFF( SECOND, created_at, UTC_TIMESTAMP() ) ) <= %d
			     OR ABS( TIMESTAMPDIFF( SECOND, created_at, NOW() ) ) <= %d
			   )
			 ORDER BY id DESC LIMIT 1",
			$mobile,
			$seconds,
			$seconds
		), ARRAY_A );
		return $row ? $row : null;
	}
}

if ( ! function_exists( 'rkspb_extend_otp_expiry' ) ) {
	/** اعتبار آخرین کد این شماره را تمدید می‌کند. */
	function rkspb_extend_otp_expiry( $mobile ) {
		global $wpdb;
		$table = $wpdb->prefix . 'rksp_otp';
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) { return; }
		$id = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM `{$table}` WHERE mobile = %s ORDER BY id DESC LIMIT 1", $mobile ) );
		if ( ! $id ) { return; }
		$wpdb->query( $wpdb->prepare(
			"UPDATE `{$table}` SET expires_at = DATE_ADD(NOW(), INTERVAL %d SECOND) WHERE id = %d",
			(int) RKSPB_OTP_TTL,
			(int) $id
		) );
	}
}

if ( ! function_exists( 'rkspb_send_pattern_sms' ) ) {
	/**
	 * یک کد تأیید را از مسیر الگو می‌فرستد و شکل احراز هویتِ کارآمد را کش می‌کند.
	 *
	 * @return array{ok:bool, scheme:string, status:int, body:string}
	 */
	function rkspb_send_pattern_sms( $mobile, $code ) {
		$cfg = rkspb_sms_settings();
		if ( empty( $cfg['api_key'] ) || empty( $cfg['line_number'] ) ) {
			return array( 'ok' => false, 'scheme' => '', 'status' => 0, 'body' => 'faraz settings not found' );
		}

		$payload = wp_json_encode( array(
			'code'          => $cfg['otp_pattern'],
			'recipient'     => $mobile,
			'line_number'   => $cfg['line_number'],
			'number_format' => 'english',
			'attributes'    => array( $cfg['otp_var'] => (string) $code ),
		) );

		$variants = rkspb_auth_variants( $cfg['api_key'] );
		if ( 'auto' !== $cfg['auth_scheme'] && isset( $variants[ $cfg['auth_scheme'] ] ) ) {
			$variants = array( $cfg['auth_scheme'] => $variants[ $cfg['auth_scheme'] ] );
		}
		$cached = get_option( 'rkspb_sms_scheme', '' );
		if ( $cached && isset( $variants[ $cached ] ) ) {
			$variants = array_merge( array( $cached => $variants[ $cached ] ), $variants );
		}

		$last = array( 'ok' => false, 'scheme' => '', 'status' => 0, 'body' => '' );
		foreach ( $variants as $name => $headers ) {
			$res = wp_remote_post( RKSPB_PATTERN_URL, array(
				'timeout' => 20,
				'headers' => array_merge( array( 'Content-Type' => 'application/json' ), $headers ),
				'body'    => $payload,
			) );
			if ( is_wp_error( $res ) ) {
				$last = array( 'ok' => false, 'scheme' => $name, 'status' => 0, 'body' => $res->get_error_message() );
				continue;
			}
			$status = (int) wp_remote_retrieve_response_code( $res );
			$body   = substr( (string) wp_remote_retrieve_body( $res ), 0, 300 );
			$last   = array( 'ok' => ( $status >= 200 && $status < 300 ), 'scheme' => $name, 'status' => $status, 'body' => $body );
			if ( $last['ok'] ) {
				update_option( 'rkspb_sms_scheme', $name, false );
				return $last;
			}
			if ( 401 !== $status && 403 !== $status ) { return $last; }
		}
		return $last;
	}
}

/*
 * مسیر مستقیم و مطمئن برای فرستادن کد.
 *
 * افزونه‌ی rksp کد را با اکشن `rksp_send_sms` اعلام می‌کند و خودش کاری نمی‌کند؛
 * فرستادن بر عهده‌ی هندلری است که به این اکشن وصل شده باشد. هندلر داخلیِ خودش
 * (`rksp_farazsms_send_otp`) به ارسال ساده می‌زند و کلید را در هدر نمی‌گذارد،
 * پس همیشه ۴۰۱ می‌گیرد — و اگر شرط‌های بارگذاری‌اش برقرار نباشد، اصلاً وصل
 * نمی‌شود و هیچ درخواستی بیرون نمی‌رود. در آن حالت فیلتر `pre_http_request`
 * ما هم چیزی برای گرفتن ندارد و پیامک بی‌صدا ارسال نمی‌شود.
 *
 * اینجا مستقیم به همان اکشن وصل می‌شویم. کد را خودِ اکشن به ما می‌دهد، پس نه
 * به متن پیامک وابسته‌ایم، نه به ثابت RKSP_SMS_PROVIDER، نه به هندلر داخلی.
 */

if ( ! function_exists( 'rkspb_handle_send_sms' ) ) {
	function rkspb_handle_send_sms( $mobile, $code, $purpose = '' ) {
		$mobile = rkspb_normalize_mobile( $mobile );
		$code   = rkspb_normalize_digits( $code );
		if ( 11 !== strlen( $mobile ) || '' === $code ) { return; }

		// پنجره‌ی ۱۲۰ ثانیه‌ای rksp برای ایران کوتاه است؛ تمدیدش می‌کنیم.
		rkspb_extend_otp_expiry( $mobile );

		$sent = rkspb_send_pattern_sms( $mobile, $code );
		update_option( 'rkspb_last_sms', array(
			'time'    => time(),
			'ok'      => ! empty( $sent['ok'] ),
			'scheme'  => $sent['scheme'],
			'status'  => $sent['status'],
			'body'    => $sent['body'],
			'via'     => 'hook',
			'purpose' => (string) $purpose,
		), false );
	}
}
add_action( 'rksp_send_sms', 'rkspb_handle_send_sms', 5, 3 );

// هندلر داخلیِ افزونه را برمی‌داریم تا پیامک دوباره (و شکست‌خورده) فرستاده نشود.
add_action( 'init', function () {
	remove_action( 'rksp_send_sms', 'rksp_farazsms_send_otp', 10 );
}, 99 );

/* درخواست ارسال ساده‌ی rksp را می‌گیریم و به مسیر الگو می‌بریم. */
add_filter( 'pre_http_request', function ( $pre, $args, $url ) {
	if ( false === strpos( (string) $url, 'iranpayamak.com' ) ) { return $pre; }
	if ( false === strpos( (string) $url, '/sms/simple' ) ) { return $pre; }
	if ( ! RKSPB_OTP_PATTERN ) { return $pre; }

	$body = array();
	if ( ! empty( $args['body'] ) && is_string( $args['body'] ) ) {
		$decoded = json_decode( $args['body'], true );
		if ( is_array( $decoded ) ) { $body = $decoded; }
	}
	$text = isset( $body['text'] ) ? (string) $body['text'] : '';
	$to   = '';
	if ( ! empty( $body['recipients'] ) && is_array( $body['recipients'] ) ) {
		$to = rkspb_normalize_mobile( reset( $body['recipients'] ) );
	} elseif ( ! empty( $body['recipient'] ) ) {
		$to = rkspb_normalize_mobile( $body['recipient'] );
	}
	if ( 11 !== strlen( $to ) ) { return $pre; }

	// کد را از متن بیرون می‌کشیم بدون اینکه ارقام دیگرِ متن به آن بچسبند.
	$otp = rkspb_extract_otp( $text );
	if ( '' === $otp ) { return $pre; }

	// پنجره‌ی ۱۲۰ ثانیه‌ای rksp برای ایران کوتاه است؛ تمدیدش می‌کنیم.
	rkspb_extend_otp_expiry( $to );

	$sent = rkspb_send_pattern_sms( $to, $otp );
	update_option( 'rkspb_last_sms', array(
		'time'   => time(),
		'ok'     => ! empty( $sent['ok'] ),
		'scheme' => $sent['scheme'],
		'status' => $sent['status'],
		'body'   => $sent['body'],
	), false );

	// پاسخ ساختگی تا rksp روند خودش را طبیعی ادامه بدهد.
	return array(
		'headers'  => array(),
		'body'     => wp_json_encode( array( 'status' => $sent['ok'] ? 'ok' : 'error', 'via' => 'rkspb-pattern' ) ),
		'response' => array( 'code' => $sent['ok'] ? 200 : 502, 'message' => $sent['ok'] ? 'OK' : 'Bad Gateway' ),
		'cookies'  => array(),
		'filename' => null,
	);
}, 10, 3 );

/* ------------------------------------------------------- SMS AUTH FIX ---- */
/*
 * افزونه‌ی rksp کلید فراز را با defined() چک می‌کند ولی هرگز در درخواست نمی‌گذارد،
 * پس سرویس همیشه 401 می‌دهد. اینجا هدر را سر راه تزریق می‌کنیم تا افزونه دست‌نخورده بماند.
 */
if ( ! function_exists( 'rkspb_inject_sms_auth' ) ) {
	function rkspb_inject_sms_auth( $args, $url ) {
		if ( false === strpos( (string) $url, 'iranpayamak.com' ) ) { return $args; }
		if ( ! defined( 'RKSP_FARAZ_API_KEY' ) || ! constant( 'RKSP_FARAZ_API_KEY' ) ) { return $args; }
		if ( ! isset( $args['headers'] ) || ! is_array( $args['headers'] ) ) { $args['headers'] = array(); }
		$has_auth = false;
		foreach ( array_keys( $args['headers'] ) as $k ) {
			if ( 'authorization' === strtolower( $k ) ) { $has_auth = true; break; }
		}
		if ( ! $has_auth ) {
			$scheme = defined( 'RKSPB_SMS_AUTH_SCHEME' ) ? constant( 'RKSPB_SMS_AUTH_SCHEME' ) : 'AccessKey ';
			$args['headers']['Authorization'] = $scheme . constant( 'RKSP_FARAZ_API_KEY' );
		}
		return $args;
	}
}
add_filter( 'http_request_args', 'rkspb_inject_sms_auth', 10, 2 );

/* ---------------------------------------------------------- DIAGNOSTICS -- */
/* فقط برای مدیر سایت. هیچ مقدار محرمانه‌ای برنمی‌گرداند. */

add_action( 'rest_api_init', function () {

	register_rest_route( RKSPB_NS, '/diag/sms', array(
		'methods'             => 'POST',
		'permission_callback' => function () { return current_user_can( 'manage_options' ); },
		'callback'            => function ( WP_REST_Request $req ) {

			$out = array(
				'constants' => array(
					'RKSP_SMS_PROVIDER' => defined( 'RKSP_SMS_PROVIDER' ),
					'RKSP_FARAZ_API_KEY' => defined( 'RKSP_FARAZ_API_KEY' ) && (bool) constant( 'RKSP_FARAZ_API_KEY' ),
					'RKSP_FARAZ_LINE'    => defined( 'RKSP_FARAZ_LINE' ) && (bool) constant( 'RKSP_FARAZ_LINE' ),
				),
				'provider'  => defined( 'RKSP_SMS_PROVIDER' ) ? constant( 'RKSP_SMS_PROVIDER' ) : null,
			);

			if ( empty( $out['constants']['RKSP_FARAZ_API_KEY'] ) || empty( $out['constants']['RKSP_FARAZ_LINE'] ) ) {
				$out['verdict'] = 'missing_constant';
				return rest_ensure_response( $out );
			}

			$mobile = rkspb_normalize_mobile( $req->get_param( 'mobile' ) );
			if ( 11 !== strlen( $mobile ) ) {
				$out['verdict'] = 'no_mobile_supplied';
				return rest_ensure_response( $out );
			}

			// مسیر واقعی را تست می‌کنیم: الگو، با تنظیمات فرازِ افزونه‌ی لید.
			$cfg = rkspb_faraz_settings();
			$out['faraz_settings_found'] = ! empty( $cfg['api_key'] );
			$out['has_line']             = ! empty( $cfg['line_number'] );
			$out['pattern']              = RKSPB_OTP_PATTERN;

			if ( empty( $cfg['api_key'] ) ) {
				$out['verdict'] = 'faraz_settings_not_found';
				return rest_ensure_response( $out );
			}

			$sent = rkspb_send_pattern_sms( $mobile, '12345' );
			$out['scheme']      = $sent['scheme'];
			$out['http_status'] = $sent['status'];
			$out['raw_body']    = $sent['body'];
			$out['verdict']     = $sent['ok'] ? 'pattern_sent' : 'pattern_failed';
			$out['last_sms']    = get_option( 'rkspb_last_sms', null );
			return rest_ensure_response( $out );
		},
	) );
} );

/* --------------------------------------------------- DATA MANAGER (ADMIN) -- */
/*
 * افزونه‌ی rksp هیچ امکان ویرایش یا حذفی ندارد. این صفحه آن کمبود را پر می‌کند
 * بدون اینکه به ساختار ستون‌ها وابسته باشد: هر جدول rksp_ را می‌خواند و
 * فرم ویرایش را از روی ستون‌های واقعی همان جدول می‌سازد.
 */

/* ------------------------------------------------- VERIFIED-MOBILE MEMORY -- */
/*
 * افزونه‌ی اصلی بعد از تأیید کد یک reg_token می‌سازد که فقط ۱۰ دقیقه زنده است و
 * با اولین استفاده پاک می‌شود. نتیجه‌اش این بود که کاربر مدام پیام «زمان تایید
 * شماره تمام شده» می‌گرفت و مجبور می‌شد دوباره کد بگیرد. ما تأیید را خودمان و
 * با مهلت طولانی نگه می‌داریم.
 */

if ( ! defined( 'RKSPB_VERIFIED_TTL' ) ) { define( 'RKSPB_VERIFIED_TTL', 24 * HOUR_IN_SECONDS ); }

if ( ! function_exists( 'rkspb_verified_key' ) ) {
	function rkspb_verified_key( $mobile ) {
		return 'rkspb_vok_' . md5( (string) $mobile );
	}
}

if ( ! function_exists( 'rkspb_mark_verified' ) ) {
	function rkspb_mark_verified( $mobile ) {
		set_transient( rkspb_verified_key( $mobile ), 1, RKSPB_VERIFIED_TTL );
	}
}

if ( ! function_exists( 'rkspb_is_verified' ) ) {
	function rkspb_is_verified( $mobile ) {
		return (bool) get_transient( rkspb_verified_key( $mobile ) );
	}
}

if ( ! function_exists( 'rkspb_clear_verified' ) ) {
	function rkspb_clear_verified( $mobile ) {
		delete_transient( rkspb_verified_key( $mobile ) );
	}
}

if ( ! function_exists( 'rkspb_split_name' ) ) {
	/** «علی محمدی رضایی» → array( 'علی', 'محمدی رضایی' ) */
	function rkspb_split_name( $full ) {
		$full  = trim( preg_replace( '/\s+/u', ' ', (string) $full ) );
		if ( '' === $full ) { return array( '', '' ); }
		$parts = explode( ' ', $full );
		$first = array_shift( $parts );
		return array( $first, implode( ' ', $parts ) );
	}
}

if ( ! function_exists( 'rkspb_create_student' ) ) {
	/**
	 * حساب دانش‌آموز را می‌سازد: کاربر وردپرس + سطر در جدول دانش‌آموزان.
	 * ستون‌ها از روی جدول واقعی خوانده می‌شود، پس به نسخه‌ی افزونه گره نخورده.
	 *
	 * @return array{ok:bool, errors:array, user_id:int}
	 */
	function rkspb_create_student( $in ) {
		global $wpdb;
		$errors = array();

		$mob = rkspb_normalize_mobile( isset( $in['mobile'] ) ? $in['mobile'] : '' );
		$pass = (string) ( isset( $in['password'] ) ? $in['password'] : '' );

		list( $first, $last ) = rkspb_split_name( isset( $in['name'] ) ? $in['name'] : '' );
		if ( isset( $in['first_name'] ) && '' !== trim( (string) $in['first_name'] ) ) {
			$first = sanitize_text_field( trim( (string) $in['first_name'] ) );
		}
		if ( isset( $in['last_name'] ) && '' !== trim( (string) $in['last_name'] ) ) {
			$last = sanitize_text_field( trim( (string) $in['last_name'] ) );
		}
		$first = sanitize_text_field( $first );
		$last  = sanitize_text_field( $last );

		if ( '' === $first ) { $errors['name'] = 'نام و نام خانوادگی را وارد کنید.'; }
		if ( 11 !== strlen( $mob ) || '09' !== substr( $mob, 0, 2 ) ) {
			$errors['mobile'] = 'شماره موبایل باید ۱۱ رقم و با ۰۹ شروع شود.';
		} elseif ( rkspb_find_user_by_mobile( $mob ) ) {
			$errors['mobile'] = 'با این شماره قبلاً حساب ساخته شده است. وارد شوید.';
		}
		// رمز اختیاری است: اگر خالی باشد، ورود با کد پیامکی انجام می‌شود.
		if ( '' === $pass ) {
			$pass = wp_generate_password( 20, true, false );
		} elseif ( strlen( $pass ) < 6 ) {
			$errors['password'] = 'رمز عبور حداقل ۶ کاراکتر باشد.';
		}

		if ( ! empty( $errors ) ) { return array( 'ok' => false, 'errors' => $errors, 'user_id' => 0 ); }

		$login = 'student_' . $mob;
		$n = 1;
		while ( username_exists( $login ) ) { $login = 'student_' . $mob . '_' . ( ++$n ); }

		$email = $login . '@' . wp_parse_url( home_url(), PHP_URL_HOST );
		if ( email_exists( $email ) ) { $email = ''; }

		$user_args = array(
			'user_login'   => $login,
			'user_pass'    => $pass,
			'first_name'   => $first,
			'last_name'    => $last,
			'display_name' => trim( $first . ' ' . $last ),
			'role'         => 'rksp_student',
		);
		if ( $email ) { $user_args['user_email'] = $email; }

		$user_id = wp_insert_user( $user_args );
		if ( is_wp_error( $user_id ) ) {
			return array( 'ok' => false, 'errors' => array( 'wp' => $user_id->get_error_message() ), 'user_id' => 0 );
		}

		update_user_meta( $user_id, 'rksp_mobile', $mob );

		$table = rkspb_table_name( 'students' );
		if ( $table ) {
			$names = wp_list_pluck( rkspb_table_columns( $table ), 'name' );
			$vals  = array(
				'user_id'       => $user_id,
				'mobile'        => $mob,
				'first_name'    => $first,
				'last_name'     => $last,
				'national_code' => isset( $in['national_code'] ) ? sanitize_text_field( $in['national_code'] ) : '',
				'gender'        => isset( $in['gender'] ) ? sanitize_text_field( $in['gender'] ) : '',
				'province'      => isset( $in['province'] ) ? sanitize_text_field( $in['province'] ) : '',
				'city'          => isset( $in['city'] ) ? sanitize_text_field( $in['city'] ) : '',
				'field'         => isset( $in['field'] ) ? sanitize_text_field( $in['field'] ) : ( isset( $in['major'] ) ? sanitize_text_field( $in['major'] ) : '' ),
				'grade'         => isset( $in['grade'] ) ? sanitize_text_field( $in['grade'] ) : '',
				'created_at'    => current_time( 'mysql', true ),
			);
			$row = array();
			foreach ( $vals as $col => $v ) {
				if ( in_array( $col, $names, true ) ) { $row[ $col ] = $v; }
			}
			foreach ( array( 'full_name', 'name', 'display_name' ) as $nameCol ) {
				if ( in_array( $nameCol, $names, true ) ) { $row[ $nameCol ] = trim( $first . ' ' . $last ); break; }
			}
			if ( in_array( 'status', $names, true ) ) { $row['status'] = 'active'; }
			if ( ! empty( $row ) ) { $wpdb->insert( $table, $row ); }
			$student_id = (int) $wpdb->insert_id;

			// اتصال اختیاری به مشاور
			$mentor_id = isset( $in['mentor_id'] ) ? (int) $in['mentor_id'] : 0;
			if ( $student_id && $mentor_id ) {
				$atable = rkspb_table_name( 'assignments' );
				if ( $atable ) {
					$anames = wp_list_pluck( rkspb_table_columns( $atable ), 'name' );
					$arow   = array();
					if ( in_array( 'student_id', $anames, true ) ) { $arow['student_id'] = $student_id; }
					if ( in_array( 'mentor_id', $anames, true ) )  { $arow['mentor_id'] = $mentor_id; }
					if ( in_array( 'created_at', $anames, true ) ) { $arow['created_at'] = current_time( 'mysql', true ); }
					if ( in_array( 'status', $anames, true ) )     { $arow['status'] = 'active'; }
					if ( count( $arow ) >= 2 ) { $wpdb->insert( $atable, $arow ); }
				}
			}
		}

		return array( 'ok' => true, 'errors' => array(), 'user_id' => (int) $user_id );
	}
}

if ( ! function_exists( 'rkspb_tables' ) ) {
	function rkspb_tables() {
		return array(
			'students'     => 'دانش‌آموزان',
			'mentors'      => 'مشاوران',
			'assignments'  => 'اتصال دانش‌آموز به مشاور',
			'tasks'        => 'تکالیف',
			'study_logs'   => 'ساعت‌های مطالعه',
			'milestones'   => 'نقاط عطف',
			'mentor_notes' => 'یادداشت‌های مشاور',
			'plans'        => 'پلن‌ها',
			'channels'     => 'راه‌های ارتباطی',
			'otp'          => 'کدهای تأیید',
		);
	}
}

if ( ! function_exists( 'rkspb_table_name' ) ) {
	function rkspb_table_name( $slug ) {
		global $wpdb;
		$allowed = rkspb_tables();
		if ( ! isset( $allowed[ $slug ] ) ) { return ''; }
		return $wpdb->prefix . 'rksp_' . $slug;
	}
}

if ( ! function_exists( 'rkspb_table_columns' ) ) {
	function rkspb_table_columns( $table ) {
		global $wpdb;
		$cols = $wpdb->get_results( "SHOW COLUMNS FROM `{$table}`" );
		$out  = array();
		foreach ( (array) $cols as $c ) {
			$out[] = array( 'name' => $c->Field, 'key' => ( 'PRI' === $c->Key ), 'type' => $c->Type );
		}
		return $out;
	}
}

if ( ! function_exists( 'rkspb_readonly_views' ) ) {
	/**
	 * تب‌های فقط‌خواندنی. عمداً ویرایش‌پذیر نیستند: مشاور فروش کاربر وردپرس است
	 * و باید از «کاربران» مدیریت شود، و ویرایش دستی مبلغ فیش بعد از تأیید یعنی
	 * عددِ تسویه بی‌سروصدا عوض شود.
	 */
	function rkspb_readonly_views() {
		return array(
			'sales_users'   => 'مشاوران فروش',
			'payments_view' => 'فیش‌های واریزی',
		);
	}
}

if ( ! function_exists( 'rkspb_render_sales_view' ) ) {
	function rkspb_render_sales_view() {
		$users = rkspb_sales_users();
		echo '<h2>مشاوران فروش</h2>';
		echo '<p style="color:#666">این‌ها ردیف جدول نیستند، کاربر وردپرس با نقش «مشاور فروش»‌اند. ساخت و فعال/غیرفعال کردنشان در پنل است؛ تغییر نام و موبایل یا حذف کامل، در بخش «کاربران» وردپرس.</p>';
		if ( ! $users ) {
			echo '<p>هنوز مشاور فروشی ساخته نشده است. از پنل: داشبورد مدیر ← تب کارکنان.</p>';
			return;
		}
		echo '<table class="widefat striped"><thead><tr><th>نام</th><th>موبایل</th><th>درصد</th><th>وضعیت</th><th>فیش تأییدشده</th><th>در انتظار</th><th>ساخته شده</th><th></th></tr></thead><tbody>';
		foreach ( $users as $u ) {
			$sum    = rkspb_sales_payments_summary( $u->ID, '2000-01-01', '2100-01-01' );
			$paused = get_user_meta( $u->ID, 'rkspb_sales_paused', true );
			printf(
				'<tr><td><b>%s</b></td><td dir="ltr">%s</td><td>%s٪</td><td style="color:%s">%s</td><td>%s فیش · %s</td><td>%s فیش · %s</td><td>%s</td><td><a class="button button-small" href="%s">ویرایش کاربر</a></td></tr>',
				esc_html( $u->display_name ),
				esc_html( rkspb_user_mobile( $u ) ),
				esc_html( rkspb_fa_digits( (string) rkspb_share_percent( $u->ID, true ) ) ),
				$paused ? '#b32d2e' : '#1a7f37',
				$paused ? 'غیرفعال' : 'فعال',
				esc_html( rkspb_fa_digits( $sum['approved_count'] ) ),
				esc_html( number_format_i18n( $sum['approved_amount'] ) ),
				esc_html( rkspb_fa_digits( $sum['pending_count'] ) ),
				esc_html( number_format_i18n( $sum['pending_amount'] ) ),
				esc_html( rkspb_jdate( substr( $u->user_registered, 0, 10 ) ) ),
				esc_url( admin_url( 'user-edit.php?user_id=' . $u->ID ) )
			);
		}
		echo '</tbody></table>';
	}
}

if ( ! function_exists( 'rkspb_render_payments_view' ) ) {
	function rkspb_render_payments_view() {
		global $wpdb;
		if ( '1.9.0' !== get_option( 'rkspb_pay_schema' ) ) {
			echo '<p>جدول فیش‌ها هنوز ساخته نشده. یک بار صفحه‌ی «فیش‌های واریزی» را باز کن.</p>';
			return;
		}
		$q  = isset( $_GET['q'] ) ? sanitize_text_field( wp_unslash( $_GET['q'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- فقط جستجو
		$pt = rkspb_payments_table();

		echo '<h2>فیش‌های واریزی</h2>';
		echo '<p style="color:#666">فقط خواندنی. برای پیدا کردن یک شماره پیگیری، همان را اینجا بنویس. تأیید و رد در پنل یا صفحه‌ی «فیش‌های واریزی» انجام می‌شود.</p>';
		echo '<form method="get" style="margin:12px 0"><input type="hidden" name="page" value="rkspb_data"><input type="hidden" name="t" value="payments_view">';
		echo '<input type="search" name="q" value="' . esc_attr( $q ) . '" placeholder="شماره پیگیری، موبایل یا نام" style="width:280px" dir="auto"> ';
		echo '<button class="button">جستجو</button>';
		if ( '' !== $q ) {
			echo ' <a class="button" href="' . esc_url( admin_url( 'admin.php?page=rkspb_data&t=payments_view' ) ) . '">پاک کردن</a>';
		}
		echo '</form>';

		if ( '' !== $q ) {
			$needle = '%' . $wpdb->esc_like( rkspb_latin_digits( $q ) ) . '%';
			$rows   = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$pt}` WHERE ref LIKE %s ORDER BY id DESC LIMIT 200", $needle ), ARRAY_A );
			if ( ! $rows ) {
				$ids = array();
				foreach ( rkspb_payments_query( array( 'limit' => 300 ) ) as $p ) {
					if ( false !== mb_stripos( $p['student_name'], $q ) || false !== strpos( $p['mobile'], rkspb_latin_digits( $q ) ) ) { $ids[] = $p['id']; }
				}
				$rows = array();
				if ( $ids ) {
					$in   = implode( ',', array_map( 'intval', $ids ) );
					$rows = $wpdb->get_results( "SELECT * FROM `{$pt}` WHERE id IN ({$in}) ORDER BY id DESC", ARRAY_A );
				}
			}
		} else {
			$rows = $wpdb->get_results( "SELECT * FROM `{$pt}` ORDER BY id DESC LIMIT 100", ARRAY_A );
		}

		if ( ! $rows ) {
			echo '<p>چیزی پیدا نشد.</p>';
			return;
		}
		$statuses = rkspb_payment_statuses();
		echo '<table class="widefat striped"><thead><tr><th>#</th><th>دانش‌آموز</th><th>مبلغ</th><th>شماره پیگیری</th><th>تاریخ واریز</th><th>طرح</th><th>ثبت‌کننده</th><th>وضعیت</th><th>تصمیم</th></tr></thead><tbody>';
		foreach ( $rows as $r ) {
			$p     = rkspb_payment_out( $r );
			$color = 'approved' === $p['status'] ? '#1a7f37' : ( 'rejected' === $p['status'] ? '#b32d2e' : '#9a6700' );
			printf(
				'<tr><td>%s</td><td>%s<br><small dir="ltr">%s</small></td><td>%s</td><td dir="ltr"><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td><td style="color:%s;font-weight:600">%s</td><td>%s</td></tr>',
				esc_html( rkspb_fa_digits( $p['id'] ) ),
				esc_html( $p['student_name'] ),
				esc_html( $p['mobile'] ),
				esc_html( number_format_i18n( $p['amount'] ) ),
				esc_html( $p['ref'] ),
				esc_html( rkspb_jdate( $p['paid_at'] ) ),
				$p['plan_id'] ? esc_html( rkspb_fa_digits( $p['plan_id'] ) ) : '—',
				esc_html( $p['created_name'] ),
				esc_attr( $color ),
				esc_html( isset( $statuses[ $p['status'] ] ) ? $statuses[ $p['status'] ] : $p['status'] ),
				esc_html( $p['decided_name'] ? $p['decided_name'] . ' · ' . rkspb_jdate( substr( $p['decided_at'], 0, 10 ) ) : '—' )
			);
		}
		echo '</tbody></table>';
	}
}

if ( ! function_exists( 'rkspb_render_audit_box' ) ) {
	/** دفتر تغییرات دستی، پایین صفحه‌ی مدیریت داده. */
	function rkspb_render_audit_box( $slug = '' ) {
		$rows = rkspb_audit_rows( 60, $slug );
		echo '<h2 style="margin-top:32px">دفتر تغییرات دستی</h2>';
		echo '<p style="color:#666">هر ویرایش یا حذفی که از همین صفحه انجام شود اینجا ثبت می‌شود. ثبت‌نام و فیش‌ها مسیر خودشان را دارند و اینجا نمی‌آیند.</p>';
		if ( ! $rows ) {
			echo '<p>هنوز تغییری ثبت نشده است.</p>';
			return;
		}
		$labels = rkspb_tables();
		echo '<table class="widefat striped"><thead><tr><th>زمان</th><th>کاربر</th><th>کار</th><th>جدول</th><th>ردیف</th><th>تغییر</th></tr></thead><tbody>';
		foreach ( $rows as $r ) {
			$act = array( 'edit' => 'ویرایش', 'delete' => 'حذف', 'truncate' => 'خالی کردن جدول' );
			$txt = '';
			$dec = json_decode( (string) $r['changes'], true );
			if ( 'edit' === $r['action'] && is_array( $dec ) ) {
				$bits = array();
				foreach ( $dec as $col => $pair ) {
					$bits[] = esc_html( $col ) . ': <s style="color:#999">' . esc_html( (string) $pair[0] ) . '</s> ← <b>' . esc_html( (string) $pair[1] ) . '</b>';
				}
				$txt = implode( '<br>', $bits );
			} elseif ( is_array( $dec ) ) {
				$txt = esc_html( mb_substr( wp_json_encode( $dec, JSON_UNESCAPED_UNICODE ), 0, 200 ) );
			}
			printf(
				'<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td style="font-size:12px">%s</td></tr>',
				esc_html( rkspb_jdate( substr( $r['created_at'], 0, 10 ) ) . ' ' . substr( $r['created_at'], 11, 5 ) ),
				esc_html( rkspb_user_label( $r['user_id'] ) ),
				esc_html( isset( $act[ $r['action'] ] ) ? $act[ $r['action'] ] : $r['action'] ),
				esc_html( isset( $labels[ $r['table_slug'] ] ) ? $labels[ $r['table_slug'] ] : $r['table_slug'] ),
				esc_html( $r['row_id'] ),
				$txt // phpcs:ignore WordPress.Security.EscapeOutput -- بالاتر esc شده
			);
		}
		echo '</tbody></table>';
	}
}

if ( ! function_exists( 'rkspb_primary_key' ) ) {
	function rkspb_primary_key( $cols ) {
		foreach ( $cols as $c ) { if ( $c['key'] ) { return $c['name']; } }
		return isset( $cols[0]['name'] ) ? $cols[0]['name'] : 'id';
	}
}

add_action( 'admin_menu', function () {
	add_menu_page(
		'مدیریت داده‌های پرتال',
		'مدیریت داده‌های پرتال',
		'manage_options',
		'rkspb_data',
		'rkspb_render_data_page',
		'dashicons-database',
		58
	);
	$pending = 0;
	global $wpdb;
	$t = rkspb_apps_table();
	if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $t ) ) === $t ) {
		$pending = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$t}` WHERE status = 'pending'" );
	}
	add_submenu_page(
		'rkspb_data',
		'تنظیمات پیامک',
		'تنظیمات پیامک',
		'manage_options',
		'rkspb_sms',
		'rkspb_render_sms_page'
	);
	add_submenu_page(
		'rkspb_data',
		'درخواست‌های همکاری',
		'درخواست‌های همکاری' . ( $pending ? ' <span class="update-plugins count-' . $pending . '"><span class="plugin-count">' . $pending . '</span></span>' : '' ),
		'manage_options',
		'rkspb_apps',
		'rkspb_render_apps_page'
	);
}, 20 );

if ( ! function_exists( 'rkspb_render_sms_page' ) ) {
	function rkspb_render_sms_page() {
		if ( ! current_user_can( 'manage_options' ) ) { return; }

		$notice = '';
		$result = null;

		if ( ! empty( $_POST['rkspb_sms_action'] ) ) {
			check_admin_referer( 'rkspb_sms' );
			$act = sanitize_key( wp_unslash( $_POST['rkspb_sms_action'] ) );

			if ( 'save' === $act ) {
				$own = array(
					'api_key'     => isset( $_POST['s_api_key'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['s_api_key'] ) ) ) : '',
					'line_number' => isset( $_POST['s_line_number'] ) ? rkspb_normalize_digits( wp_unslash( $_POST['s_line_number'] ) ) : '',
					'otp_pattern' => isset( $_POST['s_otp_pattern'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['s_otp_pattern'] ) ) ) : '',
					'otp_var'     => isset( $_POST['s_otp_var'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['s_otp_var'] ) ) ) : '',
					'auth_scheme' => isset( $_POST['s_auth_scheme'] ) ? sanitize_key( wp_unslash( $_POST['s_auth_scheme'] ) ) : 'auto',
				);
				update_option( 'rkspb_sms_settings', array_filter( $own, function ( $v ) { return '' !== $v; } ), false );
				delete_option( 'rkspb_sms_scheme' ); // کش شکل احراز هویت را پاک کن
				$notice = '<div class="notice notice-success"><p>تنظیمات ذخیره شد.</p></div>';
			}

			if ( 'test' === $act ) {
				$mobile = rkspb_normalize_mobile( isset( $_POST['t_mobile'] ) ? wp_unslash( $_POST['t_mobile'] ) : '' );
				$code   = rkspb_normalize_digits( isset( $_POST['t_code'] ) ? wp_unslash( $_POST['t_code'] ) : '' );
				if ( '' === $code ) { $code = (string) wp_rand( 10000, 99999 ); }
				if ( 11 !== strlen( $mobile ) ) {
					$notice = '<div class="notice notice-error"><p>شماره موبایل معتبر نیست.</p></div>';
				} else {
					$result = rkspb_send_pattern_sms( $mobile, $code );
					$result['sent_code']   = $code;
					$result['sent_mobile'] = $mobile;
				}
			}
		}

		$cfg = rkspb_sms_settings();
		$own = get_option( 'rkspb_sms_settings', array() );
		if ( ! is_array( $own ) ) { $own = array(); }

		$mask = function ( $v ) {
			$v = (string) $v;
			if ( '' === $v ) { return '—'; }
			return mb_substr( $v, 0, 4 ) . str_repeat( '•', max( 0, min( 12, mb_strlen( $v ) - 8 ) ) ) . mb_substr( $v, -4 );
		};

		echo '<div class="wrap" dir="rtl"><h1>تنظیمات پیامک پرتال</h1>';
		echo $notice; // phpcs:ignore WordPress.Security.EscapeOutput
		echo '<p style="color:#666;max-width:760px">هر فیلد را خالی بگذاری، از تنظیمات افزونه‌ی «پیامک فراز اس‌ام‌اس» یا ثابت‌های <code>wp-config.php</code> خوانده می‌شود. فقط وقتی پر کن که می‌خواهی برای پرتال مقدار متفاوتی استفاده شود.</p>';

		echo '<h2>وضعیت فعلی</h2><table class="widefat striped" style="max-width:760px;margin-bottom:24px"><tbody>';
		printf( '<tr><th style="width:200px">کلید API</th><td><code>%s</code> <span style="color:#888">(از %s)</span></td></tr>', esc_html( $mask( $cfg['api_key'] ) ), esc_html( $cfg['source']['api_key'] ) );
		printf( '<tr><th>سرشماره</th><td><code>%s</code> <span style="color:#888">(از %s)</span></td></tr>', esc_html( $cfg['line_number'] ? $cfg['line_number'] : '—' ), esc_html( $cfg['source']['line_number'] ) );
		printf( '<tr><th>کد الگوی کد تأیید</th><td><code>%s</code></td></tr>', esc_html( $cfg['otp_pattern'] ? $cfg['otp_pattern'] : '—' ) );
		printf( '<tr><th>نام متغیر الگو</th><td><code>%s</code></td></tr>', esc_html( $cfg['otp_var'] ) );
		printf( '<tr><th>شکل احراز هویت</th><td><code>%s</code>%s</td></tr>', esc_html( $cfg['auth_scheme'] ), ( get_option( 'rkspb_sms_scheme' ) ? ' <span style="color:#888">(آخرین شکل موفق: <code>' . esc_html( get_option( 'rkspb_sms_scheme' ) ) . '</code>)</span>' : '' ) );

		// آخرین ارسال واقعی — تا برای عیب‌یابی مجبور نباشی پیامک آزمایشی بفرستی.
		$last = get_option( 'rkspb_last_sms', null );
		if ( is_array( $last ) ) {
			$when = ! empty( $last['time'] ) ? human_time_diff( (int) $last['time'], time() ) . ' پیش' : '—';
			printf(
				'<tr><th>آخرین ارسال واقعی</th><td>%s — <code>%s</code> (HTTP %s، مسیر %s)<br><code style="direction:ltr;display:inline-block;max-width:60em;overflow:auto">%s</code></td></tr>',
				esc_html( $when ),
				empty( $last['ok'] ) ? 'ناموفق' : 'موفق',
				esc_html( (string) ( isset( $last['status'] ) ? $last['status'] : '—' ) ),
				esc_html( (string) ( isset( $last['via'] ) ? $last['via'] : 'filter' ) ),
				esc_html( substr( (string) ( isset( $last['body'] ) ? $last['body'] : '' ), 0, 300 ) )
			);
		} else {
			echo '<tr><th>آخرین ارسال واقعی</th><td style="color:#b32d2e">هنوز هیچ ارسالی از مسیر واقعی ثبت نشده — یعنی افزونه‌ی اصلی اصلاً به مرحله‌ی فرستادن نرسیده است.</td></tr>';
		}
		echo '</tbody></table>';

		echo '<h2>ویرایش</h2><form method="post"><table class="form-table" style="max-width:760px">';
		wp_nonce_field( 'rkspb_sms' );
		echo '<input type="hidden" name="rkspb_sms_action" value="save">';
		$rows = array(
			array( 's_api_key', 'کلید API فراز', isset( $own['api_key'] ) ? $own['api_key'] : '', 'خالی = همان کلید افزونه‌ی توزیع لید' ),
			array( 's_line_number', 'سرشماره (line_number)', isset( $own['line_number'] ) ? $own['line_number'] : '', 'مثلاً 90008361' ),
			array( 's_otp_pattern', 'کد الگوی کد تأیید', isset( $own['otp_pattern'] ) ? $own['otp_pattern'] : '', 'کد الگویی که در پنل فراز تأیید شده' ),
			array( 's_otp_var', 'نام متغیر الگو', isset( $own['otp_var'] ) ? $own['otp_var'] : '', 'باید دقیقاً با نام متغیر ثبت‌شده در پنل فراز یکی باشد' ),
		);
		foreach ( $rows as $r ) {
			printf(
				'<tr><th><label for="%1$s">%2$s</label></th><td><input class="regular-text" type="text" dir="ltr" id="%1$s" name="%1$s" value="%3$s"><p class="description">%4$s</p></td></tr>',
				esc_attr( $r[0] ), esc_html( $r[1] ), esc_attr( $r[2] ), esc_html( $r[3] )
			);
		}
		echo '<tr><th><label for="s_auth_scheme">شکل احراز هویت</label></th><td><select id="s_auth_scheme" name="s_auth_scheme">';
		foreach ( array(
			'auto'      => 'خودکار (هر چهار شکل امتحان می‌شود)',
			'bare'      => 'Authorization: <کلید>',
			'AccessKey' => 'Authorization: AccessKey <کلید>',
			'Bearer'    => 'Authorization: Bearer <کلید>',
			'apikey'    => 'هدر apikey',
			'Api-Key'   => 'هدر Api-Key (همانی که افزونه‌ی توزیع لید می‌زند)',
		) as $k => $label ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $k ), selected( $cfg['auth_scheme'], $k, false ), esc_html( $label ) );
		}
		echo '</select></td></tr></table>';
		submit_button( 'ذخیره‌ی تنظیمات' );
		echo '</form>';

		echo '<hr><h2>ارسال آزمایشی</h2>';
		echo '<p style="color:#666">یک پیامک واقعی با همین تنظیمات فرستاده می‌شود و پاسخ خام سرویس را می‌بینی.</p>';
		echo '<form method="post"><table class="form-table" style="max-width:760px">';
		wp_nonce_field( 'rkspb_sms' );
		echo '<input type="hidden" name="rkspb_sms_action" value="test">';
		echo '<tr><th><label for="t_mobile">شماره مقصد</label></th><td><input class="regular-text" type="text" dir="ltr" id="t_mobile" name="t_mobile" value="' . esc_attr( isset( $_POST['t_mobile'] ) ? sanitize_text_field( wp_unslash( $_POST['t_mobile'] ) ) : '' ) . '"></td></tr>';
		echo '<tr><th><label for="t_code">کد آزمایشی</label></th><td><input class="regular-text" type="text" dir="ltr" id="t_code" name="t_code" placeholder="خالی = عدد تصادفی"></td></tr>';
		echo '</table>';
		submit_button( 'ارسال پیامک آزمایشی', 'secondary' );
		echo '</form>';

		if ( $result ) {
			$ok = ! empty( $result['ok'] );
			printf(
				'<div class="notice %s" style="margin-top:16px"><p><strong>%s</strong></p></div>',
				$ok ? 'notice-success' : 'notice-error',
				$ok ? 'سرویس درخواست را پذیرفت.' : 'سرویس درخواست را رد کرد.'
			);
			echo '<table class="widefat striped" style="max-width:760px"><tbody>';
			printf( '<tr><th style="width:200px">شماره</th><td><code>%s</code></td></tr>', esc_html( $result['sent_mobile'] ) );
			printf( '<tr><th>کد ارسالی</th><td><code>%s</code></td></tr>', esc_html( $result['sent_code'] ) );
			printf( '<tr><th>شکل احراز هویت</th><td><code>%s</code></td></tr>', esc_html( $result['scheme'] ? $result['scheme'] : '—' ) );
			printf( '<tr><th>کد وضعیت HTTP</th><td><code>%s</code></td></tr>', esc_html( (string) $result['status'] ) );
			printf( '<tr><th>پاسخ خام سرویس</th><td><pre style="white-space:pre-wrap;direction:ltr;text-align:left;margin:0">%s</pre></td></tr>', esc_html( (string) $result['body'] ) );
			echo '</tbody></table>';
			echo '<p style="color:#666;max-width:760px;margin-top:12px">اگر اینجا نوشته سرویس پذیرفت ولی پیامک نرسید، مشکل سمت پنل فراز است: یا الگو هنوز فعال نشده، یا نام متغیر فرق دارد، یا سرشماره به این الگو وصل نیست. متن پاسخ خام را برای پشتیبانی فراز بفرست.</p>';
		}

		echo '</div>';
	}
}

if ( ! function_exists( 'rkspb_render_apps_page' ) ) {
	function rkspb_render_apps_page() {
		if ( ! current_user_can( 'manage_options' ) ) { return; }
		global $wpdb;
		rkspb_maybe_create_apps_table();
		$table  = rkspb_apps_table();
		$notice = '';

		if ( ! empty( $_POST['rkspb_app_action'] ) ) {
			check_admin_referer( 'rkspb_apps' );
			$id  = isset( $_POST['app_id'] ) ? absint( $_POST['app_id'] ) : 0;
			$act = sanitize_key( wp_unslash( $_POST['rkspb_app_action'] ) );
			$app = $id ? $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$table}` WHERE id = %d", $id ), ARRAY_A ) : null;

			if ( $app && 'approve' === $act ) {
				$username = 'm' . substr( $app['mobile'], 1 );
				$suffix   = 1;
				while ( username_exists( $username ) ) { $username = 'm' . substr( $app['mobile'], 1 ) . $suffix; $suffix++; }
				$password = wp_generate_password( 10, false, false );
				$made     = rkspb_create_mentor( array(
					'first_name' => $app['first_name'],
					'last_name'  => $app['last_name'],
					'mobile'     => $app['mobile'],
					'username'   => $username,
					'password'   => $password,
					'specialty'  => $app['specialty'],
				) );
				if ( $made['ok'] ) {
					$wpdb->update( $table, array( 'status' => 'approved' ), array( 'id' => $id ) );
					$notice = '<div class="notice notice-success"><p>حساب مشاور ساخته شد.<br>'
						. 'نام کاربری: <code>' . esc_html( $username ) . '</code> &nbsp;|&nbsp; '
						. 'رمز عبور: <code>' . esc_html( $password ) . '</code><br>'
						. '<strong>این رمز فقط همین یک بار نمایش داده می‌شود؛ الان برای مشاور بفرست.</strong></p></div>';
				} else {
					$notice = '<div class="notice notice-error"><p>ساخت حساب انجام نشد: '
						. esc_html( implode( ' / ', $made['errors'] ) ) . '</p></div>';
				}
			} elseif ( $app && 'reject' === $act ) {
				$wpdb->update( $table, array( 'status' => 'rejected' ), array( 'id' => $id ) );
				$notice = '<div class="notice notice-success"><p>درخواست رد شد.</p></div>';
			}
		}

		$filter = isset( $_GET['s'] ) ? sanitize_key( wp_unslash( $_GET['s'] ) ) : 'pending';
		$rows   = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$table}` WHERE status = %s ORDER BY id DESC LIMIT 200", $filter ), ARRAY_A );

		echo '<div class="wrap" dir="rtl"><h1>درخواست‌های همکاری</h1>';
		echo $notice; // phpcs:ignore WordPress.Security.EscapeOutput
		echo '<p style="color:#666">فرم عمومی با کد کوتاه <code>[rkspb_mentor_apply]</code> در هر برگه‌ای قابل قرار دادن است.</p>';

		echo '<h2 class="nav-tab-wrapper">';
		foreach ( array( 'pending' => 'در انتظار بررسی', 'approved' => 'تأییدشده', 'rejected' => 'ردشده' ) as $s => $label ) {
			$n = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$table}` WHERE status = %s", $s ) );
			printf(
				'<a href="%s" class="nav-tab %s">%s (%d)</a>',
				esc_url( admin_url( 'admin.php?page=rkspb_apps&s=' . $s ) ),
				$s === $filter ? 'nav-tab-active' : '',
				esc_html( $label ),
				$n
			);
		}
		echo '</h2>';

		if ( empty( $rows ) ) {
			echo '<p>موردی نیست.</p></div>';
			return;
		}

		foreach ( $rows as $r ) {
			echo '<div class="card" style="max-width:100%;margin:16px 0;padding:16px">';
			echo '<h3 style="margin:0 0 10px">' . esc_html( $r['first_name'] . ' ' . $r['last_name'] ) . '</h3>';
			echo '<table class="widefat striped" style="margin-bottom:12px"><tbody>';
			$show = array(
				'موبایل' => $r['mobile'],
				'رشته' => $r['specialty'],
				'مقاطع' => $r['grades'],
				'سابقه (سال)' => $r['experience'],
				'رتبه کنکور' => $r['konkur_rank'],
				'دانشگاه' => $r['university'],
				'رزومه / تلگرام' => $r['contact_link'],
				'درباره' => $r['about'],
				'پذیرش شرایط' => ( $r['terms_accepted'] ? 'بله — ' . $r['terms_time'] . ' از ' . $r['terms_ip'] : 'خیر' ),
				'تاریخ ثبت' => $r['created_at'],
			);
			foreach ( $show as $k => $val ) {
				echo '<tr><th style="width:160px">' . esc_html( $k ) . '</th><td>' . esc_html( (string) $val ) . '</td></tr>';
			}
			echo '</tbody></table>';

			if ( 'pending' === $r['status'] ) {
				echo '<form method="post" style="display:inline" onsubmit="return confirm(\'حساب مشاور ساخته شود؟\')">';
				wp_nonce_field( 'rkspb_apps' );
				echo '<input type="hidden" name="rkspb_app_action" value="approve">';
				echo '<input type="hidden" name="app_id" value="' . esc_attr( $r['id'] ) . '">';
				echo '<button class="button button-primary">تأیید و ساخت حساب</button></form> ';
				echo '<form method="post" style="display:inline" onsubmit="return confirm(\'این درخواست رد شود؟\')">';
				wp_nonce_field( 'rkspb_apps' );
				echo '<input type="hidden" name="rkspb_app_action" value="reject">';
				echo '<input type="hidden" name="app_id" value="' . esc_attr( $r['id'] ) . '">';
				echo '<button class="button">رد درخواست</button></form>';
			}
			echo '</div>';
		}
		echo '</div>';
	}
}

if ( ! function_exists( 'rkspb_handle_data_actions' ) ) {
	function rkspb_handle_data_actions() {
		if ( ! current_user_can( 'manage_options' ) ) { return ''; }
		if ( empty( $_POST['rkspb_action'] ) ) { return ''; }
		check_admin_referer( 'rkspb_data' );

		global $wpdb;
		$slug  = isset( $_POST['table'] ) ? sanitize_key( wp_unslash( $_POST['table'] ) ) : '';
		$table = rkspb_table_name( $slug );
		if ( ! $table ) { return '<div class="notice notice-error"><p>جدول نامعتبر است.</p></div>'; }

		$cols = rkspb_table_columns( $table );
		$pk   = rkspb_primary_key( $cols );
		$act  = sanitize_key( wp_unslash( $_POST['rkspb_action'] ) );

		if ( 'delete_row' === $act ) {
			$id = isset( $_POST['row_id'] ) ? sanitize_text_field( wp_unslash( $_POST['row_id'] ) ) : '';
			if ( '' === $id ) { return ''; }
			$before = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$table}` WHERE `{$pk}` = %s", $id ), ARRAY_A );
			$done   = $wpdb->delete( $table, array( $pk => $id ) );
			if ( $done && function_exists( 'rkspb_audit_log' ) ) { rkspb_audit_log( 'delete', $slug, $id, $before ); }
			return $done
				? '<div class="notice notice-success"><p>ردیف حذف شد.</p></div>'
				: '<div class="notice notice-error"><p>حذف انجام نشد.</p></div>';
		}

		if ( 'save_row' === $act ) {
			$id   = isset( $_POST['row_id'] ) ? sanitize_text_field( wp_unslash( $_POST['row_id'] ) ) : '';
			$data = array();
			foreach ( $cols as $c ) {
				if ( $c['name'] === $pk ) { continue; }
				$field = 'f_' . $c['name'];
				if ( ! isset( $_POST[ $field ] ) ) { continue; }
				$data[ $c['name'] ] = sanitize_textarea_field( wp_unslash( $_POST[ $field ] ) );
			}
			if ( empty( $data ) ) { return ''; }
			$before = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$table}` WHERE `{$pk}` = %s", $id ), ARRAY_A );
			$wpdb->update( $table, $data, array( $pk => $id ) );
			if ( function_exists( 'rkspb_audit_log' ) ) {
				$diff = array();
				foreach ( $data as $col => $new_val ) {
					$old_val = isset( $before[ $col ] ) ? (string) $before[ $col ] : '';
					if ( $old_val !== (string) $new_val ) { $diff[ $col ] = array( $old_val, (string) $new_val ); }
				}
				if ( $diff ) { rkspb_audit_log( 'edit', $slug, $id, $diff ); }
			}
			return '<div class="notice notice-success"><p>تغییرات ذخیره شد.</p></div>';
		}

		if ( 'empty_table' === $act ) {
			$confirm = isset( $_POST['confirm_text'] ) ? trim( (string) wp_unslash( $_POST['confirm_text'] ) ) : '';
			if ( 'حذف' !== $confirm && 'DELETE' !== strtoupper( $confirm ) ) {
				return '<div class="notice notice-warning"><p>برای خالی کردن جدول باید کلمه‌ی «حذف» را تایپ کنی.</p></div>';
			}
			$rows_n = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$table}`" );
			$wpdb->query( "TRUNCATE TABLE `{$table}`" );
			if ( function_exists( 'rkspb_audit_log' ) ) { rkspb_audit_log( 'truncate', $slug, '', array( 'rows' => $rows_n ) ); }
			return '<div class="notice notice-success"><p>جدول کاملاً خالی شد.</p></div>';
		}

		return '';
	}
}

/* ------------------------------------------- MENTOR APPLICATION (PUBLIC) -- */
/*
 * فرم عمومی درخواست همکاری. حساب نمی‌سازد — فقط درخواست ثبت می‌کند.
 * حساب مشاور تنها پس از تأیید دستی مدیر ساخته می‌شود.
 */

if ( ! function_exists( 'rkspb_apps_table' ) ) {
	function rkspb_apps_table() {
		global $wpdb;
		return $wpdb->prefix . 'rkspb_mentor_apps';
	}
}

if ( ! function_exists( 'rkspb_maybe_create_apps_table' ) ) {
	function rkspb_maybe_create_apps_table() {
		global $wpdb;
		$table = rkspb_apps_table();
		if ( get_option( 'rkspb_apps_table_v' ) === '1' ) { return; }
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		dbDelta( "CREATE TABLE {$table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			first_name VARCHAR(100) NOT NULL DEFAULT '',
			last_name VARCHAR(100) NOT NULL DEFAULT '',
			mobile VARCHAR(20) NOT NULL DEFAULT '',
			specialty VARCHAR(100) NOT NULL DEFAULT '',
			grades VARCHAR(190) NOT NULL DEFAULT '',
			experience VARCHAR(20) NOT NULL DEFAULT '',
			konkur_rank VARCHAR(60) NOT NULL DEFAULT '',
			university VARCHAR(190) NOT NULL DEFAULT '',
			about TEXT NULL,
			contact_link VARCHAR(255) NOT NULL DEFAULT '',
			terms_accepted TINYINT(1) NOT NULL DEFAULT 0,
			terms_time DATETIME NULL,
			terms_ip VARCHAR(45) NOT NULL DEFAULT '',
			status VARCHAR(20) NOT NULL DEFAULT 'pending',
			created_at DATETIME NULL,
			PRIMARY KEY (id),
			KEY mobile (mobile),
			KEY status (status)
		) {$charset};" );
		update_option( 'rkspb_apps_table_v', '1', false );
	}
}
add_action( 'admin_init', 'rkspb_maybe_create_apps_table' );

if ( ! function_exists( 'rkspb_client_ip' ) ) {
	function rkspb_client_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '';
		return substr( sanitize_text_field( $ip ), 0, 45 );
	}
}

if ( ! function_exists( 'rkspb_terms_text' ) ) {
	function rkspb_terms_text() {
		$default = "۱. تمام وجوه دریافتی از دانش‌آموز منحصراً به حساب موسسه واریز می‌شود؛ دریافت مستقیم وجه از دانش‌آموز یا خانواده‌ی او تحت هیچ عنوانی مجاز نیست.\n\n"
			. "۲. اطلاعات دانش‌آموزان — نام، شماره تماس، سوابق و گزارش‌ها — متعلق به موسسه است و صرفاً برای انجام وظایف در اختیار مشاور قرار می‌گیرد. نگهداری یا انتقال آن خارج از سامانه ممنوع است و این تعهد پس از پایان همکاری نیز ادامه دارد.\n\n"
			. "۳. مشاور متعهد می‌شود در طول همکاری و تا مدت توافق‌شده پس از آن، با دانش‌آموزانِ معرفی‌شده از سوی موسسه وارد رابطه‌ی مالی مستقل نشود. این تعهد فعالیت مستقل مشاور با دانش‌آموزان دیگر را محدود نمی‌کند.\n\n"
			. "۴. حق‌الزحمه به‌صورت درصدی از بسته‌ی هر دانش‌آموز فعال و به‌صورت ماهانه پرداخت می‌شود؛ مبنای محاسبه گزارش سامانه است.\n\n"
			. "۵. ثبت برنامه، پیگیری و یادداشت‌ها در سامانه بخشی از وظایف است، نه امری اختیاری.\n\n"
			. "۶. با توجه به اینکه بخش عمده‌ی دانش‌آموزان زیر هجده سال هستند، رعایت کامل شئون حرفه‌ای و پرهیز از هر ارتباط خارج از چارچوب آموزشی الزامی است.\n\n"
			. "۷. نقض بندهای بالا موجب فسخ فوری همکاری و مطالبه‌ی وجه التزام مقرر در قرارداد کتبی خواهد بود.\n\n"
			. "متن کامل قرارداد پیش از شروع همکاری در اختیار شما قرار می‌گیرد و امضا می‌شود.";
		return get_option( 'rkspb_terms_text', $default );
	}
}

if ( ! function_exists( 'rkspb_handle_application' ) ) {
	function rkspb_handle_application() {
		$out = array( 'ok' => false, 'errors' => array(), 'old' => array() );

		$get = function ( $k ) { return isset( $_POST[ $k ] ) ? sanitize_text_field( wp_unslash( $_POST[ $k ] ) ) : ''; };

		$data = array(
			'first_name'   => trim( $get( 'ma_first_name' ) ),
			'last_name'    => trim( $get( 'ma_last_name' ) ),
			'mobile'       => rkspb_normalize_mobile( $get( 'ma_mobile' ) ),
			'specialty'    => trim( $get( 'ma_specialty' ) ),
			'grades'       => trim( $get( 'ma_grades' ) ),
			'experience'   => rkspb_normalize_digits( $get( 'ma_experience' ) ),
			'konkur_rank'  => trim( $get( 'ma_konkur_rank' ) ),
			'university'   => trim( $get( 'ma_university' ) ),
			'about'        => isset( $_POST['ma_about'] ) ? sanitize_textarea_field( wp_unslash( $_POST['ma_about'] ) ) : '',
			'contact_link' => trim( $get( 'ma_contact_link' ) ),
		);
		$out['old'] = $data;

		// تله‌ی ربات: این فیلد برای آدم نامرئی است و باید خالی بماند.
		if ( ! empty( $_POST['ma_website'] ) ) { $out['errors']['bot'] = 'درخواست نامعتبر.'; return $out; }

		$ip  = rkspb_client_ip();
		$key = 'rkspb_ma_' . md5( $ip );
		if ( (int) get_transient( $key ) >= 3 ) {
			$out['errors']['rate'] = 'تعداد درخواست‌ها از این دستگاه زیاد بوده است. کمی بعد دوباره تلاش کن.';
			return $out;
		}

		if ( '' === $data['first_name'] ) { $out['errors']['first_name'] = 'نام را وارد کن.'; }
		if ( '' === $data['last_name'] )  { $out['errors']['last_name']  = 'نام خانوادگی را وارد کن.'; }
		if ( 11 !== strlen( $data['mobile'] ) || '09' !== substr( $data['mobile'], 0, 2 ) ) {
			$out['errors']['mobile'] = 'شماره موبایل باید ۱۱ رقم و با ۰۹ شروع شود.';
		}
		if ( '' === $data['specialty'] ) { $out['errors']['specialty'] = 'رشته‌ی تخصصی را وارد کن.'; }
		if ( '' === $data['grades'] )    { $out['errors']['grades']    = 'مقطعی که می‌توانی مشاوره بدهی را بنویس.'; }
		if ( '' === $data['experience'] ){ $out['errors']['experience'] = 'سابقه‌ی مشاوره را به سال وارد کن (اگر نداری صفر بنویس).'; }
		if ( mb_strlen( $data['about'] ) > 1500 ) { $out['errors']['about'] = 'توضیحات طولانی است؛ حداکثر ۱۵۰۰ کاراکتر.'; }
		if ( empty( $_POST['ma_terms'] ) ) { $out['errors']['terms'] = 'برای ارسال درخواست باید شرایط همکاری را بپذیری.'; }

		if ( empty( $out['errors'] ) ) {
			global $wpdb;
			$table = rkspb_apps_table();
			$dup   = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM `{$table}` WHERE mobile = %s AND status = 'pending'", $data['mobile'] ) );
			if ( $dup ) {
				$out['errors']['mobile'] = 'با این شماره یک درخواست در حال بررسی وجود دارد.';
				return $out;
			}
			$data['terms_accepted'] = 1;
			$data['terms_time']     = current_time( 'mysql' );
			$data['terms_ip']       = $ip;
			$data['status']         = 'pending';
			$data['created_at']     = current_time( 'mysql' );
			$wpdb->insert( $table, $data );

			set_transient( $key, (int) get_transient( $key ) + 1, HOUR_IN_SECONDS );

			$admin = get_option( 'admin_email' );
			if ( $admin ) {
				wp_mail(
					$admin,
					'درخواست همکاری جدید — راه کنکور',
					"یک درخواست همکاری تازه ثبت شد:\n\n"
					. $data['first_name'] . ' ' . $data['last_name'] . "\n"
					. 'موبایل: ' . $data['mobile'] . "\n"
					. 'رشته: ' . $data['specialty'] . "\n\n"
					. 'بررسی: ' . admin_url( 'admin.php?page=rkspb_apps' )
				);
			}
			$out['ok'] = true;
		}
		return $out;
	}
}

if ( ! function_exists( 'rkspb_mentor_apply_shortcode' ) ) {
	function rkspb_mentor_apply_shortcode() {
		rkspb_maybe_create_apps_table();

		$res = array( 'ok' => false, 'errors' => array(), 'old' => array() );
		if ( ! empty( $_POST['rkspb_apply'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['rkspb_apply_nonce'] ?? '' ) ), 'rkspb_apply' ) ) {
			$res = rkspb_handle_application();
		}

		ob_start();
		echo '<div class="rkspb-apply" dir="rtl" style="max-width:720px;margin:0 auto;font-family:inherit;line-height:2">';

		if ( $res['ok'] ) {
			echo '<div style="background:#eaf7ee;border:1px solid #b6e0c2;border-radius:12px;padding:20px">'
				. '<h3 style="margin:0 0 8px">درخواستت ثبت شد</h3>'
				. '<p style="margin:0">بررسی می‌کنیم و در صورت تأیید، با همین شماره تماس می‌گیریم. اگر تأیید شد، حساب کاربری پرتال برایت ساخته می‌شود.</p>'
				. '</div></div>';
			return ob_get_clean();
		}

		$old = $res['old'];
		$err = $res['errors'];
		$v   = function ( $k ) use ( $old ) { return isset( $old[ $k ] ) ? esc_attr( $old[ $k ] ) : ''; };
		$e   = function ( $k ) use ( $err ) {
			return isset( $err[ $k ] ) ? '<p style="color:#c0392b;margin:4px 0 0;font-size:.9em">' . esc_html( $err[ $k ] ) . '</p>' : '';
		};

		if ( ! empty( $err['rate'] ) || ! empty( $err['bot'] ) ) {
			echo '<div style="background:#fdecea;border:1px solid #f5c6cb;border-radius:12px;padding:14px;margin-bottom:16px">'
				. esc_html( $err['rate'] ?? $err['bot'] ) . '</div>';
		}

		echo '<h2 style="margin:0 0 6px">درخواست همکاری به عنوان مشاور</h2>';
		echo '<p style="color:#666;margin:0 0 20px">فرم را پر کن. بعد از بررسی با تو تماس می‌گیریم.</p>';

		echo '<form method="post">';
		wp_nonce_field( 'rkspb_apply', 'rkspb_apply_nonce' );
		echo '<input type="hidden" name="rkspb_apply" value="1">';
		echo '<div style="position:absolute;left:-9999px" aria-hidden="true"><label>وب‌سایت<input type="text" name="ma_website" tabindex="-1" autocomplete="off"></label></div>';

		$style = 'width:100%;padding:10px 12px;border:1px solid #ccc;border-radius:10px;font-family:inherit;font-size:1em';
		$row   = function ( $label, $name, $val, $errHtml, $type = 'text' ) use ( $style ) {
			printf(
				'<div style="margin-bottom:16px"><label for="%1$s" style="display:block;font-weight:600;margin-bottom:6px">%2$s</label>'
				. '<input type="%5$s" id="%1$s" name="%1$s" value="%3$s" style="%6$s">%4$s</div>',
				esc_attr( $name ), esc_html( $label ), $val, $errHtml, esc_attr( $type ), esc_attr( $style )
			);
		};

		$row( 'نام', 'ma_first_name', $v( 'first_name' ), $e( 'first_name' ) );
		$row( 'نام خانوادگی', 'ma_last_name', $v( 'last_name' ), $e( 'last_name' ) );
		$row( 'شماره موبایل', 'ma_mobile', $v( 'mobile' ), $e( 'mobile' ) );
		$row( 'رشته‌ی تخصصی (تجربی، ریاضی، انسانی…)', 'ma_specialty', $v( 'specialty' ), $e( 'specialty' ) );
		$row( 'مقاطعی که می‌توانی مشاوره بدهی', 'ma_grades', $v( 'grades' ), $e( 'grades' ) );
		$row( 'سابقه‌ی مشاوره (سال)', 'ma_experience', $v( 'experience' ), $e( 'experience' ) );
		$row( 'رتبه و رشته‌ی کنکور خودت', 'ma_konkur_rank', $v( 'konkur_rank' ), $e( 'konkur_rank' ) );
		$row( 'دانشگاه محل تحصیل', 'ma_university', $v( 'university' ), $e( 'university' ) );
		$row( 'لینک رزومه یا آیدی تلگرام', 'ma_contact_link', $v( 'contact_link' ), $e( 'contact_link' ) );

		printf(
			'<div style="margin-bottom:16px"><label for="ma_about" style="display:block;font-weight:600;margin-bottom:6px">%s</label>'
			. '<textarea id="ma_about" name="ma_about" rows="5" style="%s">%s</textarea>%s</div>',
			'کمی درباره‌ی خودت و روش کارت بنویس',
			esc_attr( $style ),
			esc_textarea( isset( $old['about'] ) ? $old['about'] : '' ),
			$e( 'about' )
		);

		echo '<div style="border:1px solid #ddd;border-radius:12px;padding:16px;margin-bottom:14px;background:#fafafa">';
		echo '<strong style="display:block;margin-bottom:10px">شرایط همکاری</strong>';
		echo '<div style="max-height:220px;overflow:auto;font-size:.92em;color:#333;white-space:pre-line">' . esc_html( rkspb_terms_text() ) . '</div>';
		echo '</div>';

		echo '<label style="display:flex;gap:10px;align-items:flex-start;margin-bottom:6px;cursor:pointer">'
			. '<input type="checkbox" name="ma_terms" value="1" style="margin-top:8px"'
			. ( ! empty( $_POST['ma_terms'] ) ? ' checked' : '' ) . '>'
			. '<span>شرایط بالا را خوانده‌ام و می‌پذیرم.</span></label>';
		echo $e( 'terms' ); // phpcs:ignore WordPress.Security.EscapeOutput

		echo '<button type="submit" style="margin-top:18px;width:100%;padding:14px;border:0;border-radius:12px;background:#ea580c;color:#fff;font-size:1.05em;font-weight:700;cursor:pointer;font-family:inherit">ارسال درخواست</button>';
		echo '</form></div>';

		return ob_get_clean();
	}
}
add_shortcode( 'rkspb_mentor_apply', 'rkspb_mentor_apply_shortcode' );

if ( ! function_exists( 'rkspb_create_mentor' ) ) {
	/**
	 * ساخت مشاور با خطای دقیق برای هر فیلد، به‌جای پیام مبهم افزونه‌ی اصلی.
	 *
	 * @return array{ok:bool, errors:array, user_id:int}
	 */
	function rkspb_create_mentor( $in ) {
		global $wpdb;
		$errors = array();

		$first = sanitize_text_field( trim( (string) ( isset( $in['first_name'] ) ? $in['first_name'] : '' ) ) );
		$last  = sanitize_text_field( trim( (string) ( isset( $in['last_name'] ) ? $in['last_name'] : '' ) ) );
		$mob   = rkspb_normalize_mobile( isset( $in['mobile'] ) ? $in['mobile'] : '' );
		$user  = sanitize_user( trim( (string) ( isset( $in['username'] ) ? $in['username'] : '' ) ), true );
		$pass  = (string) ( isset( $in['password'] ) ? $in['password'] : '' );
		$spec  = sanitize_text_field( trim( (string) ( isset( $in['specialty'] ) ? $in['specialty'] : '' ) ) );
		$email = sanitize_email( trim( (string) ( isset( $in['email'] ) ? $in['email'] : '' ) ) );

		if ( '' === $first ) { $errors['first_name'] = 'نام را وارد کن.'; }
		if ( '' === $last )  { $errors['last_name']  = 'نام خانوادگی را وارد کن.'; }

		if ( 11 !== strlen( $mob ) || '09' !== substr( $mob, 0, 2 ) ) {
			$errors['mobile'] = 'شماره موبایل باید ۱۱ رقم و با ۰۹ شروع شود. ارقام فارسی هم قبول است.';
		} elseif ( rkspb_find_user_by_mobile( $mob ) ) {
			$errors['mobile'] = 'این شماره قبلاً برای کاربر دیگری ثبت شده است.';
		}

		if ( '' === $user ) {
			$errors['username'] = 'نام کاربری باید با حروف انگلیسی باشد؛ فارسی و فاصله پذیرفته نمی‌شود.';
		} elseif ( ! validate_username( $user ) ) {
			$errors['username'] = 'این نام کاربری معتبر نیست. فقط حروف انگلیسی، عدد، نقطه و خط تیره.';
		} elseif ( username_exists( $user ) ) {
			$errors['username'] = 'این نام کاربری قبلاً گرفته شده است.';
		}

		if ( strlen( $pass ) < 6 ) { $errors['password'] = 'رمز عبور حداقل ۶ کاراکتر باشد.'; }

		if ( '' === $email ) { $email = $user . '@' . wp_parse_url( home_url(), PHP_URL_HOST ); }
		if ( email_exists( $email ) ) { $errors['email'] = 'این ایمیل قبلاً استفاده شده است.'; }

		if ( ! empty( $errors ) ) { return array( 'ok' => false, 'errors' => $errors, 'user_id' => 0 ); }

		$user_id = wp_insert_user( array(
			'user_login'   => $user,
			'user_pass'    => $pass,
			'user_email'   => $email,
			'first_name'   => $first,
			'last_name'    => $last,
			'display_name' => trim( $first . ' ' . $last ),
			'role'         => 'rksp_mentor',
		) );

		if ( is_wp_error( $user_id ) ) {
			return array( 'ok' => false, 'errors' => array( 'wp' => $user_id->get_error_message() ), 'user_id' => 0 );
		}

		update_user_meta( $user_id, 'rksp_mobile', $mob );
		update_user_meta( $user_id, 'rkspb_force_pw', 1 ); // در اولین ورود باید رمز را عوض کند

		$table = rkspb_table_name( 'mentors' );
		$cols  = rkspb_table_columns( $table );
		$names = wp_list_pluck( $cols, 'name' );
		$row   = array();
		if ( in_array( 'user_id', $names, true ) )    { $row['user_id'] = $user_id; }
		if ( in_array( 'mobile', $names, true ) )     { $row['mobile'] = $mob; }
		if ( in_array( 'username', $names, true ) )   { $row['username'] = $user; }
		if ( in_array( 'specialty', $names, true ) )  { $row['specialty'] = $spec; }
		if ( in_array( 'created_at', $names, true ) ) { $row['created_at'] = current_time( 'mysql' ); }
		foreach ( array( 'full_name', 'name', 'display_name' ) as $nameCol ) {
			if ( in_array( $nameCol, $names, true ) ) { $row[ $nameCol ] = trim( $first . ' ' . $last ); break; }
		}
		if ( in_array( 'first_name', $names, true ) ) { $row['first_name'] = $first; }
		if ( in_array( 'last_name', $names, true ) )  { $row['last_name'] = $last; }
		if ( in_array( 'status', $names, true ) )     { $row['status'] = 'active'; }

		if ( ! empty( $row ) ) { $wpdb->insert( $table, $row ); }

		return array( 'ok' => true, 'errors' => array(), 'user_id' => (int) $user_id );
	}
}

if ( ! function_exists( 'rkspb_render_mentor_form' ) ) {
	function rkspb_render_mentor_form() {
		$errors = array();
		$old    = array();
		$done   = '';

		if ( ! empty( $_POST['rkspb_action'] ) && 'create_mentor' === sanitize_key( wp_unslash( $_POST['rkspb_action'] ) ) ) {
			check_admin_referer( 'rkspb_data' );
			$old = array(
				'first_name' => isset( $_POST['m_first_name'] ) ? sanitize_text_field( wp_unslash( $_POST['m_first_name'] ) ) : '',
				'last_name'  => isset( $_POST['m_last_name'] ) ? sanitize_text_field( wp_unslash( $_POST['m_last_name'] ) ) : '',
				'mobile'     => isset( $_POST['m_mobile'] ) ? sanitize_text_field( wp_unslash( $_POST['m_mobile'] ) ) : '',
				'username'   => isset( $_POST['m_username'] ) ? sanitize_text_field( wp_unslash( $_POST['m_username'] ) ) : '',
				'password'   => isset( $_POST['m_password'] ) ? (string) wp_unslash( $_POST['m_password'] ) : '',
				'specialty'  => isset( $_POST['m_specialty'] ) ? sanitize_text_field( wp_unslash( $_POST['m_specialty'] ) ) : '',
				'email'      => isset( $_POST['m_email'] ) ? sanitize_text_field( wp_unslash( $_POST['m_email'] ) ) : '',
			);
			$res = rkspb_create_mentor( $old );
			if ( $res['ok'] ) {
				$done = 'مشاور ساخته شد (شناسه کاربر ' . $res['user_id'] . ').';
				$old  = array();
			} else {
				$errors = $res['errors'];
			}
		}

		echo '<hr><h3>افزودن مشاور</h3>';
		if ( $done ) { echo '<div class="notice notice-success"><p>' . esc_html( $done ) . '</p></div>'; }
		if ( ! empty( $errors['wp'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html( $errors['wp'] ) . '</p></div>';
		}

		$fields = array(
			'first_name' => array( 'نام', 'text' ),
			'last_name'  => array( 'نام خانوادگی', 'text' ),
			'mobile'     => array( 'موبایل', 'text' ),
			'username'   => array( 'نام کاربری (انگلیسی)', 'text' ),
			'password'   => array( 'رمز عبور (حداقل ۶ کاراکتر)', 'text' ),
			'email'      => array( 'ایمیل (اختیاری)', 'text' ),
			'specialty'  => array( 'رشته / تخصص', 'text' ),
		);

		echo '<form method="post"><table class="form-table">';
		wp_nonce_field( 'rkspb_data' );
		echo '<input type="hidden" name="rkspb_action" value="create_mentor">';
		echo '<input type="hidden" name="table" value="mentors">';
		foreach ( $fields as $key => $meta ) {
			$val = isset( $old[ $key ] ) ? $old[ $key ] : '';
			$err = isset( $errors[ $key ] ) ? $errors[ $key ] : '';
			printf(
				'<tr><th><label for="m_%1$s">%2$s</label></th><td><input class="regular-text" type="%3$s" id="m_%1$s" name="m_%1$s" value="%4$s">%5$s</td></tr>',
				esc_attr( $key ),
				esc_html( $meta[0] ),
				esc_attr( $meta[1] ),
				esc_attr( $val ),
				$err ? '<p style="color:#b32d2e;margin:4px 0 0">' . esc_html( $err ) . '</p>' : ''
			);
		}
		echo '</table>';
		submit_button( 'ساخت اکانت مشاور' );
		echo '</form>';
	}
}

if ( ! function_exists( 'rkspb_render_data_page' ) ) {
	function rkspb_render_data_page() {
		if ( ! current_user_can( 'manage_options' ) ) { return; }
		global $wpdb;

		$notice = rkspb_handle_data_actions();
		$tables = rkspb_tables();
		$views  = rkspb_readonly_views();
		$slug   = isset( $_GET['t'] ) ? sanitize_key( wp_unslash( $_GET['t'] ) ) : 'students';
		if ( ! isset( $tables[ $slug ] ) && ! isset( $views[ $slug ] ) ) { $slug = 'students'; }
		$table  = isset( $tables[ $slug ] ) ? rkspb_table_name( $slug ) : '';
		$edit   = isset( $_GET['edit'] ) ? sanitize_text_field( wp_unslash( $_GET['edit'] ) ) : '';

		echo '<div class="wrap" dir="rtl"><h1>مدیریت داده‌های پرتال</h1>';
		echo '<p style="color:#666">این صفحه بخشی از افزونه‌ی «پل پرتال» است و ویرایش و حذفی را فراهم می‌کند که افزونه‌ی اصلی ندارد. دو تب آخر فقط خواندنی‌اند.</p>';
		echo $notice; // phpcs:ignore WordPress.Security.EscapeOutput

		echo '<h2 class="nav-tab-wrapper">';
		foreach ( $tables as $s => $label ) {
			$count = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM `' . rkspb_table_name( $s ) . '`' );
			printf(
				'<a href="%s" class="nav-tab %s">%s (%d)</a>',
				esc_url( admin_url( 'admin.php?page=rkspb_data&t=' . $s ) ),
				$s === $slug ? 'nav-tab-active' : '',
				esc_html( $label ),
				$count
			);
		}
		foreach ( $views as $s => $label ) {
			printf(
				'<a href="%s" class="nav-tab %s">%s</a>',
				esc_url( admin_url( 'admin.php?page=rkspb_data&t=' . $s ) ),
				$s === $slug ? 'nav-tab-active' : '',
				esc_html( $label )
			);
		}
		echo '</h2>';

		if ( isset( $views[ $slug ] ) ) {
			if ( 'sales_users' === $slug ) { rkspb_render_sales_view(); }
			if ( 'payments_view' === $slug ) { rkspb_render_payments_view(); }
			if ( function_exists( 'rkspb_render_audit_box' ) ) { rkspb_render_audit_box(); }
			echo '</div>';
			return;
		}

		$cols = rkspb_table_columns( $table );
		$pk   = rkspb_primary_key( $cols );
		$rows = $wpdb->get_results( "SELECT * FROM `{$table}` ORDER BY `{$pk}` DESC LIMIT 200", ARRAY_A );

		if ( '' !== $edit ) {
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$table}` WHERE `{$pk}` = %s", $edit ), ARRAY_A );
			if ( $row ) {
				echo '<h3>ویرایش ردیف ' . esc_html( $edit ) . '</h3><form method="post"><table class="form-table">';
				wp_nonce_field( 'rkspb_data' );
				echo '<input type="hidden" name="rkspb_action" value="save_row">';
				echo '<input type="hidden" name="table" value="' . esc_attr( $slug ) . '">';
				echo '<input type="hidden" name="row_id" value="' . esc_attr( $edit ) . '">';
				foreach ( $cols as $c ) {
					if ( $c['name'] === $pk ) { continue; }
					printf(
						'<tr><th><label for="f_%1$s">%1$s</label><br><small style="color:#888">%2$s</small></th><td><input class="regular-text" type="text" id="f_%1$s" name="f_%1$s" value="%3$s"></td></tr>',
						esc_attr( $c['name'] ),
						esc_html( $c['type'] ),
						esc_attr( isset( $row[ $c['name'] ] ) ? $row[ $c['name'] ] : '' )
					);
				}
				echo '</table>';
				submit_button( 'ذخیره‌ی تغییرات' );
				echo ' <a href="' . esc_url( admin_url( 'admin.php?page=rkspb_data&t=' . $slug ) ) . '" class="button">انصراف</a>';
				echo '</form><hr>';
			}
		}

		if ( empty( $rows ) ) {
			echo '<p>این جدول خالی است. ستون‌ها: <code dir="ltr">' . esc_html( implode( ', ', wp_list_pluck( $cols, 'name' ) ) ) . '</code></p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			foreach ( $cols as $c ) { echo '<th>' . esc_html( $c['name'] ) . '</th>'; }
			echo '<th style="width:150px">عملیات</th></tr></thead><tbody>';
			foreach ( $rows as $row ) {
				echo '<tr>';
				foreach ( $cols as $c ) {
					$v = isset( $row[ $c['name'] ] ) ? (string) $row[ $c['name'] ] : '';
					if ( mb_strlen( $v ) > 60 ) { $v = mb_substr( $v, 0, 60 ) . '…'; }
					echo '<td>' . esc_html( $v ) . '</td>';
				}
				$id = isset( $row[ $pk ] ) ? $row[ $pk ] : '';
				echo '<td><a class="button button-small" href="' . esc_url( admin_url( 'admin.php?page=rkspb_data&t=' . $slug . '&edit=' . rawurlencode( $id ) ) ) . '">ویرایش</a> ';
				echo '<form method="post" style="display:inline" onsubmit="return confirm(\'این ردیف برای همیشه حذف می‌شود. مطمئنی؟\')">';
				wp_nonce_field( 'rkspb_data' );
				echo '<input type="hidden" name="rkspb_action" value="delete_row">';
				echo '<input type="hidden" name="table" value="' . esc_attr( $slug ) . '">';
				echo '<input type="hidden" name="row_id" value="' . esc_attr( $id ) . '">';
				echo '<button type="submit" class="button button-small" style="color:#b32d2e">حذف</button>';
				echo '</form></td></tr>';
			}
			echo '</tbody></table>';
		}

		if ( 'mentors' === $slug ) { rkspb_render_mentor_form(); }

		echo '<hr><h3>خالی کردن کامل این جدول</h3>';
		echo '<p style="color:#b32d2e">این کار برگشت ندارد. اول از phpMyAdmin بکاپ بگیر.</p>';
		echo '<form method="post" onsubmit="return confirm(\'کل این جدول خالی می‌شود و برگشت ندارد. ادامه؟\')">';
		wp_nonce_field( 'rkspb_data' );
		echo '<input type="hidden" name="rkspb_action" value="empty_table">';
		echo '<input type="hidden" name="table" value="' . esc_attr( $slug ) . '">';
		echo '<input type="text" name="confirm_text" placeholder="کلمه‌ی حذف را تایپ کن" style="width:220px"> ';
		echo '<button type="submit" class="button">خالی کردن جدول</button>';
		echo '</form>';
		if ( function_exists( 'rkspb_render_audit_box' ) ) { rkspb_render_audit_box(); }
		echo '</div>';
	}
}

/* ------------------------------------------------ PORTAL DATA (1.2.8) ---- */
/*
 * روت‌های داده‌ی پرتال برای مشاور و دانش‌آموز.
 *
 * چرا اینجا و نه در rksp: روت‌های نوشتنِ rksp (mentor/tasks، mentor/notes) درخواست
 * پرتال را با «درخواست نامعتبر است» رد می‌کنند و نمی‌گویند چرا، و روت خواندنِ
 * mentor/students نام، موبایل، طرح و تکالیف را برنمی‌گرداند. این روت‌ها مستقیم روی
 * همان جدول‌های rksp کار می‌کنند و ستون‌ها را از خود جدول می‌خوانند (SHOW COLUMNS)،
 * پس به نسخه‌ی rksp گره نخورده‌اند. هیچ عدد پیش‌فرض یا داده‌ی نمایشی برنمی‌گردانند.
 */

if ( ! function_exists( 'rkspb_cols_meta' ) ) {
	/** @return array<string,array{type:string,null:bool,default:mixed,extra:string,key:string}> */
	function rkspb_cols_meta( $slug ) {
		static $cache = array();
		if ( isset( $cache[ $slug ] ) ) { return $cache[ $slug ]; }
		global $wpdb;
		$table = rkspb_table_name( $slug );
		$out   = array();
		if ( $table && $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table ) {
			foreach ( (array) $wpdb->get_results( "SHOW COLUMNS FROM `{$table}`" ) as $c ) {
				$out[ $c->Field ] = array(
					'type'    => strtolower( (string) $c->Type ),
					'null'    => ( 'YES' === $c->Null ),
					'default' => $c->Default,
					'extra'   => strtolower( (string) $c->Extra ),
					'key'     => (string) $c->Key,
				);
			}
		}
		$cache[ $slug ] = $out;
		return $out;
	}
}

if ( ! function_exists( 'rkspb_pick' ) ) {
	/** اولین ستونی از فهرست که در جدول وجود دارد. */
	function rkspb_pick( $slug, $candidates ) {
		$meta = rkspb_cols_meta( $slug );
		foreach ( (array) $candidates as $c ) {
			if ( isset( $meta[ $c ] ) ) { return $c; }
		}
		return '';
	}
}

if ( ! function_exists( 'rkspb_now' ) ) {
	function rkspb_now() { return current_time( 'mysql' ); }
}

if ( ! function_exists( 'rkspb_empty_date' ) ) {
	function rkspb_empty_date( $v ) {
		$v = trim( (string) $v );
		return '' === $v || 0 === strpos( $v, '0000-00-00' );
	}
}

if ( ! function_exists( 'rkspb_enum_values' ) ) {
	function rkspb_enum_values( $type ) {
		if ( ! preg_match( '/^(enum|set)\((.*)\)$/i', $type, $m ) ) { return array(); }
		preg_match_all( "/'((?:[^'\\\\]|\\\\.)*)'/", $m[2], $mm );
		return $mm[1];
	}
}

if ( ! function_exists( 'rkspb_fit_value' ) ) {
	/** مقدار را با نوع ستون جور می‌کند (مخصوصاً enum). */
	function rkspb_fit_value( $slug, $col, $value, $prefer = array() ) {
		$meta = rkspb_cols_meta( $slug );
		if ( ! isset( $meta[ $col ] ) ) { return $value; }
		$enum = rkspb_enum_values( $meta[ $col ]['type'] );
		if ( empty( $enum ) ) { return $value; }
		if ( in_array( $value, $enum, true ) ) { return $value; }
		foreach ( (array) $prefer as $p ) {
			if ( in_array( $p, $enum, true ) ) { return $p; }
		}
		return $enum[0];
	}
}

if ( ! function_exists( 'rkspb_insert_row' ) ) {
	/**
	 * فقط ستون‌های موجود را درج می‌کند و ستون‌های اجباریِ بی‌پیش‌فرض را با مقدار خنثی پر می‌کند.
	 *
	 * @return int|WP_Error
	 */
	function rkspb_insert_row( $slug, $data ) {
		global $wpdb;
		$meta = rkspb_cols_meta( $slug );
		if ( empty( $meta ) ) {
			return new WP_Error( 'rkspb_no_table', 'جدول ' . $slug . ' در دیتابیس پیدا نشد.', array( 'status' => 500 ) );
		}
		$row = array();
		foreach ( (array) $data as $k => $v ) {
			if ( isset( $meta[ $k ] ) && null !== $v ) { $row[ $k ] = $v; }
		}
		foreach ( $meta as $col => $m ) {
			if ( array_key_exists( $col, $row ) ) { continue; }
			if ( false !== strpos( $m['extra'], 'auto_increment' ) ) { continue; }
			if ( $m['null'] || null !== $m['default'] ) { continue; }
			$t = $m['type'];
			if ( preg_match( '/int|decimal|float|double|bit/', $t ) ) {
				$row[ $col ] = 0;
			} elseif ( 0 === strpos( $t, 'datetime' ) || 0 === strpos( $t, 'timestamp' ) ) {
				$row[ $col ] = rkspb_now();
			} elseif ( 0 === strpos( $t, 'date' ) ) {
				$row[ $col ] = current_time( 'Y-m-d' );
			} elseif ( rkspb_enum_values( $t ) ) {
				$vals        = rkspb_enum_values( $t );
				$row[ $col ] = $vals[0];
			} else {
				$row[ $col ] = '';
			}
		}
		$ok = $wpdb->insert( rkspb_table_name( $slug ), $row );
		if ( false === $ok ) {
			return new WP_Error( 'rkspb_db', 'ذخیره انجام نشد: ' . $wpdb->last_error, array( 'status' => 500 ) );
		}
		return (int) $wpdb->insert_id;
	}
}

/* ------------------------------------------------ هویت مشاور و دانش‌آموز -- */

if ( ! function_exists( 'rkspb_student_by_id' ) ) {
	function rkspb_student_by_id( $sid ) {
		global $wpdb;
		$t = rkspb_table_name( 'students' );
		if ( ! rkspb_cols_meta( 'students' ) ) { return null; }
		return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d LIMIT 1", $sid ), ARRAY_A );
	}
}

if ( ! function_exists( 'rkspb_student_name' ) ) {
	function rkspb_student_name( $row ) {
		$name = trim( ( isset( $row['first_name'] ) ? $row['first_name'] : '' ) . ' ' . ( isset( $row['last_name'] ) ? $row['last_name'] : '' ) );
		if ( '' === $name ) {
			foreach ( array( 'full_name', 'name', 'display_name' ) as $c ) {
				if ( ! empty( $row[ $c ] ) ) { $name = $row[ $c ]; break; }
			}
		}
		if ( '' === $name && ! empty( $row['user_id'] ) ) {
			$u = get_user_by( 'id', (int) $row['user_id'] );
			if ( $u ) { $name = $u->display_name; }
		}
		return $name;
	}
}

if ( ! function_exists( 'rkspb_student_mobile' ) ) {
	function rkspb_student_mobile( $row ) {
		if ( ! empty( $row['mobile'] ) ) { return rkspb_normalize_mobile( $row['mobile'] ); }
		if ( ! empty( $row['user_id'] ) ) {
			$u = get_user_by( 'id', (int) $row['user_id'] );
			if ( $u ) { return rkspb_user_mobile( $u ); }
		}
		return '';
	}
}

if ( ! function_exists( 'rkspb_ctx_mentor' ) ) {
	/** @return array|WP_Error */
	function rkspb_ctx_mentor() {
		global $wpdb;
		$user = wp_get_current_user();
		if ( ! $user || ! $user->ID ) {
			return new WP_Error( 'rkspb_auth', 'ابتدا وارد شوید.', array( 'status' => 401 ) );
		}
		$is_mentor = in_array( 'rksp_mentor', (array) $user->roles, true );
		if ( ! $is_mentor && ! user_can( $user, 'manage_options' ) ) {
			return new WP_Error( 'rkspb_role', 'این بخش مخصوص مشاوران است.', array( 'status' => 403 ) );
		}
		$row = null;
		if ( rkspb_cols_meta( 'mentors' ) ) {
			$t   = rkspb_table_name( 'mentors' );
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE user_id = %d LIMIT 1", $user->ID ), ARRAY_A );
			$mob = rkspb_user_mobile( $user );
			if ( ! $row && $mob && rkspb_pick( 'mentors', array( 'mobile' ) ) ) {
				$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE mobile = %s LIMIT 1", $mob ), ARRAY_A );
			}
		}
		// بدون ردیف mentors (مثلاً مدیر)، فقط با شناسه‌ی کاربر کار می‌کند
		$keys = $row ? array( rkspb_mentor_assign_value( $row ) ) : array( (int) $user->ID );
		return array(
			'user' => $user,
			'row'  => $row,
			'keys' => array_values( array_unique( $keys ) ),
		);
	}
}

if ( ! function_exists( 'rkspb_active_assignment_sql' ) ) {
	function rkspb_active_assignment_sql() {
		if ( ! rkspb_pick( 'assignments', array( 'status' ) ) ) { return ''; }
		return " AND ( status IS NULL OR status NOT IN ('ended','inactive','cancelled','canceled','removed','deleted','expired') )";
	}
}

if ( ! function_exists( 'rkspb_mentor_links' ) ) {
	/** @return array<int,array> student_id => ردیف اتصال */
	function rkspb_mentor_links( $keys ) {
		global $wpdb;
		if ( ! rkspb_cols_meta( 'assignments' ) || empty( $keys ) ) { return array(); }
		$t    = rkspb_table_name( 'assignments' );
		$in   = implode( ',', array_map( 'intval', $keys ) );
		$rows = $wpdb->get_results( "SELECT * FROM `{$t}` WHERE mentor_id IN ({$in})" . rkspb_active_assignment_sql() . ' ORDER BY id ASC', ARRAY_A );
		$out  = array();
		foreach ( (array) $rows as $r ) { $out[ (int) $r['student_id'] ] = $r; } // آخرین اتصال برنده است
		return $out;
	}
}

if ( ! function_exists( 'rkspb_mentor_can' ) ) {
	/** @return array|WP_Error ردیف اتصال */
	function rkspb_mentor_can( $ctx, $sid ) {
		$links = rkspb_mentor_links( $ctx['keys'] );
		if ( ! isset( $links[ (int) $sid ] ) ) {
			return new WP_Error( 'rkspb_not_yours', 'این دانش‌آموز به شما متصل نیست.', array( 'status' => 403 ) );
		}
		return $links[ (int) $sid ];
	}
}

if ( ! function_exists( 'rkspb_ctx_student' ) ) {
	/** @return array|WP_Error */
	function rkspb_ctx_student() {
		global $wpdb;
		$user = wp_get_current_user();
		if ( ! $user || ! $user->ID ) {
			return new WP_Error( 'rkspb_auth', 'ابتدا وارد شوید.', array( 'status' => 401 ) );
		}
		if ( ! rkspb_cols_meta( 'students' ) ) {
			return new WP_Error( 'rkspb_no_table', 'جدول دانش‌آموزان پیدا نشد.', array( 'status' => 500 ) );
		}
		$t   = rkspb_table_name( 'students' );
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE user_id = %d ORDER BY id DESC LIMIT 1", $user->ID ), ARRAY_A );
		$mob = rkspb_user_mobile( $user );
		if ( ! $row && $mob && rkspb_pick( 'students', array( 'mobile' ) ) ) {
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE mobile = %s ORDER BY id DESC LIMIT 1", $mob ), ARRAY_A );
		}
		if ( ! $row ) {
			return new WP_Error( 'rkspb_no_student', 'پرونده‌ی دانش‌آموزی برای این حساب ساخته نشده است. با پشتیبانی راه کنکور تماس بگیرید.', array( 'status' => 404 ) );
		}

		$link   = null;
		$mentor = null;
		if ( rkspb_cols_meta( 'assignments' ) ) {
			$at   = rkspb_table_name( 'assignments' );
			$link = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$at}` WHERE student_id = %d" . rkspb_active_assignment_sql() . ' ORDER BY id DESC LIMIT 1', $row['id'] ), ARRAY_A );
		}
		if ( $link && rkspb_cols_meta( 'mentors' ) ) {
			$mt     = rkspb_table_name( 'mentors' );
			$mentor = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$mt}` WHERE id = %d LIMIT 1", $link['mentor_id'] ), ARRAY_A );
			if ( ! $mentor ) {
				$mentor = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$mt}` WHERE user_id = %d LIMIT 1", $link['mentor_id'] ), ARRAY_A );
			}
		}
		return array( 'user' => $user, 'row' => $row, 'link' => $link, 'mentor' => $mentor );
	}
}

/* ------------------------------------------------------------ طرح و اشتراک -- */

if ( ! function_exists( 'rkspb_plan_info' ) ) {
	/**
	 * طرح دانش‌آموز. جدول plans در rksp با student_id کار می‌کند
	 * (plan_name, start_date, end_date, status)؛ plan_id ِ اتصال فقط پشتیبان است.
	 */
	function rkspb_plan_info( $link, $sid = 0 ) {
		global $wpdb;
		$out  = array( 'name' => '', 'start' => '', 'end' => '', 'status' => '' );
		$plan = null;
		if ( rkspb_cols_meta( 'plans' ) ) {
			$pt = rkspb_table_name( 'plans' );
			if ( $sid && rkspb_pick( 'plans', array( 'student_id' ) ) ) {
				$order = rkspb_pick( 'plans', array( 'status' ) ) ? "(status = 'active') DESC, id DESC" : 'id DESC';
				$plan  = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$pt}` WHERE student_id = %d ORDER BY {$order} LIMIT 1", $sid ), ARRAY_A );
			}
			if ( ! $plan && $link && ! empty( $link['plan_id'] ) ) {
				$plan = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$pt}` WHERE id = %d LIMIT 1", $link['plan_id'] ), ARRAY_A );
			}
		}
		if ( $plan ) {
			foreach ( array( 'plan_name', 'name', 'title', 'label', 'plan_type' ) as $c ) {
				if ( ! empty( $plan[ $c ] ) ) { $out['name'] = (string) $plan[ $c ]; break; }
			}
			foreach ( array( 'start_date', 'started_at', 'starts_at' ) as $c ) {
				if ( isset( $plan[ $c ] ) && ! rkspb_empty_date( $plan[ $c ] ) ) { $out['start'] = (string) $plan[ $c ]; break; }
			}
			foreach ( array( 'end_date', 'expires_at', 'ends_at' ) as $c ) {
				if ( isset( $plan[ $c ] ) && ! rkspb_empty_date( $plan[ $c ] ) ) { $out['end'] = (string) $plan[ $c ]; break; }
			}
			$out['status'] = isset( $plan['status'] ) ? (string) $plan['status'] : '';
			if ( '' === $out['end'] && '' !== $out['start'] ) {
				foreach ( array( 'duration_days', 'days' ) as $c ) {
					if ( ! empty( $plan[ $c ] ) ) {
						$out['end'] = gmdate( 'Y-m-d', strtotime( $out['start'] ) + DAY_IN_SECONDS * (int) $plan[ $c ] );
						break;
					}
				}
			}
		}
		if ( '' === $out['start'] && $link ) {
			$start = rkspb_pick( 'assignments', array( 'assigned_at', 'started_at', 'created_at' ) );
			if ( $start && ! rkspb_empty_date( $link[ $start ] ) ) { $out['start'] = (string) $link[ $start ]; }
		}
		// روزهای باقی‌مانده تا پایان طرح؛ منفی یعنی منقضی شده.
		$out['days_left'] = null;
		if ( '' !== $out['end'] ) {
			$end  = strtotime( substr( $out['end'], 0, 10 ) . ' 12:00:00' );
			$now  = strtotime( current_time( 'Y-m-d' ) . ' 12:00:00' );
			if ( $end ) { $out['days_left'] = (int) round( ( $end - $now ) / DAY_IN_SECONDS ); }
		}
		$out['expired'] = ( null !== $out['days_left'] && $out['days_left'] < 0 );
		// قسط: چقدر از مبلغ طرح واقعاً با فیش تأییدشده پرداخت شده.
		$out['plan_id'] = ( $plan && isset( $plan['id'] ) ) ? (int) $plan['id'] : 0;
		$out['price']   = 0;
		if ( $plan ) {
			foreach ( array( 'price', 'amount', 'total', 'fee' ) as $c ) {
				if ( isset( $plan[ $c ] ) && '' !== $plan[ $c ] ) { $out['price'] = (int) $plan[ $c ]; break; }
			}
		}
		$out['paid'] = ( $out['plan_id'] && function_exists( 'rkspb_plan_paid' ) ) ? rkspb_plan_paid( $out['plan_id'] ) : 0;
		$out['due']  = max( 0, $out['price'] - $out['paid'] );
		return $out;
	}
}

/* ------------------------------------------------------------------ تکالیف -- */

if ( ! function_exists( 'rkspb_task_statuses' ) ) {
	/** @return array{done:string,pending:string} */
	function rkspb_task_statuses() {
		global $wpdb;
		static $st = null;
		if ( null !== $st ) { return $st; }
		$st = array( 'done' => 'done', 'pending' => 'pending' );
		if ( ! rkspb_pick( 'tasks', array( 'status' ) ) ) { return $st; }
		$t     = rkspb_table_name( 'tasks' );
		$found = array_map( 'strval', (array) $wpdb->get_col( "SELECT DISTINCT status FROM `{$t}` WHERE status IS NOT NULL AND status <> '' LIMIT 20" ) );
		if ( in_array( 'completed', $found, true ) ) { $st['done'] = 'completed'; }
		$st['done']    = rkspb_fit_value( 'tasks', 'status', $st['done'], array( 'done', 'completed', 'complete' ) );
		$st['pending'] = rkspb_fit_value( 'tasks', 'status', 'pending', array( 'pending', 'open', 'todo', 'new', 'active' ) );
		return $st;
	}
}

if ( ! function_exists( 'rkspb_task_is_done' ) ) {
	function rkspb_task_is_done( $t ) {
		$s = isset( $t['status'] ) ? strtolower( (string) $t['status'] ) : '';
		if ( in_array( $s, array( 'done', 'completed', 'complete', 'finished' ), true ) ) { return true; }
		if ( in_array( $s, array( 'pending', 'open', 'todo', 'new' ), true ) ) { return false; }
		foreach ( array( 'done_at', 'completed_at' ) as $c ) {
			if ( isset( $t[ $c ] ) && ! rkspb_empty_date( $t[ $c ] ) ) { return true; }
		}
		return false;
	}
}

if ( ! function_exists( 'rkspb_task_out' ) ) {
	function rkspb_task_out( $t ) {
		$done_at = '';
		foreach ( array( 'completed_at', 'done_at' ) as $c ) {
			if ( isset( $t[ $c ] ) && ! rkspb_empty_date( $t[ $c ] ) ) { $done_at = (string) $t[ $c ]; break; }
		}
		return array(
			'id'          => (int) $t['id'],
			'title'       => isset( $t['title'] ) ? (string) $t['title'] : '',
			'description' => isset( $t['description'] ) ? (string) $t['description'] : '',
			'due_date'    => ( isset( $t['due_date'] ) && ! rkspb_empty_date( $t['due_date'] ) ) ? (string) $t['due_date'] : '',
			'done'        => rkspb_task_is_done( $t ),
			'done_at'     => $done_at,
			'created_at'  => isset( $t['created_at'] ) ? (string) $t['created_at'] : '',
		);
	}
}

if ( ! function_exists( 'rkspb_tasks_for' ) ) {
	function rkspb_tasks_for( $sid ) {
		global $wpdb;
		if ( ! rkspb_cols_meta( 'tasks' ) ) { return array(); }
		$t    = rkspb_table_name( 'tasks' );
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE student_id = %d ORDER BY id DESC LIMIT 200", $sid ), ARRAY_A );
		return array_map( 'rkspb_task_out', (array) $rows );
	}
}

if ( ! function_exists( 'rkspb_set_task_done' ) ) {
	function rkspb_set_task_done( $task_id, $done ) {
		global $wpdb;
		$st   = rkspb_task_statuses();
		$meta = rkspb_cols_meta( 'tasks' );
		$data = array();
		if ( isset( $meta['status'] ) ) { $data['status'] = $done ? $st['done'] : $st['pending']; }
		foreach ( array( 'done_at', 'completed_at' ) as $c ) {
			if ( ! isset( $meta[ $c ] ) ) { continue; }
			$data[ $c ] = $done ? rkspb_now() : ( $meta[ $c ]['null'] ? null : '0000-00-00 00:00:00' );
		}
		if ( empty( $data ) ) { return false; }
		return false !== $wpdb->update( rkspb_table_name( 'tasks' ), $data, array( 'id' => (int) $task_id ) );
	}
}

/* ------------------------------------------------------------- یادداشت‌ها -- */

if ( ! function_exists( 'rkspb_note_cols' ) ) {
	function rkspb_note_cols() {
		return array(
			'text'    => rkspb_pick( 'mentor_notes', array( 'note', 'content', 'body', 'text', 'message', 'comment' ) ),
			'vis'     => rkspb_pick( 'mentor_notes', array( 'visibility' ) ),
			'priv'    => rkspb_pick( 'mentor_notes', array( 'rkspb_private', 'is_private', 'private', 'confidential' ) ),
			'pub'     => rkspb_pick( 'mentor_notes', array( 'is_public', 'visible_to_student', 'public', 'show_to_student' ) ),
			'cat'     => rkspb_pick( 'mentor_notes', array( 'category', 'type' ) ),
			'created' => rkspb_pick( 'mentor_notes', array( 'created_at', 'date' ) ),
		);
	}
}

if ( ! function_exists( 'rkspb_note_is_private' ) ) {
	function rkspb_note_is_private( $n, $c ) {
		if ( $c['vis'] ) {
			return in_array( strtolower( (string) $n[ $c['vis'] ] ), array( 'private', 'mentor', 'internal', 'hidden', 'confidential' ), true );
		}
		if ( $c['priv'] && (int) $n[ $c['priv'] ] ) { return true; }
		if ( $c['pub'] && ! (int) $n[ $c['pub'] ] ) { return true; }
		// لایه‌ی دوم: نوع «private» هم محرمانه حساب می‌شود
		if ( $c['cat'] && in_array( strtolower( (string) $n[ $c['cat'] ] ), array( 'private', 'confidential', 'mentor_only' ), true ) ) { return true; }
		return false;
	}
}

if ( ! function_exists( 'rkspb_notes_for' ) ) {
	function rkspb_notes_for( $sid, $include_private ) {
		global $wpdb;
		if ( ! rkspb_cols_meta( 'mentor_notes' ) ) { return array(); }
		$c    = rkspb_note_cols();
		$t    = rkspb_table_name( 'mentor_notes' );
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE student_id = %d ORDER BY id DESC LIMIT 100", $sid ), ARRAY_A );
		$out  = array();
		foreach ( (array) $rows as $n ) {
			$private = rkspb_note_is_private( $n, $c );
			if ( $private && ! $include_private ) { continue; }
			$out[] = array(
				'id'         => (int) $n['id'],
				'note'       => $c['text'] ? (string) $n[ $c['text'] ] : '',
				'private'    => $private,
				'created_at' => $c['created'] ? (string) $n[ $c['created'] ] : '',
			);
		}
		return $out;
	}
}

/* -------------------------------------------------------- ساعت‌های مطالعه -- */

if ( ! function_exists( 'rkspb_log_cols' ) ) {
	function rkspb_log_cols() {
		$min = rkspb_pick( 'study_logs', array( 'minutes', 'duration_minutes', 'study_minutes', 'duration' ) );
		$sec = $min ? '' : rkspb_pick( 'study_logs', array( 'seconds', 'duration_seconds', 'total_seconds' ) );
		return array(
			'sid'     => rkspb_pick( 'study_logs', array( 'student_id' ) ),
			'uid'     => rkspb_pick( 'study_logs', array( 'user_id' ) ),
			'min'     => $min,
			'sec'     => $sec,
			'date'    => rkspb_pick( 'study_logs', array( 'log_date', 'study_date', 'date', 'started_at', 'start_time', 'created_at' ) ),
			'subject' => rkspb_pick( 'study_logs', array( 'subject', 'subject_name', 'lesson', 'course' ) ),
			'topic'   => rkspb_pick( 'study_logs', array( 'topic', 'chapter', 'title', 'description', 'note', 'notes' ) ),
			'tests'   => rkspb_pick( 'study_logs', array( 'tests', 'test_count', 'tests_count', 'questions', 'question_count' ) ),
			'status'  => rkspb_pick( 'study_logs', array( 'status' ) ),
		);
	}
}

if ( ! function_exists( 'rkspb_log_where' ) ) {
	/** شرط انتخاب ردیف‌های یک دانش‌آموز؛ رشته‌ی خالی یعنی جدول قابل استفاده نیست. */
	function rkspb_log_where( $student_row ) {
		global $wpdb;
		$c = rkspb_log_cols();
		if ( ! $c['min'] && ! $c['sec'] ) { return ''; }
		if ( $c['sid'] ) {
			$w = $wpdb->prepare( "`{$c['sid']}` = %d", $student_row['id'] );
		} elseif ( $c['uid'] && ! empty( $student_row['user_id'] ) ) {
			$w = $wpdb->prepare( "`{$c['uid']}` = %d", $student_row['user_id'] );
		} else {
			return '';
		}
		if ( $c['status'] ) {
			$w .= " AND ( `{$c['status']}` IS NULL OR `{$c['status']}` NOT IN ('active','running','started','in_progress','deleted') )";
		}
		return $w;
	}
}

if ( ! function_exists( 'rkspb_min_expr' ) ) {
	function rkspb_min_expr() {
		$c = rkspb_log_cols();
		return $c['min'] ? "COALESCE(`{$c['min']}`,0)" : "COALESCE(`{$c['sec']}`,0)/60";
	}
}

if ( ! function_exists( 'rkspb_study_totals' ) ) {
	/** جمع دقیقه‌ها، هفت روز اخیر، امروز و آخرین ثبت. */
	function rkspb_study_totals( $student_row ) {
		global $wpdb;
		$out = array( 'total_minutes' => 0, 'week_minutes' => 0, 'today_minutes' => 0, 'last_at' => '', 'sessions' => 0, 'total_tests' => 0 );
		$w   = rkspb_log_where( $student_row );
		if ( '' === $w ) { return $out; }
		$c     = rkspb_log_cols();
		$t     = rkspb_table_name( 'study_logs' );
		$m     = rkspb_min_expr();
		$today = current_time( 'Y-m-d' );
		$week  = gmdate( 'Y-m-d', strtotime( $today ) - 6 * DAY_IN_SECONDS );
		$tests = $c['tests'] ? "SUM(COALESCE(`{$c['tests']}`,0))" : '0';
		if ( $c['date'] ) {
			$d   = "`{$c['date']}`";
			$sql = $wpdb->prepare(
				"SELECT SUM({$m}) total, SUM(CASE WHEN DATE({$d}) >= %s THEN {$m} ELSE 0 END) week,
				        SUM(CASE WHEN DATE({$d}) = %s THEN {$m} ELSE 0 END) today, MAX({$d}) last_at, COUNT(*) n, {$tests} tests
				 FROM `{$t}` WHERE {$w}",
				$week,
				$today
			);
		} else {
			$sql = "SELECT SUM({$m}) total, 0 week, 0 today, '' last_at, COUNT(*) n, {$tests} tests FROM `{$t}` WHERE {$w}";
		}
		$r = $wpdb->get_row( $sql, ARRAY_A );
		if ( $r ) {
			$out = array(
				'total_minutes' => (int) round( (float) $r['total'] ),
				'week_minutes'  => (int) round( (float) $r['week'] ),
				'today_minutes' => (int) round( (float) $r['today'] ),
				'last_at'       => (string) $r['last_at'],
				'sessions'      => (int) $r['n'],
				'total_tests'   => (int) $r['tests'],
			);
		}
		return $out;
	}
}

if ( ! function_exists( 'rkspb_study_detail' ) ) {
	function rkspb_study_detail( $student_row ) {
		global $wpdb;
		$out = array( 'subjects' => array(), 'days' => array(), 'logs' => array(), 'streak_days' => 0 );
		$w   = rkspb_log_where( $student_row );
		if ( '' === $w ) { return $out; }
		$c = rkspb_log_cols();
		$t = rkspb_table_name( 'study_logs' );
		$m = rkspb_min_expr();

		if ( $c['subject'] ) {
			$tests = $c['tests'] ? "SUM(COALESCE(`{$c['tests']}`,0))" : '0';
			$rows  = $wpdb->get_results( "SELECT `{$c['subject']}` subject, SUM({$m}) minutes, {$tests} tests, COUNT(*) sessions FROM `{$t}` WHERE {$w} GROUP BY `{$c['subject']}` ORDER BY minutes DESC", ARRAY_A );
			foreach ( (array) $rows as $r ) {
				$out['subjects'][] = array(
					'subject'  => '' !== (string) $r['subject'] ? (string) $r['subject'] : 'بدون درس',
					'minutes'  => (int) round( (float) $r['minutes'] ),
					'tests'    => (int) $r['tests'],
					'sessions' => (int) $r['sessions'],
				);
			}
		}

		if ( $c['date'] ) {
			$d     = "`{$c['date']}`";
			$today = current_time( 'Y-m-d' );
			$from  = gmdate( 'Y-m-d', strtotime( $today ) - 59 * DAY_IN_SECONDS );
			$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT DATE({$d}) day, SUM({$m}) minutes FROM `{$t}` WHERE {$w} AND DATE({$d}) >= %s GROUP BY DATE({$d})", $from ), ARRAY_A );
			$map   = array();
			foreach ( (array) $rows as $r ) { $map[ $r['day'] ] = (int) round( (float) $r['minutes'] ); }
			for ( $i = 13; $i >= 0; $i-- ) {
				$day           = gmdate( 'Y-m-d', strtotime( $today ) - $i * DAY_IN_SECONDS );
				$out['days'][] = array( 'date' => $day, 'minutes' => isset( $map[ $day ] ) ? $map[ $day ] : 0 );
			}
			// پیوستگی: روزهای پشت‌سرِ هم تا امروز (اگر امروز هنوز ثبتی ندارد، از دیروز حساب می‌شود)
			$streak = 0;
			$start  = empty( $map[ $today ] ) ? 1 : 0;
			for ( $i = $start; $i < 60; $i++ ) {
				$day = gmdate( 'Y-m-d', strtotime( $today ) - $i * DAY_IN_SECONDS );
				if ( empty( $map[ $day ] ) ) { break; }
				$streak++;
			}
			$out['streak_days'] = $streak;
		}

		$order = $c['date'] ? "`{$c['date']}` DESC, id DESC" : 'id DESC';
		$rows  = $wpdb->get_results( "SELECT * FROM `{$t}` WHERE {$w} ORDER BY {$order} LIMIT 30", ARRAY_A );
		foreach ( (array) $rows as $r ) {
			$minutes         = $c['min'] ? (float) $r[ $c['min'] ] : (float) $r[ $c['sec'] ] / 60;
			$out['logs'][] = array(
				'id'      => (int) $r['id'],
				'date'    => $c['date'] ? (string) $r[ $c['date'] ] : '',
				'subject' => $c['subject'] ? (string) $r[ $c['subject'] ] : '',
				'topic'   => $c['topic'] ? (string) $r[ $c['topic'] ] : '',
				'minutes' => (int) round( $minutes ),
				'tests'   => $c['tests'] ? (int) $r[ $c['tests'] ] : 0,
			);
		}
		return $out;
	}
}

if ( ! function_exists( 'rkspb_week_ready' ) ) {
	function rkspb_week_ready() {
		global $wpdb;
		static $ready = null;
		if ( null === $ready ) {
			$t     = $wpdb->prefix . 'rkspb_week_items';
			$ready = ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $t ) ) === $t );
		}
		return $ready;
	}
}

if ( ! function_exists( 'rkspb_student_card' ) ) {
	/** خلاصه‌ی یک دانش‌آموز برای فهرست مشاور. */
	function rkspb_student_card( $row, $link ) {
		$tasks   = rkspb_tasks_for( $row['id'] );
		$done    = count( array_filter( $tasks, function ( $t ) { return $t['done']; } ) );
		$plan    = rkspb_plan_info( $link, (int) $row['id'] );
		$totals  = rkspb_study_totals( $row );
		return array(
			'student_id'    => (int) $row['id'],
			'name'          => rkspb_student_name( $row ),
			'mobile'        => rkspb_student_mobile( $row ),
			'grade'         => isset( $row['grade'] ) ? (string) $row['grade'] : '',
			'field'         => isset( $row['field'] ) ? (string) $row['field'] : '',
			'city'          => isset( $row['city'] ) ? (string) $row['city'] : '',
			'plan_name'     => $plan['name'],
			'plan_start'    => $plan['start'],
			'plan_end'      => $plan['end'],
			'tasks_total'   => count( $tasks ),
			'tasks_done'    => $done,
			'tasks_pending' => count( $tasks ) - $done,
			'study'         => $totals,
			'week'          => rkspb_week_ready() ? rkspb_week_stats( (int) $row['id'], rkspb_week_start() ) : null,
		);
	}
}

if ( ! function_exists( 'rkspb_json_params' ) ) {
	function rkspb_json_params( WP_REST_Request $req ) {
		$p = (array) $req->get_json_params();
		if ( empty( $p ) ) { $p = (array) $req->get_body_params(); }
		return $p;
	}
}

if ( ! function_exists( 'rkspb_clean_date' ) ) {
	/** فقط تاریخ میلادی YYYY-MM-DD را می‌پذیرد. */
	function rkspb_clean_date( $v ) {
		$v = rkspb_latin_digits( trim( (string) $v ) );
		return preg_match( '/^\d{4}-\d{2}-\d{2}$/', $v ) ? $v : '';
	}
}

/* ------------------------------------------------------------------ روت‌ها -- */

add_action( 'rest_api_init', function () {

	$logged_in = function () { return is_user_logged_in(); };

	/* ---------- مشاور ---------- */

	register_rest_route( RKSPB_NS, '/mentor/students', array(
		'methods'             => 'GET',
		'permission_callback' => $logged_in,
		'callback'            => function () {
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$out = array();
			foreach ( rkspb_mentor_links( $ctx['keys'] ) as $sid => $link ) {
				$row = rkspb_student_by_id( $sid );
				if ( $row ) { $out[] = rkspb_student_card( $row, $link ); }
			}
			return rest_ensure_response( array( 'students' => $out ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/mentor/students/(?P<id>\d+)', array(
		'methods'             => 'GET',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$sid  = (int) $req['id'];
			$link = rkspb_mentor_can( $ctx, $sid );
			if ( is_wp_error( $link ) ) { return $link; }
			$row = rkspb_student_by_id( $sid );
			if ( ! $row ) { return new WP_Error( 'rkspb_404', 'دانش‌آموز پیدا نشد.', array( 'status' => 404 ) ); }
			return rest_ensure_response( array(
				'student' => rkspb_student_card( $row, $link ),
				'tasks'   => rkspb_tasks_for( $sid ),
				'notes'   => rkspb_notes_for( $sid, true ),
				'study'   => rkspb_study_detail( $row ),
			) );
		},
	) );

	register_rest_route( RKSPB_NS, '/mentor/tasks', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$p     = rkspb_json_params( $req );
			$sid   = isset( $p['student_id'] ) ? (int) $p['student_id'] : 0;
			$title = isset( $p['title'] ) ? sanitize_text_field( $p['title'] ) : '';
			if ( '' === $title ) {
				return new WP_Error( 'rkspb_bad', 'عنوان تکلیف را بنویسید.', array( 'status' => 400 ) );
			}
			$link = rkspb_mentor_can( $ctx, $sid );
			if ( is_wp_error( $link ) ) { return $link; }
			$st  = rkspb_task_statuses();
			$due = rkspb_clean_date( isset( $p['due_date'] ) ? $p['due_date'] : '' );
			$id  = rkspb_insert_row( 'tasks', array(
				'student_id'  => $sid,
				'mentor_id'   => (int) $link['mentor_id'],
				'title'       => $title,
				'description' => isset( $p['description'] ) ? sanitize_textarea_field( $p['description'] ) : '',
				'due_date'    => '' !== $due ? $due : null,
				'status'      => $st['pending'],
				'created_at'  => rkspb_now(),
			) );
			if ( is_wp_error( $id ) ) { return $id; }
			return rest_ensure_response( array( 'ok' => true, 'id' => $id, 'tasks' => rkspb_tasks_for( $sid ) ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/mentor/tasks/(?P<id>\d+)/delete', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			global $wpdb;
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$t    = rkspb_table_name( 'tasks' );
			$task = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d", (int) $req['id'] ), ARRAY_A );
			if ( ! $task ) { return new WP_Error( 'rkspb_404', 'تکلیف پیدا نشد.', array( 'status' => 404 ) ); }
			$link = rkspb_mentor_can( $ctx, (int) $task['student_id'] );
			if ( is_wp_error( $link ) ) { return $link; }
			$wpdb->delete( $t, array( 'id' => (int) $task['id'] ) );
			return rest_ensure_response( array( 'ok' => true, 'tasks' => rkspb_tasks_for( (int) $task['student_id'] ) ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/mentor/notes', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$p    = rkspb_json_params( $req );
			$sid  = isset( $p['student_id'] ) ? (int) $p['student_id'] : 0;
			$note = isset( $p['note'] ) ? sanitize_textarea_field( $p['note'] ) : '';
			if ( '' === trim( $note ) ) {
				return new WP_Error( 'rkspb_bad', 'متن یادداشت خالی است.', array( 'status' => 400 ) );
			}
			$link = rkspb_mentor_can( $ctx, $sid );
			if ( is_wp_error( $link ) ) { return $link; }
			$c       = rkspb_note_cols();
			if ( ! $c['text'] ) {
				return new WP_Error( 'rkspb_schema', 'ستون متن در جدول یادداشت‌ها پیدا نشد.', array( 'status' => 500 ) );
			}
			$private = isset( $p['visibility'] ) && 'private' === $p['visibility'];
			if ( $private && ! $c['vis'] && ! $c['priv'] && ! $c['pub'] ) {
				// بدون ستون محرمانه، یادداشت محرمانه به دانش‌آموز نشان داده می‌شد. ثبتش نمی‌کنیم.
				return new WP_Error( 'rkspb_no_private', 'ثبت یادداشت محرمانه هنوز فعال نشده است. یک بار پیشخوان وردپرس را باز کنید تا به‌روزرسانی جدول انجام شود.', array( 'status' => 409 ) );
			}
			$data    = array(
				'student_id' => $sid,
				'mentor_id'  => (int) $link['mentor_id'],
				$c['text']   => $note,
			);
			if ( $c['vis'] )  { $data[ $c['vis'] ] = rkspb_fit_value( 'mentor_notes', $c['vis'], $private ? 'private' : 'public', $private ? array( 'private', 'mentor' ) : array( 'public', 'student' ) ); }
			if ( $c['priv'] ) { $data[ $c['priv'] ] = $private ? 1 : 0; }
			if ( $c['pub'] )  { $data[ $c['pub'] ] = $private ? 0 : 1; }
			if ( $c['cat'] )  {
				$data[ $c['cat'] ] = $private
					? rkspb_fit_value( 'mentor_notes', $c['cat'], 'private', array( 'private', 'mentor' ) )
					: rkspb_fit_value( 'mentor_notes', $c['cat'], 'feedback', array( 'feedback', 'general', 'note' ) );
			}
			if ( $c['created'] ) { $data[ $c['created'] ] = rkspb_now(); }
			$id = rkspb_insert_row( 'mentor_notes', $data );
			if ( is_wp_error( $id ) ) { return $id; }
			return rest_ensure_response( array( 'ok' => true, 'id' => $id, 'notes' => rkspb_notes_for( $sid, true ) ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/mentor/notes/(?P<id>\d+)/delete', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			global $wpdb;
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$t    = rkspb_table_name( 'mentor_notes' );
			$note = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d", (int) $req['id'] ), ARRAY_A );
			if ( ! $note ) { return new WP_Error( 'rkspb_404', 'یادداشت پیدا نشد.', array( 'status' => 404 ) ); }
			$link = rkspb_mentor_can( $ctx, (int) $note['student_id'] );
			if ( is_wp_error( $link ) ) { return $link; }
			$wpdb->delete( $t, array( 'id' => (int) $note['id'] ) );
			return rest_ensure_response( array( 'ok' => true, 'notes' => rkspb_notes_for( (int) $note['student_id'], true ) ) );
		},
	) );

	/* ---------- دانش‌آموز ---------- */

	$student_overview = function ( $ctx ) {
		$row    = $ctx['row'];
		$mentor = null;
		if ( $ctx['mentor'] ) {
			$m      = $ctx['mentor'];
			$name   = trim( ( isset( $m['first_name'] ) ? $m['first_name'] : '' ) . ' ' . ( isset( $m['last_name'] ) ? $m['last_name'] : '' ) );
			if ( '' === $name && ! empty( $m['user_id'] ) ) {
				$u    = get_user_by( 'id', (int) $m['user_id'] );
				$name = $u ? $u->display_name : '';
			}
			$mentor = array(
				'name'      => $name,
				'mobile'    => ! empty( $m['mobile'] ) ? rkspb_normalize_mobile( $m['mobile'] ) : '',
				'specialty' => isset( $m['specialty'] ) ? (string) $m['specialty'] : '',
			);
		}
		$plan = rkspb_plan_info( $ctx['link'], (int) $row['id'] );
		return array(
			'student' => array(
				'student_id' => (int) $row['id'],
				'name'       => rkspb_student_name( $row ),
				'mobile'     => rkspb_student_mobile( $row ),
				'grade'      => isset( $row['grade'] ) ? (string) $row['grade'] : '',
				'field'      => isset( $row['field'] ) ? (string) $row['field'] : '',
				'city'       => isset( $row['city'] ) ? (string) $row['city'] : '',
			),
			'mentor'  => $mentor,
			'plan'    => ( '' !== $plan['name'] || '' !== $plan['end'] ) ? $plan : null,
			'payments' => function_exists( 'rkspb_student_payments' ) ? rkspb_student_payments( (int) $row['id'] ) : array(),
			'tasks'   => rkspb_tasks_for( (int) $row['id'] ),
			'notes'   => rkspb_notes_for( (int) $row['id'], false ),
			'totals'  => rkspb_study_totals( $row ),
			'study'   => rkspb_study_detail( $row ),
			'can_log' => '' !== rkspb_log_where( $row ),
		);
	};

	register_rest_route( RKSPB_NS, '/student/overview', array(
		'methods'             => 'GET',
		'permission_callback' => $logged_in,
		'callback'            => function () use ( $student_overview ) {
			$ctx = rkspb_ctx_student();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			return rest_ensure_response( $student_overview( $ctx ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/student/study-log', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) use ( $student_overview ) {
			$ctx = rkspb_ctx_student();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$row = $ctx['row'];
			if ( '' === rkspb_log_where( $row ) ) {
				return new WP_Error( 'rkspb_schema', 'جدول ساعت مطالعه ستون‌های لازم را ندارد.', array( 'status' => 500 ) );
			}
			$p       = rkspb_json_params( $req );
			$minutes = (int) rkspb_latin_digits( isset( $p['minutes'] ) ? $p['minutes'] : 0 );
			$subject = isset( $p['subject'] ) ? sanitize_text_field( $p['subject'] ) : '';
			if ( $minutes < 1 || $minutes > 16 * 60 ) {
				return new WP_Error( 'rkspb_bad', 'مدت مطالعه باید بین ۱ دقیقه و ۱۶ ساعت باشد.', array( 'status' => 400 ) );
			}
			if ( '' === $subject ) {
				return new WP_Error( 'rkspb_bad', 'درس را انتخاب کنید.', array( 'status' => 400 ) );
			}
			$date = rkspb_clean_date( isset( $p['date'] ) ? $p['date'] : '' );
			$today = current_time( 'Y-m-d' );
			if ( '' === $date || $date > $today ) { $date = $today; }

			$c    = rkspb_log_cols();
			$meta = rkspb_cols_meta( 'study_logs' );
			$now  = rkspb_now();
			$when = $date === $today ? $now : $date . ' 12:00:00';
			$data = array();
			if ( $c['sid'] ) { $data[ $c['sid'] ] = (int) $row['id']; }
			if ( $c['uid'] ) { $data[ $c['uid'] ] = (int) ( ! empty( $row['user_id'] ) ? $row['user_id'] : get_current_user_id() ); }
			if ( $c['min'] ) { $data[ $c['min'] ] = $minutes; } else { $data[ $c['sec'] ] = $minutes * 60; }
			if ( $c['subject'] ) { $data[ $c['subject'] ] = $subject; }
			if ( $c['topic'] && ! empty( $p['topic'] ) ) { $data[ $c['topic'] ] = sanitize_text_field( $p['topic'] ); }
			if ( $c['tests'] ) { $data[ $c['tests'] ] = max( 0, (int) rkspb_latin_digits( isset( $p['tests'] ) ? $p['tests'] : 0 ) ); }
			if ( $c['date'] ) {
				$data[ $c['date'] ] = ( 0 === strpos( $meta[ $c['date'] ]['type'], 'date' ) && false === strpos( $meta[ $c['date'] ]['type'], 'datetime' ) ) ? $date : $when;
			}
			if ( isset( $meta['started_at'] ) && 'started_at' !== $c['date'] ) { $data['started_at'] = gmdate( 'Y-m-d H:i:s', strtotime( $when ) - $minutes * 60 ); }
			if ( isset( $meta['ended_at'] ) )   { $data['ended_at'] = $when; }
			if ( isset( $meta['created_at'] ) && 'created_at' !== $c['date'] ) { $data['created_at'] = $now; }
			if ( isset( $meta['source'] ) )     { $data['source'] = rkspb_fit_value( 'study_logs', 'source', 'panel', array( 'panel', 'manual' ) ); }
			if ( $c['status'] ) { $data[ $c['status'] ] = rkspb_fit_value( 'study_logs', $c['status'], 'completed', array( 'completed', 'done', 'ended', 'finished', 'closed' ) ); }

			$id = rkspb_insert_row( 'study_logs', $data );
			if ( is_wp_error( $id ) ) { return $id; }
			$out       = $student_overview( $ctx );
			$out['ok'] = true;
			$out['id'] = $id;
			return rest_ensure_response( $out );
		},
	) );

	register_rest_route( RKSPB_NS, '/student/study-log/(?P<id>\d+)/delete', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) use ( $student_overview ) {
			global $wpdb;
			$ctx = rkspb_ctx_student();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$w = rkspb_log_where( $ctx['row'] );
			if ( '' === $w ) { return new WP_Error( 'rkspb_schema', 'جدول ساعت مطالعه قابل استفاده نیست.', array( 'status' => 500 ) ); }
			$t     = rkspb_table_name( 'study_logs' );
			$found = (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM `{$t}` WHERE id = %d AND {$w}", (int) $req['id'] ) );
			if ( ! $found ) { return new WP_Error( 'rkspb_404', 'این ثبت پیدا نشد.', array( 'status' => 404 ) ); }
			$wpdb->delete( $t, array( 'id' => $found ) );
			if ( rkspb_week_ready() ) {
				$wpdb->query( $wpdb->prepare(
					'UPDATE `' . $wpdb->prefix . 'rkspb_week_items` SET done = 0, done_minutes = 0, done_tests = 0, done_at = NULL, log_id = NULL WHERE log_id = %d AND student_id = %d',
					$found,
					(int) $ctx['row']['id']
				) );
			}
			$out       = $student_overview( $ctx );
			$out['ok'] = true;
			return rest_ensure_response( $out );
		},
	) );

	register_rest_route( RKSPB_NS, '/student/tasks/(?P<id>\d+)', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) use ( $student_overview ) {
			global $wpdb;
			$ctx = rkspb_ctx_student();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$t    = rkspb_table_name( 'tasks' );
			$task = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d AND student_id = %d", (int) $req['id'], (int) $ctx['row']['id'] ), ARRAY_A );
			if ( ! $task ) { return new WP_Error( 'rkspb_404', 'این تکلیف پیدا نشد.', array( 'status' => 404 ) ); }
			$p    = rkspb_json_params( $req );
			$done = ! empty( $p['done'] );
			if ( ! rkspb_set_task_done( (int) $task['id'], $done ) ) {
				return new WP_Error( 'rkspb_db', 'وضعیت تکلیف ذخیره نشد.', array( 'status' => 500 ) );
			}
			$out       = $student_overview( $ctx );
			$out['ok'] = true;
			return rest_ensure_response( $out );
		},
	) );
} );

/* ------------------------------------------ SCHEMA + WEEKLY PLAN (1.3.0) -- */

if ( ! defined( 'RKSPB_SCHEMA' ) ) { define( 'RKSPB_SCHEMA', '1.3.0' ); }

if ( ! function_exists( 'rkspb_week_table' ) ) {
	function rkspb_week_table() {
		global $wpdb;
		return $wpdb->prefix . 'rkspb_week_items';
	}
}

if ( ! function_exists( 'rkspb_upgrade_schema' ) ) {
	/**
	 * ستون‌ها و جدول‌هایی که پل لازم دارد. فقط «اضافه» می‌کند، هرگز چیزی را حذف یا عوض نمی‌کند.
	 * - mentor_notes.rkspb_private : جدول rksp ستونی برای محرمانه ندارد
	 * - study_logs.topic           : جدول rksp ستونی برای مبحث ندارد
	 * - rkspb_week_items           : برنامه‌ی هفتگی
	 */
	function rkspb_upgrade_schema() {
		global $wpdb;
		$ok = true;

		$nt = rkspb_table_name( 'mentor_notes' );
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $nt ) ) === $nt ) {
			if ( ! $wpdb->get_var( "SHOW COLUMNS FROM `{$nt}` LIKE 'rkspb_private'" ) ) {
				$ok = ( false !== $wpdb->query( "ALTER TABLE `{$nt}` ADD COLUMN `rkspb_private` TINYINT(1) NOT NULL DEFAULT 0" ) ) && $ok;
			}
		}

		$lt = rkspb_table_name( 'study_logs' );
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $lt ) ) === $lt ) {
			$has_topic = $wpdb->get_var( "SHOW COLUMNS FROM `{$lt}` LIKE 'topic'" );
			if ( ! $has_topic ) {
				$ok = ( false !== $wpdb->query( "ALTER TABLE `{$lt}` ADD COLUMN `topic` VARCHAR(190) NULL DEFAULT NULL" ) ) && $ok;
			}
		}

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$wt      = rkspb_week_table();
		$charset = $wpdb->get_charset_collate();
		dbDelta( "CREATE TABLE {$wt} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			student_id bigint(20) unsigned NOT NULL,
			mentor_id bigint(20) unsigned NOT NULL DEFAULT 0,
			plan_date date NOT NULL,
			subject varchar(100) NOT NULL DEFAULT '',
			topic varchar(190) NOT NULL DEFAULT '',
			minutes smallint(5) unsigned NOT NULL DEFAULT 0,
			tests smallint(5) unsigned NOT NULL DEFAULT 0,
			note varchar(255) NOT NULL DEFAULT '',
			done tinyint(1) NOT NULL DEFAULT 0,
			done_minutes smallint(5) unsigned NOT NULL DEFAULT 0,
			done_tests smallint(5) unsigned NOT NULL DEFAULT 0,
			done_at datetime NULL DEFAULT NULL,
			log_id bigint(20) unsigned NULL DEFAULT NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY student_date (student_id,plan_date)
		) {$charset};" );
		$ok = ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wt ) ) === $wt ) && $ok;

		if ( $ok ) {
			update_option( 'rkspb_schema', RKSPB_SCHEMA, false );
			delete_option( 'rkspb_schema_error' );
		} else {
			update_option( 'rkspb_schema_error', $wpdb->last_error, false );
		}
		return $ok;
	}
}

// روی هر درخواست ارزان است (یک get_option)؛ اگر شکست خورد، ساعتی یک بار دوباره تلاش می‌کند.
add_action( 'init', function () {
	if ( RKSPB_SCHEMA === get_option( 'rkspb_schema' ) ) { return; }
	if ( get_transient( 'rkspb_schema_try' ) ) { return; }
	set_transient( 'rkspb_schema_try', 1, HOUR_IN_SECONDS );
	rkspb_upgrade_schema();
}, 5 );

add_action( 'admin_notices', function () {
	$err = get_option( 'rkspb_schema_error' );
	if ( ! $err || ! current_user_can( 'manage_options' ) ) { return; }
	echo '<div class="notice notice-error"><p><strong>پل پرتال:</strong> به‌روزرسانی جدول‌ها انجام نشد: <code>' . esc_html( $err ) . '</code></p></div>';
} );

/* ------------------------------------------------------ تاریخ هفته (شنبه) -- */

if ( ! function_exists( 'rkspb_week_start' ) ) {
	/** شنبه‌ی هفته‌ای که تاریخ داده‌شده در آن است (Y-m-d). */
	function rkspb_week_start( $date = '' ) {
		$date = rkspb_clean_date( $date );
		if ( '' === $date ) { $date = current_time( 'Y-m-d' ); }
		$ts   = strtotime( $date . ' 12:00:00 UTC' );
		$back = ( (int) gmdate( 'w', $ts ) + 1 ) % 7; // شنبه=0 … جمعه=6
		return gmdate( 'Y-m-d', $ts - $back * DAY_IN_SECONDS );
	}
}

if ( ! function_exists( 'rkspb_add_days' ) ) {
	function rkspb_add_days( $date, $n ) {
		return gmdate( 'Y-m-d', strtotime( $date . ' 12:00:00 UTC' ) + (int) $n * DAY_IN_SECONDS );
	}
}

if ( ! function_exists( 'rkspb_week_item_out' ) ) {
	function rkspb_week_item_out( $r ) {
		return array(
			'id'           => (int) $r['id'],
			'date'         => (string) $r['plan_date'],
			'subject'      => (string) $r['subject'],
			'topic'        => (string) $r['topic'],
			'minutes'      => (int) $r['minutes'],
			'tests'        => (int) $r['tests'],
			'note'         => (string) $r['note'],
			'done'         => (bool) (int) $r['done'],
			'done_minutes' => (int) $r['done_minutes'],
			'done_tests'   => (int) $r['done_tests'],
			'done_at'      => $r['done_at'] ? (string) $r['done_at'] : '',
		);
	}
}

if ( ! function_exists( 'rkspb_week_stats' ) ) {
	function rkspb_week_stats( $sid, $start ) {
		global $wpdb;
		$wt  = rkspb_week_table();
		$end = rkspb_add_days( $start, 6 );
		$r   = $wpdb->get_row( $wpdb->prepare(
			"SELECT COUNT(*) items, COALESCE(SUM(done),0) done_items, COALESCE(SUM(minutes),0) planned, COALESCE(SUM(CASE WHEN done=1 THEN done_minutes ELSE 0 END),0) done_minutes
			 FROM `{$wt}` WHERE student_id = %d AND plan_date BETWEEN %s AND %s",
			$sid,
			$start,
			$end
		), ARRAY_A );
		$items = $r ? (int) $r['items'] : 0;
		$done  = $r ? (int) $r['done_items'] : 0;
		// فقط آیتم‌هایی که روزشان رسیده در «عمل به برنامه» حساب می‌شوند
		$due = (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM `{$wt}` WHERE student_id = %d AND plan_date BETWEEN %s AND %s AND plan_date <= %s",
			$sid,
			$start,
			$end,
			current_time( 'Y-m-d' )
		) );
		$due_done = (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM `{$wt}` WHERE student_id = %d AND plan_date BETWEEN %s AND %s AND plan_date <= %s AND done = 1",
			$sid,
			$start,
			$end,
			current_time( 'Y-m-d' )
		) );
		return array(
			'items'           => $items,
			'done_items'      => $done,
			'due_items'       => $due,
			'due_done_items'  => $due_done,
			'rate'            => $due ? (int) round( 100 * $due_done / $due ) : null,
			'planned_minutes' => $r ? (int) $r['planned'] : 0,
			'done_minutes'    => $r ? (int) $r['done_minutes'] : 0,
		);
	}
}

if ( ! function_exists( 'rkspb_week_payload' ) ) {
	function rkspb_week_payload( $sid, $start ) {
		global $wpdb;
		$start = rkspb_week_start( $start );
		$end   = rkspb_add_days( $start, 6 );
		$wt    = rkspb_week_table();
		$rows  = array();
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wt ) ) === $wt ) {
			$rows = $wpdb->get_results( $wpdb->prepare(
				"SELECT * FROM `{$wt}` WHERE student_id = %d AND plan_date BETWEEN %s AND %s ORDER BY plan_date ASC, id ASC",
				$sid,
				$start,
				$end
			), ARRAY_A );
		} else {
			return new WP_Error( 'rkspb_no_week', 'جدول برنامه‌ی هفتگی هنوز ساخته نشده است. یک بار پیشخوان وردپرس را باز کنید.', array( 'status' => 500 ) );
		}
		$days = array();
		for ( $i = 0; $i < 7; $i++ ) {
			$d          = rkspb_add_days( $start, $i );
			$days[ $d ] = array( 'date' => $d, 'items' => array() );
		}
		foreach ( (array) $rows as $r ) {
			if ( isset( $days[ $r['plan_date'] ] ) ) { $days[ $r['plan_date'] ]['items'][] = rkspb_week_item_out( $r ); }
		}
		return array(
			'start' => $start,
			'end'   => $end,
			'today' => current_time( 'Y-m-d' ),
			'days'  => array_values( $days ),
			'stats' => rkspb_week_stats( $sid, $start ),
		);
	}
}

if ( ! function_exists( 'rkspb_week_item_input' ) ) {
	/** @return array|WP_Error */
	function rkspb_week_item_input( $p, $partial = false ) {
		$out = array();
		if ( ! $partial || isset( $p['date'] ) ) {
			$d = rkspb_clean_date( isset( $p['date'] ) ? $p['date'] : '' );
			if ( '' === $d ) { return new WP_Error( 'rkspb_bad', 'روز را انتخاب کنید.', array( 'status' => 400 ) ); }
			$out['plan_date'] = $d;
		}
		if ( ! $partial || isset( $p['subject'] ) ) {
			$sub = isset( $p['subject'] ) ? sanitize_text_field( $p['subject'] ) : '';
			if ( '' === $sub ) { return new WP_Error( 'rkspb_bad', 'درس را انتخاب کنید.', array( 'status' => 400 ) ); }
			$out['subject'] = mb_substr( $sub, 0, 100 );
		}
		foreach ( array( 'topic' => 190, 'note' => 255 ) as $k => $len ) {
			if ( ! $partial || isset( $p[ $k ] ) ) { $out[ $k ] = mb_substr( sanitize_text_field( isset( $p[ $k ] ) ? $p[ $k ] : '' ), 0, $len ); }
		}
		foreach ( array( 'minutes' => 960, 'tests' => 1000 ) as $k => $max ) {
			if ( ! $partial || isset( $p[ $k ] ) ) {
				$out[ $k ] = min( $max, max( 0, (int) rkspb_latin_digits( isset( $p[ $k ] ) ? $p[ $k ] : 0 ) ) );
			}
		}
		if ( isset( $out['minutes'], $out['tests'] ) && ! $out['minutes'] && ! $out['tests'] ) {
			return new WP_Error( 'rkspb_bad', 'مدت یا تعداد تست را مشخص کنید.', array( 'status' => 400 ) );
		}
		return $out;
	}
}

if ( ! function_exists( 'rkspb_week_item_for_mentor' ) ) {
	/** @return array|WP_Error ردیف آیتم، اگر به دانش‌آموزِ این مشاور تعلق دارد */
	function rkspb_week_item_for_mentor( $ctx, $id ) {
		global $wpdb;
		$wt  = rkspb_week_table();
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$wt}` WHERE id = %d", $id ), ARRAY_A );
		if ( ! $row ) { return new WP_Error( 'rkspb_404', 'این مورد برنامه پیدا نشد.', array( 'status' => 404 ) ); }
		$link = rkspb_mentor_can( $ctx, (int) $row['student_id'] );
		if ( is_wp_error( $link ) ) { return $link; }
		return $row;
	}
}

if ( ! function_exists( 'rkspb_delete_log_row' ) ) {
	function rkspb_delete_log_row( $student_row, $log_id ) {
		global $wpdb;
		$w = rkspb_log_where( $student_row );
		if ( '' === $w || ! $log_id ) { return; }
		$t = rkspb_table_name( 'study_logs' );
		$wpdb->query( $wpdb->prepare( "DELETE FROM `{$t}` WHERE id = %d AND {$w}", $log_id ) );
	}
}

if ( ! function_exists( 'rkspb_insert_study_log' ) ) {
	/**
	 * یک ثبت مطالعه می‌سازد (مشترک بین فرم ثبت و تیک برنامه).
	 *
	 * @return int|WP_Error
	 */
	function rkspb_insert_study_log( $row, $subject, $minutes, $tests, $topic, $date ) {
		$c = rkspb_log_cols();
		if ( '' === rkspb_log_where( $row ) ) {
			return new WP_Error( 'rkspb_schema', 'جدول ساعت مطالعه ستون‌های لازم را ندارد.', array( 'status' => 500 ) );
		}
		$meta  = rkspb_cols_meta( 'study_logs' );
		$today = current_time( 'Y-m-d' );
		$now   = rkspb_now();
		$when  = $date === $today ? $now : $date . ' 12:00:00';
		$data  = array();
		if ( $c['sid'] ) { $data[ $c['sid'] ] = (int) $row['id']; }
		if ( $c['uid'] ) { $data[ $c['uid'] ] = (int) ( ! empty( $row['user_id'] ) ? $row['user_id'] : get_current_user_id() ); }
		if ( $c['min'] ) { $data[ $c['min'] ] = (int) $minutes; } else { $data[ $c['sec'] ] = (int) $minutes * 60; }
		if ( $c['subject'] ) { $data[ $c['subject'] ] = $subject; }
		if ( $c['topic'] && '' !== $topic ) { $data[ $c['topic'] ] = $topic; }
		if ( $c['tests'] ) { $data[ $c['tests'] ] = max( 0, (int) $tests ); }
		if ( $c['date'] ) {
			$type               = $meta[ $c['date'] ]['type'];
			$data[ $c['date'] ] = ( 0 === strpos( $type, 'date' ) && false === strpos( $type, 'datetime' ) ) ? $date : $when;
		}
		if ( isset( $meta['started_at'] ) && 'started_at' !== $c['date'] ) { $data['started_at'] = gmdate( 'Y-m-d H:i:s', strtotime( $when ) - $minutes * 60 ); }
		if ( isset( $meta['ended_at'] ) )   { $data['ended_at'] = $when; }
		if ( isset( $meta['created_at'] ) && 'created_at' !== $c['date'] ) { $data['created_at'] = $now; }
		if ( isset( $meta['source'] ) )     { $data['source'] = rkspb_fit_value( 'study_logs', 'source', 'panel', array( 'panel', 'manual' ) ); }
		if ( $c['status'] ) { $data[ $c['status'] ] = rkspb_fit_value( 'study_logs', $c['status'], 'completed', array( 'completed', 'done', 'ended', 'finished', 'closed' ) ); }
		return rkspb_insert_row( 'study_logs', $data );
	}
}

add_action( 'rest_api_init', function () {

	$logged_in = function () { return is_user_logged_in(); };

	/* ---------- ویرایش تکلیف و یادداشت (مشاور) ---------- */

	register_rest_route( RKSPB_NS, '/mentor/tasks/(?P<id>\d+)', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			global $wpdb;
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$t    = rkspb_table_name( 'tasks' );
			$task = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d", (int) $req['id'] ), ARRAY_A );
			if ( ! $task ) { return new WP_Error( 'rkspb_404', 'تکلیف پیدا نشد.', array( 'status' => 404 ) ); }
			$link = rkspb_mentor_can( $ctx, (int) $task['student_id'] );
			if ( is_wp_error( $link ) ) { return $link; }
			$p     = rkspb_json_params( $req );
			$title = isset( $p['title'] ) ? sanitize_text_field( $p['title'] ) : '';
			if ( '' === $title ) { return new WP_Error( 'rkspb_bad', 'عنوان تکلیف را بنویسید.', array( 'status' => 400 ) ); }
			$meta = rkspb_cols_meta( 'tasks' );
			$data = array( 'title' => $title );
			if ( isset( $meta['description'] ) ) { $data['description'] = isset( $p['description'] ) ? sanitize_textarea_field( $p['description'] ) : ''; }
			if ( isset( $meta['due_date'] ) ) {
				$due              = rkspb_clean_date( isset( $p['due_date'] ) ? $p['due_date'] : '' );
				$data['due_date'] = '' !== $due ? $due : ( $meta['due_date']['null'] ? null : $task['due_date'] );
			}
			if ( false === $wpdb->update( $t, $data, array( 'id' => (int) $task['id'] ) ) ) {
				return new WP_Error( 'rkspb_db', 'ویرایش ذخیره نشد: ' . $wpdb->last_error, array( 'status' => 500 ) );
			}
			return rest_ensure_response( array( 'ok' => true, 'tasks' => rkspb_tasks_for( (int) $task['student_id'] ) ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/mentor/notes/(?P<id>\d+)', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			global $wpdb;
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$t    = rkspb_table_name( 'mentor_notes' );
			$note = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d", (int) $req['id'] ), ARRAY_A );
			if ( ! $note ) { return new WP_Error( 'rkspb_404', 'یادداشت پیدا نشد.', array( 'status' => 404 ) ); }
			$link = rkspb_mentor_can( $ctx, (int) $note['student_id'] );
			if ( is_wp_error( $link ) ) { return $link; }
			$p    = rkspb_json_params( $req );
			$text = isset( $p['note'] ) ? sanitize_textarea_field( $p['note'] ) : '';
			if ( '' === trim( $text ) ) { return new WP_Error( 'rkspb_bad', 'متن یادداشت خالی است.', array( 'status' => 400 ) ); }
			$c    = rkspb_note_cols();
			$data = array( $c['text'] => $text );
			if ( isset( $p['visibility'] ) ) {
				$private = 'private' === $p['visibility'];
				if ( $private && ! $c['vis'] && ! $c['priv'] && ! $c['pub'] ) {
					return new WP_Error( 'rkspb_no_private', 'ثبت یادداشت محرمانه هنوز فعال نشده است.', array( 'status' => 409 ) );
				}
				if ( $c['vis'] )  { $data[ $c['vis'] ] = rkspb_fit_value( 'mentor_notes', $c['vis'], $private ? 'private' : 'public', $private ? array( 'private', 'mentor' ) : array( 'public', 'student' ) ); }
				if ( $c['priv'] ) { $data[ $c['priv'] ] = $private ? 1 : 0; }
				if ( $c['pub'] )  { $data[ $c['pub'] ] = $private ? 0 : 1; }
				if ( $c['cat'] )  {
					$data[ $c['cat'] ] = $private
						? rkspb_fit_value( 'mentor_notes', $c['cat'], 'private', array( 'private', 'mentor' ) )
						: rkspb_fit_value( 'mentor_notes', $c['cat'], 'feedback', array( 'feedback', 'general', 'note' ) );
				}
			}
			if ( false === $wpdb->update( $t, $data, array( 'id' => (int) $note['id'] ) ) ) {
				return new WP_Error( 'rkspb_db', 'ویرایش ذخیره نشد: ' . $wpdb->last_error, array( 'status' => 500 ) );
			}
			return rest_ensure_response( array( 'ok' => true, 'notes' => rkspb_notes_for( (int) $note['student_id'], true ) ) );
		},
	) );

	/* ---------- برنامه‌ی هفتگی: مشاور ---------- */

	register_rest_route( RKSPB_NS, '/mentor/students/(?P<id>\d+)/week', array(
		'methods'             => 'GET',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$link = rkspb_mentor_can( $ctx, (int) $req['id'] );
			if ( is_wp_error( $link ) ) { return $link; }
			return rest_ensure_response( rkspb_week_payload( (int) $req['id'], (string) $req->get_param( 'start' ) ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/mentor/students/(?P<id>\d+)/week/items', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			global $wpdb;
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$sid  = (int) $req['id'];
			$link = rkspb_mentor_can( $ctx, $sid );
			if ( is_wp_error( $link ) ) { return $link; }
			$in = rkspb_week_item_input( rkspb_json_params( $req ) );
			if ( is_wp_error( $in ) ) { return $in; }
			$in['student_id'] = $sid;
			$in['mentor_id']  = (int) $link['mentor_id'];
			$in['created_at'] = rkspb_now();
			if ( false === $wpdb->insert( rkspb_week_table(), $in ) ) {
				return new WP_Error( 'rkspb_db', 'ذخیره نشد: ' . $wpdb->last_error, array( 'status' => 500 ) );
			}
			return rest_ensure_response( rkspb_week_payload( $sid, $in['plan_date'] ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/mentor/week/items/(?P<id>\d+)', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			global $wpdb;
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$row = rkspb_week_item_for_mentor( $ctx, (int) $req['id'] );
			if ( is_wp_error( $row ) ) { return $row; }
			$in = rkspb_week_item_input( rkspb_json_params( $req ), true );
			if ( is_wp_error( $in ) ) { return $in; }
			if ( $in && false === $wpdb->update( rkspb_week_table(), $in, array( 'id' => (int) $row['id'] ) ) ) {
				return new WP_Error( 'rkspb_db', 'ذخیره نشد: ' . $wpdb->last_error, array( 'status' => 500 ) );
			}
			return rest_ensure_response( rkspb_week_payload( (int) $row['student_id'], $row['plan_date'] ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/mentor/week/items/(?P<id>\d+)/delete', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			global $wpdb;
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$row = rkspb_week_item_for_mentor( $ctx, (int) $req['id'] );
			if ( is_wp_error( $row ) ) { return $row; }
			// ساعتی که دانش‌آموز با تیک این مورد ثبت کرده، سر جایش می‌ماند.
			$wpdb->delete( rkspb_week_table(), array( 'id' => (int) $row['id'] ) );
			return rest_ensure_response( rkspb_week_payload( (int) $row['student_id'], $row['plan_date'] ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/mentor/students/(?P<id>\d+)/week/copy', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			global $wpdb;
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$sid  = (int) $req['id'];
			$link = rkspb_mentor_can( $ctx, $sid );
			if ( is_wp_error( $link ) ) { return $link; }
			$p    = rkspb_json_params( $req );
			$to   = rkspb_week_start( isset( $p['start'] ) ? $p['start'] : '' );
			$from = rkspb_add_days( $to, -7 );
			$wt   = rkspb_week_table();
			$has  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$wt}` WHERE student_id = %d AND plan_date BETWEEN %s AND %s", $sid, $to, rkspb_add_days( $to, 6 ) ) );
			if ( $has && empty( $p['append'] ) ) {
				return new WP_Error( 'rkspb_not_empty', 'این هفته از قبل برنامه دارد.', array( 'status' => 409 ) );
			}
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$wt}` WHERE student_id = %d AND plan_date BETWEEN %s AND %s ORDER BY plan_date, id", $sid, $from, rkspb_add_days( $from, 6 ) ), ARRAY_A );
			if ( ! $rows ) {
				return new WP_Error( 'rkspb_empty', 'هفته‌ی قبل برنامه‌ای ندارد که کپی شود.', array( 'status' => 404 ) );
			}
			foreach ( $rows as $r ) {
				$wpdb->insert( $wt, array(
					'student_id' => $sid,
					'mentor_id'  => (int) $link['mentor_id'],
					'plan_date'  => rkspb_add_days( $r['plan_date'], 7 ),
					'subject'    => $r['subject'],
					'topic'      => $r['topic'],
					'minutes'    => (int) $r['minutes'],
					'tests'      => (int) $r['tests'],
					'note'       => $r['note'],
					'created_at' => rkspb_now(),
				) );
			}
			return rest_ensure_response( rkspb_week_payload( $sid, $to ) );
		},
	) );

	/* ---------- برنامه‌ی هفتگی: دانش‌آموز ---------- */

	register_rest_route( RKSPB_NS, '/student/week', array(
		'methods'             => 'GET',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			$ctx = rkspb_ctx_student();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			return rest_ensure_response( rkspb_week_payload( (int) $ctx['row']['id'], (string) $req->get_param( 'start' ) ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/student/week/items/(?P<id>\d+)', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			global $wpdb;
			$ctx = rkspb_ctx_student();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$row = $ctx['row'];
			$wt  = rkspb_week_table();
			$it  = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$wt}` WHERE id = %d AND student_id = %d", (int) $req['id'], (int) $row['id'] ), ARRAY_A );
			if ( ! $it ) { return new WP_Error( 'rkspb_404', 'این مورد برنامه پیدا نشد.', array( 'status' => 404 ) ); }
			$p     = rkspb_json_params( $req );
			$done  = ! empty( $p['done'] );
			$today = current_time( 'Y-m-d' );

			if ( $done ) {
				if ( $it['plan_date'] > $today ) {
					return new WP_Error( 'rkspb_future', 'برنامه‌ی روزهای آینده را هنوز نمی‌شود تیک زد.', array( 'status' => 400 ) );
				}
				$min   = isset( $p['minutes'] ) ? (int) rkspb_latin_digits( $p['minutes'] ) : (int) $it['minutes'];
				$tests = isset( $p['tests'] ) ? (int) rkspb_latin_digits( $p['tests'] ) : (int) $it['tests'];
				if ( $min < 0 || $min > 960 ) {
					return new WP_Error( 'rkspb_bad', 'مدت مطالعه باید بین ۰ و ۱۶ ساعت باشد.', array( 'status' => 400 ) );
				}
				// اگر قبلاً ثبتی ساخته شده، اول پاکش می‌کنیم تا دوبار شمرده نشود
				if ( ! empty( $it['log_id'] ) ) { rkspb_delete_log_row( $row, (int) $it['log_id'] ); }
				$log_id = null;
				if ( $min > 0 ) {
					$lid = rkspb_insert_study_log( $row, $it['subject'], $min, max( 0, $tests ), (string) $it['topic'], $it['plan_date'] );
					if ( is_wp_error( $lid ) ) { return $lid; }
					$log_id = $lid;
				}
				$wpdb->update( $wt, array(
					'done'         => 1,
					'done_minutes' => $min,
					'done_tests'   => max( 0, $tests ),
					'done_at'      => rkspb_now(),
					'log_id'       => $log_id,
				), array( 'id' => (int) $it['id'] ) );
			} else {
				if ( ! empty( $it['log_id'] ) ) { rkspb_delete_log_row( $row, (int) $it['log_id'] ); }
				$wpdb->update( $wt, array(
					'done'         => 0,
					'done_minutes' => 0,
					'done_tests'   => 0,
					'done_at'      => null,
					'log_id'       => null,
				), array( 'id' => (int) $it['id'] ) );
			}
			return rest_ensure_response( array( 'ok' => true, 'week' => rkspb_week_payload( (int) $row['id'], $it['plan_date'] ) ) );
		},
	) );
} );

/* ------------------------------------- SALES + ADMIN DASHBOARD (1.4.0) ---- */
/*
 * مشاور فروش (نقش rksp_sales): لیدهای فرم سایت را نوبتی تحویل می‌گیرد، تماس و وضعیت را ثبت
 * می‌کند و در پایان دانش‌آموز را با طرح و مشاور تحصیلی ثبت می‌کند.
 * داشبورد مدیر: آمار، طرح‌های رو به پایان، دانش‌آموزان کم‌کار، و حق‌الزحمه‌ی ماهانه.
 *
 * درصد هر نفر در متای کاربر rkspb_share_percent است. پیش‌فرض مشاور فروش ۱۵٪ (تصمیم امیر)؛
 * مشاور تحصیلی پیش‌فرض ندارد و تا مدیر تعیین نکند حق‌الزحمه‌اش محاسبه نمی‌شود.
 */

if ( ! defined( 'RKSPB_SALES_DEFAULT_SHARE' ) ) { define( 'RKSPB_SALES_DEFAULT_SHARE', 15 ); }
if ( ! defined( 'RKSPB_INGEST_KEY' ) )          { define( 'RKSPB_INGEST_KEY', '1lkB8_YiskARIkryOgdm3QzElW6iuV7IBMJ0RUr2V90' ); }

if ( ! function_exists( 'rkspb_leads_table' ) ) {
	function rkspb_leads_table() { global $wpdb; return $wpdb->prefix . 'rkspb_leads'; }
}
if ( ! function_exists( 'rkspb_lead_events_table' ) ) {
	function rkspb_lead_events_table() { global $wpdb; return $wpdb->prefix . 'rkspb_lead_events'; }
}

if ( ! function_exists( 'rkspb_lead_statuses' ) ) {
	function rkspb_lead_statuses() {
		return array(
			'new'       => 'جدید',
			'contacted' => 'تماس گرفته شد',
			'followup'  => 'در حال پیگیری',
			'won'       => 'ثبت‌نام شد',
			'lost'      => 'منصرف شد',
		);
	}
}

if ( ! function_exists( 'rkspb_upgrade_sales_schema' ) ) {
	function rkspb_upgrade_sales_schema() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$lt      = rkspb_leads_table();
		$et      = rkspb_lead_events_table();
		dbDelta( "CREATE TABLE {$lt} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ext_id varchar(64) NOT NULL DEFAULT '',
			name varchar(120) NOT NULL DEFAULT '',
			mobile varchar(20) NOT NULL DEFAULT '',
			grade varchar(40) NOT NULL DEFAULT '',
			field varchar(40) NOT NULL DEFAULT '',
			message text NULL,
			source_page varchar(255) NOT NULL DEFAULT '',
			plan_wanted varchar(120) NOT NULL DEFAULT '',
			plan_term varchar(60) NOT NULL DEFAULT '',
			status varchar(20) NOT NULL DEFAULT 'new',
			sales_user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			next_followup date NULL DEFAULT NULL,
			lost_reason varchar(255) NOT NULL DEFAULT '',
			student_id bigint(20) unsigned NOT NULL DEFAULT 0,
			won_amount bigint(20) unsigned NOT NULL DEFAULT 0,
			won_at datetime NULL DEFAULT NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY sales_status (sales_user_id,status),
			KEY mobile (mobile),
			KEY ext_id (ext_id)
		) {$charset};" );
		dbDelta( "CREATE TABLE {$et} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			lead_id bigint(20) unsigned NOT NULL,
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			type varchar(20) NOT NULL DEFAULT 'note',
			body text NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY lead_id (lead_id)
		) {$charset};" );
		if ( ! get_role( 'rksp_sales' ) ) {
			add_role( 'rksp_sales', 'مشاور فروش', array( 'read' => true ) );
		}
		$ok = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $lt ) ) === $lt
			&& $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $et ) ) === $et;
		if ( $ok ) {
			update_option( 'rkspb_sales_schema', '1.4.0', false );
		} else {
			update_option( 'rkspb_schema_error', 'leads: ' . $wpdb->last_error, false );
		}
		return $ok;
	}
}

add_action( 'init', function () {
	if ( '1.4.0' === get_option( 'rkspb_sales_schema' ) ) { return; }
	if ( get_transient( 'rkspb_sales_schema_try' ) ) { return; }
	set_transient( 'rkspb_sales_schema_try', 1, HOUR_IN_SECONDS );
	rkspb_upgrade_sales_schema();
}, 6 );

/* ------------------------------------------------------------- کمکی‌ها -- */

if ( ! function_exists( 'rkspb_mentor_assign_value' ) ) {
	/**
	 * ستون mentor_id در اتصال‌ها و تکالیف rksp، شناسه‌ی ردیف جدول mentors است یا شناسه‌ی کاربر وردپرس؟
	 * از روی داده‌های موجود تشخیص می‌دهیم تا دو مشاور با شناسه‌های هم‌عدد با هم مخلوط نشوند.
	 */
	function rkspb_mentor_assign_value( $mentor_row ) {
		global $wpdb;
		static $mode = null;
		if ( null === $mode ) {
			$mode = 'id';
			$at   = rkspb_table_name( 'assignments' );
			$mt   = rkspb_table_name( 'mentors' );
			if ( rkspb_cols_meta( 'assignments' ) && rkspb_cols_meta( 'mentors' ) && rkspb_pick( 'mentors', array( 'user_id' ) ) ) {
				$by_id   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$at}` a WHERE a.mentor_id IN (SELECT id FROM `{$mt}`) AND a.mentor_id NOT IN (SELECT user_id FROM `{$mt}` WHERE user_id IS NOT NULL)" );
				$by_user = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$at}` a WHERE a.mentor_id IN (SELECT user_id FROM `{$mt}` WHERE user_id IS NOT NULL) AND a.mentor_id NOT IN (SELECT id FROM `{$mt}`)" );
				if ( $by_user > $by_id ) { $mode = 'user'; }
			}
		}
		return 'user' === $mode && ! empty( $mentor_row['user_id'] ) ? (int) $mentor_row['user_id'] : (int) $mentor_row['id'];
	}
}


if ( ! function_exists( 'rkspb_is_admin_user' ) ) {
	function rkspb_is_admin_user( $user = null ) {
		$user = $user ? $user : wp_get_current_user();
		return $user && $user->ID && user_can( $user, 'manage_options' );
	}
}

if ( ! function_exists( 'rkspb_is_sales_user' ) ) {
	function rkspb_is_sales_user( $user = null ) {
		$user = $user ? $user : wp_get_current_user();
		return $user && $user->ID && in_array( 'rksp_sales', (array) $user->roles, true );
	}
}

if ( ! function_exists( 'rkspb_ctx_sales' ) ) {
	/** @return WP_User|WP_Error */
	function rkspb_ctx_sales() {
		$user = wp_get_current_user();
		if ( ! $user || ! $user->ID ) { return new WP_Error( 'rkspb_auth', 'ابتدا وارد شوید.', array( 'status' => 401 ) ); }
		if ( ! rkspb_is_sales_user( $user ) && ! rkspb_is_admin_user( $user ) ) {
			return new WP_Error( 'rkspb_role', 'این بخش مخصوص مشاوران فروش است.', array( 'status' => 403 ) );
		}
		if ( '1.4.0' !== get_option( 'rkspb_sales_schema' ) && ! rkspb_upgrade_sales_schema() ) {
			return new WP_Error( 'rkspb_schema', 'جدول لیدها ساخته نشد.', array( 'status' => 500 ) );
		}
		return $user;
	}
}

if ( ! function_exists( 'rkspb_share_percent' ) ) {
	/** درصد سهم کاربر؛ null یعنی تعیین نشده. */
	function rkspb_share_percent( $user_id, $is_sales ) {
		$v = get_user_meta( $user_id, 'rkspb_share_percent', true );
		if ( '' === $v || null === $v ) { return $is_sales ? (float) RKSPB_SALES_DEFAULT_SHARE : null; }
		return (float) $v;
	}
}

if ( ! function_exists( 'rkspb_sales_users' ) ) {
	function rkspb_sales_users() {
		return get_users( array( 'role' => 'rksp_sales', 'orderby' => 'ID', 'order' => 'ASC' ) );
	}
}

if ( ! function_exists( 'rkspb_next_sales_user' ) ) {
	/** تقسیم نوبتی: نفر بعدی بعد از آخرین کسی که لید گرفته. */
	function rkspb_next_sales_user() {
		$users = rkspb_sales_users();
		$users = array_values( array_filter( $users, function ( $u ) { return ! get_user_meta( $u->ID, 'rkspb_sales_paused', true ); } ) );
		if ( ! $users ) { return 0; }
		$last = (int) get_option( 'rkspb_rr_last', 0 );
		foreach ( $users as $u ) {
			if ( $u->ID > $last ) { update_option( 'rkspb_rr_last', $u->ID, false ); return (int) $u->ID; }
		}
		update_option( 'rkspb_rr_last', $users[0]->ID, false );
		return (int) $users[0]->ID;
	}
}

if ( ! function_exists( 'rkspb_lead_event' ) ) {
	function rkspb_lead_event( $lead_id, $type, $body, $user_id = null ) {
		global $wpdb;
		$wpdb->insert( rkspb_lead_events_table(), array(
			'lead_id'    => (int) $lead_id,
			'user_id'    => null === $user_id ? get_current_user_id() : (int) $user_id,
			'type'       => $type,
			'body'       => $body,
			'created_at' => rkspb_now(),
		) );
	}
}

if ( ! function_exists( 'rkspb_user_label' ) ) {
	function rkspb_user_label( $uid ) {
		static $cache = array();
		$uid = (int) $uid;
		if ( ! $uid ) { return ''; }
		if ( ! isset( $cache[ $uid ] ) ) {
			$u             = get_user_by( 'id', $uid );
			$cache[ $uid ] = $u ? $u->display_name : '';
		}
		return $cache[ $uid ];
	}
}

if ( ! function_exists( 'rkspb_lead_out' ) ) {
	function rkspb_lead_out( $r ) {
		return array(
			'id'            => (int) $r['id'],
			'name'          => (string) $r['name'],
			'mobile'        => (string) $r['mobile'],
			'grade'         => (string) $r['grade'],
			'field'         => (string) $r['field'],
			'message'       => (string) $r['message'],
			'source_page'   => (string) $r['source_page'],
			'plan_wanted'   => (string) $r['plan_wanted'],
			'plan_term'     => (string) $r['plan_term'],
			'status'        => (string) $r['status'],
			'sales_user_id' => (int) $r['sales_user_id'],
			'sales_name'    => rkspb_user_label( $r['sales_user_id'] ),
			'next_followup' => $r['next_followup'] ? (string) $r['next_followup'] : '',
			'lost_reason'   => (string) $r['lost_reason'],
			'student_id'    => (int) $r['student_id'],
			'won_amount'    => (int) $r['won_amount'],
			'won_at'        => $r['won_at'] ? (string) $r['won_at'] : '',
			'created_at'    => (string) $r['created_at'],
			'updated_at'    => (string) $r['updated_at'],
		);
	}
}

if ( ! function_exists( 'rkspb_get_lead_for' ) ) {
	/** @return array|WP_Error */
	function rkspb_get_lead_for( $user, $id ) {
		global $wpdb;
		$lt  = rkspb_leads_table();
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$lt}` WHERE id = %d", $id ), ARRAY_A );
		if ( ! $row ) { return new WP_Error( 'rkspb_404', 'این لید پیدا نشد.', array( 'status' => 404 ) ); }
		if ( ! rkspb_is_admin_user( $user ) && (int) $row['sales_user_id'] !== (int) $user->ID ) {
			return new WP_Error( 'rkspb_not_yours', 'این لید به شما سپرده نشده است.', array( 'status' => 403 ) );
		}
		return $row;
	}
}

if ( ! function_exists( 'rkspb_insert_lead' ) ) {
	/**
	 * لید تازه. اگر برای همین موبایل لید باز (غیر از ثبت‌نام‌شده/منصرف) وجود داشته باشد،
	 * لید تکراری نمی‌سازد و فقط رویداد «فرم دوباره پر شد» اضافه می‌کند.
	 *
	 * @return array{id:int,created:bool}|WP_Error
	 */
	function rkspb_insert_lead( $in, $assign_to = null ) {
		global $wpdb;
		$lt     = rkspb_leads_table();
		$mobile = rkspb_normalize_mobile( isset( $in['mobile'] ) ? $in['mobile'] : ( isset( $in['phone'] ) ? $in['phone'] : '' ) );
		$name   = sanitize_text_field( isset( $in['name'] ) ? $in['name'] : '' );
		if ( '' === $name && '' === $mobile ) {
			return new WP_Error( 'rkspb_bad', 'نام یا موبایل لازم است.', array( 'status' => 400 ) );
		}
		$ext = sanitize_text_field( isset( $in['ext_id'] ) ? (string) $in['ext_id'] : '' );
		if ( '' !== $ext ) {
			$dup = (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM `{$lt}` WHERE ext_id = %s LIMIT 1", $ext ) );
			if ( $dup ) { return array( 'id' => $dup, 'created' => false ); }
		}
		$message = sanitize_textarea_field( isset( $in['message'] ) ? $in['message'] : '' );
		if ( '' !== $mobile ) {
			$open = (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM `{$lt}` WHERE mobile = %s AND status NOT IN ('won','lost') ORDER BY id DESC LIMIT 1", $mobile ) );
			if ( $open ) {
				rkspb_lead_event( $open, 'refill', 'فرم دوباره پر شد' . ( '' !== $message ? ': ' . $message : '' ), 0 );
				$wpdb->update( $lt, array( 'updated_at' => rkspb_now() ), array( 'id' => $open ) );
				return array( 'id' => $open, 'created' => false );
			}
		}
		$created = rkspb_now();
		if ( ! empty( $in['received_at'] ) ) {
			$ts = strtotime( (string) $in['received_at'] );
			if ( $ts ) { $created = get_date_from_gmt( gmdate( 'Y-m-d H:i:s', $ts ) ); }
		}
		$sales = null === $assign_to ? rkspb_next_sales_user() : (int) $assign_to;
		$status = isset( $in['status'] ) && isset( rkspb_lead_statuses()[ $in['status'] ] ) ? $in['status'] : 'new';
		$ok    = $wpdb->insert( $lt, array(
			'ext_id'        => $ext,
			'name'          => mb_substr( $name, 0, 120 ),
			'mobile'        => $mobile,
			'grade'         => mb_substr( sanitize_text_field( isset( $in['grade'] ) ? $in['grade'] : '' ), 0, 40 ),
			'field'         => mb_substr( sanitize_text_field( isset( $in['field'] ) ? $in['field'] : '' ), 0, 40 ),
			'message'       => $message,
			'source_page'   => mb_substr( sanitize_text_field( isset( $in['source_page'] ) ? $in['source_page'] : '' ), 0, 255 ),
			'plan_wanted'   => mb_substr( sanitize_text_field( isset( $in['plan'] ) ? $in['plan'] : '' ), 0, 120 ),
			'plan_term'     => mb_substr( sanitize_text_field( isset( $in['plan_term'] ) ? $in['plan_term'] : '' ), 0, 60 ),
			'status'        => $status,
			'sales_user_id' => $sales,
			'created_at'    => $created,
			'updated_at'    => rkspb_now(),
		) );
		if ( false === $ok ) {
			return new WP_Error( 'rkspb_db', 'لید ذخیره نشد: ' . $wpdb->last_error, array( 'status' => 500 ) );
		}
		$id = (int) $wpdb->insert_id;
		rkspb_lead_event( $id, 'assign', $sales ? 'سپرده شد به ' . rkspb_user_label( $sales ) : ( null === $assign_to ? 'هنوز مشاور فروشی تعریف نشده؛ بدون مسئول' : 'لید قدیمی؛ بدون مسئول' ), 0 );
		return array( 'id' => $id, 'created' => true );
	}
}

if ( ! function_exists( 'rkspb_lead_detail' ) ) {
	function rkspb_lead_detail( $row ) {
		global $wpdb;
		$et     = rkspb_lead_events_table();
		$events = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$et}` WHERE lead_id = %d ORDER BY id DESC LIMIT 200", $row['id'] ), ARRAY_A );
		$out    = rkspb_lead_out( $row );
		$out['events'] = array_map( function ( $e ) {
			return array(
				'id'         => (int) $e['id'],
				'type'       => (string) $e['type'],
				'body'       => (string) $e['body'],
				'user_name'  => rkspb_user_label( $e['user_id'] ),
				'created_at' => (string) $e['created_at'],
			);
		}, (array) $events );
		// اگر برای این موبایل حساب دانش‌آموز هست، بگو
		$out['existing_student'] = null;
		if ( $row['mobile'] && rkspb_cols_meta( 'students' ) ) {
			$st = rkspb_table_name( 'students' );
			$s  = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$st}` WHERE mobile = %s ORDER BY id DESC LIMIT 1", $row['mobile'] ), ARRAY_A );
			if ( $s ) { $out['existing_student'] = array( 'student_id' => (int) $s['id'], 'name' => rkspb_student_name( $s ) ); }
		}
		return $out;
	}
}

if ( ! function_exists( 'rkspb_mentor_options' ) ) {
	function rkspb_mentor_options() {
		global $wpdb;
		if ( ! rkspb_cols_meta( 'mentors' ) ) { return array(); }
		$mt   = rkspb_table_name( 'mentors' );
		$rows = $wpdb->get_results( "SELECT * FROM `{$mt}` ORDER BY id ASC", ARRAY_A );
		$out  = array();
		foreach ( (array) $rows as $m ) {
			$name = trim( ( isset( $m['first_name'] ) ? $m['first_name'] : '' ) . ' ' . ( isset( $m['last_name'] ) ? $m['last_name'] : '' ) );
			if ( '' === $name ) { $name = rkspb_user_label( isset( $m['user_id'] ) ? $m['user_id'] : 0 ); }
			$keys  = array( rkspb_mentor_assign_value( $m ) );
			$out[] = array(
				'mentor_id'       => (int) $m['id'],
				'user_id'         => isset( $m['user_id'] ) ? (int) $m['user_id'] : 0,
				'name'            => $name,
				'specialty'       => isset( $m['specialty'] ) ? (string) $m['specialty'] : '',
				'active_students' => count( rkspb_mentor_links( $keys ) ),
			);
		}
		return $out;
	}
}

if ( ! function_exists( 'rkspb_months_between' ) ) {
	function rkspb_months_between( $start, $end ) {
		$s = strtotime( $start );
		$e = strtotime( $end );
		if ( ! $s || ! $e || $e <= $s ) { return 1; }
		return max( 1, (int) round( ( $e - $s ) / ( 30 * DAY_IN_SECONDS ) ) );
	}
}

if ( ! function_exists( 'rkspb_convert_lead' ) ) {
	/**
	 * لید → دانش‌آموز + طرح + اتصال به مشاور تحصیلی.
	 *
	 * @return array|WP_Error
	 */
	function rkspb_convert_lead( $lead, $p ) {
		global $wpdb;
		$name   = sanitize_text_field( isset( $p['name'] ) ? $p['name'] : $lead['name'] );
		$mobile = rkspb_normalize_mobile( isset( $p['mobile'] ) ? $p['mobile'] : $lead['mobile'] );
		$grade  = sanitize_text_field( isset( $p['grade'] ) ? $p['grade'] : $lead['grade'] );
		$field  = sanitize_text_field( isset( $p['field'] ) ? $p['field'] : $lead['field'] );
		$plan   = sanitize_text_field( isset( $p['plan_name'] ) ? $p['plan_name'] : '' );
		$price  = (int) rkspb_latin_digits( isset( $p['price'] ) ? preg_replace( '/[^\d۰-۹٠-٩]/u', '', (string) $p['price'] ) : 0 );
		$months = max( 1, min( 24, (int) rkspb_latin_digits( isset( $p['months'] ) ? $p['months'] : 1 ) ) );
		$start  = rkspb_clean_date( isset( $p['start_date'] ) ? $p['start_date'] : '' );
		$mentor = isset( $p['mentor_id'] ) ? (int) $p['mentor_id'] : 0;

		$errors = array();
		if ( '' === $name ) { $errors[] = 'نام دانش‌آموز لازم است.'; }
		if ( 11 !== strlen( $mobile ) || '09' !== substr( $mobile, 0, 2 ) ) { $errors[] = 'موبایل دانش‌آموز معتبر نیست.'; }
		if ( '' === $grade ) { $errors[] = 'پایه را انتخاب کنید.'; }
		if ( '' === $plan ) { $errors[] = 'نام طرح لازم است.'; }
		if ( $price <= 0 ) { $errors[] = 'مبلغ پرداختی را وارد کنید.'; }
		if ( ! $mentor ) { $errors[] = 'مشاور تحصیلی را انتخاب کنید.'; }
		if ( $errors ) { return new WP_Error( 'rkspb_bad', implode( ' ', $errors ), array( 'status' => 400 ) ); }
		if ( '' === $start ) { $start = current_time( 'Y-m-d' ); }
		$end = rkspb_add_jmonths( $start, $months );

		$mt   = rkspb_table_name( 'mentors' );
		$mrow = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$mt}` WHERE id = %d", $mentor ), ARRAY_A );
		if ( ! $mrow ) {
			return new WP_Error( 'rkspb_bad', 'مشاور تحصیلی انتخاب‌شده پیدا نشد.', array( 'status' => 400 ) );
		}
		$mentor_row_id = $mentor;
		$mentor        = rkspb_mentor_assign_value( $mrow ); // مقداری که در ستون mentor_id اتصال‌ها نوشته می‌شود

		// ۱) دانش‌آموز: اگر با این موبایل وجود دارد، همان؛ وگرنه حساب تازه
		$st      = rkspb_table_name( 'students' );
		$student = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$st}` WHERE mobile = %s ORDER BY id DESC LIMIT 1", $mobile ), ARRAY_A );
		$created = false;
		if ( ! $student ) {
			$user = rkspb_find_user_by_mobile( $mobile );
			if ( $user && ! in_array( 'rksp_student', (array) $user->roles, true ) ) {
				return new WP_Error( 'rkspb_bad', 'این شماره متعلق به حساب دیگری (مشاور یا کارمند) است.', array( 'status' => 409 ) );
			}
			if ( $user ) {
				$names = wp_list_pluck( rkspb_table_columns( $st ), 'name' );
				list( $first, $last ) = rkspb_split_name( $name );
				$row = array();
				foreach ( array( 'user_id' => $user->ID, 'mobile' => $mobile, 'first_name' => $first, 'last_name' => $last, 'grade' => $grade, 'field' => $field, 'national_code' => '', 'gender' => '', 'created_at' => current_time( 'mysql', true ) ) as $k => $v ) {
					if ( in_array( $k, $names, true ) ) { $row[ $k ] = $v; }
				}
				$wpdb->insert( $st, $row );
			} else {
				$made = rkspb_create_student( array( 'name' => $name, 'mobile' => $mobile, 'password' => '', 'grade' => $grade, 'field' => $field ) );
				if ( empty( $made['ok'] ) ) {
					return new WP_Error( 'rkspb_bad', implode( ' ', (array) $made['errors'] ), array( 'status' => 400 ) );
				}
				$created = true;
			}
			$student = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$st}` WHERE mobile = %s ORDER BY id DESC LIMIT 1", $mobile ), ARRAY_A );
			if ( ! $student ) { return new WP_Error( 'rkspb_db', 'پرونده‌ی دانش‌آموز ساخته نشد: ' . $wpdb->last_error, array( 'status' => 500 ) ); }
		}
		$sid = (int) $student['id'];

		// ۲) اتصال به مشاور (اتصال قبلیِ فعال به مشاور دیگر بسته می‌شود)
		$at   = rkspb_table_name( 'assignments' );
		$meta = rkspb_cols_meta( 'assignments' );
		$cur  = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$at}` WHERE student_id = %d" . rkspb_active_assignment_sql() . ' ORDER BY id DESC LIMIT 1', $sid ), ARRAY_A );
		if ( ! $cur || (int) $cur['mentor_id'] !== $mentor ) {
			if ( $cur && isset( $meta['status'] ) ) {
				$close = array( 'status' => rkspb_fit_value( 'assignments', 'status', 'ended', array( 'ended', 'inactive' ) ) );
				if ( isset( $meta['ended_at'] ) ) { $close['ended_at'] = rkspb_now(); }
				$wpdb->update( $at, $close, array( 'id' => (int) $cur['id'] ) );
			}
			$aid = rkspb_insert_row( 'assignments', array(
				'student_id'  => $sid,
				'mentor_id'   => $mentor,
				'assigned_at' => rkspb_now(),
				'status'      => rkspb_fit_value( 'assignments', 'status', 'active', array( 'active' ) ),
			) );
			if ( is_wp_error( $aid ) ) { return $aid; }
		}

		// ۳) طرح
		$plan_id = rkspb_insert_row( 'plans', array(
			'student_id' => $sid,
			'plan_name'  => $plan,
			'name'       => $plan,
			'price'      => $price,
			'start_date' => $start,
			'end_date'   => $end,
			'status'     => rkspb_fit_value( 'plans', 'status', 'active', array( 'active' ) ),
			'plan_type'  => $months . 'm',
			'created_at' => rkspb_now(),
		) );
		if ( is_wp_error( $plan_id ) ) { return $plan_id; }
		if ( isset( $meta['plan_id'] ) ) {
			$wpdb->query( $wpdb->prepare( "UPDATE `{$at}` SET plan_id = %d WHERE student_id = %d AND mentor_id = %d" . rkspb_active_assignment_sql(), $plan_id, $sid, $mentor ) );
		}

		// ۴) لید
		$wpdb->update( rkspb_leads_table(), array(
			'status'      => 'won',
			'student_id'  => $sid,
			'won_amount'  => $price,
			'won_at'      => rkspb_now(),
			'next_followup' => null,
			'updated_at'  => rkspb_now(),
		), array( 'id' => (int) $lead['id'] ) );
		rkspb_lead_event( $lead['id'], 'won', sprintf( 'ثبت‌نام شد: %s، %d ماه، %s تومان — مشاور: %s', $plan, $months, number_format( $price ), rkspb_user_label( isset( $mrow['user_id'] ) ? $mrow['user_id'] : 0 ) ) );

		// فیش واریزی، اگر مشاور فروش شماره پیگیری را داده باشد.
		$pay_ref = sanitize_text_field( isset( $p['ref'] ) ? $p['ref'] : '' );
		$paid    = null;
		if ( '' !== $pay_ref && function_exists( 'rkspb_record_payment' ) ) {
			$paid = rkspb_record_payment( array(
				'student_id' => $sid,
				'plan_id'    => (int) $plan_id,
				'lead_id'    => (int) $lead['id'],
				'amount'     => $price,
				'ref'        => $pay_ref,
				'paid_at'    => isset( $p['paid_at'] ) ? $p['paid_at'] : current_time( 'Y-m-d' ),
			), get_current_user_id() );
			if ( is_wp_error( $paid ) ) {
				rkspb_lead_event( $lead['id'], 'note', 'فیش ثبت نشد: ' . $paid->get_error_message() );
				$paid = null;
			}
		}

		return array( 'student_id' => $sid, 'account_created' => $created, 'plan_id' => (int) $plan_id, 'end_date' => $end, 'payment' => $paid );
	}
}

/* ------------------------------------------------------ داشبورد مدیر -- */

if ( ! function_exists( 'rkspb_admin_dashboard' ) ) {
	function rkspb_admin_dashboard( $from, $to ) {
		global $wpdb;
		$today = current_time( 'Y-m-d' );
		$out   = array( 'from' => $from, 'to' => $to, 'today' => $today );

		// دانش‌آموزان
		$st       = rkspb_table_name( 'students' );
		$students = rkspb_cols_meta( 'students' ) ? (array) $wpdb->get_results( "SELECT * FROM `{$st}` ORDER BY id DESC", ARRAY_A ) : array();
		$at       = rkspb_table_name( 'assignments' );
		$links    = array();
		if ( rkspb_cols_meta( 'assignments' ) ) {
			foreach ( (array) $wpdb->get_results( "SELECT * FROM `{$at}` WHERE 1=1" . rkspb_active_assignment_sql() . ' ORDER BY id ASC', ARRAY_A ) as $l ) {
				$links[ (int) $l['student_id'] ] = $l;
			}
		}
		$mentors = rkspb_mentor_options();
		$mname   = array();
		foreach ( $mentors as $m ) { $mname[ $m['mentor_id'] ] = $m['name']; if ( $m['user_id'] ) { $mname[ 'u' . $m['user_id'] ] = $m['name']; } }

		$expiring = array();
		$inactive = array();
		$no_mentor = array();
		$active_count = 0;
		foreach ( $students as $s ) {
			$sid  = (int) $s['id'];
			$link = isset( $links[ $sid ] ) ? $links[ $sid ] : null;
			$plan = rkspb_plan_info( $link, $sid );
			$tot  = rkspb_study_totals( $s );
			$has_active_plan = '' !== $plan['end'] && $plan['end'] >= $today;
			if ( $has_active_plan ) { $active_count++; }
			$base = array(
				'student_id'  => $sid,
				'name'        => rkspb_student_name( $s ),
				'mobile'      => rkspb_student_mobile( $s ),
				'grade'       => isset( $s['grade'] ) ? (string) $s['grade'] : '',
				'mentor_name' => $link ? ( isset( $mname[ (int) $link['mentor_id'] ] ) ? $mname[ (int) $link['mentor_id'] ] : ( isset( $mname[ 'u' . (int) $link['mentor_id'] ] ) ? $mname[ 'u' . (int) $link['mentor_id'] ] : '' ) ) : '',
				'plan_name'   => $plan['name'],
				'plan_end'    => $plan['end'],
				'last_at'     => $tot['last_at'],
			);
			if ( '' !== $plan['end'] ) {
				$days = (int) floor( ( strtotime( $plan['end'] ) - strtotime( $today ) ) / DAY_IN_SECONDS );
				if ( $days <= 10 && $days >= -30 ) { $expiring[] = $base + array( 'days_left' => $days ); }
			}
			if ( $link ) {
				$idle = '' === $tot['last_at'] ? null : (int) floor( ( strtotime( $today ) - strtotime( substr( $tot['last_at'], 0, 10 ) ) ) / DAY_IN_SECONDS );
				if ( null === $idle || $idle >= 3 ) { $inactive[] = $base + array( 'idle_days' => $idle ); }
			} else {
				$no_mentor[] = $base;
			}
		}
		usort( $expiring, function ( $a, $b ) { return $a['days_left'] - $b['days_left']; } );
		usort( $inactive, function ( $a, $b ) { return ( null === $b['idle_days'] ? 9999 : $b['idle_days'] ) - ( null === $a['idle_days'] ? 9999 : $a['idle_days'] ); } );

		$new_students = 0;
		foreach ( $students as $s ) {
			if ( ! empty( $s['created_at'] ) && substr( $s['created_at'], 0, 10 ) >= $from && substr( $s['created_at'], 0, 10 ) <= $to ) { $new_students++; }
		}
		$out['students'] = array(
			'total'     => count( $students ),
			'active'    => $active_count,
			'new'       => $new_students,
			'expiring'  => array_slice( $expiring, 0, 50 ),
			'inactive'  => array_slice( $inactive, 0, 50 ),
			'no_mentor' => array_slice( $no_mentor, 0, 50 ),
		);

		// حق‌الزحمه‌ی مشاوران تحصیلی: مبلغ ماهانه‌ی طرحِ هر دانش‌آموزی که در این بازه طرح فعال دارد
		$pt       = rkspb_table_name( 'plans' );
		$has_plan = rkspb_cols_meta( 'plans' ) && rkspb_pick( 'plans', array( 'student_id' ) ) && rkspb_pick( 'plans', array( 'price' ) );
		$mrows    = array();
		foreach ( $mentors as $m ) {
			$slinks = rkspb_mentor_links( array( rkspb_mentor_assign_value( array( 'id' => $m['mentor_id'], 'user_id' => $m['user_id'] ) ) ) );
			$base    = 0;
			$paying  = 0;
			$partial = 0;
			$rates   = array();
			foreach ( $slinks as $sid => $l ) {
				if ( rkspb_week_ready() ) {
					$ws = rkspb_week_stats( $sid, rkspb_week_start() );
					if ( null !== $ws['rate'] ) { $rates[] = $ws['rate']; }
				}
				if ( ! $has_plan ) { continue; }
				// فقط یک طرح به ازای هر دانش‌آموز. قبلاً همه‌ی ردیف‌های هم‌پوشان جمع
				// می‌شدند، پس طرح تمام‌شده یا تمدیدشده مبنا را دو برابر می‌کرد.
				$order = rkspb_pick( 'plans', array( 'status' ) ) ? "(status = 'active') DESC, id DESC" : 'id DESC';
				$plan_row = $wpdb->get_row( $wpdb->prepare(
					"SELECT * FROM `{$pt}` WHERE student_id = %d AND start_date <= %s AND end_date >= %s ORDER BY {$order} LIMIT 1",
					$sid,
					$to,
					$from
				), ARRAY_A );
				$monthly = 0;
				if ( $plan_row ) {
					$pprice  = (int) $plan_row['price'];
					$monthly = $pprice / rkspb_months_between( $plan_row['start_date'], $plan_row['end_date'] );
					// مبنای مشاور تحصیلی هم مثل مشاور فروش به پول رسیده گره خورد:
					// اگر نصف طرح وصول شده، نصف سهم. طرحی که هیچ فیشی برایش ثبت
					// نشده (دانش‌آموزان قبل از راه‌افتادن فیش) کامل حساب می‌شود.
					if ( $pprice > 0 && function_exists( 'rkspb_plan_payment_count' ) && rkspb_plan_payment_count( $plan_row['id'] ) ) {
						$ratio    = min( 1, rkspb_plan_paid( $plan_row['id'] ) / $pprice );
						$monthly *= $ratio;
						if ( $ratio < 1 ) { $partial++; }
					}
				}
				if ( $monthly > 0 ) { $paying++; $base += $monthly; }
			}
			$pct     = $m['user_id'] ? rkspb_share_percent( $m['user_id'], false ) : null;
			$mrows[] = array(
				'user_id'         => $m['user_id'],
				'name'            => $m['name'],
				'active_students' => count( $slinks ),
				'paying_students' => $paying,
				'partial_students' => $partial,
				'base_amount'     => (int) round( $base ),
				'percent'         => $pct,
				'payout'          => null === $pct ? null : (int) round( $base * $pct / 100 ),
				'week_rate'       => $rates ? (int) round( array_sum( $rates ) / count( $rates ) ) : null,
			);
		}
		$out['mentors'] = $mrows;

		// فروش و لیدها
		$lt = rkspb_leads_table();
		$srows = array();
		$leads = array( 'by_status' => array(), 'new_in_period' => 0, 'unassigned' => 0, 'won_amount' => 0, 'won_count' => 0 );
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $lt ) ) === $lt ) {
			foreach ( rkspb_lead_statuses() as $k => $label ) {
				$leads['by_status'][ $k ] = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$lt}` WHERE status = %s", $k ) );
			}
			$leads['new_in_period'] = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$lt}` WHERE DATE(created_at) BETWEEN %s AND %s", $from, $to ) );
			$leads['unassigned']    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$lt}` WHERE sales_user_id = 0 AND status NOT IN ('won','lost')" );
			$won = $wpdb->get_row( $wpdb->prepare( "SELECT COUNT(*) n, COALESCE(SUM(won_amount),0) s FROM `{$lt}` WHERE status = 'won' AND DATE(won_at) BETWEEN %s AND %s", $from, $to ), ARRAY_A );
			$leads['won_count']  = (int) $won['n'];
			$leads['won_amount'] = (int) $won['s'];
			foreach ( rkspb_sales_users() as $u ) {
				$r = $wpdb->get_row( $wpdb->prepare(
					"SELECT SUM(status NOT IN ('won','lost')) open_n,
					        SUM(DATE(created_at) BETWEEN %s AND %s) new_n,
					        SUM(status = 'won' AND DATE(won_at) BETWEEN %s AND %s) won_n,
					        COALESCE(SUM(CASE WHEN status = 'won' AND DATE(won_at) BETWEEN %s AND %s THEN won_amount ELSE 0 END),0) won_s,
					        SUM(status NOT IN ('won','lost') AND next_followup IS NOT NULL AND next_followup < %s) overdue_n
					 FROM `{$lt}` WHERE sales_user_id = %d",
					$from, $to, $from, $to, $from, $to, $today, $u->ID
				), ARRAY_A );
				$pct     = rkspb_share_percent( $u->ID, true );
				$srows[] = array(
					'user_id'     => (int) $u->ID,
					'name'        => $u->display_name,
					'mobile'      => rkspb_user_mobile( $u ),
					'paused'      => (bool) get_user_meta( $u->ID, 'rkspb_sales_paused', true ),
					'open_leads'  => (int) $r['open_n'],
					'new_leads'   => (int) $r['new_n'],
					'overdue'     => (int) $r['overdue_n'],
					'won_count'   => (int) $r['won_n'],
					'won_amount'  => (int) $r['won_s'],
					'percent'     => $pct,
					'payout'      => (int) round( (int) $r['won_s'] * $pct / 100 ),
				);
			}
		}
		$out['sales'] = $srows;
		$out['leads'] = $leads;
		$out['kind']  = function_exists( 'rkspb_user_kind' ) ? rkspb_user_kind() : 'admin';
		$out['tickets'] = function_exists( 'rkspb_tickets_waiting' ) ? rkspb_tickets_waiting( 24 ) : array( 'total' => 0, 'overdue' => 0, 'rows' => array() );

		// حق‌الزحمه‌ی مشاور فروش دیگر از لید حساب نمی‌شود: مبنا فیش تأییدشده است.
		if ( function_exists( 'rkspb_sales_rows_from_payments' ) ) {
			$by_id = array();
			foreach ( $srows as $r ) { $by_id[ (int) $r['user_id'] ] = $r; }
			$merged = array();
			foreach ( rkspb_sales_rows_from_payments( $from, $to ) as $r ) {
				$old_row = isset( $by_id[ $r['user_id'] ] ) ? $by_id[ $r['user_id'] ] : array();
				$merged[] = array_merge(
					$old_row,
					array(
						'lead_won_count'  => isset( $old_row['won_count'] ) ? $old_row['won_count'] : 0,
						'lead_won_amount' => isset( $old_row['won_amount'] ) ? $old_row['won_amount'] : 0,
					),
					$r,
					array(
						'won_count'  => $r['approved_count'],
						'won_amount' => $r['approved_amount'],
					)
				);
			}
			// حقوق آدم‌ها خصوصی است: مدیر فروش عملیات را می‌بیند، درصد و سهم را نه.
			if ( ! rkspb_is_admin_user() ) {
				foreach ( $merged as $i => $row ) {
					unset( $merged[ $i ]['percent'], $merged[ $i ]['payout'] );
					$merged[ $i ]['percent'] = null;
					$merged[ $i ]['payout']  = 0;
				}
				foreach ( $out['mentors'] as $i => $row ) {
					$out['mentors'][ $i ]['percent'] = null;
					$out['mentors'][ $i ]['payout']  = 0;
				}
			}
			$out['sales']    = $merged;
			$out['payments'] = array(
				'pending'         => rkspb_pending_payments_count(),
				'pending_amount'  => array_sum( wp_list_pluck( $merged, 'pending_amount' ) ),
				'approved_amount' => array_sum( wp_list_pluck( $merged, 'approved_amount' ) ),
			);
		}
		return $out;
	}
}

if ( ! function_exists( 'rkspb_create_sales_user' ) ) {
	/** @return array|WP_Error */
	function rkspb_create_sales_user( $p ) {
		$name   = sanitize_text_field( isset( $p['name'] ) ? $p['name'] : '' );
		$mobile = rkspb_normalize_mobile( isset( $p['mobile'] ) ? $p['mobile'] : '' );
		if ( '' === $name ) { return new WP_Error( 'rkspb_bad', 'نام را وارد کنید.', array( 'status' => 400 ) ); }
		if ( 11 !== strlen( $mobile ) || '09' !== substr( $mobile, 0, 2 ) ) { return new WP_Error( 'rkspb_bad', 'موبایل معتبر نیست.', array( 'status' => 400 ) ); }
		if ( rkspb_find_user_by_mobile( $mobile ) ) { return new WP_Error( 'rkspb_bad', 'این شماره قبلاً برای کاربر دیگری ثبت شده است.', array( 'status' => 409 ) ); }
		list( $first, $last ) = rkspb_split_name( $name );
		$login = 's' . ltrim( $mobile, '0' );
		$n     = 1;
		while ( username_exists( $login ) ) { $login = 's' . ltrim( $mobile, '0' ) . '_' . ( ++$n ); }
		$pass  = wp_generate_password( 12, false, false );
		$email = $login . '@' . wp_parse_url( home_url(), PHP_URL_HOST );
		$uid   = wp_insert_user( array(
			'user_login'   => $login,
			'user_pass'    => $pass,
			'user_email'   => email_exists( $email ) ? '' : $email,
			'first_name'   => $first,
			'last_name'    => $last,
			'display_name' => $name,
			'role'         => 'rksp_sales',
		) );
		if ( is_wp_error( $uid ) ) { return new WP_Error( 'rkspb_bad', $uid->get_error_message(), array( 'status' => 400 ) ); }
		update_user_meta( $uid, 'rksp_mobile', $mobile );
		update_user_meta( $uid, 'rkspb_force_pw', 1 );
		if ( isset( $p['percent'] ) && '' !== $p['percent'] ) {
			update_user_meta( $uid, 'rkspb_share_percent', max( 0, min( 100, (float) rkspb_latin_digits( $p['percent'] ) ) ) );
		}
		return array( 'user_id' => (int) $uid, 'mobile' => $mobile, 'password' => $pass );
	}
}

/* ------------------------------------------------------------------ روت‌ها -- */

add_action( 'rest_api_init', function () {

	$logged_in = function () { return is_user_logged_in(); };
	$admin     = function () { return rkspb_is_admin_user(); };

	/* ---------- دریافت لید از n8n ---------- */
	register_rest_route( RKSPB_NS, '/leads/ingest', array(
		'methods'             => 'POST',
		'permission_callback' => function ( WP_REST_Request $req ) {
			$key = (string) $req->get_header( 'x_rkspb_key' );
			return '' !== $key && strlen( RKSPB_INGEST_KEY ) > 20 && hash_equals( RKSPB_INGEST_KEY, $key );
		},
		'callback'            => function ( WP_REST_Request $req ) {
			if ( '1.4.0' !== get_option( 'rkspb_sales_schema' ) && ! rkspb_upgrade_sales_schema() ) {
				return new WP_Error( 'rkspb_schema', 'جدول لیدها ساخته نشد.', array( 'status' => 500 ) );
			}
			$p     = rkspb_json_params( $req );
			$items = isset( $p['items'] ) && is_array( $p['items'] ) ? $p['items'] : array( $p );
			$out   = array();
			foreach ( array_slice( $items, 0, 500 ) as $it ) {
				$it = (array) $it;
				foreach ( array( 'mobile' => array( 'phone', 'tel' ), 'grade' => array( 'paye' ), 'field' => array( 'reshte' ), 'name' => array( 'fullname' ) ) as $k => $alts ) {
					if ( empty( $it[ $k ] ) ) {
						foreach ( $alts as $a ) { if ( ! empty( $it[ $a ] ) ) { $it[ $k ] = $it[ $a ]; break; } }
					}
				}
				// لیدهای قدیمی که در n8n وضعیتی جز new دارند، با همان وضعیت و بدون مسئول وارد می‌شوند
				$assign = null;
				if ( ! empty( $it['import'] ) ) {
					$map          = array( 'new' => 'new', 'contacted' => 'contacted', 'called' => 'contacted', 'done' => 'won', 'won' => 'won', 'lost' => 'lost' );
					$it['status'] = isset( $it['status'], $map[ $it['status'] ] ) ? $map[ $it['status'] ] : 'new';
					if ( 'new' !== $it['status'] ) { $assign = 0; }
				} else {
					unset( $it['status'] );
				}
				$r     = rkspb_insert_lead( $it, $assign );
				$out[] = is_wp_error( $r ) ? array( 'error' => $r->get_error_message() ) : $r;
			}
			return rest_ensure_response( array( 'ok' => true, 'results' => $out ) );
		},
	) );

	/* ---------- مشاور فروش ---------- */

	register_rest_route( RKSPB_NS, '/sales/leads', array(
		array(
			'methods'             => 'GET',
			'permission_callback' => $logged_in,
			'callback'            => function ( WP_REST_Request $req ) {
				global $wpdb;
				$user = rkspb_ctx_sales();
				if ( is_wp_error( $user ) ) { return $user; }
				$lt     = rkspb_leads_table();
				$where  = array( '1=1' );
				$args   = array();
				$is_adm = rkspb_is_admin_user( $user );
				if ( ! $is_adm || ! $req->get_param( 'all' ) ) {
					if ( $is_adm && '' !== (string) $req->get_param( 'sales_user_id' ) ) {
						$where[] = 'sales_user_id = %d';
						$args[]  = (int) $req->get_param( 'sales_user_id' );
					} elseif ( ! $is_adm ) {
						$where[] = 'sales_user_id = %d';
						$args[]  = (int) $user->ID;
					}
				}
				$base_where = $where;
				$base_args  = $args;
				$status     = (string) $req->get_param( 'status' );
				$today      = current_time( 'Y-m-d' );
				if ( 'due' === $status ) {
					$where[] = "status NOT IN ('won','lost') AND next_followup IS NOT NULL AND next_followup <= %s";
					$args[]  = $today;
				} elseif ( 'open' === $status ) {
					$where[] = "status NOT IN ('won','lost')";
				} elseif ( isset( rkspb_lead_statuses()[ $status ] ) ) {
					$where[] = 'status = %s';
					$args[]  = $status;
				}
				$q = trim( (string) $req->get_param( 'q' ) );
				if ( '' !== $q ) {
					$like    = '%' . $wpdb->esc_like( rkspb_latin_digits( $q ) ) . '%';
					$where[] = '(name LIKE %s OR mobile LIKE %s)';
					$args[]  = $like;
					$args[]  = $like;
				}
				$sql  = "SELECT * FROM `{$lt}` WHERE " . implode( ' AND ', $where ) . " ORDER BY (status = 'new') DESC, (next_followup IS NULL), next_followup ASC, id DESC LIMIT 300";
				$rows = $wpdb->get_results( $args ? $wpdb->prepare( $sql, $args ) : $sql, ARRAY_A );

				$cw     = implode( ' AND ', $base_where );
				$csql   = "SELECT status, COUNT(*) n FROM `{$lt}` WHERE {$cw} GROUP BY status";
				$counts = array_fill_keys( array_keys( rkspb_lead_statuses() ), 0 );
				foreach ( (array) $wpdb->get_results( $base_args ? $wpdb->prepare( $csql, $base_args ) : $csql, ARRAY_A ) as $c ) {
					$counts[ $c['status'] ] = (int) $c['n'];
				}
				$dsql          = "SELECT COUNT(*) FROM `{$lt}` WHERE {$cw} AND status NOT IN ('won','lost') AND next_followup IS NOT NULL AND next_followup <= %s";
				$counts['due'] = (int) $wpdb->get_var( $wpdb->prepare( $dsql, array_merge( $base_args, array( $today ) ) ) );

				// آمار ماه جاری کاربر (از روز اول ماه شمسی که کلاینت می‌فرستد)
				$from = rkspb_clean_date( (string) $req->get_param( 'from' ) );
				$to   = rkspb_clean_date( (string) $req->get_param( 'to' ) );
				$mine = null;
				if ( $from && $to ) {
					$r    = $wpdb->get_row( $wpdb->prepare(
						"SELECT COUNT(*) n, COALESCE(SUM(won_amount),0) s FROM `{$lt}` WHERE sales_user_id = %d AND status = 'won' AND DATE(won_at) BETWEEN %s AND %s",
						$user->ID,
						$from,
						$to
					), ARRAY_A );
					$pct  = rkspb_share_percent( $user->ID, true );
					$mine = array( 'won_count' => (int) $r['n'], 'won_amount' => (int) $r['s'], 'percent' => $pct, 'payout' => (int) round( (int) $r['s'] * $pct / 100 ) );
				}

				return rest_ensure_response( array(
					'leads'    => array_map( 'rkspb_lead_out', (array) $rows ),
					'counts'   => $counts,
					'mine'     => $mine,
					'is_admin' => $is_adm,
					'today'    => $today,
					'statuses' => rkspb_lead_statuses(),
				) );
			},
		),
		array(
			'methods'             => 'POST',
			'permission_callback' => $logged_in,
			'callback'            => function ( WP_REST_Request $req ) {
				global $wpdb;
				$user = rkspb_ctx_sales();
				if ( is_wp_error( $user ) ) { return $user; }
				$p = rkspb_json_params( $req );
				$m = rkspb_normalize_mobile( isset( $p['mobile'] ) ? $p['mobile'] : '' );
				if ( 11 !== strlen( $m ) ) { return new WP_Error( 'rkspb_bad', 'موبایل معتبر نیست.', array( 'status' => 400 ) ); }
				$p['mobile'] = $m;
				$r           = rkspb_insert_lead( $p, rkspb_is_sales_user( $user ) ? $user->ID : null );
				if ( is_wp_error( $r ) ) { return $r; }
				if ( ! $r['created'] ) {
					$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM `' . rkspb_leads_table() . '` WHERE id = %d', $r['id'] ), ARRAY_A );
					$who = $row && $row['sales_user_id'] ? rkspb_user_label( $row['sales_user_id'] ) : 'بدون مسئول';
					return new WP_Error( 'rkspb_dup', 'برای این شماره از قبل لید باز هست (مسئول: ' . $who . ').', array( 'status' => 409 ) );
				}
				rkspb_lead_event( $r['id'], 'note', 'لید دستی ثبت شد' );
				$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM `' . rkspb_leads_table() . '` WHERE id = %d', $r['id'] ), ARRAY_A );
				return rest_ensure_response( rkspb_lead_detail( $row ) );
			},
		),
	) );

	register_rest_route( RKSPB_NS, '/sales/leads/(?P<id>\d+)', array(
		array(
			'methods'             => 'GET',
			'permission_callback' => $logged_in,
			'callback'            => function ( WP_REST_Request $req ) {
				$user = rkspb_ctx_sales();
				if ( is_wp_error( $user ) ) { return $user; }
				$row = rkspb_get_lead_for( $user, (int) $req['id'] );
				if ( is_wp_error( $row ) ) { return $row; }
				return rest_ensure_response( rkspb_lead_detail( $row ) );
			},
		),
		array(
			'methods'             => 'POST',
			'permission_callback' => $logged_in,
			'callback'            => function ( WP_REST_Request $req ) {
				global $wpdb;
				$user = rkspb_ctx_sales();
				if ( is_wp_error( $user ) ) { return $user; }
				$row = rkspb_get_lead_for( $user, (int) $req['id'] );
				if ( is_wp_error( $row ) ) { return $row; }
				$p      = rkspb_json_params( $req );
				$data   = array();
				$events = array();
				if ( isset( $p['status'] ) && $p['status'] !== $row['status'] ) {
					$labels = rkspb_lead_statuses();
					if ( ! isset( $labels[ $p['status'] ] ) ) { return new WP_Error( 'rkspb_bad', 'وضعیت نامعتبر است.', array( 'status' => 400 ) ); }
					if ( 'won' === $p['status'] ) { return new WP_Error( 'rkspb_bad', 'برای «ثبت‌نام شد» از فرم ثبت‌نام استفاده کنید.', array( 'status' => 400 ) ); }
					if ( 'won' === $row['status'] && ! rkspb_is_admin_user( $user ) ) {
						return new WP_Error( 'rkspb_bad', 'لید ثبت‌نام‌شده را فقط مدیر می‌تواند تغییر دهد.', array( 'status' => 403 ) );
					}
					if ( 'lost' === $p['status'] && '' === trim( (string) ( isset( $p['lost_reason'] ) ? $p['lost_reason'] : '' ) ) ) {
						return new WP_Error( 'rkspb_bad', 'دلیل انصراف را بنویسید.', array( 'status' => 400 ) );
					}
					$data['status'] = $p['status'];
					if ( 'won' === $row['status'] ) { $data['won_amount'] = 0; $data['won_at'] = null; }
					$events[]       = 'وضعیت: ' . $labels[ $p['status'] ];
				}
				if ( array_key_exists( 'lost_reason', $p ) ) {
					$data['lost_reason'] = mb_substr( sanitize_text_field( (string) $p['lost_reason'] ), 0, 255 );
					if ( '' !== $data['lost_reason'] ) { $events[] = 'دلیل انصراف: ' . $data['lost_reason']; }
				}
				if ( array_key_exists( 'next_followup', $p ) ) {
					$d                     = rkspb_clean_date( (string) $p['next_followup'] );
					$data['next_followup'] = '' === $d ? null : $d;
					if ( $d !== (string) $row['next_followup'] ) { $events[] = '' === $d ? 'پیگیری بعدی حذف شد' : 'followup:' . $d; }
				}
				if ( isset( $p['sales_user_id'] ) && rkspb_is_admin_user( $user ) && (int) $p['sales_user_id'] !== (int) $row['sales_user_id'] ) {
					$to = (int) $p['sales_user_id'];
					if ( $to && ! rkspb_is_sales_user( get_user_by( 'id', $to ) ) ) { return new WP_Error( 'rkspb_bad', 'کاربر انتخاب‌شده مشاور فروش نیست.', array( 'status' => 400 ) ); }
					$data['sales_user_id'] = $to;
					$events[]              = $to ? 'سپرده شد به ' . rkspb_user_label( $to ) : 'از مسئول قبلی گرفته شد';
				}
				foreach ( array( 'name' => 120, 'grade' => 40, 'field' => 40 ) as $k => $len ) {
					if ( isset( $p[ $k ] ) ) { $data[ $k ] = mb_substr( sanitize_text_field( $p[ $k ] ), 0, $len ); }
				}
				if ( ! $data ) { return rest_ensure_response( rkspb_lead_detail( $row ) ); }
				$data['updated_at'] = rkspb_now();
				$wpdb->update( rkspb_leads_table(), $data, array( 'id' => (int) $row['id'] ) );
				foreach ( $events as $e ) {
					$type = 0 === strpos( $e, 'followup:' ) ? 'followup' : 'status';
					rkspb_lead_event( $row['id'], $type, 'followup' === $type ? substr( $e, 9 ) : $e );
				}
				$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM `' . rkspb_leads_table() . '` WHERE id = %d', $row['id'] ), ARRAY_A );
				return rest_ensure_response( rkspb_lead_detail( $row ) );
			},
		),
	) );

	register_rest_route( RKSPB_NS, '/sales/leads/(?P<id>\d+)/note', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			global $wpdb;
			$user = rkspb_ctx_sales();
			if ( is_wp_error( $user ) ) { return $user; }
			$row = rkspb_get_lead_for( $user, (int) $req['id'] );
			if ( is_wp_error( $row ) ) { return $row; }
			$p    = rkspb_json_params( $req );
			$type = isset( $p['type'] ) && in_array( $p['type'], array( 'note', 'call', 'noanswer' ), true ) ? $p['type'] : 'note';
			$body = sanitize_textarea_field( isset( $p['body'] ) ? $p['body'] : '' );
			if ( 'note' === $type && '' === trim( $body ) ) { return new WP_Error( 'rkspb_bad', 'متن یادداشت خالی است.', array( 'status' => 400 ) ); }
			rkspb_lead_event( $row['id'], $type, $body );
			$upd = array( 'updated_at' => rkspb_now() );
			if ( in_array( $type, array( 'call', 'noanswer' ), true ) && 'new' === $row['status'] ) {
				$upd['status'] = 'contacted';
				rkspb_lead_event( $row['id'], 'status', 'وضعیت: ' . rkspb_lead_statuses()['contacted'] );
			}
			$wpdb->update( rkspb_leads_table(), $upd, array( 'id' => (int) $row['id'] ) );
			$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM `' . rkspb_leads_table() . '` WHERE id = %d', $row['id'] ), ARRAY_A );
			return rest_ensure_response( rkspb_lead_detail( $row ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/sales/leads/(?P<id>\d+)/convert', array(
		'methods'             => 'POST',
		'permission_callback' => $logged_in,
		'callback'            => function ( WP_REST_Request $req ) {
			global $wpdb;
			$user = rkspb_ctx_sales();
			if ( is_wp_error( $user ) ) { return $user; }
			$row = rkspb_get_lead_for( $user, (int) $req['id'] );
			if ( is_wp_error( $row ) ) { return $row; }
			if ( 'won' === $row['status'] ) { return new WP_Error( 'rkspb_bad', 'این لید قبلاً ثبت‌نام شده است.', array( 'status' => 409 ) ); }
			$res = rkspb_convert_lead( $row, rkspb_json_params( $req ) );
			if ( is_wp_error( $res ) ) { return $res; }
			$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM `' . rkspb_leads_table() . '` WHERE id = %d', $row['id'] ), ARRAY_A );
			return rest_ensure_response( array( 'ok' => true, 'result' => $res, 'lead' => rkspb_lead_detail( $row ) ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/sales/mentors', array(
		'methods'             => 'GET',
		'permission_callback' => $logged_in,
		'callback'            => function () {
			$user = rkspb_ctx_sales();
			if ( is_wp_error( $user ) ) { return $user; }
			$list = array_map( function ( $m ) { unset( $m['user_id'] ); return $m; }, rkspb_mentor_options() );
			$sales = array();
			if ( rkspb_is_admin_user( $user ) ) {
				foreach ( rkspb_sales_users() as $u ) { $sales[] = array( 'user_id' => (int) $u->ID, 'name' => $u->display_name ); }
			}
			return rest_ensure_response( array( 'mentors' => $list, 'sales' => $sales ) );
		},
	) );

	/* ---------- مدیر ---------- */

	register_rest_route( RKSPB_NS, '/admin/dashboard', array(
		'methods'             => 'GET',
		'permission_callback' => function () { return is_user_logged_in() && rkspb_is_manager(); },
		'callback'            => function ( WP_REST_Request $req ) {
			if ( '1.4.0' !== get_option( 'rkspb_sales_schema' ) ) { rkspb_upgrade_sales_schema(); }
			$from = rkspb_clean_date( (string) $req->get_param( 'from' ) );
			$to   = rkspb_clean_date( (string) $req->get_param( 'to' ) );
			if ( '' === $from || '' === $to || $to < $from ) {
				$from = current_time( 'Y-m-01' );
				$to   = current_time( 'Y-m-t' );
			}
			return rest_ensure_response( rkspb_admin_dashboard( $from, $to ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/admin/share', array(
		'methods'             => 'POST',
		'permission_callback' => $admin,
		'callback'            => function ( WP_REST_Request $req ) {
			$p   = rkspb_json_params( $req );
			$uid = isset( $p['user_id'] ) ? (int) $p['user_id'] : 0;
			$u   = $uid ? get_user_by( 'id', $uid ) : null;
			if ( ! $u || ( ! in_array( 'rksp_mentor', (array) $u->roles, true ) && ! in_array( 'rksp_sales', (array) $u->roles, true ) ) ) {
				return new WP_Error( 'rkspb_bad', 'کاربر پیدا نشد.', array( 'status' => 404 ) );
			}
			$raw = array_key_exists( 'percent', $p ) ? trim( rkspb_latin_digits( (string) $p['percent'] ) ) : null;
			if ( null === $raw ) {
				// درصد در این درخواست نیامده؛ دست نمی‌زنیم
			} elseif ( '' === $raw ) {
				delete_user_meta( $uid, 'rkspb_share_percent' );
			} else {
				$v = (float) str_replace( array( '٫', '/' ), '.', $raw );
				if ( $v < 0 || $v > 100 ) { return new WP_Error( 'rkspb_bad', 'درصد باید بین ۰ و ۱۰۰ باشد.', array( 'status' => 400 ) ); }
				update_user_meta( $uid, 'rkspb_share_percent', $v );
			}
			if ( isset( $p['paused'] ) && in_array( 'rksp_sales', (array) $u->roles, true ) ) {
				if ( $p['paused'] ) { update_user_meta( $uid, 'rkspb_sales_paused', 1 ); } else { delete_user_meta( $uid, 'rkspb_sales_paused' ); }
			}
			return rest_ensure_response( array( 'ok' => true ) );
		},
	) );

	// ساخت مشاور فروش را مدیر فروش هم می‌تواند؛ تعیین درصد را نه.
	register_rest_route( RKSPB_NS, '/admin/sales-users', array(
		'methods'             => 'POST',
		'permission_callback' => function () { return is_user_logged_in() && rkspb_can( 'sales.manage' ); },
		'callback'            => function ( WP_REST_Request $req ) {
			if ( '1.4.0' !== get_option( 'rkspb_sales_schema' ) ) { rkspb_upgrade_sales_schema(); }
			$r = rkspb_create_sales_user( rkspb_json_params( $req ) );
			if ( is_wp_error( $r ) ) { return $r; }
			return rest_ensure_response( array( 'ok' => true ) + $r );
		},
	) );
} );

/* ------------------------------------------- CAPTURE SITE LEAD FORM (1.4.0) -- */
/*
 * فرم رزرو قالب، درخواست را به‌صورت نوشته‌ی rk_lead ذخیره و به وب‌هوک n8n (rk-lead) می‌فرستد.
 * n8n Cloud به هاست دسترسی ندارد (فایروال)، پس لید را همین‌جا در وردپرس می‌گیریم:
 * ۱) از بدنه‌ی درخواستِ خروجی به وب‌هوک (کلیدهای معلوم: name, phone, field, grade, want)
 * ۲) پشتیبان: از خود نوشته‌ی rk_lead، اگر مسیر اول چیزی نگرفت.
 * هیچ‌کدام درخواست اصلی را تغییر نمی‌دهد یا متوقف نمی‌کند.
 */

if ( ! function_exists( 'rkspb_capture_lead' ) ) {
	function rkspb_capture_lead( $in, $origin ) {
		if ( '1.4.0' !== get_option( 'rkspb_sales_schema' ) ) { return; }
		$mobile = rkspb_normalize_mobile( isset( $in['phone'] ) ? $in['phone'] : ( isset( $in['mobile'] ) ? $in['mobile'] : '' ) );
		if ( ! preg_match( '/^09\d{9}$/', $mobile ) ) { return; }
		$flag = 'rkspb_lead_seen_' . md5( $mobile );
		if ( get_transient( $flag ) ) { return; } // همین فرم از مسیر دیگر ثبت شده
		set_transient( $flag, 1, 10 * MINUTE_IN_SECONDS );
		$msg = array();
		foreach ( array( 'want', 'message', 'msg', 'note' ) as $k ) {
			if ( ! empty( $in[ $k ] ) && is_scalar( $in[ $k ] ) ) { $msg[] = (string) $in[ $k ]; }
		}
		if ( ! empty( $in['mentor'] ) && is_scalar( $in['mentor'] ) ) { $msg[] = 'مشاور درخواستی: ' . $in['mentor']; }
		$r = rkspb_insert_lead( array(
			'name'        => isset( $in['name'] ) ? $in['name'] : '',
			'mobile'      => $mobile,
			'grade'       => isset( $in['grade'] ) ? $in['grade'] : '',
			'field'       => isset( $in['field'] ) ? $in['field'] : '',
			'message'     => implode( "\n", $msg ),
			'source_page' => ! empty( $in['source_page'] ) ? $in['source_page'] : $origin,
			'plan'        => isset( $in['plan'] ) ? $in['plan'] : '',
			'plan_term'   => isset( $in['plan_term'] ) ? $in['plan_term'] : '',
		) );
		if ( is_wp_error( $r ) ) {
			update_option( 'rkspb_last_lead_error', current_time( 'mysql' ) . ' ' . $r->get_error_message(), false );
		}
	}
}

add_filter( 'pre_http_request', function ( $pre, $args, $url ) {
	if ( false === strpos( (string) $url, 'rk-lead' ) ) { return $pre; }
	try {
		$body = isset( $args['body'] ) ? $args['body'] : '';
		$data = is_array( $body ) ? $body : json_decode( (string) $body, true );
		if ( ! is_array( $data ) && is_string( $body ) ) { parse_str( $body, $data ); }
		if ( is_array( $data ) ) { rkspb_capture_lead( $data, 'فرم سایت' ); }
	} catch ( \Throwable $e ) {
		update_option( 'rkspb_last_lead_error', current_time( 'mysql' ) . ' ' . $e->getMessage(), false );
	}
	return $pre; // درخواست به n8n دست‌نخورده ادامه پیدا می‌کند
}, 1, 3 );

add_action( 'wp_after_insert_post', function ( $post_id, $post, $update ) {
	if ( $update || ! $post || 'rk_lead' !== $post->post_type ) { return; }
	try {
		$meta = get_post_meta( $post_id );
		$in   = array( 'name' => $post->post_title );
		foreach ( (array) $meta as $k => $vals ) {
			$v  = is_array( $vals ) ? (string) reset( $vals ) : (string) $vals;
			$lk = strtolower( $k );
			if ( '' === $v || '_' === substr( $lk, 0, 1 ) && false === strpos( $lk, 'rk' ) ) { continue; }
			if ( empty( $in['phone'] ) && preg_match( '/^09\d{9}$/', rkspb_normalize_mobile( $v ) ) ) { $in['phone'] = $v; continue; }
			foreach ( array( 'grade' => 'grade', 'paye' => 'grade', 'field' => 'field', 'reshte' => 'field', 'want' => 'want', 'message' => 'want', 'mentor' => 'mentor', 'plan_term' => 'plan_term', 'plan' => 'plan' ) as $needle => $key ) {
				if ( empty( $in[ $key ] ) && false !== strpos( $lk, $needle ) ) { $in[ $key ] = $v; break; }
			}
			if ( false !== strpos( $lk, 'name' ) && '' !== $v && ! preg_match( '/\d{5,}/', $v ) ) { $in['name'] = $v; }
		}
		if ( empty( $in['want'] ) && '' !== trim( wp_strip_all_tags( $post->post_content ) ) ) {
			$in['want'] = wp_trim_words( wp_strip_all_tags( $post->post_content ), 60, '…' );
		}
		rkspb_capture_lead( $in, 'فرم سایت' );
	} catch ( \Throwable $e ) {
		update_option( 'rkspb_last_lead_error', current_time( 'mysql' ) . ' ' . $e->getMessage(), false );
	}
}, 20, 3 );

/* ------------------------------------ WP-ADMIN ENTRY POINTS (1.4.1) ---- */
/*
 * داشبورد مدیر و لیدها داخل پنل (panel.rahekonkur.ir) هستند و فقط با حساب مدیر دیده می‌شوند.
 * حساب مدیر وردپرس معمولاً شماره‌ی موبایل ندارد و از فرم پنل نمی‌تواند وارد شود؛ این صفحه
 * یک توکن برای همان مدیرِ واردشده می‌سازد و مستقیم به داشبورد پنل می‌رود.
 * توکن در بخش # آدرس می‌رود که به هیچ سروری فرستاده نمی‌شود، و پنل بلافاصله پاکش می‌کند.
 */

add_action( 'admin_menu', function () {
	global $wpdb;
	$open = 0;
	$lt   = $wpdb->prefix . 'rkspb_leads';
	if ( '1.4.0' === get_option( 'rkspb_sales_schema' ) ) {
		$open = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$lt}` WHERE status = 'new'" );
	}
	add_menu_page(
		'داشبورد پرتال راه کنکور',
		'داشبورد پرتال' . ( $open ? ' <span class="update-plugins count-' . $open . '"><span class="plugin-count">' . $open . '</span></span>' : '' ),
		'manage_options',
		'rkspb_portal',
		'rkspb_render_portal_page',
		'dashicons-chart-area',
		57
	);
}, 21 );

add_action( 'admin_init', function () {
	if ( empty( $_POST['rkspb_open_panel'] ) ) { return; }
	if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'دسترسی ندارید.' ); }
	check_admin_referer( 'rkspb_open_panel' );
	$token = rkspb_issue_token( get_current_user_id() );
	$tab   = isset( $_POST['tab'] ) ? sanitize_key( wp_unslash( $_POST['tab'] ) ) : '';
	$url   = untrailingslashit( RKSPB_PANEL_ORIGIN ) . '/#rk_token=' . rawurlencode( $token ) . ( $tab ? '&tab=' . $tab : '' );
	wp_redirect( $url ); // phpcs:ignore WordPress.Security.SafeRedirect -- مقصد ثابت است
	exit;
} );

if ( ! function_exists( 'rkspb_render_portal_page' ) ) {
	function rkspb_render_portal_page() {
		if ( ! current_user_can( 'manage_options' ) ) { return; }
		global $wpdb;
		if ( '1.4.0' !== get_option( 'rkspb_sales_schema' ) ) { rkspb_upgrade_sales_schema(); }
		$err = get_option( 'rkspb_schema_error' );
		$lt  = rkspb_leads_table();

		echo '<div class="wrap" dir="rtl"><h1>داشبورد پرتال راه کنکور</h1>';
		echo '<p style="color:#555">داشبورد مدیر، حق‌الزحمه، لیدها و مشاوران فروش داخل پنل هستند. دکمه‌ی زیر با همین حساب مدیر وارد پنل می‌شود.</p>';
		if ( $err ) {
			echo '<div class="notice notice-error"><p>خطای ساخت جدول: <code>' . esc_html( $err ) . '</code></p></div>';
		}

		$buttons = array( '' => 'ورود به داشبورد مدیر', 'leads' => 'لیدها', 'money' => 'حق‌الزحمه', 'staff' => 'افزودن مشاور فروش' );
		echo '<p>';
		foreach ( $buttons as $tab => $label ) {
			echo '<form method="post" target="_blank" style="display:inline-block;margin-left:8px">';
			wp_nonce_field( 'rkspb_open_panel' );
			echo '<input type="hidden" name="rkspb_open_panel" value="1"><input type="hidden" name="tab" value="' . esc_attr( $tab ) . '">';
			echo '<button type="submit" class="button ' . ( '' === $tab ? 'button-primary button-hero' : 'button-secondary' ) . '">' . esc_html( $label ) . '</button>';
			echo '</form>';
		}
		echo '</p>';

		// وضعیت نصب
		$sales = rkspb_sales_users();
		$rows  = array(
			'نسخه‌ی پل'               => rkspb_plugin_version(),
			'جدول لیدها'              => ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $lt ) ) === $lt ) ? 'ساخته شده' : 'ساخته نشده',
			'جدول برنامه‌ی هفتگی'     => rkspb_week_ready() ? 'ساخته شده' : 'ساخته نشده',
			'مشاوران فروش'            => count( $sales ) ? implode( '، ', wp_list_pluck( $sales, 'display_name' ) ) : 'هنوز کسی تعریف نشده — لیدهای تازه بدون مسئول می‌مانند',
			'آخرین خطای دریافت لید'   => get_option( 'rkspb_last_lead_error' ) ? get_option( 'rkspb_last_lead_error' ) : '—',
		);
		echo '<table class="widefat striped" style="max-width:760px"><tbody>';
		foreach ( $rows as $k => $v ) {
			echo '<tr><th style="width:200px">' . esc_html( $k ) . '</th><td>' . esc_html( $v ) . '</td></tr>';
		}
		echo '</tbody></table>';

		// آخرین لیدها
		echo '<h2 style="margin-top:24px">آخرین لیدها</h2>';
		$leads = ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $lt ) ) === $lt )
			? $wpdb->get_results( "SELECT * FROM `{$lt}` ORDER BY id DESC LIMIT 30", ARRAY_A )
			: array();
		if ( ! $leads ) {
			echo '<p>هنوز لیدی ثبت نشده. هر فرمی که از این به بعد در سایت پر شود، اینجا و در پنل مشاور فروش نشان داده می‌شود.</p>';
		} else {
			$labels = rkspb_lead_statuses();
			echo '<table class="widefat striped"><thead><tr><th>تاریخ</th><th>نام</th><th>موبایل</th><th>پایه</th><th>وضعیت</th><th>مسئول</th><th>مبلغ ثبت‌نام</th></tr></thead><tbody>';
			foreach ( $leads as $l ) {
				printf(
					'<tr><td>%s</td><td>%s</td><td dir="ltr">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
					esc_html( date_i18n( 'Y/m/d H:i', strtotime( $l['created_at'] ) ) ),
					esc_html( $l['name'] ),
					esc_html( $l['mobile'] ),
					esc_html( $l['grade'] ),
					esc_html( isset( $labels[ $l['status'] ] ) ? $labels[ $l['status'] ] : $l['status'] ),
					esc_html( $l['sales_user_id'] ? rkspb_user_label( $l['sales_user_id'] ) : 'بدون مسئول' ),
					$l['won_amount'] ? esc_html( number_format_i18n( $l['won_amount'] ) . ' تومان' ) : '—'
				);
			}
			echo '</tbody></table>';
		}
		echo '</div>';
	}
}

/* ------------------------------------------------- OPTIONAL REDIRECTS ---- */

add_action( 'template_redirect', function () {
	if ( ! defined( 'RKSPB_REDIRECT_OLD_PAGES' ) || ! RKSPB_REDIRECT_OLD_PAGES ) { return; }
	if ( is_admin() ) { return; }
	$path = isset( $_SERVER['REQUEST_URI'] ) ? wp_parse_url( wp_unslash( $_SERVER['REQUEST_URI'] ), PHP_URL_PATH ) : '';
	$path = trim( (string) $path, '/' );
	$map  = array(
		'student-portal'   => '/',
		'student-register' => '/?tab=register',
	);
	if ( isset( $map[ $path ] ) ) {
		wp_redirect( untrailingslashit( RKSPB_PANEL_ORIGIN ) . $map[ $path ], 302 );
		exit;
	}
}, 1 );

/* ==========================================================================
 * فیش واریزی و طرح — نسخه‌ی ۱.۵.۰
 *
 * جریان کار (تصمیم امیر): دانش‌آموز فیش را برای مشاور فروش می‌فرستد،
 * مشاور فروش آن را در سامانه ثبت می‌کند (شماره پیگیری، مبلغ، تاریخ)،
 * و تأیید نهایی با مدیر است. عکس فیش ذخیره نمی‌شود.
 *
 * تا پیش از این، مبلغ فقط در ستون price جدول plans و won_amount لید
 * می‌نشست و هیچ ردیف پرداختی وجود نداشت؛ ضمناً ردیف طرح فقط موقع
 * «تبدیل لید» ساخته می‌شد، پس دانش‌آموزی که خودش ثبت‌نام کرده بود
 * هیچ طرحی در پرتال نمی‌دید. هر دو کمبود اینجا پر می‌شود.
 * ========================================================================== */

if ( ! function_exists( 'rkspb_student_has_mentor' ) ) {
	/** آیا دانش‌آموز اتصال فعال به مشاور تحصیلی دارد. */
	function rkspb_student_has_mentor( $sid ) {
		global $wpdb;
		if ( ! rkspb_cols_meta( 'assignments' ) ) { return false; }
		$at = rkspb_table_name( 'assignments' );
		return (bool) $wpdb->get_var( $wpdb->prepare(
			"SELECT id FROM `{$at}` WHERE student_id = %d" . rkspb_active_assignment_sql() . ' LIMIT 1',
			(int) $sid
		) );
	}
}

if ( ! function_exists( 'rkspb_sales_may_work' ) ) {
	/**
	 * مدیر همیشه؛ مشاور فروش فقط وقتی مدیر حسابش را غیرفعال نکرده باشد.
	 * حساب مشاور فروش را فقط مدیر می‌سازد، پس «تأیید مدیر» شرط ورود است؛
	 * غیرفعال کردن هم دسترسی ثبت‌نام و ثبت فیش را می‌بندد بدون حذف حساب.
	 */
	function rkspb_sales_may_work( $user = null ) {
		$user = $user ? $user : wp_get_current_user();
		if ( ! $user || ! $user->ID ) { return false; }
		if ( rkspb_is_admin_user( $user ) ) { return true; }
		if ( ! rkspb_is_sales_user( $user ) ) { return false; }
		return ! get_user_meta( $user->ID, 'rkspb_sales_paused', true );
	}
}

if ( ! function_exists( 'rkspb_payments_table' ) ) {
	function rkspb_payments_table() {
		global $wpdb;
		return $wpdb->prefix . 'rkspb_payments';
	}
}

if ( ! function_exists( 'rkspb_upgrade_pay_schema' ) ) {
	function rkspb_upgrade_pay_schema() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$pt      = rkspb_payments_table();
		dbDelta( "CREATE TABLE {$pt} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			student_id bigint(20) unsigned NOT NULL DEFAULT 0,
			plan_id bigint(20) unsigned NOT NULL DEFAULT 0,
			lead_id bigint(20) unsigned NOT NULL DEFAULT 0,
			amount bigint(20) unsigned NOT NULL DEFAULT 0,
			ref varchar(64) NOT NULL DEFAULT '',
			paid_at date NULL DEFAULT NULL,
			status varchar(20) NOT NULL DEFAULT 'pending',
			note varchar(500) NOT NULL DEFAULT '',
			created_by bigint(20) unsigned NOT NULL DEFAULT 0,
			created_at datetime NOT NULL,
			decided_by bigint(20) unsigned NOT NULL DEFAULT 0,
			decided_at datetime NULL DEFAULT NULL,
			PRIMARY KEY  (id),
			KEY student_status (student_id,status),
			KEY status (status),
			KEY ref (ref)
		) {$charset};" );

		$role = get_role( 'administrator' );
		if ( $role ) { $role->add_cap( 'rkspb_payments' ); }
		// مشاور فروش دیگر به پیشخوان وردپرس نیاز ندارد؛ کارش کامل در پنل است.
		$role = get_role( 'rksp_sales' );
		if ( $role ) { $role->remove_cap( 'rkspb_payments' ); }

		$ok = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $pt ) ) === $pt;
		if ( $ok ) {
			update_option( 'rkspb_pay_schema', '1.9.0', false );
		} else {
			update_option( 'rkspb_schema_error', 'payments: ' . $wpdb->last_error, false );
		}
		return $ok;
	}
}

add_action( 'init', function () {
	if ( '1.9.0' === get_option( 'rkspb_pay_schema' ) ) { return; }
	if ( get_transient( 'rkspb_pay_schema_try' ) ) { return; }
	set_transient( 'rkspb_pay_schema_try', 1, HOUR_IN_SECONDS );
	rkspb_upgrade_pay_schema();
}, 6 );

if ( ! function_exists( 'rkspb_pay_ready' ) ) {
	function rkspb_pay_ready() {
		if ( '1.9.0' === get_option( 'rkspb_pay_schema' ) ) { return true; }
		return rkspb_upgrade_pay_schema();
	}
}

/* ------------------------------------------------------------- تاریخ شمسی -- */

if ( ! function_exists( 'rkspb_jalali_to_gregorian' ) ) {
	/** الگوریتم استاندارد jdf. ورودی و خروجی آرایه‌ی سه‌تایی. */
	function rkspb_jalali_to_gregorian( $jy, $jm, $jd ) {
		$jy  += 1595;
		$days = -355668 + ( 365 * $jy ) + ( (int) ( $jy / 33 ) * 8 ) + (int) ( ( ( $jy % 33 ) + 3 ) / 4 ) + $jd
			+ ( ( $jm < 7 ) ? ( $jm - 1 ) * 31 : ( ( $jm - 7 ) * 30 ) + 186 );
		$gy   = 400 * (int) ( $days / 146097 );
		$days %= 146097;
		if ( $days > 36524 ) {
			$gy   += 100 * (int) ( --$days / 36524 );
			$days %= 36524;
			if ( $days >= 365 ) { $days++; }
		}
		$gy   += 4 * (int) ( $days / 1461 );
		$days %= 1461;
		if ( $days > 365 ) {
			$gy  += (int) ( ( $days - 1 ) / 365 );
			$days = ( $days - 1 ) % 365;
		}
		$gd    = $days + 1;
		$leap  = ( ( 0 === $gy % 4 && 0 !== $gy % 100 ) || 0 === $gy % 400 );
		$month = array( 0, 31, $leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 );
		for ( $gm = 0; $gm < 13 && $gd > $month[ $gm ]; $gm++ ) { $gd -= $month[ $gm ]; }
		return array( $gy, $gm, $gd );
	}
}

if ( ! function_exists( 'rkspb_gregorian_to_jalali' ) ) {
	function rkspb_gregorian_to_jalali( $gy, $gm, $gd ) {
		$g_d_m = array( 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 );
		$gy2   = ( $gm > 2 ) ? ( $gy + 1 ) : $gy;
		$days  = 355666 + ( 365 * $gy ) + (int) ( ( $gy2 + 3 ) / 4 ) - (int) ( ( $gy2 + 99 ) / 100 )
			+ (int) ( ( $gy2 + 399 ) / 400 ) + $gd + $g_d_m[ $gm - 1 ];
		$jy    = -1595 + ( 33 * (int) ( $days / 12053 ) );
		$days %= 12053;
		$jy   += 4 * (int) ( $days / 1461 );
		$days %= 1461;
		if ( $days > 365 ) {
			$jy  += (int) ( ( $days - 1 ) / 365 );
			$days = ( $days - 1 ) % 365;
		}
		if ( $days < 186 ) {
			$jm = 1 + (int) ( $days / 31 );
			$jd = 1 + ( $days % 31 );
		} else {
			$jm = 7 + (int) ( ( $days - 186 ) / 30 );
			$jd = 1 + ( ( $days - 186 ) % 30 );
		}
		return array( $jy, $jm, $jd );
	}
}

if ( ! function_exists( 'rkspb_fa_digits' ) ) {
	function rkspb_fa_digits( $s ) {
		return strtr( (string) $s, array( '0' => '۰', '1' => '۱', '2' => '۲', '3' => '۳', '4' => '۴', '5' => '۵', '6' => '۶', '7' => '۷', '8' => '۸', '9' => '۹' ) );
	}
}

if ( ! function_exists( 'rkspb_jdate' ) ) {
	/** 'Y-m-d' میلادی ← رشته‌ی شمسی با ارقام فارسی. */
	function rkspb_jdate( $ymd, $fa = true ) {
		$ymd = (string) $ymd;
		if ( ! preg_match( '/^(\d{4})-(\d{2})-(\d{2})/', $ymd, $m ) ) { return '—'; }
		list( $jy, $jm, $jd ) = rkspb_gregorian_to_jalali( (int) $m[1], (int) $m[2], (int) $m[3] );
		$out = sprintf( '%04d/%02d/%02d', $jy, $jm, $jd );
		return $fa ? rkspb_fa_digits( $out ) : $out;
	}
}

if ( ! function_exists( 'rkspb_date_input' ) ) {
	/**
	 * ورودی تاریخ را می‌پذیرد چه شمسی چه میلادی و همیشه 'Y-m-d' میلادی می‌دهد.
	 * سال کوچک‌تر از ۱۷۰۰ یعنی شمسی. خالی یعنی خالی.
	 */
	function rkspb_date_input( $v ) {
		$v = rkspb_latin_digits( trim( (string) $v ) );
		$v = str_replace( array( '/', '.' ), '-', $v );
		if ( ! preg_match( '/^(\d{4})-(\d{1,2})-(\d{1,2})$/', $v, $m ) ) { return ''; }
		$y = (int) $m[1];
		$o = (int) $m[2];
		$d = (int) $m[3];
		if ( $o < 1 || $o > 12 || $d < 1 || $d > 31 ) { return ''; }
		if ( $y < 1700 ) {
			list( $y, $o, $d ) = rkspb_jalali_to_gregorian( $y, $o, $d );
		}
		if ( ! checkdate( $o, $d, $y ) ) { return ''; }
		return sprintf( '%04d-%02d-%02d', $y, $o, $d );
	}
}

if ( ! function_exists( 'rkspb_jalali_month_len' ) ) {
	/** طول ماه شمسی؛ اسفند بسته به کبیسه ۲۹ یا ۳۰ روز است. */
	function rkspb_jalali_month_len( $jy, $jm ) {
		if ( $jm <= 6 ) { return 31; }
		if ( $jm <= 11 ) { return 30; }
		$g = rkspb_jalali_to_gregorian( $jy, 12, 30 );
		$b = rkspb_gregorian_to_jalali( $g[0], $g[1], $g[2] );
		return ( 12 === $b[1] && 30 === $b[2] ) ? 30 : 29;
	}
}

if ( ! function_exists( 'rkspb_add_jmonths' ) ) {
	/**
	 * n ماه شمسی به یک تاریخ میلادی اضافه می‌کند و میلادی برمی‌گرداند.
	 *
	 * طرح‌ها ماهانه و به تقویم شمسی فروخته می‌شوند؛ جمع‌زدن ماه میلادی
	 * هم روزِ پایان را یکی‌دو روز جابه‌جا می‌کرد و هم در ماه‌های ۳۱ روزه
	 * سرریز می‌شد (۳۱ فروردین + ۱ ماه می‌شد ۳ خرداد).
	 */
	function rkspb_add_jmonths( $ymd, $n ) {
		$p = explode( '-', substr( (string) $ymd, 0, 10 ) );
		if ( 3 !== count( $p ) ) { return (string) $ymd; }
		list( $jy, $jm, $jd ) = rkspb_gregorian_to_jalali( (int) $p[0], (int) $p[1], (int) $p[2] );
		$total = ( $jm - 1 ) + (int) $n;
		$jy   += intdiv( $total, 12 );
		$jm    = ( $total % 12 ) + 1;
		if ( $jm < 1 ) { $jm += 12; $jy--; }
		$jd = min( $jd, rkspb_jalali_month_len( $jy, $jm ) );
		$g  = rkspb_jalali_to_gregorian( $jy, $jm, $jd );
		return sprintf( '%04d-%02d-%02d', $g[0], $g[1], $g[2] );
	}
}

if ( ! function_exists( 'rkspb_today_jalali' ) ) {
	function rkspb_today_jalali() {
		$t = explode( '-', current_time( 'Y-m-d' ) );
		list( $jy, $jm, $jd ) = rkspb_gregorian_to_jalali( (int) $t[0], (int) $t[1], (int) $t[2] );
		return sprintf( '%04d/%02d/%02d', $jy, $jm, $jd );
	}
}

/* ---------------------------------------------------------- فهرست طرح‌ها -- */

if ( ! function_exists( 'rkspb_plan_catalog' ) ) {
	/**
	 * پکیج‌های سایت. «برنامه‌ی پایه» در هر دو مسیر هست با دو قیمت، پس
	 * اسمشان اینجا تفکیک شده وگرنه گزارش درآمد قاطی می‌شود.
	 */
	function rkspb_plan_catalog() {
		$default = array(
			array( 'name' => 'برنامه‌ی پایه (کنکور)', 'price' => 1500000, 'track' => 'کنکور' ),
			array( 'name' => 'برنامه و پیگیری', 'price' => 2500000, 'track' => 'کنکور' ),
			array( 'name' => 'همراهی کامل', 'price' => 3500000, 'track' => 'کنکور' ),
			array( 'name' => 'برنامه‌ی پایه (نهایی)', 'price' => 1200000, 'track' => 'نهایی و پایه' ),
			array( 'name' => 'برنامه و نهایی', 'price' => 2700000, 'track' => 'نهایی و پایه' ),
			array( 'name' => 'همراهی پایه', 'price' => 3900000, 'track' => 'نهایی و پایه' ),
		);
		$saved = get_option( 'rkspb_plan_catalog' );
		return ( is_array( $saved ) && $saved ) ? $saved : $default;
	}
}

/* ------------------------------------------------------------- کمک‌کارها -- */

if ( ! function_exists( 'rkspb_money_input' ) ) {
	function rkspb_money_input( $v ) {
		$v = rkspb_latin_digits( (string) $v );
		return (int) preg_replace( '/\D/', '', $v );
	}
}

if ( ! function_exists( 'rkspb_student_by_mobile' ) ) {
	function rkspb_student_by_mobile( $mobile ) {
		global $wpdb;
		$mobile = rkspb_normalize_mobile( $mobile );
		if ( 11 !== strlen( $mobile ) || ! rkspb_cols_meta( 'students' ) ) { return null; }
		$t = rkspb_table_name( 'students' );
		if ( rkspb_pick( 'students', array( 'mobile' ) ) ) {
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE mobile = %s ORDER BY id DESC LIMIT 1", $mobile ), ARRAY_A );
			if ( $row ) { return $row; }
		}
		$user = rkspb_find_user_by_mobile( $mobile );
		if ( $user ) {
			return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE user_id = %d ORDER BY id DESC LIMIT 1", $user->ID ), ARRAY_A );
		}
		return null;
	}
}

if ( ! function_exists( 'rkspb_payment_out' ) ) {
	function rkspb_payment_out( $r ) {
		$st = rkspb_student_by_id( $r['student_id'] );
		return array(
			'id'           => (int) $r['id'],
			'student_id'   => (int) $r['student_id'],
			'student_name' => $st ? rkspb_student_name( $st ) : '',
			'mobile'       => $st ? rkspb_student_mobile( $st ) : '',
			'plan_id'      => (int) $r['plan_id'],
			'amount'       => (int) $r['amount'],
			'ref'          => (string) $r['ref'],
			'paid_at'      => (string) $r['paid_at'],
			'status'       => (string) $r['status'],
			'note'         => (string) $r['note'],
			'created_by'   => (int) $r['created_by'],
			'created_name' => rkspb_user_label( $r['created_by'] ),
			'created_at'   => (string) $r['created_at'],
			'decided_by'   => (int) $r['decided_by'],
			'decided_name' => rkspb_user_label( $r['decided_by'] ),
			'decided_at'   => (string) $r['decided_at'],
		);
	}
}

if ( ! function_exists( 'rkspb_payment_statuses' ) ) {
	function rkspb_payment_statuses() {
		return array(
			'pending'  => 'در انتظار تأیید مدیر',
			'approved' => 'تأیید شده',
			'rejected' => 'رد شده',
		);
	}
}

/* -------------------------------------------------------- ساخت طرح و فیش -- */

if ( ! function_exists( 'rkspb_create_plan_for_student' ) ) {
	/**
	 * طرح تازه برای دانش‌آموزی که از قبل پرونده دارد (ثبت‌نام مستقیم یا تمدید).
	 * طرح فعال قبلی بسته می‌شود تا دو طرح فعال هم‌زمان نماند.
	 *
	 * @return int|WP_Error شناسه‌ی طرح
	 */
	function rkspb_create_plan_for_student( $sid, $args ) {
		global $wpdb;
		$sid = (int) $sid;
		if ( ! rkspb_student_by_id( $sid ) ) {
			return new WP_Error( 'rkspb_bad', 'پرونده‌ی دانش‌آموز پیدا نشد.', array( 'status' => 404 ) );
		}
		if ( ! rkspb_cols_meta( 'plans' ) ) {
			return new WP_Error( 'rkspb_no_table', 'جدول طرح‌ها پیدا نشد.', array( 'status' => 500 ) );
		}
		$name   = sanitize_text_field( isset( $args['plan_name'] ) ? $args['plan_name'] : '' );
		$price  = rkspb_money_input( isset( $args['price'] ) ? $args['price'] : 0 );
		$months = max( 1, min( 24, (int) rkspb_latin_digits( isset( $args['months'] ) ? $args['months'] : 1 ) ) );
		$start  = rkspb_date_input( isset( $args['start_date'] ) ? $args['start_date'] : '' );
		if ( '' === $name ) { return new WP_Error( 'rkspb_bad', 'نام طرح لازم است.', array( 'status' => 400 ) ); }
		if ( '' === $start ) { $start = current_time( 'Y-m-d' ); }
		$end = rkspb_add_jmonths( $start, $months );

		$pt   = rkspb_table_name( 'plans' );
		$meta = rkspb_cols_meta( 'plans' );
		if ( isset( $meta['status'] ) && rkspb_pick( 'plans', array( 'student_id' ) ) ) {
			$wpdb->query( $wpdb->prepare(
				"UPDATE `{$pt}` SET status = %s WHERE student_id = %d AND status = %s",
				rkspb_fit_value( 'plans', 'status', 'ended', array( 'ended', 'expired', 'inactive' ) ),
				$sid,
				'active'
			) );
		}
		$plan_id = rkspb_insert_row( 'plans', array(
			'student_id' => $sid,
			'plan_name'  => $name,
			'name'       => $name,
			'price'      => $price,
			'start_date' => $start,
			'end_date'   => $end,
			'status'     => rkspb_fit_value( 'plans', 'status', 'active', array( 'active' ) ),
			'plan_type'  => $months . 'm',
			'created_at' => rkspb_now(),
		) );
		if ( is_wp_error( $plan_id ) ) { return $plan_id; }

		// اتصال فعال را به طرح تازه وصل کن تا rkspb_plan_info پشتیبان هم درست باشد.
		if ( rkspb_cols_meta( 'assignments' ) ) {
			$am = rkspb_cols_meta( 'assignments' );
			if ( isset( $am['plan_id'] ) ) {
				$at = rkspb_table_name( 'assignments' );
				$wpdb->query( $wpdb->prepare( "UPDATE `{$at}` SET plan_id = %d WHERE student_id = %d" . rkspb_active_assignment_sql(), (int) $plan_id, $sid ) );
			}
		}
		return (int) $plan_id;
	}
}

if ( ! function_exists( 'rkspb_record_payment' ) ) {
	/**
	 * ثبت فیش. مشاور فروش ثبت می‌کند، وضعیت pending می‌ماند تا مدیر تأیید کند.
	 *
	 * @return array|WP_Error
	 */
	function rkspb_record_payment( $args, $user_id = 0 ) {
		global $wpdb;
		if ( ! rkspb_pay_ready() ) {
			return new WP_Error( 'rkspb_schema', 'جدول فیش‌ها ساخته نشد.', array( 'status' => 500 ) );
		}
		$student = null;
		if ( ! empty( $args['student_id'] ) ) {
			$student = rkspb_student_by_id( $args['student_id'] );
		}
		if ( ! $student && ! empty( $args['mobile'] ) ) {
			$student = rkspb_student_by_mobile( $args['mobile'] );
		}
		$amount  = rkspb_money_input( isset( $args['amount'] ) ? $args['amount'] : 0 );
		$ref     = mb_substr( sanitize_text_field( rkspb_latin_digits( isset( $args['ref'] ) ? $args['ref'] : '' ) ), 0, 64 );
		$paid_at = rkspb_date_input( isset( $args['paid_at'] ) ? $args['paid_at'] : '' );
		$note    = mb_substr( sanitize_textarea_field( isset( $args['note'] ) ? $args['note'] : '' ), 0, 500 );

		$errors = array();
		if ( ! $student ) { $errors[] = 'دانش‌آموز پیدا نشد؛ موبایل را درست وارد کنید.'; }
		if ( $amount < 1000 ) { $errors[] = 'مبلغ واریزی را وارد کنید.'; }
		if ( '' === $ref ) { $errors[] = 'شماره پیگیری لازم است.'; }
		if ( '' === $paid_at ) { $errors[] = 'تاریخ واریز را درست وارد کنید (مثل ۱۴۰۵/۰۶/۲۵).'; }
		if ( $errors ) { return new WP_Error( 'rkspb_bad', implode( ' ', $errors ), array( 'status' => 400 ) ); }

		$pt   = rkspb_payments_table();
		$dup  = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$pt}` WHERE ref = %s AND status <> 'rejected' LIMIT 1", $ref ), ARRAY_A );
		if ( $dup ) {
			return new WP_Error( 'rkspb_dup', 'این شماره پیگیری قبلاً ثبت شده است (فیش #' . (int) $dup['id'] . ').', array( 'status' => 409 ) );
		}

		$sid     = (int) $student['id'];
		$plan_id = isset( $args['plan_id'] ) ? (int) $args['plan_id'] : 0;
		// فیش قسطی که طرح همراهش نیامده، به طرح فعالِ همان دانش‌آموز بچسبد
		// وگرنه در «چقدر از این طرح پرداخت شده» دیده نمی‌شود.
		if ( ! $plan_id && empty( $args['plan_name'] ) && function_exists( 'rkspb_active_plan_id' ) ) {
			$plan_id = rkspb_active_plan_id( $sid );
		}

		// طرح همراه فیش، اگر خواسته شده باشد
		if ( ! $plan_id && ! empty( $args['plan_name'] ) ) {
			$made = rkspb_create_plan_for_student( $sid, array(
				'plan_name'  => $args['plan_name'],
				'price'      => isset( $args['plan_price'] ) && '' !== $args['plan_price'] ? $args['plan_price'] : $amount,
				'months'     => isset( $args['months'] ) ? $args['months'] : 1,
				'start_date' => isset( $args['start_date'] ) ? $args['start_date'] : '',
			) );
			if ( is_wp_error( $made ) ) { return $made; }
			$plan_id = (int) $made;
		}

		$ok = $wpdb->insert( $pt, array(
			'student_id' => $sid,
			'plan_id'    => $plan_id,
			'lead_id'    => isset( $args['lead_id'] ) ? (int) $args['lead_id'] : 0,
			'amount'     => $amount,
			'ref'        => $ref,
			'paid_at'    => $paid_at,
			'status'     => 'pending',
			'note'       => $note,
			'created_by' => $user_id ? (int) $user_id : get_current_user_id(),
			'created_at' => rkspb_now(),
		) );
		if ( ! $ok ) {
			return new WP_Error( 'rkspb_db', 'فیش ثبت نشد: ' . $wpdb->last_error, array( 'status' => 500 ) );
		}
		$id  = (int) $wpdb->insert_id;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$pt}` WHERE id = %d", $id ), ARRAY_A );
		$out = rkspb_payment_out( $row );
		do_action( 'rkspb_payment_recorded', $out );
		return $out;
	}
}

if ( ! function_exists( 'rkspb_decide_payment' ) ) {
	/**
	 * تأیید یا رد فیش — فقط مدیر.
	 *
	 * @return array|WP_Error
	 */
	function rkspb_decide_payment( $id, $decision, $note = '' ) {
		global $wpdb;
		if ( ! rkspb_can( 'payments.decide' ) ) {
			return new WP_Error( 'rkspb_role', 'تأیید فیش با مدیر یا مدیر فروش است.', array( 'status' => 403 ) );
		}
		if ( ! rkspb_pay_ready() ) {
			return new WP_Error( 'rkspb_schema', 'جدول فیش‌ها پیدا نشد.', array( 'status' => 500 ) );
		}
		$decision = in_array( $decision, array( 'approved', 'rejected' ), true ) ? $decision : '';
		if ( '' === $decision ) {
			return new WP_Error( 'rkspb_bad', 'تصمیم نامعتبر است.', array( 'status' => 400 ) );
		}
		$pt  = rkspb_payments_table();
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$pt}` WHERE id = %d", (int) $id ), ARRAY_A );
		if ( ! $row ) { return new WP_Error( 'rkspb_404', 'فیش پیدا نشد.', array( 'status' => 404 ) ); }

		$data = array(
			'status'     => $decision,
			'decided_by' => get_current_user_id(),
			'decided_at' => rkspb_now(),
		);
		$note = mb_substr( sanitize_textarea_field( $note ), 0, 500 );
		if ( '' !== $note ) {
			$data['note'] = trim( $row['note'] . ( $row['note'] ? "\n" : '' ) . $note );
		}
		$wpdb->update( $pt, $data, array( 'id' => (int) $id ) );

		// فیش رد شده نباید طرحی را فعال نگه دارد که فقط با همان فیش ساخته شده بود.
		if ( 'rejected' === $decision && (int) $row['plan_id'] && rkspb_cols_meta( 'plans' ) ) {
			$meta = rkspb_cols_meta( 'plans' );
			if ( isset( $meta['status'] ) ) {
				$plt = rkspb_table_name( 'plans' );
				$wpdb->update( $plt, array( 'status' => rkspb_fit_value( 'plans', 'status', 'ended', array( 'ended', 'expired', 'inactive' ) ) ), array( 'id' => (int) $row['plan_id'] ) );
			}
		}
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$pt}` WHERE id = %d", (int) $id ), ARRAY_A );
		$out = rkspb_payment_out( $row );
		// بعد از تأیید مالی، دانش‌آموزِ بی‌مشاور باید فوری به یک مشاور تحصیلی وصل شود.
		$out['needs_mentor'] = ( 'approved' === $decision && ! rkspb_student_has_mentor( $row['student_id'] ) );
		return $out;
	}
}

if ( ! function_exists( 'rkspb_payments_query' ) ) {
	/** فهرست فیش‌ها. مشاور فروش فقط ردیف‌های خودش را می‌بیند. */
	function rkspb_payments_query( $args = array() ) {
		global $wpdb;
		if ( ! rkspb_pay_ready() ) { return array(); }
		$pt    = rkspb_payments_table();
		$where = array( '1=1' );
		$vals  = array();
		if ( ! empty( $args['status'] ) && isset( rkspb_payment_statuses()[ $args['status'] ] ) ) {
			$where[] = 'status = %s';
			$vals[]  = $args['status'];
		}
		if ( ! empty( $args['student_id'] ) ) {
			$where[] = 'student_id = %d';
			$vals[]  = (int) $args['student_id'];
		}
		if ( ! empty( $args['mine_for'] ) ) {
			$where[] = 'created_by = %d';
			$vals[]  = (int) $args['mine_for'];
		}
		$limit = isset( $args['limit'] ) ? max( 1, min( 300, (int) $args['limit'] ) ) : 100;
		$sql   = "SELECT * FROM `{$pt}` WHERE " . implode( ' AND ', $where ) . " ORDER BY (status = 'pending') DESC, id DESC LIMIT {$limit}";
		$rows  = $vals ? $wpdb->get_results( $wpdb->prepare( $sql, $vals ), ARRAY_A ) : $wpdb->get_results( $sql, ARRAY_A );
		return array_map( 'rkspb_payment_out', (array) $rows );
	}
}

if ( ! function_exists( 'rkspb_student_payments' ) ) {
	/** فیش‌های خود دانش‌آموز برای نمایش در پرتال. */
	function rkspb_student_payments( $sid ) {
		global $wpdb;
		if ( ! rkspb_pay_ready() ) { return array(); }
		$pt   = rkspb_payments_table();
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$pt}` WHERE student_id = %d ORDER BY id DESC LIMIT 12", (int) $sid ), ARRAY_A );
		$out  = array();
		foreach ( (array) $rows as $r ) {
			$out[] = array(
				'id'      => (int) $r['id'],
				'amount'  => (int) $r['amount'],
				'ref'     => (string) $r['ref'],
				'paid_at' => (string) $r['paid_at'],
				'status'  => (string) $r['status'],
			);
		}
		return $out;
	}
}

if ( ! function_exists( 'rkspb_pending_payments_count' ) ) {
	function rkspb_pending_payments_count() {
		global $wpdb;
		if ( '1.9.0' !== get_option( 'rkspb_pay_schema' ) ) { return 0; }
		$pt = rkspb_payments_table();
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$pt}` WHERE status = 'pending'" );
	}
}

/* ------------------------------------------------------------------ روت‌ها -- */

add_action( 'rest_api_init', function () {

	$sales_or_admin = function () {
		return is_user_logged_in() && ( rkspb_can( 'students.register' ) || rkspb_can( 'payments.view' ) );
	};

	register_rest_route( RKSPB_NS, '/plans/catalog', array(
		'methods'             => 'GET',
		'permission_callback' => function () { return is_user_logged_in(); },
		'callback'            => function () {
			return rest_ensure_response( array( 'plans' => rkspb_plan_catalog() ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/payments', array(
		array(
			'methods'             => 'GET',
			'permission_callback' => $sales_or_admin,
			'callback'            => function ( $req ) {
				$user = wp_get_current_user();
				return rest_ensure_response( array(
					'payments' => rkspb_payments_query( array(
						'status'     => sanitize_key( (string) $req->get_param( 'status' ) ),
						'student_id' => (int) $req->get_param( 'student_id' ),
						'mine_for'   => rkspb_can( 'payments.decide', $user ) ? 0 : $user->ID,
					) ),
					'pending'  => rkspb_can( 'payments.decide', $user ) ? rkspb_pending_payments_count() : 0,
				) );
			},
		),
		array(
			'methods'             => 'POST',
			'permission_callback' => $sales_or_admin,
			'callback'            => function ( $req ) {
				$in  = (array) $req->get_json_params();
				if ( ! $in ) { $in = (array) $req->get_body_params(); }
				$out = rkspb_record_payment( $in, get_current_user_id() );
				if ( is_wp_error( $out ) ) { return $out; }
				return rest_ensure_response( array( 'ok' => true, 'payment' => $out ) );
			},
		),
	) );

	register_rest_route( RKSPB_NS, '/payments/(?P<id>\d+)/decide', array(
		'methods'             => 'POST',
		'permission_callback' => function () { return is_user_logged_in() && rkspb_can( 'payments.decide' ); },
		'callback'            => function ( $req ) {
			$in  = (array) $req->get_json_params();
			if ( ! $in ) { $in = (array) $req->get_body_params(); }
			$out = rkspb_decide_payment(
				(int) $req['id'],
				isset( $in['decision'] ) ? sanitize_key( $in['decision'] ) : '',
				isset( $in['note'] ) ? $in['note'] : ''
			);
			if ( is_wp_error( $out ) ) { return $out; }
			return rest_ensure_response( array( 'ok' => true, 'payment' => $out ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/payments/(?P<id>\d+)/delete', array(
		'methods'             => 'POST',
		'permission_callback' => $sales_or_admin,
		'callback'            => function ( $req ) {
			global $wpdb;
			if ( ! rkspb_pay_ready() ) { return new WP_Error( 'rkspb_schema', 'جدول فیش‌ها پیدا نشد.', array( 'status' => 500 ) ); }
			$pt   = rkspb_payments_table();
			$row  = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$pt}` WHERE id = %d", (int) $req['id'] ), ARRAY_A );
			if ( ! $row ) { return new WP_Error( 'rkspb_404', 'فیش پیدا نشد.', array( 'status' => 404 ) ); }
			$mine = (int) $row['created_by'] === get_current_user_id() && 'pending' === $row['status'];
			if ( ! rkspb_can( 'payments.decide' ) && ! $mine ) {
				return new WP_Error( 'rkspb_role', 'فقط فیش ثبت‌شده‌ی خودتان و پیش از تأیید قابل حذف است.', array( 'status' => 403 ) );
			}
			$wpdb->delete( $pt, array( 'id' => (int) $row['id'] ) );
			return rest_ensure_response( array( 'ok' => true ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/students/(?P<id>\d+)/mentor', array(
		'methods'             => 'POST',
		'permission_callback' => function () { return is_user_logged_in() && rkspb_can( 'mentor.assign' ); },
		'callback'            => function ( $req ) {
			$in = (array) $req->get_json_params();
			if ( ! $in ) { $in = (array) $req->get_body_params(); }
			$mentor = isset( $in['mentor_id'] ) ? (int) $in['mentor_id'] : 0;
			if ( ! $mentor ) { return new WP_Error( 'rkspb_bad', 'مشاور تحصیلی را انتخاب کنید.', array( 'status' => 400 ) ); }
			$ok = rkspb_assign_mentor_to_student( (int) $req['id'], $mentor );
			if ( is_wp_error( $ok ) ) { return $ok; }
			return rest_ensure_response( array( 'ok' => true, 'student_id' => (int) $req['id'], 'mentor_id' => $mentor ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/students/(?P<id>\d+)/plan', array(
		'methods'             => 'POST',
		'permission_callback' => $sales_or_admin,
		'callback'            => function ( $req ) {
			$in = (array) $req->get_json_params();
			if ( ! $in ) { $in = (array) $req->get_body_params(); }
			$made = rkspb_create_plan_for_student( (int) $req['id'], $in );
			if ( is_wp_error( $made ) ) { return $made; }
			$plan = rkspb_plan_info( null, (int) $req['id'] );
			return rest_ensure_response( array( 'ok' => true, 'plan_id' => (int) $made, 'plan' => $plan ) );
		},
	) );
}, 11 );

/* -------------------------------------------------- صفحه‌ی پیشخوان فیش‌ها -- */

add_action( 'admin_menu', function () {
	$pending = rkspb_pending_payments_count();
	add_menu_page(
		'فیش‌های واریزی',
		'فیش‌های واریزی' . ( $pending ? ' <span class="update-plugins count-' . $pending . '"><span class="plugin-count">' . $pending . '</span></span>' : '' ),
		'manage_options',
		'rkspb_pay',
		'rkspb_render_pay_page',
		'dashicons-media-spreadsheet',
		59
	);
}, 22 );

add_action( 'admin_post_rkspb_pay_decide', function () {
	check_admin_referer( 'rkspb_pay' );
	if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'تأیید فیش فقط با مدیر است.' ); }
	$in  = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- بالاتر بررسی شد
	$out = rkspb_decide_payment(
		isset( $in['id'] ) ? (int) $in['id'] : 0,
		isset( $in['decision'] ) ? sanitize_key( $in['decision'] ) : '',
		isset( $in['note'] ) ? $in['note'] : ''
	);
	rkspb_pay_redirect( $out, is_array( $out ) && 'approved' === $out['status'] ? 'فیش تأیید شد.' : 'فیش رد شد.' );
} );

add_action( 'admin_post_rkspb_pay_delete', function () {
	check_admin_referer( 'rkspb_pay' );
	global $wpdb;
	if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'حذف فیش فقط با مدیر است.' ); }
	$pt = rkspb_payments_table();
	$wpdb->delete( $pt, array( 'id' => isset( $_POST['id'] ) ? (int) $_POST['id'] : 0 ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- بالاتر بررسی شد
	rkspb_pay_redirect( true, 'فیش حذف شد.' );
} );

add_action( 'admin_post_rkspb_plan_add', function () {
	check_admin_referer( 'rkspb_pay' );
	if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'ثبت طرح بدون فیش فقط با مدیر است.' ); }
	$in      = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- بالاتر بررسی شد
	$student = rkspb_student_by_mobile( isset( $in['p_mobile'] ) ? $in['p_mobile'] : '' );
	if ( ! $student ) {
		rkspb_pay_redirect( new WP_Error( 'rkspb_bad', 'دانش‌آموزی با این موبایل پیدا نشد.' ), '' );
	}
	$out = rkspb_create_plan_for_student( (int) $student['id'], array(
		'plan_name'  => isset( $in['p_plan_name'] ) ? $in['p_plan_name'] : '',
		'price'      => isset( $in['p_price'] ) ? $in['p_price'] : 0,
		'months'     => isset( $in['p_months'] ) ? $in['p_months'] : 1,
		'start_date' => isset( $in['p_start'] ) ? $in['p_start'] : '',
	) );
	rkspb_pay_redirect( $out, 'طرح ثبت شد و از همین حالا در پرتال دانش‌آموز دیده می‌شود.' );
} );

if ( ! function_exists( 'rkspb_pay_redirect' ) ) {
	function rkspb_pay_redirect( $result, $ok_msg ) {
		$args = array( 'page' => 'rkspb_pay' );
		if ( is_wp_error( $result ) ) {
			$args['rkspb_err'] = rawurlencode( $result->get_error_message() );
		} else {
			$args['rkspb_ok'] = rawurlencode( $ok_msg );
		}
		wp_safe_redirect( add_query_arg( $args, admin_url( 'admin.php' ) ) );
		exit;
	}
}

if ( ! function_exists( 'rkspb_render_pay_page' ) ) {
	function rkspb_render_pay_page() {
		if ( ! current_user_can( 'manage_options' ) ) { return; }
		if ( ! rkspb_sales_may_work() ) {
			echo '<div class="wrap" dir="rtl"><h1>فیش‌های واریزی</h1><div class="notice notice-warning"><p>حساب شما فعلاً توسط مدیر غیرفعال شده است.</p></div></div>';
			return;
		}
		rkspb_pay_ready();
		$is_admin = rkspb_is_admin_user();
		$user     = wp_get_current_user();
		$statuses = rkspb_payment_statuses();
		$filter   = isset( $_GET['st'] ) ? sanitize_key( wp_unslash( $_GET['st'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- فقط فیلتر نمایش
		$today    = rkspb_today_jalali();

		echo '<div class="wrap" dir="rtl"><h1>فیش‌های واریزی</h1>';
		echo '<p style="color:#555;max-width:760px">ثبت‌نام و ثبت فیش کامل در پنل انجام می‌شود (panel.rahekonkur.ir). این صفحه پشتیبان مدیر است: تنظیم اطلاع‌رسانی، ثبت طرح برای دانش‌آموزهای قدیمی، و دیدن و تأیید فیش‌ها وقتی به پنل دسترسی نداری.</p>';

		if ( isset( $_GET['rkspb_err'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- فقط پیام
			echo '<div class="notice notice-error"><p>' . esc_html( rawurldecode( wp_unslash( $_GET['rkspb_err'] ) ) ) . '</p></div>'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}
		if ( isset( $_GET['rkspb_ok'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- فقط پیام
			echo '<div class="notice notice-success"><p>' . esc_html( rawurldecode( wp_unslash( $_GET['rkspb_ok'] ) ) ) . '</p></div>'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}

		$catalog = rkspb_plan_catalog();

		/* ---- فرم طرح بدون فیش، فقط مدیر ---- */
		if ( $is_admin ) {
			echo '<div class="card" style="max-width:none;padding:16px 20px"><h2 style="margin-top:0">ثبت طرح بدون فیش</h2>';
			echo '<p class="description" style="margin-bottom:10px">برای دانش‌آموزهایی که قبل از راه‌افتادن این بخش ثبت‌نام کرده‌اند و طرحشان در پرتال خالی است.</p>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			wp_nonce_field( 'rkspb_pay' );
			echo '<input type="hidden" name="action" value="rkspb_plan_add">';
			echo '<table class="form-table"><tbody>';
			echo '<tr><th><label for="rk-pm">موبایل دانش‌آموز</label></th><td><input required id="rk-pm" name="p_mobile" class="regular-text" dir="ltr" placeholder="09xxxxxxxxx"></td></tr>';
			echo '<tr><th><label for="rk-pp">نام طرح</label></th><td><select id="rk-pp" name="p_plan_name">';
			foreach ( $catalog as $p ) {
				echo '<option value="' . esc_attr( $p['name'] ) . '">' . esc_html( $p['name'] ) . '</option>';
			}
			echo '</select></td></tr>';
			echo '<tr><th><label for="rk-pr">مبلغ (تومان)</label></th><td><input id="rk-pr" name="p_price" class="regular-text" dir="ltr" inputmode="numeric"></td></tr>';
			echo '<tr><th><label for="rk-pmo">مدت (ماه)</label></th><td><input id="rk-pmo" name="p_months" type="number" min="1" max="24" value="1" class="small-text"> ماه</td></tr>';
			echo '<tr><th><label for="rk-ps">شروع</label></th><td><input id="rk-ps" name="p_start" class="regular-text" dir="ltr" value="' . esc_attr( $today ) . '"></td></tr>';
			echo '</tbody></table>';
			submit_button( 'ثبت طرح', 'secondary' );
			echo '</form></div>';
		}

		/* ---- گزارش مالی خودکار ---- */
		if ( $is_admin && function_exists( 'rkspb_report_settings' ) ) {
			$rc  = rkspb_report_settings();
			$url = rest_url( RKSPB_NS . '/report/finance' ) . '?token=' . rkspb_report_token();
			echo '<div class="card" style="max-width:none;padding:16px 20px"><h2 style="margin-top:0">گزارش مالی خودکار</h2>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			wp_nonce_field( 'rkspb_pay' );
			echo '<input type="hidden" name="action" value="rkspb_report_save">';
			echo '<table class="form-table"><tbody>';
			echo '<tr><th>ارسال خودکار</th><td><label><input type="checkbox" name="enabled" value="1" ' . checked( '1', $rc['enabled'], false ) . '> گزارش مالی با پیوست CSV ایمیل شود</label></td></tr>';
			echo '<tr><th>دوره</th><td><label><input type="radio" name="every" value="weekly" ' . checked( 'weekly', $rc['every'], false ) . '> هفتگی</label> &nbsp; <label><input type="radio" name="every" value="monthly" ' . checked( 'monthly', $rc['every'], false ) . '> ماهانه</label></td></tr>';
			echo '<tr><th><label for="r-to">گیرنده‌ها</label></th><td><input id="r-to" name="to" class="regular-text" dir="ltr" value="' . esc_attr( $rc['to'] ) . '"><p class="description">با ویرگول جدا کن. خالی یعنی ایمیل مدیر سایت.</p></td></tr>';
			echo '<tr><th>نشانی گزارش برای اپ بیرونی</th><td><input class="large-text" dir="ltr" readonly onclick="this.select()" value="' . esc_attr( $url ) . '">';
			echo '<p class="description">فقط‌خواندنی است و پشت توکن. هرکس این نشانی را داشته باشد گزارش مالی را می‌بیند — مثل رمز باهاش رفتار کن.</p>';
			echo '<label><input type="checkbox" name="regen" value="1"> توکن تازه بساز (نشانی قبلی از کار می‌افتد)</label></td></tr>';
			echo '<tr><th>آزمایش</th><td><label><input type="checkbox" name="send_now" value="1"> همین حالا یک گزارش بفرست</label></td></tr>';
			echo '</tbody></table>';
			submit_button( 'ذخیره', 'secondary' );
			echo '</form>';
			$last = (int) get_option( 'rkspb_report_last', 0 );
			if ( $last ) {
				echo '<p style="color:#666">آخرین ارسال: ' . esc_html( rkspb_jdate( gmdate( 'Y-m-d', $last ), false ) ) . '</p>';
			}
			echo '</div>';
		}

		/* ---- خروجی اکسل ---- */
		$nonce = wp_create_nonce( 'rkspb_pay' );
		echo '<div class="card" style="max-width:none;padding:16px 20px"><h2 style="margin-top:0">خروجی اکسل</h2>';
		echo '<p class="description" style="margin-bottom:10px">فایل CSV با کدگذاری یونیکد؛ اکسل مستقیم بازش می‌کند و فارسی سالم می‌ماند.</p><p>';
		foreach ( array(
			'payments'    => 'فیش‌های واریزی',
			'students'    => 'دانش‌آموزان و طرح‌ها',
			'settlements' => 'تسویه‌های قفل‌شده',
		) as $what => $label ) {
			if ( 'settlements' === $what && ! $is_admin ) { continue; }
			$url = add_query_arg( array( 'action' => 'rkspb_export', 'what' => $what, '_wpnonce' => $nonce ), admin_url( 'admin-post.php' ) );
			echo '<a class="button button-secondary" style="margin-left:8px" href="' . esc_url( $url ) . '">' . esc_html( $label ) . '</a>';
		}
		echo '</p></div>';

		/* ---- اطلاع‌رسانی ---- */
		if ( $is_admin && function_exists( 'rkspb_notify_settings' ) ) {
			$n = rkspb_notify_settings();
			echo '<div class="card" style="max-width:none;padding:16px 20px"><h2 style="margin-top:0">اطلاع‌رسانی فیش تازه</h2>';
			echo '<p class="description" style="margin-bottom:10px">پیامک به الگوی تأییدشده در پنل فراز نیاز دارد. متن الگو مثلاً: «فیش تازه از {name} به مبلغ {amount} تومان ثبت شد.» — همان نام متغیرها را اینجا به همان ترتیب بنویس.</p>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			wp_nonce_field( 'rkspb_pay' );
			echo '<input type="hidden" name="action" value="rkspb_notify_save">';
			echo '<table class="form-table"><tbody>';
			echo '<tr><th><label for="n-pat">کد الگوی پیامک</label></th><td><input id="n-pat" name="pay_pattern" class="regular-text" dir="ltr" value="' . esc_attr( $n['pay_pattern'] ) . '"><p class="description">خالی یعنی پیامکی فرستاده نشود.</p></td></tr>';
			echo '<tr><th><label for="n-var">نام متغیرهای الگو</label></th><td><input id="n-var" name="pay_vars" class="regular-text" dir="ltr" value="' . esc_attr( $n['pay_vars'] ) . '"><p class="description">به ترتیب: نام دانش‌آموز، مبلغ، شماره پیگیری. اگر الگویت دو متغیر دارد، دو تا بنویس.</p></td></tr>';
			echo '<tr><th><label for="n-mob">شماره‌های گیرنده</label></th><td><input id="n-mob" name="mobiles" class="regular-text" dir="ltr" value="' . esc_attr( $n['mobiles'] ) . '"><p class="description">با ویرگول جدا کن. خالی یعنی موبایل حساب مدیر.</p></td></tr>';
			echo '<tr><th>ایمیل</th><td><label><input type="checkbox" name="email" value="1" ' . checked( '1', $n['email'], false ) . '> ایمیل هم فرستاده شود</label></td></tr>';
			echo '</tbody></table>';
			submit_button( 'ذخیره', 'secondary' );
			echo '</form>';
			$err = get_option( 'rkspb_notify_last_error' );
			if ( $err ) {
				echo '<p style="color:#b32d2e">آخرین خطای پیامک: <code>' . esc_html( $err ) . '</code></p>';
			}
			echo '</div>';
		}

		/* ---- فهرست ---- */
		echo '<h2>فهرست فیش‌ها</h2><p>';
		$tabs = array_merge( array( '' => 'همه' ), $statuses );
		foreach ( $tabs as $k => $label ) {
			$url = add_query_arg( array( 'page' => 'rkspb_pay', 'st' => $k ), admin_url( 'admin.php' ) );
			echo '<a class="button ' . ( $filter === $k ? 'button-primary' : '' ) . '" style="margin-left:6px" href="' . esc_url( $url ) . '">' . esc_html( $label ) . '</a>';
		}
		echo '</p>';

		$rows = rkspb_payments_query( array(
			'status'   => $filter,
			'mine_for' => $is_admin ? 0 : $user->ID,
			'limit'    => 200,
		) );

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>#</th><th>دانش‌آموز</th><th>مبلغ</th><th>شماره پیگیری</th><th>تاریخ واریز</th><th>ثبت‌کننده</th><th>وضعیت</th><th>عملیات</th>';
		echo '</tr></thead><tbody>';
		if ( ! $rows ) {
			echo '<tr><td colspan="8">هنوز فیشی ثبت نشده است.</td></tr>';
		}
		foreach ( $rows as $r ) {
			$color = 'approved' === $r['status'] ? '#1a7f37' : ( 'rejected' === $r['status'] ? '#b32d2e' : '#9a6700' );
			echo '<tr>';
			echo '<td>' . esc_html( rkspb_fa_digits( $r['id'] ) ) . '</td>';
			echo '<td>' . esc_html( $r['student_name'] ) . '<br><small dir="ltr">' . esc_html( $r['mobile'] ) . '</small></td>';
			echo '<td>' . esc_html( number_format_i18n( $r['amount'] ) ) . '</td>';
			echo '<td dir="ltr">' . esc_html( $r['ref'] ) . '</td>';
			echo '<td>' . esc_html( rkspb_jdate( $r['paid_at'] ) ) . '</td>';
			echo '<td>' . esc_html( $r['created_name'] ) . '</td>';
			echo '<td style="color:' . esc_attr( $color ) . ';font-weight:600">' . esc_html( isset( $statuses[ $r['status'] ] ) ? $statuses[ $r['status'] ] : $r['status'] );
			if ( $r['decided_name'] ) {
				echo '<br><small style="color:#666;font-weight:400">' . esc_html( $r['decided_name'] ) . '</small>';
			}
			echo '</td><td>';
			if ( $is_admin ) {
				foreach ( array( 'approved' => 'تأیید', 'rejected' => 'رد' ) as $dec => $label ) {
					if ( $r['status'] === $dec ) { continue; }
					echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline">';
					wp_nonce_field( 'rkspb_pay' );
					echo '<input type="hidden" name="action" value="rkspb_pay_decide"><input type="hidden" name="id" value="' . esc_attr( $r['id'] ) . '"><input type="hidden" name="decision" value="' . esc_attr( $dec ) . '">';
					echo '<button class="button button-small" style="margin-left:4px">' . esc_html( $label ) . '</button></form>';
				}
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline" onsubmit="return confirm(\'این فیش حذف شود؟\')">';
				wp_nonce_field( 'rkspb_pay' );
				echo '<input type="hidden" name="action" value="rkspb_pay_delete"><input type="hidden" name="id" value="' . esc_attr( $r['id'] ) . '">';
				echo '<button class="button button-small button-link-delete">حذف</button></form>';
			} else {
				echo '—';
			}
			echo '</td></tr>';
			if ( $r['note'] ) {
				echo '<tr><td></td><td colspan="7" style="color:#555">' . nl2br( esc_html( $r['note'] ) ) . '</td></tr>';
			}
		}
		echo '</tbody></table>';
		echo '</div>';
	}
}

/* ==========================================================================
 * ثبت‌نام مستقیم توسط مشاور فروش + حق‌الزحمه از روی فیش تأییدشده
 *
 * تصمیم امیر: مسیر لید از پرتال برداشته می‌شود — افزونه‌ی توزیع لید روال
 * خودش را دارد. مشاور فروش مستقیم در داشبورد دانش‌آموز را ثبت‌نام می‌کند و
 * همان‌جا فیش را ثبت می‌کند؛ فیش برای مدیر می‌رود و فقط بعدِ تأیید مدیر،
 * سهم مشاور فروش حساب می‌شود.
 *
 * پس مبنای حق‌الزحمه دیگر won_amount لید نیست، مجموع فیش‌های approved ای
 * است که خودِ آن مشاور فروش ثبت کرده.
 * ========================================================================== */

if ( ! function_exists( 'rkspb_assign_mentor_to_student' ) ) {
	/**
	 * اتصال دانش‌آموز به مشاور تحصیلی؛ اتصال فعال قبلی بسته می‌شود.
	 *
	 * @return true|WP_Error
	 */
	function rkspb_assign_mentor_to_student( $sid, $mentor_row_id ) {
		global $wpdb;
		$sid           = (int) $sid;
		$mentor_row_id = (int) $mentor_row_id;
		if ( ! $mentor_row_id ) { return true; }
		if ( ! rkspb_cols_meta( 'mentors' ) || ! rkspb_cols_meta( 'assignments' ) ) {
			return new WP_Error( 'rkspb_no_table', 'جدول مشاوران یا اتصال‌ها پیدا نشد.', array( 'status' => 500 ) );
		}
		$mt   = rkspb_table_name( 'mentors' );
		$mrow = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$mt}` WHERE id = %d", $mentor_row_id ), ARRAY_A );
		if ( ! $mrow ) { return new WP_Error( 'rkspb_bad', 'مشاور تحصیلی پیدا نشد.', array( 'status' => 400 ) ); }
		$mentor = rkspb_mentor_assign_value( $mrow );

		$at   = rkspb_table_name( 'assignments' );
		$meta = rkspb_cols_meta( 'assignments' );
		$cur  = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$at}` WHERE student_id = %d" . rkspb_active_assignment_sql() . ' ORDER BY id DESC LIMIT 1', $sid ), ARRAY_A );
		if ( $cur && (int) $cur['mentor_id'] === (int) $mentor ) { return true; }
		if ( $cur && isset( $meta['status'] ) ) {
			$close = array( 'status' => rkspb_fit_value( 'assignments', 'status', 'ended', array( 'ended', 'inactive' ) ) );
			if ( isset( $meta['ended_at'] ) ) { $close['ended_at'] = rkspb_now(); }
			$wpdb->update( $at, $close, array( 'id' => (int) $cur['id'] ) );
		}
		$aid = rkspb_insert_row( 'assignments', array(
			'student_id'  => $sid,
			'mentor_id'   => $mentor,
			'assigned_at' => rkspb_now(),
			'status'      => rkspb_fit_value( 'assignments', 'status', 'active', array( 'active' ) ),
		) );
		return is_wp_error( $aid ) ? $aid : true;
	}
}

if ( ! function_exists( 'rkspb_sales_register_student' ) ) {
	/**
	 * ثبت‌نام مستقیم دانش‌آموز توسط مشاور فروش — بدون لید.
	 * اگر شماره پیگیری داده شود، فیش هم همان‌جا ثبت و به‌نام همین مشاور فروش
	 * نوشته می‌شود و در انتظار تأیید مدیر می‌ماند.
	 *
	 * @return array|WP_Error
	 */
	function rkspb_sales_register_student( $p, $user_id = 0 ) {
		global $wpdb;
		$user_id = $user_id ? (int) $user_id : get_current_user_id();
		$name    = sanitize_text_field( isset( $p['name'] ) ? $p['name'] : '' );
		$mobile  = rkspb_normalize_mobile( isset( $p['mobile'] ) ? $p['mobile'] : '' );
		$grade   = sanitize_text_field( isset( $p['grade'] ) ? $p['grade'] : '' );
		$field   = sanitize_text_field( isset( $p['field'] ) ? $p['field'] : '' );
		$plan    = sanitize_text_field( isset( $p['plan_name'] ) ? $p['plan_name'] : '' );
		$price   = rkspb_money_input( isset( $p['price'] ) ? $p['price'] : 0 );
		$months  = max( 1, min( 24, (int) rkspb_latin_digits( isset( $p['months'] ) ? $p['months'] : 1 ) ) );
		$mentor  = isset( $p['mentor_id'] ) ? (int) $p['mentor_id'] : 0;
		$ref     = mb_substr( sanitize_text_field( rkspb_latin_digits( isset( $p['ref'] ) ? $p['ref'] : '' ) ), 0, 64 );

		$errors = array();
		if ( '' === $name ) { $errors[] = 'نام دانش‌آموز لازم است.'; }
		if ( 11 !== strlen( $mobile ) || '09' !== substr( $mobile, 0, 2 ) ) { $errors[] = 'موبایل دانش‌آموز معتبر نیست.'; }
		if ( '' === $grade ) { $errors[] = 'پایه را انتخاب کنید.'; }
		if ( '' === $plan ) { $errors[] = 'نام طرح لازم است.'; }
		if ( $price <= 0 ) { $errors[] = 'مبلغ طرح را وارد کنید.'; }
		if ( $errors ) { return new WP_Error( 'rkspb_bad', implode( ' ', $errors ), array( 'status' => 400 ) ); }

		// ۱) پرونده‌ی دانش‌آموز
		$student = rkspb_student_by_mobile( $mobile );
		$created = false;
		if ( ! $student ) {
			$user = rkspb_find_user_by_mobile( $mobile );
			if ( $user && ! in_array( 'rksp_student', (array) $user->roles, true ) ) {
				return new WP_Error( 'rkspb_bad', 'این شماره متعلق به حساب دیگری (مشاور یا کارمند) است.', array( 'status' => 409 ) );
			}
			$made = rkspb_create_student( array(
				'name'     => $name,
				'mobile'   => $mobile,
				'password' => '',
				'grade'    => $grade,
				'field'    => $field,
			) );
			if ( empty( $made['ok'] ) ) {
				return new WP_Error( 'rkspb_bad', implode( ' ', (array) $made['errors'] ), array( 'status' => 400 ) );
			}
			$created = true;
			$student = rkspb_student_by_mobile( $mobile );
			if ( ! $student ) {
				return new WP_Error( 'rkspb_db', 'پرونده‌ی دانش‌آموز ساخته نشد: ' . $wpdb->last_error, array( 'status' => 500 ) );
			}
		}
		$sid = (int) $student['id'];

		// ۲) مشاور تحصیلی، اگر انتخاب شده باشد
		if ( $mentor ) {
			$ok = rkspb_assign_mentor_to_student( $sid, $mentor );
			if ( is_wp_error( $ok ) ) { return $ok; }
		}

		// ۳) طرح
		$plan_id = rkspb_create_plan_for_student( $sid, array(
			'plan_name'  => $plan,
			'price'      => $price,
			'months'     => $months,
			'start_date' => isset( $p['start_date'] ) ? $p['start_date'] : '',
		) );
		if ( is_wp_error( $plan_id ) ) { return $plan_id; }

		// ۴) فیش، اگر همان لحظه داده شده باشد
		$payment = null;
		if ( '' !== $ref ) {
			$payment = rkspb_record_payment( array(
				'student_id' => $sid,
				'plan_id'    => (int) $plan_id,
				'amount'     => isset( $p['amount'] ) && '' !== $p['amount'] ? $p['amount'] : $price,
				'ref'        => $ref,
				'paid_at'    => isset( $p['paid_at'] ) ? $p['paid_at'] : current_time( 'Y-m-d' ),
				'note'       => isset( $p['note'] ) ? $p['note'] : '',
			), $user_id );
			if ( is_wp_error( $payment ) ) { return $payment; }
		}

		return array(
			'ok'              => true,
			'student_id'      => $sid,
			'account_created' => $created,
			'plan_id'         => (int) $plan_id,
			'payment'         => $payment,
		);
	}
}

/* ------------------------------------------------- حق‌الزحمه از روی فیش -- */

if ( ! function_exists( 'rkspb_sales_payments_summary' ) ) {
	/**
	 * جمع فیش‌های هر مشاور فروش در بازه. مبنا تاریخ واریز است نه تاریخ ثبت،
	 * چون ماه مالی با تاریخ پول عوض می‌شود نه با اینکه کِی تایپ شده.
	 */
	function rkspb_sales_payments_summary( $user_id, $from, $to ) {
		global $wpdb;
		$out = array(
			'approved_count'  => 0,
			'approved_amount' => 0,
			'pending_count'   => 0,
			'pending_amount'  => 0,
		);
		if ( '1.9.0' !== get_option( 'rkspb_pay_schema' ) ) { return $out; }
		$pt = rkspb_payments_table();
		$r  = $wpdb->get_row( $wpdb->prepare(
			"SELECT
				SUM(status = 'approved') a_n,
				COALESCE(SUM(CASE WHEN status = 'approved' THEN amount ELSE 0 END),0) a_s,
				SUM(status = 'pending') p_n,
				COALESCE(SUM(CASE WHEN status = 'pending' THEN amount ELSE 0 END),0) p_s
			 FROM `{$pt}` WHERE created_by = %d AND paid_at BETWEEN %s AND %s",
			(int) $user_id, $from, $to
		), ARRAY_A );
		if ( $r ) {
			$out['approved_count']  = (int) $r['a_n'];
			$out['approved_amount'] = (int) $r['a_s'];
			$out['pending_count']   = (int) $r['p_n'];
			$out['pending_amount']  = (int) $r['p_s'];
		}
		return $out;
	}
}

if ( ! function_exists( 'rkspb_sales_rows_from_payments' ) ) {
	function rkspb_sales_rows_from_payments( $from, $to ) {
		$rows = array();
		foreach ( rkspb_sales_users() as $u ) {
			$sum = rkspb_sales_payments_summary( $u->ID, $from, $to );
			$pct = rkspb_share_percent( $u->ID, true );
			$rows[] = array(
				'user_id'         => (int) $u->ID,
				'name'            => $u->display_name,
				'mobile'          => rkspb_user_mobile( $u ),
				'paused'          => (bool) get_user_meta( $u->ID, 'rkspb_sales_paused', true ),
				'approved_count'  => $sum['approved_count'],
				'approved_amount' => $sum['approved_amount'],
				'pending_count'   => $sum['pending_count'],
				'pending_amount'  => $sum['pending_amount'],
				'percent'         => $pct,
				'payout'          => (int) round( $sum['approved_amount'] * $pct / 100 ),
			);
		}
		return $rows;
	}
}

/* ------------------------------------------- خبر دادن به مدیر بعد از ثبت -- */

add_action( 'rkspb_payment_recorded', function ( $payment ) {
	if ( ! is_array( $payment ) ) { return; }
	if ( function_exists( 'rkspb_notify_settings' ) ) {
		$cfg = rkspb_notify_settings();
		if ( '' === $cfg['email'] ) { return; }
	}
	$to = get_option( 'admin_email' );
	if ( ! $to ) { return; }
	$body = sprintf(
		"فیش تازه‌ای ثبت شد و منتظر تأیید شماست.\n\nدانش‌آموز: %s (%s)\nمبلغ: %s تومان\nشماره پیگیری: %s\nتاریخ واریز: %s\nثبت‌کننده: %s\n\nتأیید یا رد: %s",
		$payment['student_name'],
		$payment['mobile'],
		number_format( $payment['amount'] ),
		$payment['ref'],
		function_exists( 'rkspb_jdate' ) ? rkspb_jdate( $payment['paid_at'], false ) : $payment['paid_at'],
		$payment['created_name'],
		admin_url( 'admin.php?page=rkspb_pay' )
	);
	wp_mail( $to, 'فیش تازه در انتظار تأیید — راه کنکور', $body );
}, 10, 1 );

/* ------------------------------------------------------------------ روت‌ها -- */

add_action( 'rest_api_init', function () {

	$sales_or_admin = function () {
		return is_user_logged_in() && ( rkspb_can( 'students.register' ) || rkspb_can( 'payments.view' ) );
	};

	// ثبت‌نام مستقیم دانش‌آموز توسط فروش — جایگزین مسیر لید
	register_rest_route( RKSPB_NS, '/sales/register-student', array(
		'methods'             => 'POST',
		'permission_callback' => $sales_or_admin,
		'callback'            => function ( $req ) {
			$in = (array) $req->get_json_params();
			if ( ! $in ) { $in = (array) $req->get_body_params(); }
			$out = rkspb_sales_register_student( $in, get_current_user_id() );
			if ( is_wp_error( $out ) ) { return $out; }
			return rest_ensure_response( $out );
		},
	) );

	// کارنامه‌ی خود مشاور فروش: فیش‌ها و سهمش
	register_rest_route( RKSPB_NS, '/sales/summary', array(
		'methods'             => 'GET',
		'permission_callback' => $sales_or_admin,
		'callback'            => function ( $req ) {
			$user = wp_get_current_user();
			$to   = rkspb_clean_date( (string) $req->get_param( 'to' ) );
			$from = rkspb_clean_date( (string) $req->get_param( 'from' ) );
			if ( '' === $to ) { $to = current_time( 'Y-m-d' ); }
			if ( '' === $from ) { $from = gmdate( 'Y-m-d', strtotime( $to . ' 12:00:00 UTC -30 days' ) ); }
			$sum = rkspb_sales_payments_summary( $user->ID, $from, $to );
			$pct = rkspb_share_percent( $user->ID, true );
			return rest_ensure_response( array(
				'from'     => $from,
				'to'       => $to,
				'percent'  => $pct,
				'payout'   => (int) round( $sum['approved_amount'] * $pct / 100 ),
				'summary'  => $sum,
				'payments' => rkspb_payments_query( array( 'mine_for' => $user->ID, 'limit' => 100 ) ),
			) );
		},
	) );
}, 12 );

/* ==========================================================================
 * تسویه‌ی ماهانه و اطلاع‌رسانی — نسخه‌ی ۱.۸.۰
 *
 * دو کمبودی که پر می‌شود:
 * ۱) سهم‌ها لحظه‌ای حساب می‌شد؛ عوض‌کردن درصدِ یک نفر، عدد ماه‌های گذشته را
 *    هم عوض می‌کرد و هیچ‌جا ثبت نبود که واقعاً چه پرداخت شده. حالا ماه
 *    «بسته» می‌شود: عددها عکس گرفته و قفل می‌شوند.
 * ۲) اطلاع فیش فقط ایمیل بود که روی هاست ایرانی مرتب گم می‌شود. پیامک هم
 *    اضافه شد — با الگوی جداگانه که باید در پنل فراز تأیید شده باشد.
 * ========================================================================== */

if ( ! function_exists( 'rkspb_payouts_table' ) ) {
	function rkspb_payouts_table() {
		global $wpdb;
		return $wpdb->prefix . 'rkspb_payouts';
	}
}

if ( ! function_exists( 'rkspb_upgrade_payouts_schema' ) ) {
	function rkspb_upgrade_payouts_schema() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$t       = rkspb_payouts_table();
		dbDelta( "CREATE TABLE {$t} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			period varchar(10) NOT NULL DEFAULT '',
			from_date date NULL DEFAULT NULL,
			to_date date NULL DEFAULT NULL,
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			role varchar(20) NOT NULL DEFAULT '',
			name varchar(190) NOT NULL DEFAULT '',
			base_amount bigint(20) unsigned NOT NULL DEFAULT 0,
			percent decimal(5,2) NOT NULL DEFAULT 0,
			payout bigint(20) unsigned NOT NULL DEFAULT 0,
			detail varchar(500) NOT NULL DEFAULT '',
			status varchar(20) NOT NULL DEFAULT 'locked',
			locked_by bigint(20) unsigned NOT NULL DEFAULT 0,
			locked_at datetime NULL DEFAULT NULL,
			paid_at datetime NULL DEFAULT NULL,
			note varchar(500) NOT NULL DEFAULT '',
			PRIMARY KEY  (id),
			KEY period (period),
			KEY user_period (user_id,period)
		) {$charset};" );
		$ok = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $t ) ) === $t;
		if ( $ok ) { update_option( 'rkspb_payouts_schema', '1.8.0', false ); }
		return $ok;
	}
}

add_action( 'init', function () {
	if ( '1.8.0' === get_option( 'rkspb_payouts_schema' ) ) { return; }
	if ( get_transient( 'rkspb_payouts_try' ) ) { return; }
	set_transient( 'rkspb_payouts_try', 1, HOUR_IN_SECONDS );
	rkspb_upgrade_payouts_schema();
}, 7 );

if ( ! function_exists( 'rkspb_payouts_ready' ) ) {
	function rkspb_payouts_ready() {
		return '1.8.0' === get_option( 'rkspb_payouts_schema' ) ? true : rkspb_upgrade_payouts_schema();
	}
}

if ( ! function_exists( 'rkspb_period_from_date' ) ) {
	/** «1405-06» از یک تاریخ میلادی. */
	function rkspb_period_from_date( $ymd ) {
		$p = explode( '-', substr( (string) $ymd, 0, 10 ) );
		if ( 3 !== count( $p ) ) { return ''; }
		list( $jy, $jm ) = rkspb_gregorian_to_jalali( (int) $p[0], (int) $p[1], (int) $p[2] );
		return sprintf( '%04d-%02d', $jy, $jm );
	}
}

if ( ! function_exists( 'rkspb_settlement_rows' ) ) {
	/** ردیف‌های قفل‌شده‌ی یک ماه. */
	function rkspb_settlement_rows( $period ) {
		global $wpdb;
		if ( ! rkspb_payouts_ready() ) { return array(); }
		$t    = rkspb_payouts_table();
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE period = %s ORDER BY role ASC, payout DESC", $period ), ARRAY_A );
		$out  = array();
		foreach ( (array) $rows as $r ) {
			$out[] = array(
				'id'          => (int) $r['id'],
				'period'      => (string) $r['period'],
				'user_id'     => (int) $r['user_id'],
				'role'        => (string) $r['role'],
				'name'        => (string) $r['name'],
				'base_amount' => (int) $r['base_amount'],
				'percent'     => (float) $r['percent'],
				'payout'      => (int) $r['payout'],
				'detail'      => (string) $r['detail'],
				'status'      => (string) $r['status'],
				'locked_at'   => (string) $r['locked_at'],
				'locked_name' => rkspb_user_label( $r['locked_by'] ),
				'paid_at'     => (string) $r['paid_at'],
				'note'        => (string) $r['note'],
			);
		}
		return $out;
	}
}

if ( ! function_exists( 'rkspb_close_settlement' ) ) {
	/**
	 * بستن ماه: از عددهای همین لحظه عکس می‌گیرد و قفلشان می‌کند.
	 * بعد از این، عوض‌کردن درصدِ کسی روی این ماه اثری ندارد.
	 *
	 * @return array|WP_Error
	 */
	function rkspb_close_settlement( $period, $from, $to ) {
		global $wpdb;
		if ( ! rkspb_is_admin_user() ) {
			return new WP_Error( 'rkspb_role', 'بستن ماه فقط با مدیر است.', array( 'status' => 403 ) );
		}
		if ( ! rkspb_payouts_ready() ) {
			return new WP_Error( 'rkspb_schema', 'جدول تسویه ساخته نشد.', array( 'status' => 500 ) );
		}
		$from = rkspb_clean_date( $from );
		$to   = rkspb_clean_date( $to );
		if ( '' === $from || '' === $to ) {
			return new WP_Error( 'rkspb_bad', 'بازه‌ی ماه درست نیست.', array( 'status' => 400 ) );
		}
		if ( '' === $period ) { $period = rkspb_period_from_date( $from ); }

		$t = rkspb_payouts_table();
		if ( (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$t}` WHERE period = %s", $period ) ) ) {
			return new WP_Error( 'rkspb_locked', 'این ماه قبلاً بسته شده است.', array( 'status' => 409 ) );
		}
		// ماهی که هنوز تمام نشده بسته نمی‌شود؛ فیش دیرثبت‌شده جا می‌ماند.
		if ( $to >= current_time( 'Y-m-d' ) ) {
			return new WP_Error( 'rkspb_early', 'این ماه هنوز تمام نشده؛ بعد از پایان ماه ببندید.', array( 'status' => 400 ) );
		}
		$pending = (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM `" . rkspb_payments_table() . "` WHERE status = 'pending' AND paid_at BETWEEN %s AND %s",
			$from, $to
		) );
		if ( $pending ) {
			return new WP_Error( 'rkspb_pending', $pending . ' فیش این ماه هنوز تأیید یا رد نشده؛ اول تکلیفشان را روشن کنید.', array( 'status' => 409 ) );
		}

		$data = rkspb_admin_dashboard( $from, $to );
		$now  = rkspb_now();
		$uid  = get_current_user_id();
		$n    = 0;

		foreach ( (array) $data['mentors'] as $m ) {
			if ( empty( $m['user_id'] ) || null === $m['percent'] || (int) $m['base_amount'] <= 0 ) { continue; }
			$wpdb->insert( $t, array(
				'period'      => $period,
				'from_date'   => $from,
				'to_date'     => $to,
				'user_id'     => (int) $m['user_id'],
				'role'        => 'mentor',
				'name'        => $m['name'],
				'base_amount' => (int) $m['base_amount'],
				'percent'     => (float) $m['percent'],
				'payout'      => (int) $m['payout'],
				'detail'      => sprintf( '%d دانش‌آموز فعال، %d با طرح پرداختی', (int) $m['active_students'], (int) $m['paying_students'] ),
				'status'      => 'locked',
				'locked_by'   => $uid,
				'locked_at'   => $now,
			) );
			$n++;
		}

		foreach ( (array) $data['sales'] as $sm ) {
			if ( empty( $sm['user_id'] ) || (int) $sm['approved_amount'] <= 0 ) { continue; }
			$wpdb->insert( $t, array(
				'period'      => $period,
				'from_date'   => $from,
				'to_date'     => $to,
				'user_id'     => (int) $sm['user_id'],
				'role'        => 'sales',
				'name'        => $sm['name'],
				'base_amount' => (int) $sm['approved_amount'],
				'percent'     => (float) $sm['percent'],
				'payout'      => (int) $sm['payout'],
				'detail'      => sprintf( '%d فیش تأییدشده', (int) $sm['approved_count'] ),
				'status'      => 'locked',
				'locked_by'   => $uid,
				'locked_at'   => $now,
			) );
			$n++;
		}

		if ( ! $n ) {
			return new WP_Error( 'rkspb_empty', 'برای این ماه هیچ سهمی قابل ثبت نبود.', array( 'status' => 400 ) );
		}
		return array( 'ok' => true, 'period' => $period, 'count' => $n, 'rows' => rkspb_settlement_rows( $period ) );
	}
}

/* ------------------------------------------------------- پیامک اطلاع فیش -- */

if ( ! function_exists( 'rkspb_notify_settings' ) ) {
	function rkspb_notify_settings() {
		$own = get_option( 'rkspb_notify_settings', array() );
		if ( ! is_array( $own ) ) { $own = array(); }
		return array(
			'pay_pattern' => isset( $own['pay_pattern'] ) ? (string) $own['pay_pattern'] : '',
			'pay_vars'    => isset( $own['pay_vars'] ) && '' !== $own['pay_vars'] ? (string) $own['pay_vars'] : 'name,amount',
			'mobiles'     => isset( $own['mobiles'] ) ? (string) $own['mobiles'] : '',
			'email'       => isset( $own['email'] ) ? (string) $own['email'] : '1',
		);
	}
}

if ( ! function_exists( 'rkspb_notify_mobiles' ) ) {
	/** شماره‌هایی که باید خبر فیش را بگیرند؛ خالی یعنی موبایل حساب مدیر. */
	function rkspb_notify_mobiles() {
		$cfg  = rkspb_notify_settings();
		$out  = array();
		foreach ( preg_split( '/[,\s،]+/', $cfg['mobiles'] ) as $m ) {
			$m = rkspb_normalize_mobile( $m );
			if ( 11 === strlen( $m ) ) { $out[] = $m; }
		}
		if ( ! $out ) {
			foreach ( get_users( array( 'role' => 'administrator', 'number' => 3 ) ) as $u ) {
				$m = rkspb_normalize_mobile( get_user_meta( $u->ID, 'rksp_mobile', true ) );
				if ( 11 === strlen( $m ) ) { $out[] = $m; }
			}
		}
		return array_unique( $out );
	}
}

if ( ! function_exists( 'rkspb_send_pattern_custom' ) ) {
	/**
	 * پیامک الگویی با متغیرهای دلخواه. الگو باید در پنل فراز تأیید شده باشد.
	 *
	 * @param array $attributes نام متغیر => مقدار
	 * @return array{ok:bool, status:int, body:string}
	 */
	function rkspb_send_pattern_custom( $mobile, $pattern, $attributes ) {
		$cfg = rkspb_sms_settings();
		if ( empty( $cfg['api_key'] ) || empty( $cfg['line_number'] ) || '' === $pattern ) {
			return array( 'ok' => false, 'status' => 0, 'body' => 'sms not configured' );
		}
		$payload = wp_json_encode( array(
			'code'          => $pattern,
			'recipient'     => $mobile,
			'line_number'   => $cfg['line_number'],
			'number_format' => 'english',
			'attributes'    => (object) $attributes,
		) );

		$variants = rkspb_auth_variants( $cfg['api_key'] );
		$cached   = get_option( 'rkspb_sms_scheme', '' );
		if ( $cached && isset( $variants[ $cached ] ) ) {
			$variants = array_merge( array( $cached => $variants[ $cached ] ), $variants );
		}
		$last = array( 'ok' => false, 'status' => 0, 'body' => '' );
		foreach ( $variants as $name => $headers ) {
			$res = wp_remote_post( RKSPB_PATTERN_URL, array(
				'timeout' => 20,
				'headers' => array_merge( array( 'Content-Type' => 'application/json' ), $headers ),
				'body'    => $payload,
			) );
			if ( is_wp_error( $res ) ) {
				$last = array( 'ok' => false, 'status' => 0, 'body' => $res->get_error_message() );
				continue;
			}
			$status = (int) wp_remote_retrieve_response_code( $res );
			$last   = array( 'ok' => ( $status >= 200 && $status < 300 ), 'status' => $status, 'body' => substr( (string) wp_remote_retrieve_body( $res ), 0, 300 ) );
			if ( $last['ok'] ) {
				update_option( 'rkspb_sms_scheme', $name, false );
				return $last;
			}
			if ( 401 !== $status && 403 !== $status ) { return $last; }
		}
		return $last;
	}
}

add_action( 'rkspb_payment_recorded', function ( $payment ) {
	if ( ! is_array( $payment ) ) { return; }
	$cfg = rkspb_notify_settings();
	if ( '' === $cfg['pay_pattern'] ) { return; }

	// نام متغیرهای الگو را خود مدیر وارد می‌کند؛ ترتیبشان: نام، مبلغ، شماره پیگیری.
	$names  = array_values( array_filter( array_map( 'trim', explode( ',', $cfg['pay_vars'] ) ) ) );
	$values = array(
		$payment['student_name'] ? $payment['student_name'] : 'دانش‌آموز',
		number_format( (int) $payment['amount'] ),
		(string) $payment['ref'],
	);
	$attrs = array();
	foreach ( $names as $i => $key ) {
		$attrs[ $key ] = isset( $values[ $i ] ) ? $values[ $i ] : '';
	}
	if ( ! $attrs ) { return; }

	foreach ( rkspb_notify_mobiles() as $mobile ) {
		$sent = rkspb_send_pattern_custom( $mobile, $cfg['pay_pattern'], $attrs );
		if ( ! $sent['ok'] ) {
			update_option( 'rkspb_notify_last_error', gmdate( 'c' ) . ' — ' . $sent['status'] . ' ' . $sent['body'], false );
		}
	}
}, 20, 1 );

/* ------------------------------------------------------------------ روت‌ها -- */

add_action( 'rest_api_init', function () {

	$admin_only = function () { return is_user_logged_in() && rkspb_is_admin_user(); };

	register_rest_route( RKSPB_NS, '/admin/settlements', array(
		'methods'             => 'GET',
		'permission_callback' => $admin_only,
		'callback'            => function ( $req ) {
			$period = sanitize_text_field( (string) $req->get_param( 'period' ) );
			return rest_ensure_response( array(
				'period' => $period,
				'rows'   => $period ? rkspb_settlement_rows( $period ) : array(),
			) );
		},
	) );

	register_rest_route( RKSPB_NS, '/admin/settlements/close', array(
		'methods'             => 'POST',
		'permission_callback' => $admin_only,
		'callback'            => function ( $req ) {
			$in  = (array) $req->get_json_params();
			if ( ! $in ) { $in = (array) $req->get_body_params(); }
			$out = rkspb_close_settlement(
				isset( $in['period'] ) ? sanitize_text_field( $in['period'] ) : '',
				isset( $in['from'] ) ? $in['from'] : '',
				isset( $in['to'] ) ? $in['to'] : ''
			);
			if ( is_wp_error( $out ) ) { return $out; }
			return rest_ensure_response( $out );
		},
	) );

	register_rest_route( RKSPB_NS, '/admin/settlements/(?P<id>\d+)/paid', array(
		'methods'             => 'POST',
		'permission_callback' => $admin_only,
		'callback'            => function ( $req ) {
			global $wpdb;
			if ( ! rkspb_payouts_ready() ) { return new WP_Error( 'rkspb_schema', 'جدول تسویه پیدا نشد.', array( 'status' => 500 ) ); }
			$t   = rkspb_payouts_table();
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d", (int) $req['id'] ), ARRAY_A );
			if ( ! $row ) { return new WP_Error( 'rkspb_404', 'ردیف پیدا نشد.', array( 'status' => 404 ) ); }
			$in   = (array) $req->get_json_params();
			$paid = ! isset( $in['paid'] ) || $in['paid'];
			$wpdb->update( $t, array(
				'status'  => $paid ? 'paid' : 'locked',
				'paid_at' => $paid ? rkspb_now() : null,
				'note'    => isset( $in['note'] ) ? mb_substr( sanitize_text_field( $in['note'] ), 0, 500 ) : $row['note'],
			), array( 'id' => (int) $row['id'] ) );
			return rest_ensure_response( array( 'ok' => true, 'rows' => rkspb_settlement_rows( $row['period'] ) ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/admin/settlements/reopen', array(
		'methods'             => 'POST',
		'permission_callback' => $admin_only,
		'callback'            => function ( $req ) {
			global $wpdb;
			if ( ! rkspb_payouts_ready() ) { return new WP_Error( 'rkspb_schema', 'جدول تسویه پیدا نشد.', array( 'status' => 500 ) ); }
			$in     = (array) $req->get_json_params();
			$period = isset( $in['period'] ) ? sanitize_text_field( $in['period'] ) : '';
			if ( '' === $period ) { return new WP_Error( 'rkspb_bad', 'ماه مشخص نیست.', array( 'status' => 400 ) ); }
			$t = rkspb_payouts_table();
			// ردیفی که پرداخت شده باز نمی‌شود؛ وگرنه سابقه‌ی پرداخت گم می‌شود.
			if ( (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$t}` WHERE period = %s AND status = 'paid'", $period ) ) ) {
				return new WP_Error( 'rkspb_paid', 'در این ماه پرداخت ثبت شده و باز نمی‌شود.', array( 'status' => 409 ) );
			}
			$wpdb->delete( $t, array( 'period' => $period ) );
			return rest_ensure_response( array( 'ok' => true, 'period' => $period ) );
		},
	) );
}, 13 );

/* --------------------------------------------- تنظیمات اطلاع‌رسانی در وردپرس */

add_action( 'admin_post_rkspb_notify_save', function () {
	check_admin_referer( 'rkspb_pay' );
	if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'دسترسی ندارید.' ); }
	$in = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- بالاتر بررسی شد
	update_option( 'rkspb_notify_settings', array(
		'pay_pattern' => isset( $in['pay_pattern'] ) ? sanitize_text_field( $in['pay_pattern'] ) : '',
		'pay_vars'    => isset( $in['pay_vars'] ) ? sanitize_text_field( $in['pay_vars'] ) : 'name,amount',
		'mobiles'     => isset( $in['mobiles'] ) ? sanitize_text_field( $in['mobiles'] ) : '',
		'email'       => empty( $in['email'] ) ? '' : '1',
	), false );
	rkspb_pay_redirect( true, 'تنظیمات اطلاع‌رسانی ذخیره شد.' );
} );

/* ==========================================================================
 * پرداخت جزئی (قسط) و دفتر تغییرات — نسخه‌ی ۱.۹.۰
 * ========================================================================== */

if ( ! function_exists( 'rkspb_plan_paid' ) ) {
	/** جمع فیش‌های تأییدشده‌ی یک طرح. */
	function rkspb_plan_paid( $plan_id ) {
		global $wpdb;
		$plan_id = (int) $plan_id;
		if ( ! $plan_id || '1.9.0' !== get_option( 'rkspb_pay_schema' ) ) { return 0; }
		$pt = rkspb_payments_table();
		return (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COALESCE(SUM(amount),0) FROM `{$pt}` WHERE plan_id = %d AND status = 'approved'",
			$plan_id
		) );
	}
}

if ( ! function_exists( 'rkspb_plan_payment_count' ) ) {
	/** تعداد فیش‌های ثبت‌شده‌ی یک طرح، صرف‌نظر از وضعیتشان. */
	function rkspb_plan_payment_count( $plan_id ) {
		global $wpdb;
		$plan_id = (int) $plan_id;
		if ( ! $plan_id || '1.9.0' !== get_option( 'rkspb_pay_schema' ) ) { return 0; }
		$pt = rkspb_payments_table();
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$pt}` WHERE plan_id = %d", $plan_id ) );
	}
}

if ( ! function_exists( 'rkspb_active_plan_id' ) ) {
	/** شناسه‌ی طرح فعال دانش‌آموز، برای چسباندن فیشی که طرح همراهش نیامده. */
	function rkspb_active_plan_id( $sid ) {
		global $wpdb;
		if ( ! rkspb_cols_meta( 'plans' ) || ! rkspb_pick( 'plans', array( 'student_id' ) ) ) { return 0; }
		$pt    = rkspb_table_name( 'plans' );
		$order = rkspb_pick( 'plans', array( 'status' ) ) ? "(status = 'active') DESC, id DESC" : 'id DESC';
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM `{$pt}` WHERE student_id = %d ORDER BY {$order} LIMIT 1", (int) $sid ) );
	}
}

/* ---------------------------------------------------------- دفتر تغییرات -- */

if ( ! function_exists( 'rkspb_audit_table' ) ) {
	function rkspb_audit_table() {
		global $wpdb;
		return $wpdb->prefix . 'rkspb_audit';
	}
}

if ( ! function_exists( 'rkspb_upgrade_audit_schema' ) ) {
	function rkspb_upgrade_audit_schema() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$t       = rkspb_audit_table();
		dbDelta( "CREATE TABLE {$t} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			action varchar(30) NOT NULL DEFAULT '',
			table_slug varchar(40) NOT NULL DEFAULT '',
			row_id varchar(64) NOT NULL DEFAULT '',
			changes text NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY created (created_at),
			KEY target (table_slug,row_id)
		) {$charset};" );
		$ok = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $t ) ) === $t;
		if ( $ok ) { update_option( 'rkspb_audit_schema', '1.9.0', false ); }
		return $ok;
	}
}

add_action( 'init', function () {
	if ( '1.9.0' === get_option( 'rkspb_audit_schema' ) ) { return; }
	if ( get_transient( 'rkspb_audit_try' ) ) { return; }
	set_transient( 'rkspb_audit_try', 1, HOUR_IN_SECONDS );
	rkspb_upgrade_audit_schema();
}, 8 );

if ( ! function_exists( 'rkspb_audit_log' ) ) {
	/**
	 * ثبت یک تغییر دستی. جایی که پول هست، باید معلوم باشد چه کسی چه چیزی را
	 * کِی عوض کرده؛ تا حالا ویرایش مبلغ طرح هیچ ردی نمی‌گذاشت.
	 */
	function rkspb_audit_log( $action, $table_slug, $row_id, $changes ) {
		global $wpdb;
		if ( '1.9.0' !== get_option( 'rkspb_audit_schema' ) && ! rkspb_upgrade_audit_schema() ) { return; }
		$wpdb->insert( rkspb_audit_table(), array(
			'user_id'    => get_current_user_id(),
			'action'     => substr( (string) $action, 0, 30 ),
			'table_slug' => substr( (string) $table_slug, 0, 40 ),
			'row_id'     => substr( (string) $row_id, 0, 64 ),
			'changes'    => is_string( $changes ) ? $changes : wp_json_encode( $changes, JSON_UNESCAPED_UNICODE ),
			'created_at' => rkspb_now(),
		) );
	}
}

if ( ! function_exists( 'rkspb_audit_rows' ) ) {
	function rkspb_audit_rows( $limit = 100, $slug = '' ) {
		global $wpdb;
		if ( '1.9.0' !== get_option( 'rkspb_audit_schema' ) ) { return array(); }
		$t     = rkspb_audit_table();
		$limit = max( 1, min( 500, (int) $limit ) );
		if ( $slug ) {
			return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE table_slug = %s ORDER BY id DESC LIMIT {$limit}", $slug ), ARRAY_A );
		}
		return (array) $wpdb->get_results( "SELECT * FROM `{$t}` ORDER BY id DESC LIMIT {$limit}", ARRAY_A );
	}
}

/* ==========================================================================
 * نقش‌های مدیریتی و خروجی اکسل — نسخه‌ی ۲.۱.۰
 *
 * دو مدیر سرگروه: مدیر فروش تیم فروش و فیش‌ها را می‌چرخاند، مدیر مشاوره
 * تیم تحصیلی و اتصال‌ها را. سه کلید مالی — تعیین درصد، بستن ماه، ثبت
 * پرداخت — فقط دست مدیر اصلی می‌ماند، چون لنگرِ درستی حساب‌هاست.
 * ========================================================================== */

if ( ! function_exists( 'rkspb_upgrade_roles' ) ) {
	function rkspb_upgrade_roles() {
		if ( ! get_role( 'rksp_sales_manager' ) ) {
			add_role( 'rksp_sales_manager', 'مدیر فروش', array( 'read' => true ) );
		}
		if ( ! get_role( 'rksp_mentor_manager' ) ) {
			add_role( 'rksp_mentor_manager', 'مدیر مشاوره', array( 'read' => true ) );
		}
		update_option( 'rkspb_roles_schema', '2.1.0', false );
		return true;
	}
}

add_action( 'init', function () {
	if ( '2.1.0' === get_option( 'rkspb_roles_schema' ) ) { return; }
	rkspb_upgrade_roles();
}, 5 );

if ( ! function_exists( 'rkspb_user_kind' ) ) {
	/** نقش کارکردی کاربر: admin | sales_manager | mentor_manager | sales | mentor | student | '' */
	function rkspb_user_kind( $user = null ) {
		$user = $user ? $user : wp_get_current_user();
		if ( ! $user || ! $user->ID ) { return ''; }
		if ( user_can( $user, 'manage_options' ) ) { return 'admin'; }
		$roles = (array) $user->roles;
		foreach ( array( 'rksp_sales_manager' => 'sales_manager', 'rksp_mentor_manager' => 'mentor_manager', 'rksp_sales' => 'sales', 'rksp_mentor' => 'mentor', 'rksp_student' => 'student' ) as $wp => $kind ) {
			if ( in_array( $wp, $roles, true ) ) { return $kind; }
		}
		return '';
	}
}

if ( ! function_exists( 'rkspb_can' ) ) {
	/**
	 * تنها مرجع دسترسی. هر روت تازه باید از همین بپرسد، نه از rkspb_is_admin_user.
	 *
	 * @param string $what payments.view|payments.decide|sales.manage|students.register|
	 *                     mentor.assign|apps.approve|money.rates|money.close|money.view
	 */
	function rkspb_can( $what, $user = null ) {
		$kind = rkspb_user_kind( $user );
		if ( 'admin' === $kind ) { return true; }

		$map = array(
			'sales_manager'  => array( 'payments.view', 'payments.decide', 'sales.manage', 'students.register', 'mentor.assign' ),
			'mentor_manager' => array( 'mentor.assign', 'apps.approve', 'students.view' ),
			'sales'          => array( 'payments.view', 'students.register' ),
		);
		if ( ! isset( $map[ $kind ] ) ) { return false; }
		if ( in_array( $kind, array( 'sales', 'sales_manager' ), true ) && ! rkspb_sales_may_work( $user ) ) { return false; }
		return in_array( $what, $map[ $kind ], true );
	}
}

if ( ! function_exists( 'rkspb_is_manager' ) ) {
	function rkspb_is_manager( $user = null ) {
		return in_array( rkspb_user_kind( $user ), array( 'admin', 'sales_manager', 'mentor_manager' ), true );
	}
}

/* ---------------------------------------------------------- خروجی اکسل -- */

if ( ! function_exists( 'rkspb_csv_out' ) ) {
	/**
	 * CSV با BOM یونیکد. اکسل بدون BOM فارسی را جویده نشان می‌دهد.
	 * عمداً CSV و نه xlsx: بدون کتابخانه، و اکسل مستقیم بازش می‌کند.
	 */
	function rkspb_csv_out( $filename, $head, $rows ) {
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '-' . rkspb_jdate( current_time( 'Y-m-d' ), false ) . '.csv"' );
		echo "\xEF\xBB\xBF";
		$out = fopen( 'php://output', 'w' );
		fputcsv( $out, $head );
		foreach ( $rows as $r ) { fputcsv( $out, $r ); }
		fclose( $out );
		exit;
	}
}

add_action( 'admin_post_rkspb_export', function () {
	check_admin_referer( 'rkspb_pay' );
	if ( ! rkspb_can( 'payments.view' ) && ! rkspb_is_manager() ) { wp_die( 'دسترسی ندارید.' ); }
	global $wpdb;
	$what = isset( $_GET['what'] ) ? sanitize_key( wp_unslash( $_GET['what'] ) ) : 'payments'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- بالاتر بررسی شد

	if ( 'payments' === $what ) {
		$rows = array();
		foreach ( rkspb_payments_query( array( 'limit' => 300 ) ) as $p ) {
			$st   = rkspb_payment_statuses();
			$rows[] = array(
				$p['id'],
				$p['student_name'],
				$p['mobile'],
				$p['amount'],
				$p['ref'],
				rkspb_jdate( $p['paid_at'], false ),
				isset( $st[ $p['status'] ] ) ? $st[ $p['status'] ] : $p['status'],
				$p['created_name'],
				$p['decided_name'],
				$p['decided_at'] ? rkspb_jdate( substr( $p['decided_at'], 0, 10 ), false ) : '',
			);
		}
		rkspb_csv_out( 'fish', array( 'شناسه', 'دانش‌آموز', 'موبایل', 'مبلغ', 'شماره پیگیری', 'تاریخ واریز', 'وضعیت', 'ثبت‌کننده', 'تأییدکننده', 'تاریخ تصمیم' ), $rows );
	}

	if ( 'settlements' === $what ) {
		if ( ! rkspb_is_admin_user() ) { wp_die( 'دسترسی ندارید.' ); }
		$period = isset( $_GET['period'] ) ? sanitize_text_field( wp_unslash( $_GET['period'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$t      = rkspb_payouts_table();
		$src    = $period ? rkspb_settlement_rows( $period ) : array_map( 'rkspb_payout_out_row', (array) $wpdb->get_results( "SELECT * FROM `{$t}` ORDER BY period DESC, id DESC LIMIT 500", ARRAY_A ) );
		$rows   = array();
		foreach ( $src as $r ) {
			$rows[] = array(
				$r['period'],
				$r['name'],
				'sales' === $r['role'] ? 'مشاور فروش' : 'مشاور تحصیلی',
				$r['base_amount'],
				$r['percent'],
				$r['payout'],
				'paid' === $r['status'] ? 'پرداخت شد' : 'پرداخت نشده',
				$r['detail'],
			);
		}
		rkspb_csv_out( 'tasvieh', array( 'ماه', 'نفر', 'نقش', 'مبنا', 'درصد', 'سهم', 'وضعیت', 'توضیح' ), $rows );
	}

	if ( 'students' === $what ) {
		$rows = array();
		$st   = rkspb_table_name( 'students' );
		foreach ( (array) $wpdb->get_results( "SELECT * FROM `{$st}` ORDER BY id DESC LIMIT 1000", ARRAY_A ) as $s ) {
			$plan = rkspb_plan_info( null, (int) $s['id'] );
			$rows[] = array(
				$s['id'],
				rkspb_student_name( $s ),
				rkspb_student_mobile( $s ),
				isset( $s['grade'] ) ? $s['grade'] : '',
				isset( $s['field'] ) ? $s['field'] : '',
				$plan['name'],
				$plan['start'] ? rkspb_jdate( $plan['start'], false ) : '',
				$plan['end'] ? rkspb_jdate( $plan['end'], false ) : '',
				null === $plan['days_left'] ? '' : $plan['days_left'],
				$plan['price'],
				$plan['paid'],
				$plan['due'],
			);
		}
		rkspb_csv_out( 'daneshamuzan', array( 'شناسه', 'نام', 'موبایل', 'پایه', 'رشته', 'طرح', 'شروع', 'پایان', 'روز مانده', 'مبلغ طرح', 'پرداخت‌شده', 'مانده' ), $rows );
	}
	wp_die( 'نوع خروجی نامعتبر است.' );
} );

if ( ! function_exists( 'rkspb_payout_out_row' ) ) {
	function rkspb_payout_out_row( $r ) {
		return array(
			'period'      => (string) $r['period'],
			'name'        => (string) $r['name'],
			'role'        => (string) $r['role'],
			'base_amount' => (int) $r['base_amount'],
			'percent'     => (float) $r['percent'],
			'payout'      => (int) $r['payout'],
			'status'      => (string) $r['status'],
			'detail'      => (string) $r['detail'],
		);
	}
}

/* ==========================================================================
 * گزارش مالی: اندپوینت فقط‌خواندنی + ایمیل خودکار — نسخه‌ی ۲.۲.۰
 *
 * دو مصرف دارد: اپ بیرونی (AI Studio) که زنده می‌خواندش، و ایمیل دوره‌ای
 * که حتی اگر کسی هیچ‌وقت داشبورد را باز نکند، عددها جایی بیرون از هاست
 * بایگانی می‌شوند. توکن جداست از توکن ورود و فقط خواندن می‌دهد.
 * ========================================================================== */

if ( ! function_exists( 'rkspb_report_token' ) ) {
	function rkspb_report_token( $regenerate = false ) {
		$t = get_option( 'rkspb_report_token' );
		if ( $regenerate || ! $t ) {
			$t = wp_generate_password( 40, false, false );
			update_option( 'rkspb_report_token', $t, false );
		}
		return $t;
	}
}

if ( ! function_exists( 'rkspb_finance_report' ) ) {
	/**
	 * عکس مالی یک بازه. همان اعدادی که داشبورد نشان می‌دهد، بدون رابط.
	 */
	function rkspb_finance_report( $from, $to ) {
		global $wpdb;
		$from = rkspb_clean_date( $from );
		$to   = rkspb_clean_date( $to );
		if ( '' === $to ) { $to = current_time( 'Y-m-d' ); }
		if ( '' === $from ) { $from = gmdate( 'Y-m-d', strtotime( $to . ' 12:00:00 UTC -30 days' ) ); }

		$data   = rkspb_admin_dashboard( $from, $to );
		$period = rkspb_period_from_date( $from );

		$sales = array();
		foreach ( (array) $data['sales'] as $r ) {
			$sales[] = array(
				'name'            => $r['name'],
				'approved_count'  => (int) $r['approved_count'],
				'approved_amount' => (int) $r['approved_amount'],
				'pending_count'   => (int) $r['pending_count'],
				'pending_amount'  => (int) $r['pending_amount'],
				'percent'         => $r['percent'],
				'payout'          => (int) $r['payout'],
			);
		}
		$mentors = array();
		foreach ( (array) $data['mentors'] as $r ) {
			$mentors[] = array(
				'name'             => $r['name'],
				'active_students'  => (int) $r['active_students'],
				'paying_students'  => (int) $r['paying_students'],
				'partial_students' => isset( $r['partial_students'] ) ? (int) $r['partial_students'] : 0,
				'base_amount'      => (int) $r['base_amount'],
				'percent'          => $r['percent'],
				'payout'           => (int) $r['payout'],
			);
		}

		$pt      = rkspb_payments_table();
		$totals  = $wpdb->get_row( $wpdb->prepare(
			"SELECT
				COALESCE(SUM(CASE WHEN status='approved' THEN amount ELSE 0 END),0) approved,
				SUM(status='approved') approved_n,
				COALESCE(SUM(CASE WHEN status='pending' THEN amount ELSE 0 END),0) pending,
				SUM(status='pending') pending_n
			 FROM `{$pt}` WHERE paid_at BETWEEN %s AND %s",
			$from, $to
		), ARRAY_A );

		$payments = array();
		foreach ( rkspb_payments_query( array( 'limit' => 300 ) ) as $p ) {
			if ( $p['paid_at'] < $from || $p['paid_at'] > $to ) { continue; }
			$payments[] = array(
				'id'      => $p['id'],
				'student' => $p['student_name'],
				'mobile'  => $p['mobile'],
				'amount'  => $p['amount'],
				'ref'     => $p['ref'],
				'paid_at' => $p['paid_at'],
				'paid_at_jalali' => rkspb_jdate( $p['paid_at'], false ),
				'status'  => $p['status'],
				'by'      => $p['created_name'],
			);
		}

		// مانده‌ی وصول‌نشده‌ی طرح‌های فعال
		$unpaid = array();
		foreach ( array_merge( (array) $data['students']['expiring'], (array) $data['students']['no_mentor'] ) as $st ) {
			$plan = rkspb_plan_info( null, (int) $st['student_id'] );
			if ( $plan['due'] > 0 ) {
				$unpaid[ $st['student_id'] ] = array(
					'student' => $st['name'],
					'mobile'  => $st['mobile'],
					'plan'    => $plan['name'],
					'price'   => $plan['price'],
					'paid'    => $plan['paid'],
					'due'     => $plan['due'],
				);
			}
		}

		return array(
			'site'         => get_bloginfo( 'name' ),
			'generated_at' => current_time( 'c' ),
			'period'       => $period,
			'from'         => $from,
			'to'           => $to,
			'from_jalali'  => rkspb_jdate( $from, false ),
			'to_jalali'    => rkspb_jdate( $to, false ),
			'totals'       => array(
				'approved_amount' => (int) $totals['approved'],
				'approved_count'  => (int) $totals['approved_n'],
				'pending_amount'  => (int) $totals['pending'],
				'pending_count'   => (int) $totals['pending_n'],
				'sales_payout'    => array_sum( wp_list_pluck( $sales, 'payout' ) ),
				'mentor_payout'   => array_sum( wp_list_pluck( $mentors, 'payout' ) ),
			),
			'sales'        => $sales,
			'mentors'      => $mentors,
			'payments'     => $payments,
			'unpaid'       => array_values( $unpaid ),
			'settlements'  => $period ? rkspb_settlement_rows( $period ) : array(),
			'students'     => array(
				'total'    => (int) $data['students']['total'],
				'expiring' => count( (array) $data['students']['expiring'] ),
			),
		);
	}
}

add_action( 'rest_api_init', function () {
	register_rest_route( RKSPB_NS, '/report/finance', array(
		'methods'             => 'GET',
		'permission_callback' => '__return_true',
		'callback'            => function ( $req ) {
			$gate = rkspb_throttle_check( 'report', 'token', 10 );
			if ( is_wp_error( $gate ) ) { return $gate; }
			$given = (string) $req->get_param( 'token' );
			$real  = rkspb_report_token();
			if ( '' === $given || ! hash_equals( $real, $given ) ) {
				rkspb_throttle_fail( 'report', 'token' );
				return new WP_Error( 'rkspb_token', 'توکن گزارش معتبر نیست.', array( 'status' => 401 ) );
			}
			$out = rkspb_finance_report( (string) $req->get_param( 'from' ), (string) $req->get_param( 'to' ) );
			$res = rest_ensure_response( $out );
			// فقط‌خواندنی و پشت توکن است، پس از هر مبدأیی قابل خواندن باشد.
			$res->header( 'Access-Control-Allow-Origin', '*' );
			return $res;
		},
	) );
}, 14 );

/* ------------------------------------------------- ایمیل خودکار دوره‌ای -- */

if ( ! function_exists( 'rkspb_report_settings' ) ) {
	function rkspb_report_settings() {
		$o = get_option( 'rkspb_report_settings', array() );
		if ( ! is_array( $o ) ) { $o = array(); }
		return array(
			'enabled' => isset( $o['enabled'] ) ? (string) $o['enabled'] : '',
			'every'   => isset( $o['every'] ) && 'monthly' === $o['every'] ? 'monthly' : 'weekly',
			'to'      => isset( $o['to'] ) ? (string) $o['to'] : '',
		);
	}
}

add_filter( 'cron_schedules', function ( $s ) {
	if ( ! isset( $s['rkspb_weekly'] ) ) {
		$s['rkspb_weekly'] = array( 'interval' => WEEK_IN_SECONDS, 'display' => 'هفتگی (راه کنکور)' );
	}
	return $s;
} );

add_action( 'init', function () {
	$cfg = rkspb_report_settings();
	$has = wp_next_scheduled( 'rkspb_send_finance_report' );
	if ( '' === $cfg['enabled'] ) {
		if ( $has ) { wp_unschedule_event( $has, 'rkspb_send_finance_report' ); }
		return;
	}
	if ( ! $has ) {
		wp_schedule_event( time() + 300, 'rkspb_weekly', 'rkspb_send_finance_report' );
	}
}, 20 );

add_action( 'rkspb_send_finance_report', 'rkspb_mail_finance_report' );

if ( ! function_exists( 'rkspb_mail_finance_report' ) ) {
	function rkspb_mail_finance_report() {
		$cfg = rkspb_report_settings();
		if ( '' === $cfg['enabled'] ) { return; }

		// ماهانه: فقط اگر از آخرین ارسال بیش از ۲۸ روز گذشته باشد
		if ( 'monthly' === $cfg['every'] ) {
			$last = (int) get_option( 'rkspb_report_last', 0 );
			if ( $last && ( time() - $last ) < 28 * DAY_IN_SECONDS ) { return; }
		}

		$to = array();
		foreach ( preg_split( '/[,\s،]+/', $cfg['to'] ) as $m ) {
			if ( is_email( $m ) ) { $to[] = $m; }
		}
		if ( ! $to ) { $to = array( get_option( 'admin_email' ) ); }

		$days = 'monthly' === $cfg['every'] ? 30 : 7;
		$end  = current_time( 'Y-m-d' );
		$rep  = rkspb_finance_report( gmdate( 'Y-m-d', strtotime( $end . ' 12:00:00 UTC -' . $days . ' days' ) ), $end );
		$t    = $rep['totals'];

		$lines   = array();
		$lines[] = 'گزارش مالی راه کنکور — از ' . $rep['from_jalali'] . ' تا ' . $rep['to_jalali'];
		$lines[] = '';
		$lines[] = 'فیش تأییدشده: ' . number_format( $t['approved_amount'] ) . ' تومان (' . $t['approved_count'] . ' فیش)';
		$lines[] = 'در انتظار تأیید: ' . number_format( $t['pending_amount'] ) . ' تومان (' . $t['pending_count'] . ' فیش)';
		$lines[] = 'سهم مشاوران فروش: ' . number_format( $t['sales_payout'] ) . ' تومان';
		$lines[] = 'سهم مشاوران تحصیلی: ' . number_format( $t['mentor_payout'] ) . ' تومان';
		$lines[] = '';
		if ( $rep['unpaid'] ) {
			$lines[] = 'مانده‌ی وصول‌نشده:';
			foreach ( $rep['unpaid'] as $u ) {
				$lines[] = '  - ' . $u['student'] . ' (' . $u['mobile'] . '): ' . number_format( $u['due'] ) . ' تومان';
			}
			$lines[] = '';
		}
		if ( $t['pending_count'] > 0 ) {
			$lines[] = 'توجه: ' . $t['pending_count'] . ' فیش هنوز تأیید یا رد نشده. تا تعیین تکلیفشان، ماه بسته نمی‌شود.';
			$lines[] = '';
		}
		$lines[] = 'فایل CSV پیوست است. این ایمیل خودکار فرستاده می‌شود.';

		// پیوست CSV
		$up   = wp_upload_dir();
		$dir  = trailingslashit( $up['basedir'] ) . 'rkspb-reports';
		wp_mkdir_p( $dir );
		$file = $dir . '/finance-' . gmdate( 'Ymd-His' ) . '.csv';
		$fh   = fopen( $file, 'w' );
		if ( $fh ) {
			fwrite( $fh, "\xEF\xBB\xBF" );
			fputcsv( $fh, array( 'دانش‌آموز', 'موبایل', 'مبلغ', 'شماره پیگیری', 'تاریخ واریز', 'وضعیت', 'ثبت‌کننده' ) );
			foreach ( $rep['payments'] as $p ) {
				fputcsv( $fh, array( $p['student'], $p['mobile'], $p['amount'], $p['ref'], $p['paid_at_jalali'], $p['status'], $p['by'] ) );
			}
			fclose( $fh );
		}

		wp_mail(
			$to,
			'گزارش مالی راه کنکور — ' . $rep['to_jalali'],
			implode( "\n", $lines ),
			array( 'Content-Type: text/plain; charset=UTF-8' ),
			file_exists( $file ) ? array( $file ) : array()
		);
		update_option( 'rkspb_report_last', time(), false );

		// بایگانی را تمیز نگه دار: بیش از ۱۲ فایل نماند
		$old = glob( $dir . '/finance-*.csv' );
		if ( is_array( $old ) && count( $old ) > 12 ) {
			sort( $old );
			foreach ( array_slice( $old, 0, count( $old ) - 12 ) as $f ) { @unlink( $f ); } // phpcs:ignore
		}
	}
}

add_action( 'admin_post_rkspb_report_save', function () {
	check_admin_referer( 'rkspb_pay' );
	if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'دسترسی ندارید.' ); }
	$in = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- بالاتر بررسی شد
	update_option( 'rkspb_report_settings', array(
		'enabled' => empty( $in['enabled'] ) ? '' : '1',
		'every'   => ( isset( $in['every'] ) && 'monthly' === $in['every'] ) ? 'monthly' : 'weekly',
		'to'      => isset( $in['to'] ) ? sanitize_text_field( $in['to'] ) : '',
	), false );
	$has = wp_next_scheduled( 'rkspb_send_finance_report' );
	if ( $has ) { wp_unschedule_event( $has, 'rkspb_send_finance_report' ); }
	if ( ! empty( $in['enabled'] ) ) { wp_schedule_event( time() + 300, 'rkspb_weekly', 'rkspb_send_finance_report' ); }
	if ( ! empty( $in['regen'] ) ) { rkspb_report_token( true ); }
	if ( ! empty( $in['send_now'] ) ) { rkspb_mail_finance_report(); }
	rkspb_pay_redirect( true, 'تنظیمات گزارش ذخیره شد.' );
} );

/* ==========================================================================
 * تیکت پشتیبانی — نسخه‌ی ۲.۳.۰
 *
 * دانش‌آموز تیکت می‌زند و گیرنده را انتخاب می‌کند: مشاور تحصیلی یا مدیر.
 * گفت‌وگو داخل همان تیکت ادامه پیدا می‌کند.
 *
 * دو قاعده‌ی عمدی:
 * ۱) تیکتِ روبه‌مشاور را مدیر هم می‌بیند. اینجا بچه‌های زیر ۱۸ سال با بزرگسال
 *    حرف می‌زنند؛ کانال خصوصیِ نادیده نمی‌سازیم. این قاعده باید به هر دو طرف
 *    گفته شود، و در متن پنل هم نوشته شده.
 * ۲) تیکتِ روبه‌مدیر را مشاور اصلاً نمی‌بیند، وگرنه هیچ دانش‌آموزی از مشاورش
 *    شکایت نمی‌کند.
 * ========================================================================== */

if ( ! function_exists( 'rkspb_tickets_table' ) ) {
	function rkspb_tickets_table() {
		global $wpdb;
		return $wpdb->prefix . 'rkspb_tickets';
	}
}

if ( ! function_exists( 'rkspb_ticket_msgs_table' ) ) {
	function rkspb_ticket_msgs_table() {
		global $wpdb;
		return $wpdb->prefix . 'rkspb_ticket_msgs';
	}
}

if ( ! function_exists( 'rkspb_upgrade_tickets_schema' ) ) {
	function rkspb_upgrade_tickets_schema() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$t       = rkspb_tickets_table();
		$m       = rkspb_ticket_msgs_table();
		dbDelta( "CREATE TABLE {$t} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			student_id bigint(20) unsigned NOT NULL DEFAULT 0,
			target varchar(10) NOT NULL DEFAULT 'mentor',
			kind varchar(10) NOT NULL DEFAULT 'student',
			opener_id bigint(20) unsigned NOT NULL DEFAULT 0,
			to_user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			subject varchar(190) NOT NULL DEFAULT '',
			status varchar(20) NOT NULL DEFAULT 'open',
			created_at datetime NOT NULL,
			last_at datetime NOT NULL,
			last_role varchar(20) NOT NULL DEFAULT 'student',
			PRIMARY KEY  (id),
			KEY student (student_id),
			KEY target_status (target,status),
			KEY last_at (last_at)
		) {$charset};" );
		dbDelta( "CREATE TABLE {$m} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ticket_id bigint(20) unsigned NOT NULL DEFAULT 0,
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			role varchar(20) NOT NULL DEFAULT '',
			body text NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY ticket (ticket_id,id)
		) {$charset};" );
		$ok = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $t ) ) === $t
			&& $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $m ) ) === $m;
		if ( $ok ) { update_option( 'rkspb_tickets_schema', '2.4.0', false ); }
		return $ok;
	}
}

add_action( 'init', function () {
	if ( '2.4.0' === get_option( 'rkspb_tickets_schema' ) ) { return; }
	if ( get_transient( 'rkspb_tickets_try' ) ) { return; }
	set_transient( 'rkspb_tickets_try', 1, HOUR_IN_SECONDS );
	rkspb_upgrade_tickets_schema();
}, 9 );

if ( ! function_exists( 'rkspb_tickets_ready' ) ) {
	function rkspb_tickets_ready() {
		return '2.4.0' === get_option( 'rkspb_tickets_schema' ) ? true : rkspb_upgrade_tickets_schema();
	}
}

if ( ! function_exists( 'rkspb_ticket_actor' ) ) {
	/**
	 * نقش کاربر در نظام تیکت و دامنه‌ی دیدش.
	 *
	 * @return array{role:string, student_id:int, student_ids:int[]}|WP_Error
	 */
	function rkspb_ticket_actor() {
		$user = wp_get_current_user();
		if ( ! $user || ! $user->ID ) {
			return new WP_Error( 'rkspb_auth', 'ابتدا وارد شوید.', array( 'status' => 401 ) );
		}
		if ( rkspb_is_manager( $user ) ) {
			return array( 'role' => 'admin', 'kind' => rkspb_user_kind( $user ), 'user_id' => (int) $user->ID, 'student_id' => 0, 'student_ids' => array() );
		}
		if ( in_array( 'rksp_sales', (array) $user->roles, true ) ) {
			return array( 'role' => 'sales', 'kind' => 'sales', 'user_id' => (int) $user->ID, 'student_id' => 0, 'student_ids' => array() );
		}
		if ( in_array( 'rksp_mentor', (array) $user->roles, true ) ) {
			$ctx = rkspb_ctx_mentor();
			if ( is_wp_error( $ctx ) ) { return $ctx; }
			$ids = array_keys( rkspb_mentor_links( $ctx['keys'] ) );
			return array( 'role' => 'mentor', 'kind' => 'mentor', 'user_id' => (int) $user->ID, 'student_id' => 0, 'student_ids' => array_map( 'intval', $ids ) );
		}
		$ctx = rkspb_ctx_student();
		if ( is_wp_error( $ctx ) ) { return $ctx; }
		return array( 'role' => 'student', 'kind' => 'student', 'user_id' => (int) $user->ID, 'student_id' => (int) $ctx['row']['id'], 'student_ids' => array() );
	}
}

if ( ! function_exists( 'rkspb_ticket_can_see' ) ) {
	function rkspb_ticket_can_see( $ticket, $actor ) {
		$kind = isset( $ticket['kind'] ) ? $ticket['kind'] : 'student';
		$uid  = isset( $actor['user_id'] ) ? (int) $actor['user_id'] : 0;

		// گفت‌وگوی کارکنان: طرفین، و مدیر اصلی که ناظر همه است.
		if ( 'staff' === $kind ) {
			if ( (int) $ticket['opener_id'] === $uid ) { return true; }
			if ( (int) $ticket['to_user_id'] === $uid ) { return true; }
			// تیکتی که کارمند «به مدیریت» زده، برای مدیر و سرگروه‌ها باز است.
			if ( 0 === (int) $ticket['to_user_id'] && 'admin' === $actor['role'] ) { return true; }
			return rkspb_is_admin_user();
		}

		if ( 'admin' === $actor['role'] ) { return true; }
		if ( 'student' === $actor['role'] ) { return (int) $ticket['student_id'] === $actor['student_id']; }
		if ( 'mentor' === $actor['role'] ) {
			return 'mentor' === $ticket['target'] && in_array( (int) $ticket['student_id'], $actor['student_ids'], true );
		}
		return false;
	}
}

if ( ! function_exists( 'rkspb_ticket_out' ) ) {
	function rkspb_ticket_out( $r, $with_messages = false ) {
		global $wpdb;
		$st  = rkspb_student_by_id( $r['student_id'] );
		$out = array(
			'id'         => (int) $r['id'],
			'student_id' => (int) $r['student_id'],
			'student'    => $st ? rkspb_student_name( $st ) : '',
			'mobile'     => $st ? rkspb_student_mobile( $st ) : '',
			'target'     => (string) $r['target'],
			'kind'       => isset( $r['kind'] ) ? (string) $r['kind'] : 'student',
			'opener'     => rkspb_user_label( isset( $r['opener_id'] ) ? $r['opener_id'] : 0 ),
			'to_user_id' => isset( $r['to_user_id'] ) ? (int) $r['to_user_id'] : 0,
			'to_name'    => ( isset( $r['to_user_id'] ) && $r['to_user_id'] ) ? rkspb_user_label( $r['to_user_id'] ) : 'مدیریت',
			'subject'    => (string) $r['subject'],
			'status'     => (string) $r['status'],
			'created_at' => (string) $r['created_at'],
			'last_at'    => (string) $r['last_at'],
			'last_role'  => (string) $r['last_role'],
			'waiting'    => ( 'open' === $r['status'] && 'student' === $r['last_role'] ),
		);
		// چند ساعت است که منتظر جواب مانده
		$out['waiting_hours'] = $out['waiting']
			? max( 0, (int) round( ( strtotime( current_time( 'mysql' ) ) - strtotime( $r['last_at'] ) ) / HOUR_IN_SECONDS ) )
			: 0;
		if ( $with_messages ) {
			$mt   = rkspb_ticket_msgs_table();
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$mt}` WHERE ticket_id = %d ORDER BY id ASC LIMIT 200", (int) $r['id'] ), ARRAY_A );
			$msgs = array();
			foreach ( (array) $rows as $m ) {
				$msgs[] = array(
					'id'         => (int) $m['id'],
					'role'       => (string) $m['role'],
					'name'       => rkspb_user_label( $m['user_id'] ),
					'body'       => (string) $m['body'],
					'created_at' => (string) $m['created_at'],
				);
			}
			$out['messages'] = $msgs;
		}
		return $out;
	}
}

if ( ! function_exists( 'rkspb_tickets_for' ) ) {
	function rkspb_tickets_for( $actor, $limit = 100 ) {
		global $wpdb;
		if ( ! rkspb_tickets_ready() ) { return array(); }
		$t     = rkspb_tickets_table();
		$limit = max( 1, min( 200, (int) $limit ) );
		$order = " ORDER BY (status = 'open' AND last_role = 'student') DESC, last_at DESC LIMIT {$limit}";

		$uid = isset( $actor['user_id'] ) ? (int) $actor['user_id'] : 0;
		if ( 'student' === $actor['role'] ) {
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE kind = 'student' AND student_id = %d" . $order, $actor['student_id'] ), ARRAY_A );
		} elseif ( 'mentor' === $actor['role'] ) {
			$in   = $actor['student_ids'] ? implode( ',', array_map( 'intval', $actor['student_ids'] ) ) : '0';
			$rows = $wpdb->get_results( $wpdb->prepare(
				"SELECT * FROM `{$t}` WHERE ( kind = 'student' AND target = 'mentor' AND student_id IN ({$in}) )"
				. " OR ( kind = 'staff' AND ( opener_id = %d OR to_user_id = %d ) )" . $order,
				$uid, $uid
			), ARRAY_A );
		} elseif ( 'sales' === $actor['role'] ) {
			$rows = $wpdb->get_results( $wpdb->prepare(
				"SELECT * FROM `{$t}` WHERE kind = 'staff' AND ( opener_id = %d OR to_user_id = %d )" . $order,
				$uid, $uid
			), ARRAY_A );
		} elseif ( rkspb_is_admin_user() ) {
			$rows = $wpdb->get_results( "SELECT * FROM `{$t}`" . $order, ARRAY_A );
		} else {
			// سرگروه: گفت‌وگوهای دانش‌آموزان، به‌علاوه‌ی تیکت‌های کارکنان که طرفش است یا به مدیریت زده شده
			$rows = $wpdb->get_results( $wpdb->prepare(
				"SELECT * FROM `{$t}` WHERE kind = 'student'"
				. " OR ( kind = 'staff' AND ( opener_id = %d OR to_user_id = %d OR to_user_id = 0 ) )" . $order,
				$uid, $uid
			), ARRAY_A );
		}
		return array_map( 'rkspb_ticket_out', (array) $rows );
	}
}

if ( ! function_exists( 'rkspb_tickets_waiting' ) ) {
	/** تیکت‌های بی‌جواب، برای نشان دادن کم‌کاری در داشبورد مدیر. */
	function rkspb_tickets_waiting( $hours = 24 ) {
		global $wpdb;
		if ( '2.4.0' !== get_option( 'rkspb_tickets_schema' ) ) { return array( 'total' => 0, 'overdue' => 0, 'rows' => array() ); }
		$t    = rkspb_tickets_table();
		$rows = $wpdb->get_results( "SELECT * FROM `{$t}` WHERE status = 'open' AND last_role = 'student' ORDER BY last_at ASC LIMIT 50", ARRAY_A );
		$out  = array();
		$over = 0;
		foreach ( (array) $rows as $r ) {
			$o = rkspb_ticket_out( $r );
			if ( $o['waiting_hours'] >= $hours ) { $over++; }
			$out[] = $o;
		}
		return array( 'total' => count( $out ), 'overdue' => $over, 'rows' => $out );
	}
}

add_action( 'rest_api_init', function () {

	$logged = function () { return is_user_logged_in(); };

	register_rest_route( RKSPB_NS, '/tickets', array(
		array(
			'methods'             => 'GET',
			'permission_callback' => $logged,
			'callback'            => function () {
				$actor = rkspb_ticket_actor();
				if ( is_wp_error( $actor ) ) { return $actor; }
				$rows = rkspb_tickets_for( $actor );
				return rest_ensure_response( array(
					'role'    => $actor['role'],
					'tickets' => $rows,
					'waiting' => count( array_filter( $rows, function ( $r ) { return $r['waiting']; } ) ),
				) );
			},
		),
		array(
			'methods'             => 'POST',
			'permission_callback' => $logged,
			'callback'            => function ( $req ) {
				global $wpdb;
				$actor = rkspb_ticket_actor();
				if ( is_wp_error( $actor ) ) { return $actor; }
				if ( ! rkspb_tickets_ready() ) { return new WP_Error( 'rkspb_schema', 'جدول تیکت ساخته نشد.', array( 'status' => 500 ) ); }
				$in      = (array) $req->get_json_params();
				$kind    = ( isset( $in['kind'] ) && 'staff' === $in['kind'] ) ? 'staff' : 'student';
				$subject = mb_substr( sanitize_text_field( isset( $in['subject'] ) ? $in['subject'] : '' ), 0, 190 );
				$body    = mb_substr( sanitize_textarea_field( isset( $in['body'] ) ? $in['body'] : '' ), 0, 4000 );
				if ( '' === $subject || '' === $body ) {
					return new WP_Error( 'rkspb_bad', 'موضوع و متن پیام لازم است.', array( 'status' => 400 ) );
				}
				$t   = rkspb_tickets_table();
				$now = rkspb_now();

				if ( 'student' === $actor['role'] ) {
					$kind   = 'student';
					$target = ( isset( $in['target'] ) && 'admin' === $in['target'] ) ? 'admin' : 'mentor';
					$open   = (int) $wpdb->get_var( $wpdb->prepare(
						"SELECT COUNT(*) FROM `{$t}` WHERE student_id = %d AND kind = 'student' AND status = 'open'",
						$actor['student_id']
					) );
					if ( $open >= 5 ) {
						return new WP_Error( 'rkspb_many', 'پنج گفت‌وگوی باز دارید؛ اول یکی را ببندید.', array( 'status' => 429 ) );
					}
					$row_data = array(
						'student_id' => $actor['student_id'],
						'target'     => $target,
						'kind'       => 'student',
						'opener_id'  => get_current_user_id(),
						'to_user_id' => 0,
					);
				} else {
					// کارکنان و مدیران: گفت‌وگوی کاری، هر دو جهت.
					$to = isset( $in['to_user_id'] ) ? (int) $in['to_user_id'] : 0;
					if ( 'admin' === $actor['role'] ) {
						if ( ! $to ) { return new WP_Error( 'rkspb_bad', 'گیرنده را انتخاب کنید.', array( 'status' => 400 ) ); }
						$u = get_user_by( 'id', $to );
						if ( ! $u || ! array_intersect( array( 'rksp_mentor', 'rksp_sales', 'rksp_sales_manager', 'rksp_mentor_manager' ), (array) $u->roles ) ) {
							return new WP_Error( 'rkspb_bad', 'گیرنده باید یکی از همکاران باشد.', array( 'status' => 400 ) );
						}
					} else {
						$to = 0; // کارمند فقط «به مدیریت» می‌نویسد
					}
					$row_data = array(
						'student_id' => isset( $in['about_student_id'] ) ? (int) $in['about_student_id'] : 0,
						'target'     => 'admin',
						'kind'       => 'staff',
						'opener_id'  => get_current_user_id(),
						'to_user_id' => $to,
					);
				}

				$wpdb->insert( $t, array_merge( $row_data, array(
					'subject'    => $subject,
					'status'     => 'open',
					'created_at' => $now,
					'last_at'    => $now,
					'last_role'  => $actor['role'],
				) ) );
				$tid = (int) $wpdb->insert_id;
				$wpdb->insert( rkspb_ticket_msgs_table(), array(
					'ticket_id'  => $tid,
					'user_id'    => get_current_user_id(),
					'role'       => $actor['role'],
					'body'       => $body,
					'created_at' => $now,
				) );
				$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d", $tid ), ARRAY_A );
				return rest_ensure_response( array( 'ok' => true, 'ticket' => rkspb_ticket_out( $row, true ) ) );
			},
		),
	) );

	register_rest_route( RKSPB_NS, '/tickets/recipients', array(
		'methods'             => 'GET',
		'permission_callback' => function () { return is_user_logged_in() && rkspb_is_manager(); },
		'callback'            => function () {
			$out = array();
			foreach ( array( 'rksp_mentor_manager' => 'مدیر مشاوره', 'rksp_sales_manager' => 'مدیر فروش', 'rksp_mentor' => 'مشاور تحصیلی', 'rksp_sales' => 'مشاور فروش' ) as $role => $label ) {
				foreach ( get_users( array( 'role' => $role, 'number' => 200 ) ) as $u ) {
					$out[] = array( 'user_id' => (int) $u->ID, 'name' => $u->display_name, 'role' => $label );
				}
			}
			return rest_ensure_response( array( 'recipients' => $out ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/tickets/(?P<id>\d+)', array(
		'methods'             => 'GET',
		'permission_callback' => $logged,
		'callback'            => function ( $req ) {
			global $wpdb;
			$actor = rkspb_ticket_actor();
			if ( is_wp_error( $actor ) ) { return $actor; }
			if ( ! rkspb_tickets_ready() ) { return new WP_Error( 'rkspb_schema', 'جدول تیکت پیدا نشد.', array( 'status' => 500 ) ); }
			$t   = rkspb_tickets_table();
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d", (int) $req['id'] ), ARRAY_A );
			if ( ! $row || ! rkspb_ticket_can_see( $row, $actor ) ) {
				return new WP_Error( 'rkspb_404', 'گفت‌وگو پیدا نشد.', array( 'status' => 404 ) );
			}
			if ( function_exists( 'rkspb_mark_ticket_read' ) ) { rkspb_mark_ticket_read( (int) $row['id'] ); }
			return rest_ensure_response( array( 'role' => $actor['role'], 'ticket' => rkspb_ticket_out( $row, true ) ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/tickets/(?P<id>\d+)/reply', array(
		'methods'             => 'POST',
		'permission_callback' => $logged,
		'callback'            => function ( $req ) {
			global $wpdb;
			$actor = rkspb_ticket_actor();
			if ( is_wp_error( $actor ) ) { return $actor; }
			if ( ! rkspb_tickets_ready() ) { return new WP_Error( 'rkspb_schema', 'جدول تیکت پیدا نشد.', array( 'status' => 500 ) ); }
			$t   = rkspb_tickets_table();
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d", (int) $req['id'] ), ARRAY_A );
			if ( ! $row || ! rkspb_ticket_can_see( $row, $actor ) ) {
				return new WP_Error( 'rkspb_404', 'گفت‌وگو پیدا نشد.', array( 'status' => 404 ) );
			}
			if ( 'closed' === $row['status'] ) {
				return new WP_Error( 'rkspb_closed', 'این گفت‌وگو بسته شده است.', array( 'status' => 409 ) );
			}
			$in   = (array) $req->get_json_params();
			$body = mb_substr( sanitize_textarea_field( isset( $in['body'] ) ? $in['body'] : '' ), 0, 4000 );
			if ( '' === $body ) { return new WP_Error( 'rkspb_bad', 'متن پیام خالی است.', array( 'status' => 400 ) ); }
			$now = rkspb_now();
			$wpdb->insert( rkspb_ticket_msgs_table(), array(
				'ticket_id'  => (int) $row['id'],
				'user_id'    => get_current_user_id(),
				'role'       => $actor['role'],
				'body'       => $body,
				'created_at' => $now,
			) );
			$wpdb->update( $t, array(
				'last_at'   => $now,
				'last_role' => $actor['role'],
				'status'    => 'open',
			), array( 'id' => (int) $row['id'] ) );
			if ( function_exists( 'rkspb_mark_ticket_read' ) ) { rkspb_mark_ticket_read( (int) $row['id'] ); }
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d", (int) $row['id'] ), ARRAY_A );
			return rest_ensure_response( array( 'ok' => true, 'ticket' => rkspb_ticket_out( $row, true ) ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/tickets/(?P<id>\d+)/close', array(
		'methods'             => 'POST',
		'permission_callback' => $logged,
		'callback'            => function ( $req ) {
			global $wpdb;
			$actor = rkspb_ticket_actor();
			if ( is_wp_error( $actor ) ) { return $actor; }
			$t   = rkspb_tickets_table();
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d", (int) $req['id'] ), ARRAY_A );
			if ( ! $row || ! rkspb_ticket_can_see( $row, $actor ) ) {
				return new WP_Error( 'rkspb_404', 'گفت‌وگو پیدا نشد.', array( 'status' => 404 ) );
			}
			$in     = (array) $req->get_json_params();
			$reopen = isset( $in['reopen'] ) && $in['reopen'];
			$wpdb->update( $t, array( 'status' => $reopen ? 'open' : 'closed' ), array( 'id' => (int) $row['id'] ) );
			return rest_ensure_response( array( 'ok' => true ) );
		},
	) );
}, 15 );

/* ==========================================================================
 * خوانده‌نشده‌ها — نسخه‌ی ۲.۵.۰
 *
 * تا حالا هیچ‌کس خبردار نمی‌شد پیامی آمده. برای هر کاربر نگه می‌داریم تا کدام
 * پیامِ هر گفت‌وگو را دیده؛ بقیه خوانده‌نشده حساب می‌شوند.
 * ========================================================================== */

if ( ! function_exists( 'rkspb_reads_table' ) ) {
	function rkspb_reads_table() {
		global $wpdb;
		return $wpdb->prefix . 'rkspb_ticket_reads';
	}
}

if ( ! function_exists( 'rkspb_upgrade_reads_schema' ) ) {
	function rkspb_upgrade_reads_schema() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$t       = rkspb_reads_table();
		dbDelta( "CREATE TABLE {$t} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			ticket_id bigint(20) unsigned NOT NULL DEFAULT 0,
			last_read_id bigint(20) unsigned NOT NULL DEFAULT 0,
			updated_at datetime NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY user_ticket (user_id,ticket_id)
		) {$charset};" );
		$ok = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $t ) ) === $t;
		if ( $ok ) { update_option( 'rkspb_reads_schema', '2.5.0', false ); }
		return $ok;
	}
}

add_action( 'init', function () {
	if ( '2.5.0' === get_option( 'rkspb_reads_schema' ) ) { return; }
	if ( get_transient( 'rkspb_reads_try' ) ) { return; }
	set_transient( 'rkspb_reads_try', 1, HOUR_IN_SECONDS );
	rkspb_upgrade_reads_schema();
}, 9 );

if ( ! function_exists( 'rkspb_reads_ready' ) ) {
	function rkspb_reads_ready() {
		return '2.5.0' === get_option( 'rkspb_reads_schema' ) ? true : rkspb_upgrade_reads_schema();
	}
}

if ( ! function_exists( 'rkspb_mark_ticket_read' ) ) {
	function rkspb_mark_ticket_read( $ticket_id, $user_id = 0 ) {
		global $wpdb;
		if ( ! rkspb_reads_ready() ) { return; }
		$user_id = $user_id ? (int) $user_id : get_current_user_id();
		if ( ! $user_id ) { return; }
		$mt   = rkspb_ticket_msgs_table();
		$last = (int) $wpdb->get_var( $wpdb->prepare( "SELECT MAX(id) FROM `{$mt}` WHERE ticket_id = %d", (int) $ticket_id ) );
		$wpdb->query( $wpdb->prepare(
			"INSERT INTO `" . rkspb_reads_table() . "` (user_id, ticket_id, last_read_id, updated_at)
			 VALUES (%d, %d, %d, %s)
			 ON DUPLICATE KEY UPDATE last_read_id = GREATEST(last_read_id, VALUES(last_read_id)), updated_at = VALUES(updated_at)",
			$user_id, (int) $ticket_id, $last, rkspb_now()
		) );
	}
}

if ( ! function_exists( 'rkspb_unread_for_actor' ) ) {
	/**
	 * گفت‌وگوهایی که پیام نادیده دارند. پیام خودِ کاربر خوانده‌نشده حساب نمی‌شود.
	 */
	function rkspb_unread_for_actor( $actor ) {
		global $wpdb;
		if ( ! rkspb_reads_ready() ) { return array( 'count' => 0, 'messages' => 0, 'items' => array() ); }
		$uid   = isset( $actor['user_id'] ) ? (int) $actor['user_id'] : 0;
		$rows  = rkspb_tickets_for( $actor, 60 );
		if ( ! $rows || ! $uid ) { return array( 'count' => 0, 'messages' => 0, 'items' => array() ); }

		$ids = array_map( function ( $r ) { return (int) $r['id']; }, $rows );
		$in  = implode( ',', $ids );
		$rt  = rkspb_reads_table();
		$mt  = rkspb_ticket_msgs_table();

		$seen = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT ticket_id, last_read_id FROM `{$rt}` WHERE user_id = %d AND ticket_id IN ({$in})", $uid ), ARRAY_A ) as $r ) {
			$seen[ (int) $r['ticket_id'] ] = (int) $r['last_read_id'];
		}

		$items = array();
		$total = 0;
		foreach ( $rows as $t ) {
			$after = isset( $seen[ $t['id'] ] ) ? $seen[ $t['id'] ] : 0;
			$new   = $wpdb->get_results( $wpdb->prepare(
				"SELECT id, user_id, role, body, created_at FROM `{$mt}` WHERE ticket_id = %d AND id > %d AND user_id <> %d ORDER BY id DESC LIMIT 5",
				$t['id'], $after, $uid
			), ARRAY_A );
			if ( ! $new ) { continue; }
			$total += count( $new );
			$last   = $new[0];
			$items[] = array(
				'ticket_id' => (int) $t['id'],
				'subject'   => $t['subject'],
				'kind'      => $t['kind'],
				'student'   => $t['student'],
				'from'      => rkspb_user_label( $last['user_id'] ),
				'role'      => (string) $last['role'],
				'preview'   => mb_substr( (string) $last['body'], 0, 90 ),
				'at'        => (string) $last['created_at'],
				'count'     => count( $new ),
			);
		}
		return array( 'count' => count( $items ), 'messages' => $total, 'items' => $items );
	}
}

add_action( 'rest_api_init', function () {
	register_rest_route( RKSPB_NS, '/tickets/unread', array(
		'methods'             => 'GET',
		'permission_callback' => function () { return is_user_logged_in(); },
		'callback'            => function () {
			$actor = rkspb_ticket_actor();
			if ( is_wp_error( $actor ) ) { return $actor; }
			return rest_ensure_response( rkspb_unread_for_actor( $actor ) );
		},
	) );

	register_rest_route( RKSPB_NS, '/tickets/(?P<id>\d+)/read', array(
		'methods'             => 'POST',
		'permission_callback' => function () { return is_user_logged_in(); },
		'callback'            => function ( $req ) {
			global $wpdb;
			$actor = rkspb_ticket_actor();
			if ( is_wp_error( $actor ) ) { return $actor; }
			$t   = rkspb_tickets_table();
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$t}` WHERE id = %d", (int) $req['id'] ), ARRAY_A );
			if ( ! $row || ! rkspb_ticket_can_see( $row, $actor ) ) {
				return new WP_Error( 'rkspb_404', 'گفت‌وگو پیدا نشد.', array( 'status' => 404 ) );
			}
			rkspb_mark_ticket_read( (int) $row['id'] );
			return rest_ensure_response( array( 'ok' => true ) );
		},
	) );
}, 16 );
