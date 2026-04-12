<?php
if(session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function require_login() {
    if(!isset($_SESSION['user_id'])) {
        $_SESSION['auth_error'] = 'Need to login to access this page.';
        header('Location: /index.php', true, 303);
        exit();
    }
}

function require_login_json() {
    if(!isset($_SESSION['user_id'])) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'Need to login to access']);
        exit();
    }
}

function is_admin_user() {
    return isset($_SESSION['is_admin']) && (int) $_SESSION['is_admin'] === 1;
}

function require_admin() {
    require_login();
    if(!is_admin_user()) {
        $_SESSION['auth_error'] = 'Admin access required.';
        header('Location: /list_page.php', true, 303);
        exit();
    }
}

function consume_auth_error() {
    $message = $_SESSION['auth_error'] ?? '';
    unset($_SESSION['auth_error']);
    return $message;
}

function logout_user() {
    $_SESSION = [];
    if(ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
}

function get_csrf_token() {
    if(empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token($token) {
    return isset($_SESSION['csrf_token']) && is_string($token) && hash_equals($_SESSION['csrf_token'], $token);
}

function enforce_csrf_or_redirect($token, $redirect) {
    if(!verify_csrf_token($token)) {
        $_SESSION['auth_error'] = 'Session expired. Please try again.';
        header('Location: ' . $redirect, true, 303);
        exit();
    }
}

function enforce_csrf_or_json($token) {
    if(!verify_csrf_token($token)) {
        http_response_code(419);
        echo json_encode(['success' => false, 'message' => 'Session expired. Refresh page and try again.']);
        exit();
    }
}
