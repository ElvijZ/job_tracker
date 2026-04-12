<?php
$success = "";
if (isset($_GET['registered'])) {
    $success = "Registration successful! Please log in.";
}
if (isset($_GET['reset'])) {
    $success = "If the account exists, password reset was processed. Please log in.";
}
include_once 'backend/auth.php';
include_once 'backend/rate_limit.php';

if(isset($_GET['logout']) && $_GET['logout'] === '1') {
    logout_user();
    header("Location: index.php?logged_out=1", true, 303);
    exit();
}

if (isset($_GET['logged_out'])) {
    $success = 'You have been logged out.';
}

$authError = consume_auth_error();
$loginError = '';
$csrfToken = get_csrf_token();
// Include the database connection file
include_once 'db/conn/connection.php';

if (isset($_POST['login-btn'])) {
    enforce_csrf_or_redirect($_POST['csrf_token'] ?? '', '/index.php');
    $loginIdentity = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');

    if($loginIdentity === '' || $password === '') {
        $loginError = 'Username/email and password are required.';
    } else {

    $ipKey = client_ip_address();
    $userIpKey = strtolower($loginIdentity) . '|' . $ipKey;
    $rateByIp = check_rate_limit($conn, 'login_ip', $ipKey, 25, 300, 300);
    $rateByUser = check_rate_limit($conn, 'login_user_ip', $userIpKey, 8, 300, 300);
    if(!$rateByIp['allowed'] || !$rateByUser['allowed']) {
        $loginError = 'Too many login attempts. Try again in a few minutes.';
    } else {

        // Prepare and execute the SQL statement to fetch the user
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = :identity OR email = :identity LIMIT 1");
        $stmt->bindParam(':identity', $loginIdentity);
        $stmt->execute();

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password_hash'])) {
            // Start a session and store user information
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['is_admin'] = (int) ($user['is_admin'] ?? 0);

            // Redirect admins to dashboard and regular users to their board
            if((int) ($_SESSION['is_admin'] ?? 0) === 1) {
                header("Location: admin.php", true, 303);
                exit();
            }

            header("Location: list_page.php", true, 303);
            exit();

        } else {
            $loginError = 'Invalid username or password.';
        }
    }
    }
}


?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Job Tracker</title>

    <link rel="stylesheet" href="style/login.css">
</head>

<body>
    <div class="login-container">
        <h1>Login to Job Tracker</h1>
        <form method="POST" action="index.php">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
            <?php if (!empty($success)): ?>
                <p style="color: green;"><?php echo $success; ?></p>
            <?php endif; ?>

            <?php if (!empty($authError)): ?>
                <p style="color: #b91c1c;"><?php echo htmlspecialchars($authError, ENT_QUOTES, 'UTF-8'); ?></p>
            <?php endif; ?>

            <?php if (!empty($loginError)): ?>
                <p style="color: #b91c1c;"><?php echo htmlspecialchars($loginError, ENT_QUOTES, 'UTF-8'); ?></p>
            <?php endif; ?>







            <div class="form-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button class="login-btn" id="login-btn" name="login-btn">Login</button>


            <div class="signup-link">
                <a href="register.php">Don't have an account? Register here.</a>
                <br>

                <a href="backend/update_User.php">Forgot your password?</a>
            </div>
</body>

</html>