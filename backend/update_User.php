<?php
include_once '../db/conn/connection.php';
include_once 'auth.php';
include_once 'rate_limit.php';
include_once 'validators.php';
include_once 'email.php';

$error = '';
$success = '';
$csrfToken = get_csrf_token();

if(isset($_POST['request-reset-code-btn'])) {
    enforce_csrf_or_redirect($_POST['csrf_token'] ?? '', '/backend/update_User.php');
    $email = strtolower(trim((string) ($_POST['email'] ?? '')));
    $ipKey = client_ip_address();

    $rateByIp = check_rate_limit($conn, 'reset_request_ip', $ipKey, 12, 300, 300);
    $rateByUser = check_rate_limit($conn, 'reset_request_email_ip', strtolower($email) . '|' . $ipKey, 5, 300, 300);
    if(!$rateByIp['allowed'] || !$rateByUser['allowed']) {
        $error = 'Too many reset requests. Try again in a few minutes.';
    } elseif($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    } else {
        $code = (string) random_int(100000, 999999);
        $codeHash = hash('sha256', $code);

        $userStmt = $conn->prepare('SELECT username FROM users WHERE email = :email LIMIT 1');
        $userStmt->bindParam(':email', $email);
        $userStmt->execute();
        $username = (string) ($userStmt->fetchColumn() ?: '');

        if($username !== '') {
            $deleteStmt = $conn->prepare('DELETE FROM password_reset_tokens WHERE username = :username');
            $deleteStmt->bindParam(':username', $username);
            $deleteStmt->execute();

            $insertStmt = $conn->prepare('INSERT INTO password_reset_tokens (username, token_hash, expires_at) VALUES (:username, :token_hash, DATE_ADD(NOW(), INTERVAL 15 MINUTE))');
            $insertStmt->bindParam(':username', $username);
            $insertStmt->bindParam(':token_hash', $codeHash);
            $insertStmt->execute();
        }

        $mailSent = false;
        if($username !== '') {
            $subject = 'JobTracker Password Reset Code';
            $body = "Your password reset code is: {$code}\n\nThis code expires in 15 minutes.\n\nIf you did not request this, please ignore this email.";
            $mailSent = send_email($email, $subject, $body, false, $conn);
        }

        $success = $mailSent
            ? 'If the account exists, a 6-digit code was sent to your email. Check your inbox and spam folder.'
            : 'If the account exists, a reset code was created, but email delivery is not configured yet. Ask the admin to save email settings in the admin dashboard.';

    }
}

if(isset($_POST['reset-password-btn'])) {
    enforce_csrf_or_redirect($_POST['csrf_token'] ?? '', '/backend/update_User.php');
    $email = strtolower(trim((string) ($_POST['email'] ?? '')));
    $resetCode = trim($_POST['reset_code'] ?? '');
    $newPassword = $_POST['new_password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $ipKey = client_ip_address();

    $rateByIp = check_rate_limit($conn, 'reset_submit_ip', $ipKey, 12, 300, 300);
    $rateByUser = check_rate_limit($conn, 'reset_submit_email_ip', strtolower($email) . '|' . $ipKey, 6, 300, 300);
    if(!$rateByIp['allowed'] || !$rateByUser['allowed']) {
        $error = 'Too many reset attempts. Try again in a few minutes.';
    } elseif($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || $resetCode === '' || $newPassword === '' || $confirmPassword === '') {
        $error = 'Please fill all fields.';
    } elseif($newPassword !== $confirmPassword) {
        $error = 'Passwords do not match.';
    } elseif(!is_valid_password_policy($newPassword)) {
        $error = 'Password must be 8+ chars and include uppercase, lowercase, and number.';
    } else {
        $userStmt = $conn->prepare('SELECT username FROM users WHERE email = :email LIMIT 1');
        $userStmt->bindParam(':email', $email);
        $userStmt->execute();
        $username = (string) ($userStmt->fetchColumn() ?: '');

        if($username === '') {
            $error = 'Invalid or expired reset code.';
        } else {
            $codeHash = hash('sha256', $resetCode);
            $tokenStmt = $conn->prepare('SELECT id FROM password_reset_tokens WHERE username = :username AND token_hash = :token_hash AND used_at IS NULL AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1');
            $tokenStmt->bindParam(':username', $username);
            $tokenStmt->bindParam(':token_hash', $codeHash);
            $tokenStmt->execute();
            $token = $tokenStmt->fetch(PDO::FETCH_ASSOC);

            if(!$token) {
                $error = 'Invalid or expired reset code.';
            } else {
                $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);

                $updateUserStmt = $conn->prepare('UPDATE users SET password_hash = :password_hash WHERE username = :username');
                $updateUserStmt->bindParam(':password_hash', $passwordHash);
                $updateUserStmt->bindParam(':username', $username);
                $updateUserStmt->execute();

                $consumeTokenStmt = $conn->prepare('UPDATE password_reset_tokens SET used_at = NOW() WHERE id = :id');
                $consumeTokenStmt->bindParam(':id', $token['id'], PDO::PARAM_INT);
                $consumeTokenStmt->execute();

                header('Location: ../index.php?reset=1', true, 303);
                exit();
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
    <title>Forgot Password</title>
    <link rel="stylesheet" href="../style/register.css">
</head>
<body>
    <div class="register-container">
        <h1>Forgot Password</h1>
        <p>Enter your email to get a 6-digit reset code, then set your new password.</p>

        <?php if($success !== ''): ?>
            <div class="error-message" style="background:#e6faef;border-color:#b7e7ca;color:#177245;">
                <p><?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
        <?php endif; ?>

        <?php if($error !== ''): ?>
            <div class="error-message">
                <p><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
        <?php endif; ?>

        <form method="POST" action="update_User.php">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <button class="register-btn" id="request-reset-code-btn" name="request-reset-code-btn" value="1">Request Reset Code</button>
        </form>

        <hr style="border:0;border-top:1px solid #d7e3f1;margin:16px 0;">

        <form method="POST" action="update_User.php">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
            <div class="form-group">
                <label for="email_reset">Email:</label>
                <input type="email" id="email_reset" name="email" required>
            </div>
            <div class="form-group">
                <label for="reset_code">Reset Code:</label>
                <input type="text" id="reset_code" name="reset_code" maxlength="6" placeholder="6-digit code" required>
            </div>

            <div class="form-group">
                <label for="new_password">New Password:</label>
                <input type="password" id="new_password" name="new_password" required>
            </div>

            <div class="form-group">
                <label for="confirm_password">Confirm Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>

            <button class="register-btn" id="reset-password-btn" name="reset-password-btn" value="1">Reset Password</button>
        </form>

        <div class="login-link">
            <p>Back to login? <a href="../index.php">Login here</a></p>
        </div>
    </div>
</body>
</html>
