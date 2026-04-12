<?php
include_once 'backend/auth.php';
include_once 'backend/rate_limit.php';
include_once 'backend/validators.php';

// Include the database connection file
include 'db/conn/connection.php';
$csrfToken = get_csrf_token();

if (isset($_POST['register-btn'])) {
    enforce_csrf_or_redirect($_POST['csrf_token'] ?? '', '/register.php');
    $username = trim((string) ($_POST['username'] ?? ''));
    $email = strtolower(trim((string) ($_POST['email'] ?? '')));
    $password = $_POST['password'];

    $limit = check_rate_limit($conn, 'register_ip', client_ip_address(), 10, 600, 600);
    if(!$limit['allowed']) {
        $error = 'Too many registration attempts. Try again later.';
    } elseif($username === '' || strlen($username) < 3 || strlen($username) > 100 || !preg_match('/^[A-Za-z0-9_.-]+$/', $username)) {
        $error = 'Username must be 3-100 chars and use letters, numbers, dot, underscore or dash.';
    } elseif($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    } elseif(!is_valid_password_policy($password)) {
        $error = 'Password must be 8+ chars and include uppercase, lowercase, and number.';
    } else {

        // Hash the password before storing it
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        try {
            $stmt = $conn->prepare("INSERT INTO users (username, email, password_hash) VALUES (:username, :email, :password)");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':password', $hashed_password);
            $stmt->execute();
            header("Location: index.php?registered=1", true, 303);
            exit();

        } catch (PDOException $e) {
            if ($e->getCode() == 23000) { // Duplicate entry error code
                $error = "Username or email already exists. Please choose different values.";

            } else {
                $error = "Something went wrong. Please try again later.";
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
    <title>Register</title>
    <link rel="stylesheet" href="style/register.css">
</head>

<body>
    <form method="POST" action="">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
        <div class="register-container">
            <h1>Register</h1>
            <p>Create your account</p>
            <?php if (!empty($error)): ?>
                <div class="error-message">
                    <p><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
                </div>
            <?php endif; ?>
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username_id" name="username" required>
        </div>
        <div class="form-group">
            <label for="email">Email:</label>
            <input type="email" id="email_id" name="email" required>
        </div>
        <div class="form-group">
            <label for="password"> Create Password:</label>
            <input type="password" id="password_id" name="password" required>
        </div>

        <button class="register-btn" id="register-btn" name="register-btn">Register</button>
        <div class="login-link">
            <p>Already have an account? <a href="index.php">Login here</a></p>
        </div>
        </div>
    </form>
</body>

</html>