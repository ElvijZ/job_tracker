<?php
$success = "";
if (isset($_GET['registered'])) {
    $success = "Registration successful! Please log in.";
}
// Include the database connection file
include_once 'db/conn/connection.php';

if (isset($_POST['login-btn'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Prepare and execute the SQL statement to fetch the user
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username");
    $stmt->bindParam(':username', $username);
    $stmt->execute();

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password_hash'])) {
        // Start a session and store user information
        session_start();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];

        // Redirect to the list page after successful login
        header("Location: list_page.php", true, 303);
        exit();

    } else {
        echo "<script>alert('Invalid username or password');</script>";
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
        <form method="POST" action="">
            <?php if (!empty($success)): ?>
                <p style="color: green;"><?php echo $success; ?></p>
            <?php endif; ?>







            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password">
            </div>
            <button class="login-btn" id="login-btn" name="login-btn">Login</button>


            <div class="signup-link">
                <a href="register.php">Don't have an account? Register here.</a>
                <br>

                <a href="update_User.php">Forgot your password?</a>
            </div>
</body>

</html>