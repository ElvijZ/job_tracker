<?php
    
    // Include the database connection file
    include 'db/conn/connection.php';

    if (isset($_POST['register-btn'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];

        // Hash the password before storing it
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        try {
            $stmt = $conn->prepare("INSERT INTO users (username, password_hash) VALUES (:username, :password)");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':password', $hashed_password);
            $stmt->execute();
            header("Location: index.php?registered=1", true, 303);
            exit();

        } catch (PDOException $e) {
                 if ($e->getCode() == 23000) { // Duplicate entry error code
                $error = "Username already exists. Please choose a different username.";
                
            } else {
                $error = "Something went wrong. Please try again later.";
                $error = "Error: " . $e->getMessage();
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
        <div class="register-container">
            <h1>Register</h1>
            <p>Create your account</p>
            <div class="error-message">
            <?php if(!empty($error)): ?>
                <p><?php echo $error; ?></p>
            <?php endif ?>
            </div>
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username_id" name="username">
            </div>
            <div class="form-group">
                <label for="password"> Create Password:</label>
                <input type="password" id="password_id" name="password">
            </div>

            <button class="register-btn" id="register-btn" name="register-btn">Register</button>
            <div class="login-link">
                <p>Already have an account? <a href="index.php">Login here</a></p>
            </div>
        </div>
    </form>
</body>

</html>