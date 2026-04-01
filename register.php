<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
</head>
<body>
<form method="POST" action="">
    <h1>Register</h1>

    <label for="username">Username:</label>
    <input type="text" id="username_id" name="username">

    <label for="password"> Create Password:</label>
    <input type="password" id="password_id" name="password">

    <button id="register-btn" name="register-btn">Register</button>

    <?php
    // Include the database connection file
    include 'db/conn/connection.php';
    
    if(isset($_POST['register-btn'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];

        // Hash the password before storing it
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Prepare and execute the SQL statement to insert the new user
        $stmt = $conn->prepare("INSERT INTO users (username, password_hash) VALUES (:username, :password)");
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $hashed_password);
        
        if($stmt->execute()) {
            echo "Registration successful!";
        } else {
            echo "Error: " . $stmt->errorInfo()[2];
        }
    }
    ?>
</body>
</html>