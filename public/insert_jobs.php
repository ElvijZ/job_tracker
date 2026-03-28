<?php
include_once '../db/conn/connection.php';
session_start();

if(isset($_POST['insert-job-btn'])) {
    if(!isset($_SESSION['user_id'])) {
        header("Location: ../public/index.php", true, 303);
        exit();
    }

    $user_id = (int) $_SESSION['user_id'];
    $position = trim($_POST['position'] ?? '');
    $company = trim($_POST['company'] ?? '');
    $status = trim($_POST['status'] ?? 'applied');
    $notes = trim($_POST['notes'] ?? '');

    if($position === '' || $company === '') {
        echo "Position and company are required.";
    } else {
        // Prepare and execute the SQL statement to insert the new job
        $stmt = $conn->prepare("INSERT INTO jobs (user_id, position, company, status, notes) VALUES (:user_id, :position, :company, :status, :notes)");
        $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt->bindParam(':position', $position);
        $stmt->bindParam(':company', $company);
        $stmt->bindParam(':status', $status);
        $stmt->bindParam(':notes', $notes);

        if($stmt->execute()) {
            echo "Job inserted successfully!";
        } else {
            echo "Error: " . $stmt->errorInfo()[2];
        }
    }
}

?>



<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Insert Job</title>
</head>
<body>
    <h1>Insert Job</h1>
    <form action="insert_jobs.php" method="POST">
        <label for="position">Job Title:</label>
        <input type="text" id="position" name="position" required>
        <br><br>
        <label for="company">Company:</label>
        <input type="text" id="company" name="company" required>
        <br><br>
        <label for="status">Status:</label>
        <select id="status" name="status" required>
            <option value="Applied">Applied</option>
            <option value="Interviewing">Interviewing</option>
            <option value="Offered">Offered</option>
            <option value="Rejected">Rejected</option>
        </select>
        <br><br>
        <label for="job_description">Job Description:</label>
        <textarea id="notes" name="notes"></textarea>
        <br><br>
        <input type="submit" id="insert-job-btn" name="insert-job-btn" value="Insert Job">
    </form>
</body>
</html>