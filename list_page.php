<?php
include_once 'db/conn/connection.php';
session_start();
if(!isset($_SESSION['user_id'])) {
    header("Location: index.php", true, 303);
    exit();
}

    $stmt = $conn->prepare("SELECT position, company, status, notes, created_at FROM jobs WHERE user_id = :user_id ORDER BY created_at DESC");
    $stmt->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->execute();
    $jobs = $stmt->fetchAll(PDO::FETCH_ASSOC);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Job Tracker - List Page</title>
</head>
<body>
    <h1>Job Tracker - List Page</h1>
    <p>This is page where you can see all of your job applications.</p>
    <a href="index.php">Log Out</a>
    <a href="insert_jobs.php">Insert New Job</a>

    <?php if(empty($jobs)): ?>
        <p>No jobs found yet. Add your first one.</p>
    <?php else: ?>
        <table border="1" cellpadding="8" cellspacing="0">
            <thead>
                <tr>
                    <th>Position</th>
                    <th>Company</th>
                    <th>Status</th>
                    <th>Applied Date</th>
                    <th>Notes</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach($jobs as $job): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($job['position'] ?? '', ENT_QUOTES, 'UTF-8'); ?></td>
                        <td><?php echo htmlspecialchars($job['company'] ?? '', ENT_QUOTES, 'UTF-8'); ?></td>
                        <td><?php echo htmlspecialchars($job['status'] ?? '', ENT_QUOTES, 'UTF-8'); ?></td>
                        <td><?php echo htmlspecialchars($job['applied_date'] ?? '', ENT_QUOTES, 'UTF-8'); ?></td>
                        <td><?php echo htmlspecialchars($job['notes'] ?? '', ENT_QUOTES, 'UTF-8'); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</body>
</html>