<?php
include_once 'db/conn/connection.php';
include_once 'backend/auth.php';
include_once 'backend/validators.php';
require_login();

if(is_admin_user()) {
    header('Location: admin.php', true, 303);
    exit();
}

$csrfToken = get_csrf_token();
$flashMessage = trim($_GET['message'] ?? '');
$flashType = ($_GET['type'] ?? '') === 'error' ? 'error' : 'success';
$defaultAppliedDate = date('Y-m-d');

if(isset($_POST['insert-job-btn'])) {
    enforce_csrf_or_redirect($_POST['csrf_token'] ?? '', '/insert_jobs.php');
    $user_id = (int) $_SESSION['user_id'];
    $position = trim($_POST['position'] ?? '');
    $company = trim($_POST['company'] ?? '');
    $status = normalize_status($_POST['status'] ?? 'applied');
    $appliedDate = trim($_POST['applied_date'] ?? $defaultAppliedDate);
    $notes = trim($_POST['notes'] ?? '');

    if($position === '' || $company === '') {
        header('Location: insert_jobs.php?type=error&message=' . urlencode('Position and company are required.'), true, 303);
        exit();
    } elseif(!is_valid_iso_date($appliedDate)) {
        header('Location: insert_jobs.php?type=error&message=' . urlencode('Please choose a valid applied date.'), true, 303);
        exit();
    } else {
        // Prepare and execute the SQL statement to insert the new job
        $stmt = $conn->prepare("INSERT INTO jobs (user_id, position, company, status, applied_date, notes, status_changed_at, last_action) VALUES (:user_id, :position, :company, :status, :applied_date, :notes, NOW(), 'created')");
        $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt->bindParam(':position', $position);
        $stmt->bindParam(':company', $company);
        $stmt->bindParam(':status', $status);
        $stmt->bindParam(':applied_date', $appliedDate);
        $stmt->bindParam(':notes', $notes);

        if($stmt->execute()) {
            header('Location: insert_jobs.php?type=success&message=' . urlencode('Job inserted successfully.'), true, 303);
            exit();
        } else {
            header('Location: insert_jobs.php?type=error&message=' . urlencode('Could not insert job.'), true, 303);
            exit();
        }


    }
}
if(isset($_POST['back-list-btn'])) {
    header("Location: list_page.php", true, 303);
    exit();
} 
?>



<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Insert Job</title>
    <link rel="stylesheet" href="style/insert_jobs.css?v=2">
</head>
<body>
    <main class="insert-page">
        <section class="insert-card">
            <h1>Insert Job</h1>
            <p class="subtitle">Add a new application and track it in your board.</p>

            <?php if($flashMessage !== ''): ?>
                <div class="flash-message <?php echo $flashType === 'error' ? 'flash-error' : 'flash-success'; ?>">
                    <?php echo htmlspecialchars($flashMessage, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            <?php endif; ?>

            <form class="insert-form" action="insert_jobs.php" method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
                <label for="position">Job Title</label>
                <input type="text" id="position" name="position" required>

                <label for="company">Company</label>
                <input type="text" id="company" name="company" required>

                <label for="status">Status</label>
                <select id="status" name="status" required>
                    <option value="applied">Applied</option>
                    <option value="interview">Interview</option>
                    <option value="offered">Offered</option>
                    <option value="rejected">Rejected</option>
                </select>

                <label for="applied_date">Applied Date</label>
                <input type="date" id="applied_date" name="applied_date" value="<?php echo htmlspecialchars($defaultAppliedDate, ENT_QUOTES, 'UTF-8'); ?>" required>

                <label for="notes">Notes</label>
                <textarea id="notes" name="notes" rows="5" placeholder="Add any details, links, or reminders..."></textarea>

                <div class="form-actions">
                    <button type="submit" class="btn btn-primary" id="insert-job-btn" name="insert-job-btn" value="1">Insert Job</button>
                    <a class="btn btn-secondary" href="list_page.php">Back to List</a>
                </div>
            </form>
        </section>
    </main>
</body>
</html>