<?php
include_once '../db/conn/connection.php';
include_once 'auth.php';
include_once 'rate_limit.php';
include_once 'validators.php';

require_login();
enforce_csrf_or_redirect($_POST['csrf_token'] ?? '', '/list_page.php');

$limit = check_rate_limit($conn, 'job_manual_update', (string) $_SESSION['user_id'] . '|' . client_ip_address(), 30, 120, 120);
if(!$limit['allowed']) {
    header('Location: /list_page.php?type=error&message=' . urlencode('Too many update attempts. Please try again in 2 minutes.'), true, 303);
    exit();
}

$jobId = isset($_POST['job_id']) ? (int) $_POST['job_id'] : 0;
$position = trim($_POST['position'] ?? '');
$company = trim($_POST['company'] ?? '');
$status = normalize_status($_POST['status'] ?? 'applied');
$appliedDate = trim($_POST['applied_date'] ?? '');
$notes = trim($_POST['notes'] ?? '');

$allowedStatuses = allowed_statuses();
if($jobId <= 0 || $position === '' || $company === '' || !in_array($status, $allowedStatuses, true) || !is_valid_iso_date($appliedDate)) {
    header('Location: /list_page.php?type=error&message=' . urlencode('Invalid job update data.'), true, 303);
    exit();
}

$stmt = $conn->prepare("UPDATE jobs SET position = :position, company = :company, status = :status, applied_date = :applied_date, notes = :notes, status_changed_at = NOW(), last_action = 'manual_update' WHERE id = :job_id AND user_id = :user_id");
$stmt->bindParam(':position', $position);
$stmt->bindParam(':company', $company);
$stmt->bindParam(':status', $status);
$stmt->bindParam(':applied_date', $appliedDate);
$stmt->bindParam(':notes', $notes);
$stmt->bindParam(':job_id', $jobId, PDO::PARAM_INT);
$stmt->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);

if(!$stmt->execute()) {
    header('Location: /list_page.php?type=error&message=' . urlencode('Could not save job changes.'), true, 303);
    exit();
}

header('Location: /list_page.php?type=success&message=' . urlencode('Job updated successfully.'), true, 303);
exit();
