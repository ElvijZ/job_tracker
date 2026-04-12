<?php
include_once '../db/conn/connection.php';
include_once 'auth.php';
include_once 'rate_limit.php';
include_once 'validators.php';

header('Content-Type: application/json');

require_login_json();
enforce_csrf_or_json($_POST['csrf_token'] ?? '');

$limit = check_rate_limit($conn, 'job_status_update', (string) $_SESSION['user_id'] . '|' . client_ip_address(), 60, 120, 120);
if(!$limit['allowed']) {
    http_response_code(429);
    echo json_encode(['success' => false, 'message' => 'Too many updates. Slow down and try again.']);
    exit();
}

$jobId = isset($_POST['job_id']) ? (int) $_POST['job_id'] : 0;
$status = normalize_status($_POST['status'] ?? '');

 $allowedStatuses = allowed_statuses();
if($jobId <= 0 || !in_array($status, $allowedStatuses, true)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Invalid request data']);
    exit();
}

$stmt = $conn->prepare("UPDATE jobs SET status = :status, status_changed_at = NOW(), last_action = 'drag_drop' WHERE id = :job_id AND user_id = :user_id");
$stmt->bindParam(':status', $status);
$stmt->bindParam(':job_id', $jobId, PDO::PARAM_INT);
$stmt->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);

if(!$stmt->execute()) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Could not update status']);
    exit();
}

if($stmt->rowCount() < 1) {
    http_response_code(404);
    echo json_encode(['success' => false, 'message' => 'Job not found']);
    exit();
}

echo json_encode(['success' => true, 'message' => 'Status updated']);
