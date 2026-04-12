<?php

function log_admin_action(PDO $conn, $adminUserId, $action, $targetType, $targetId, $details = null) {
    $stmt = $conn->prepare('INSERT INTO admin_audit_log (admin_user_id, action, target_type, target_id, details, ip_address) VALUES (:admin_user_id, :action, :target_type, :target_id, :details, :ip_address)');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $stmt->bindParam(':admin_user_id', $adminUserId, PDO::PARAM_INT);
    $stmt->bindParam(':action', $action);
    $stmt->bindParam(':target_type', $targetType);
    $stmt->bindParam(':target_id', $targetId, PDO::PARAM_INT);
    $stmt->bindParam(':details', $details);
    $stmt->bindParam(':ip_address', $ip);
    $stmt->execute();
}
