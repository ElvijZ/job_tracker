<?php

function client_ip_address() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if(!is_string($ip) || $ip === '') {
        return 'unknown';
    }
    return substr($ip, 0, 100);
}

function check_rate_limit(PDO $conn, $action, $identifier, $maxAttempts, $windowSeconds, $blockSeconds) {
    $keyHash = hash('sha256', (string) $identifier);

    $stmt = $conn->prepare('SELECT attempts, window_start, blocked_until FROM rate_limits WHERE action = :action AND key_hash = :key_hash LIMIT 1');
    $stmt->bindParam(':action', $action);
    $stmt->bindParam(':key_hash', $keyHash);
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    $nowTs = time();

    if(!$row) {
        $insert = $conn->prepare('INSERT INTO rate_limits (action, key_hash, attempts, window_start) VALUES (:action, :key_hash, 1, NOW())');
        $insert->bindParam(':action', $action);
        $insert->bindParam(':key_hash', $keyHash);
        $insert->execute();
        return ['allowed' => true, 'retry_after' => 0];
    }

    $blockedUntilTs = !empty($row['blocked_until']) ? strtotime($row['blocked_until']) : null;
    if($blockedUntilTs !== null && $blockedUntilTs > $nowTs) {
        return ['allowed' => false, 'retry_after' => $blockedUntilTs - $nowTs];
    }

    $windowStartTs = !empty($row['window_start']) ? strtotime($row['window_start']) : 0;
    $attempts = (int) ($row['attempts'] ?? 0);

    if(($nowTs - $windowStartTs) > $windowSeconds) {
        $reset = $conn->prepare('UPDATE rate_limits SET attempts = 1, window_start = NOW(), blocked_until = NULL WHERE action = :action AND key_hash = :key_hash');
        $reset->bindParam(':action', $action);
        $reset->bindParam(':key_hash', $keyHash);
        $reset->execute();
        return ['allowed' => true, 'retry_after' => 0];
    }

    $attempts++;
    if($attempts > $maxAttempts) {
        $block = $conn->prepare('UPDATE rate_limits SET attempts = :attempts, blocked_until = DATE_ADD(NOW(), INTERVAL :block_seconds SECOND) WHERE action = :action AND key_hash = :key_hash');
        $block->bindParam(':attempts', $attempts, PDO::PARAM_INT);
        $block->bindParam(':block_seconds', $blockSeconds, PDO::PARAM_INT);
        $block->bindParam(':action', $action);
        $block->bindParam(':key_hash', $keyHash);
        $block->execute();
        return ['allowed' => false, 'retry_after' => $blockSeconds];
    }

    $update = $conn->prepare('UPDATE rate_limits SET attempts = :attempts WHERE action = :action AND key_hash = :key_hash');
    $update->bindParam(':attempts', $attempts, PDO::PARAM_INT);
    $update->bindParam(':action', $action);
    $update->bindParam(':key_hash', $keyHash);
    $update->execute();

    return ['allowed' => true, 'retry_after' => 0];
}
