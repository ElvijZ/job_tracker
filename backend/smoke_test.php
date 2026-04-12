<?php
include_once __DIR__ . '/../db/conn/connection.php';
include_once __DIR__ . '/validators.php';

$checks = [];

try {
    $tableCheck = $conn->query("SHOW TABLES LIKE 'password_reset_tokens'");
    $checks[] = ['password_reset_tokens table exists', (bool) $tableCheck->fetchColumn()];

    $tableCheck2 = $conn->query("SHOW TABLES LIKE 'admin_audit_log'");
    $checks[] = ['admin_audit_log table exists', (bool) $tableCheck2->fetchColumn()];

    $tableCheck3 = $conn->query("SHOW TABLES LIKE 'rate_limits'");
    $checks[] = ['rate_limits table exists', (bool) $tableCheck3->fetchColumn()];

    $columnsStmt = $conn->query("SHOW COLUMNS FROM jobs LIKE 'status_changed_at'");
    $checks[] = ['jobs.status_changed_at exists', (bool) $columnsStmt->fetchColumn()];

    $columnsStmt2 = $conn->query("SHOW COLUMNS FROM jobs LIKE 'last_action'");
    $checks[] = ['jobs.last_action exists', (bool) $columnsStmt2->fetchColumn()];

    $checks[] = ['normalize_status interviewing -> interview', normalize_status('Interviewing') === 'interview'];
    $checks[] = ['password policy validator accepts Aa123456', is_valid_password_policy('Aa123456') === true];
    $checks[] = ['password policy rejects weak', is_valid_password_policy('weak') === false];
    $checks[] = ['date validator accepts valid date', is_valid_iso_date('2026-04-12') === true];
    $checks[] = ['date validator rejects invalid date', is_valid_iso_date('2026-99-99') === false];

    $failed = array_filter($checks, function($row) {
        return $row[1] !== true;
    });

    foreach($checks as $row) {
        echo ($row[1] ? '[OK] ' : '[FAIL] ') . $row[0] . PHP_EOL;
    }

    if(count($failed) > 0) {
        exit(1);
    }

    exit(0);
} catch(Throwable $e) {
    echo '[ERROR] ' . $e->getMessage() . PHP_EOL;
    exit(1);
}
