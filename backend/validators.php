<?php

function normalize_status($status) {
    $normalized = strtolower(trim((string) $status));
    if($normalized === 'interviewing') {
        return 'interview';
    }
    if(in_array($normalized, ['applied', 'interview', 'offered', 'rejected'], true)) {
        return $normalized;
    }
    return 'applied';
}

function allowed_statuses() {
    return ['applied', 'interview', 'offered', 'rejected'];
}

function is_valid_password_policy($password) {
    return is_string($password) && (bool) preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/', $password);
}

function is_valid_iso_date($date) {
    if(!is_string($date) || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
        return false;
    }
    $parsed = DateTime::createFromFormat('Y-m-d', $date);
    return $parsed !== false && $parsed->format('Y-m-d') === $date;
}
