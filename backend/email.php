<?php

function ensure_mail_settings_table(PDO $conn): void {
    static $initialized = false;

    if($initialized) {
        return;
    }

    $conn->exec(
        'CREATE TABLE IF NOT EXISTS mail_settings (
            id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
            smtp_host VARCHAR(190) NOT NULL DEFAULT "",
            smtp_port INT UNSIGNED NOT NULL DEFAULT 587,
            smtp_encryption VARCHAR(10) NOT NULL DEFAULT "tls",
            smtp_username VARCHAR(190) NOT NULL DEFAULT "",
            smtp_password VARCHAR(255) NOT NULL DEFAULT "",
            from_email VARCHAR(190) NOT NULL DEFAULT "noreply@jobtracker.local",
            from_name VARCHAR(190) NOT NULL DEFAULT "JobTracker",
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )'
    );

    $initialized = true;
}

function get_mail_settings(?PDO $conn = null): array {
    $settings = [
        'smtp_host' => trim((string) getenv('MAIL_HOST')),
        'smtp_port' => (int) (getenv('MAIL_PORT') ?: 587),
        'smtp_encryption' => trim((string) getenv('MAIL_ENCRYPTION')) ?: 'tls',
        'smtp_username' => trim((string) getenv('MAIL_USERNAME')),
        'smtp_password' => (string) getenv('MAIL_PASSWORD'),
        'from_email' => trim((string) getenv('MAIL_FROM')) ?: 'noreply@jobtracker.local',
        'from_name' => trim((string) getenv('MAIL_FROM_NAME')) ?: 'JobTracker'
    ];

    if($conn instanceof PDO) {
        ensure_mail_settings_table($conn);
        $stmt = $conn->query('SELECT smtp_host, smtp_port, smtp_encryption, smtp_username, smtp_password, from_email, from_name FROM mail_settings WHERE id = 1 LIMIT 1');
        $row = $stmt ? $stmt->fetch(PDO::FETCH_ASSOC) : false;

        if(is_array($row) && $row !== []) {
            $settings['smtp_host'] = trim((string) ($row['smtp_host'] ?? $settings['smtp_host']));
            $settings['smtp_port'] = (int) ($row['smtp_port'] ?? $settings['smtp_port']);
            $settings['smtp_encryption'] = trim((string) ($row['smtp_encryption'] ?? $settings['smtp_encryption'])) ?: 'tls';
            $settings['smtp_username'] = trim((string) ($row['smtp_username'] ?? $settings['smtp_username']));
            $settings['smtp_password'] = (string) ($row['smtp_password'] ?? $settings['smtp_password']);
            $settings['from_email'] = trim((string) ($row['from_email'] ?? $settings['from_email'])) ?: $settings['from_email'];
            $settings['from_name'] = trim((string) ($row['from_name'] ?? $settings['from_name'])) ?: $settings['from_name'];
        }
    }

    return $settings;
}

function save_mail_settings(PDO $conn, array $settings): void {
    ensure_mail_settings_table($conn);

    $stmt = $conn->prepare(
        'INSERT INTO mail_settings (id, smtp_host, smtp_port, smtp_encryption, smtp_username, smtp_password, from_email, from_name)
         VALUES (1, :smtp_host, :smtp_port, :smtp_encryption, :smtp_username, :smtp_password, :from_email, :from_name)
         ON DUPLICATE KEY UPDATE
            smtp_host = VALUES(smtp_host),
            smtp_port = VALUES(smtp_port),
            smtp_encryption = VALUES(smtp_encryption),
            smtp_username = VALUES(smtp_username),
            smtp_password = VALUES(smtp_password),
            from_email = VALUES(from_email),
            from_name = VALUES(from_name)'
    );

    $stmt->execute([
        ':smtp_host' => trim((string) ($settings['smtp_host'] ?? '')),
        ':smtp_port' => (int) ($settings['smtp_port'] ?? 587),
        ':smtp_encryption' => trim((string) ($settings['smtp_encryption'] ?? 'tls')),
        ':smtp_username' => trim((string) ($settings['smtp_username'] ?? '')),
        ':smtp_password' => (string) ($settings['smtp_password'] ?? ''),
        ':from_email' => trim((string) ($settings['from_email'] ?? 'noreply@jobtracker.local')),
        ':from_name' => trim((string) ($settings['from_name'] ?? 'JobTracker'))
    ]);
}

function send_email($to, $subject, $body, $isHtml = false, ?PDO $conn = null) {
    $settings = get_mail_settings($conn);

    if($settings['smtp_host'] !== '' && $settings['smtp_username'] !== '' && $settings['smtp_password'] !== '') {
        return send_email_via_smtp($to, $subject, $body, $isHtml, $settings);
    }

    return send_email_via_mail($to, $subject, $body, $isHtml, $settings['from_email'], $settings['from_name']);
}

function send_email_via_smtp($to, $subject, $body, $isHtml, array $settings) {
    $host = $settings['smtp_host'];
    $port = (int) $settings['smtp_port'];
    $user = $settings['smtp_username'];
    $pass = $settings['smtp_password'];
    $from = $settings['from_email'];
    $fromName = $settings['from_name'];
    $encryption = strtolower(trim((string) $settings['smtp_encryption']));

    $remote = ($encryption === 'ssl' ? 'ssl://' : 'tcp://') . $host . ':' . $port;
    $socket = @stream_socket_client($remote, $errno, $errstr, 15, STREAM_CLIENT_CONNECT);

    if(!$socket) {
        error_log('SMTP connection failed: ' . $errstr . ' (' . $errno . ')');
        return false;
    }

    stream_set_timeout($socket, 15);

    try {
        smtp_expect($socket, [220]);
        smtp_command($socket, 'EHLO jobtracker.local', [250]);

        if($encryption === 'tls') {
            smtp_command($socket, 'STARTTLS', [220]);
            if(!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                throw new RuntimeException('Could not start TLS.');
            }
            smtp_command($socket, 'EHLO jobtracker.local', [250]);
        }

        smtp_command($socket, 'AUTH LOGIN', [334]);
        smtp_command($socket, base64_encode($user), [334]);
        smtp_command($socket, base64_encode($pass), [235]);
        smtp_command($socket, 'MAIL FROM:<' . $from . '>', [250]);
        smtp_command($socket, 'RCPT TO:<' . $to . '>', [250, 251]);
        smtp_command($socket, 'DATA', [354]);

        $headers = [];
        $headers[] = 'Date: ' . date(DATE_RFC2822);
        $headers[] = 'To: <' . $to . '>';
        $headers[] = 'From: ' . smtp_format_from_header($fromName, $from);
        $headers[] = 'Reply-To: ' . $from;
        $headers[] = 'Subject: ' . encode_subject($subject);
        $headers[] = 'MIME-Version: 1.0';
        $headers[] = $isHtml ? 'Content-Type: text/html; charset=UTF-8' : 'Content-Type: text/plain; charset=UTF-8';
        $headers[] = 'Content-Transfer-Encoding: 8bit';

        $message = implode("\r\n", $headers) . "\r\n\r\n" . smtp_escape_body($body) . "\r\n.";
        smtp_command($socket, $message, [250]);
        smtp_command($socket, 'QUIT', [221]);
        fclose($socket);
        return true;
    } catch(Throwable $exception) {
        error_log('SMTP error: ' . $exception->getMessage());
        fclose($socket);
        return false;
    }
}

function smtp_command($socket, string $command, array $expectedCodes): string {
    fwrite($socket, $command . "\r\n");
    return smtp_expect($socket, $expectedCodes);
}

function smtp_expect($socket, array $expectedCodes): string {
    $response = '';

    while(($line = fgets($socket, 515)) !== false) {
        $response .= $line;
        if(isset($line[3]) && $line[3] === ' ') {
            break;
        }
    }

    $code = (int) substr($response, 0, 3);
    if(!in_array($code, $expectedCodes, true)) {
        throw new RuntimeException('Unexpected SMTP response: ' . trim($response));
    }

    return $response;
}

function smtp_escape_body(string $body): string {
    $normalized = str_replace(["\r\n", "\r"], "\n", $body);
    $normalized = preg_replace('/^\./m', '..', $normalized);
    return str_replace("\n", "\r\n", $normalized);
}

function smtp_format_from_header(string $fromName, string $fromEmail): string {
    return '=?UTF-8?B?' . base64_encode($fromName) . '?= <' . $fromEmail . '>';
}

function send_email_via_mail($to, $subject, $body, $isHtml, $from, $fromName) {
    $headers = "From: " . smtp_format_from_header($fromName, $from) . "\r\n";
    $headers .= "Reply-To: {$from}\r\n";
    $headers .= 'MIME-Version: 1.0' . "\r\n";
    $headers .= $isHtml ? "Content-Type: text/html; charset=UTF-8\r\n" : "Content-Type: text/plain; charset=UTF-8\r\n";

    return @mail($to, $subject, $body, $headers);
}

function encode_subject($subject) {
    return '=?UTF-8?B?' . base64_encode($subject) . '?=';
}
