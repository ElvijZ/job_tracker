<?php
include_once 'db/conn/connection.php';
include_once 'backend/auth.php';
include_once 'backend/rate_limit.php';
include_once 'backend/admin_audit.php';
include_once 'backend/email.php';
require_admin();

$csrfToken = get_csrf_token();
$flashMessage = trim($_GET['message'] ?? '');
$flashType = ($_GET['type'] ?? '') === 'error' ? 'error' : 'success';
ensure_mail_settings_table($conn);

if(isset($_POST['toggle-admin-btn'])) {
    enforce_csrf_or_redirect($_POST['csrf_token'] ?? '', '/admin.php');
    $limit = check_rate_limit($conn, 'admin_toggle_role', (string) $_SESSION['user_id'] . '|' . client_ip_address(), 20, 300, 300);
    if(!$limit['allowed']) {
        header('Location: admin.php?type=error&message=' . urlencode('Too many admin actions. Try again later.'), true, 303);
        exit();
    }

    $targetUserId = (int) ($_POST['target_user_id'] ?? 0);
    $nextAdminValue = (int) ($_POST['next_admin_value'] ?? 0);

    if($targetUserId <= 0) {
        header('Location: admin.php?type=error&message=' . urlencode('Invalid user selected.'), true, 303);
        exit();
    }

    if($targetUserId === (int) $_SESSION['user_id'] && $nextAdminValue === 0) {
        header('Location: admin.php?type=error&message=' . urlencode('You cannot remove your own admin role.'), true, 303);
        exit();
    }

    $stmt = $conn->prepare('UPDATE users SET is_admin = :is_admin WHERE id = :id');
    $stmt->bindParam(':is_admin', $nextAdminValue, PDO::PARAM_INT);
    $stmt->bindParam(':id', $targetUserId, PDO::PARAM_INT);

    if($stmt->execute()) {
        log_admin_action(
            $conn,
            (int) $_SESSION['user_id'],
            'toggle_admin_role',
            'user',
            $targetUserId,
            json_encode(['next_admin_value' => $nextAdminValue])
        );
        header('Location: admin.php?type=success&message=' . urlencode('User role updated.'), true, 303);
        exit();
    }

    header('Location: admin.php?type=error&message=' . urlencode('Could not update user role.'), true, 303);
    exit();
}

if(isset($_POST['save-mail-settings-btn'])) {
    enforce_csrf_or_redirect($_POST['csrf_token'] ?? '', '/admin.php');
    $limit = check_rate_limit($conn, 'admin_save_mail_settings', (string) $_SESSION['user_id'] . '|' . client_ip_address(), 15, 300, 300);
    if(!$limit['allowed']) {
        header('Location: admin.php?type=error&message=' . urlencode('Too many mail setting updates. Try again later.'), true, 303);
        exit();
    }

    $smtpHost = trim((string) ($_POST['smtp_host'] ?? ''));
    $smtpPort = (int) ($_POST['smtp_port'] ?? 587);
    $smtpEncryption = strtolower(trim((string) ($_POST['smtp_encryption'] ?? 'tls')));
    $smtpUsername = trim((string) ($_POST['smtp_username'] ?? ''));
    $smtpPassword = (string) ($_POST['smtp_password'] ?? '');
    $fromEmail = strtolower(trim((string) ($_POST['from_email'] ?? '')));
    $fromName = trim((string) ($_POST['from_name'] ?? ''));

    if($smtpHost === '' || $smtpUsername === '' || $smtpPassword === '' || $fromEmail === '') {
        header('Location: admin.php?type=error&message=' . urlencode('Host, username, password, and from email are required.'), true, 303);
        exit();
    }

    if(!in_array($smtpEncryption, ['tls', 'ssl', 'none'], true)) {
        header('Location: admin.php?type=error&message=' . urlencode('Invalid encryption type.'), true, 303);
        exit();
    }

    if($smtpPort < 1 || $smtpPort > 65535) {
        header('Location: admin.php?type=error&message=' . urlencode('Invalid SMTP port.'), true, 303);
        exit();
    }

    if(!filter_var($fromEmail, FILTER_VALIDATE_EMAIL)) {
        header('Location: admin.php?type=error&message=' . urlencode('From email is invalid.'), true, 303);
        exit();
    }

    save_mail_settings($conn, [
        'smtp_host' => $smtpHost,
        'smtp_port' => $smtpPort,
        'smtp_encryption' => $smtpEncryption,
        'smtp_username' => $smtpUsername,
        'smtp_password' => $smtpPassword,
        'from_email' => $fromEmail,
        'from_name' => $fromName !== '' ? $fromName : 'JobTracker'
    ]);

    log_admin_action(
        $conn,
        (int) $_SESSION['user_id'],
        'save_mail_settings',
        'mail_settings',
        1,
        json_encode([
            'smtp_host' => $smtpHost,
            'smtp_port' => $smtpPort,
            'smtp_encryption' => $smtpEncryption,
            'smtp_username' => $smtpUsername,
            'from_email' => $fromEmail,
            'from_name' => $fromName !== '' ? $fromName : 'JobTracker'
        ])
    );

    header('Location: admin.php?type=success&message=' . urlencode('Mail settings saved. Password reset emails will use these settings.'), true, 303);
    exit();
}

// Handle delete actions (user or job)
if(isset($_POST['confirm_delete_action'])) {
    enforce_csrf_or_redirect($_POST['csrf_token'] ?? '', '/admin.php');
    
    $hasTargetUser = (int) ($_POST['target_user_id'] ?? 0) > 0;
    $hasTargetJob = (int) ($_POST['target_job_id'] ?? 0) > 0;
    
    if($hasTargetUser) {
        // DELETE USER
        $limit = check_rate_limit($conn, 'admin_delete_user', (string) $_SESSION['user_id'] . '|' . client_ip_address(), 10, 300, 300);
        if(!$limit['allowed']) {
            header('Location: admin.php?type=error&message=' . urlencode('Too many delete requests. Try again later.'), true, 303);
            exit();
        }

        $targetUserId = (int) ($_POST['target_user_id'] ?? 0);

        if($targetUserId <= 0) {
            header('Location: admin.php?type=error&message=' . urlencode('Invalid user selected.'), true, 303);
            exit();
        }

        if($targetUserId === (int) $_SESSION['user_id']) {
            header('Location: admin.php?type=error&message=' . urlencode('You cannot delete your own account.'), true, 303);
            exit();
        }

        $detailsStmt = $conn->prepare('SELECT username, email FROM users WHERE id = :id LIMIT 1');
        $detailsStmt->bindParam(':id', $targetUserId, PDO::PARAM_INT);
        $detailsStmt->execute();
        $targetUser = $detailsStmt->fetch(PDO::FETCH_ASSOC) ?: [];

        $stmt = $conn->prepare('DELETE FROM users WHERE id = :id');
        $stmt->bindParam(':id', $targetUserId, PDO::PARAM_INT);

        if($stmt->execute() && $stmt->rowCount() > 0) {
            log_admin_action(
                $conn,
                (int) $_SESSION['user_id'],
                'delete_user',
                'user',
                $targetUserId,
                json_encode($targetUser)
            );
            header('Location: admin.php?type=success&message=' . urlencode('User deleted successfully.'), true, 303);
            exit();
        }

        header('Location: admin.php?type=error&message=' . urlencode('Could not delete user.'), true, 303);
        exit();
    } else if($hasTargetJob) {
        // DELETE JOB
        $limit = check_rate_limit($conn, 'admin_delete_job', (string) $_SESSION['user_id'] . '|' . client_ip_address(), 25, 300, 300);
        if(!$limit['allowed']) {
            header('Location: admin.php?type=error&message=' . urlencode('Too many delete requests. Try again later.'), true, 303);
            exit();
        }

        $targetJobId = (int) ($_POST['target_job_id'] ?? 0);

        if($targetJobId <= 0) {
            header('Location: admin.php?type=error&message=' . urlencode('Invalid job selected.'), true, 303);
            exit();
        }

        $detailsStmt = $conn->prepare('SELECT company, position, status FROM jobs WHERE id = :id LIMIT 1');
        $detailsStmt->bindParam(':id', $targetJobId, PDO::PARAM_INT);
        $detailsStmt->execute();
        $targetJob = $detailsStmt->fetch(PDO::FETCH_ASSOC) ?: [];

        $stmt = $conn->prepare('DELETE FROM jobs WHERE id = :id');
        $stmt->bindParam(':id', $targetJobId, PDO::PARAM_INT);

        if($stmt->execute() && $stmt->rowCount() > 0) {
            log_admin_action(
                $conn,
                (int) $_SESSION['user_id'],
                'delete_job',
                'job',
                $targetJobId,
                json_encode($targetJob)
            );
            header('Location: admin.php?type=success&message=' . urlencode('Job deleted successfully.'), true, 303);
            exit();
        }

        header('Location: admin.php?type=error&message=' . urlencode('Could not delete job.'), true, 303);
        exit();
    }
}

$summary = [
    'users' => 0,
    'jobs' => 0,
    'applied' => 0,
    'interview' => 0,
    'offered' => 0,
    'rejected' => 0
];

$summary['users'] = (int) $conn->query('SELECT COUNT(*) FROM users')->fetchColumn();
$summary['jobs'] = (int) $conn->query('SELECT COUNT(*) FROM jobs')->fetchColumn();
$summary['applied'] = (int) $conn->query("SELECT COUNT(*) FROM jobs WHERE status = 'applied'")->fetchColumn();
$summary['interview'] = (int) $conn->query("SELECT COUNT(*) FROM jobs WHERE status = 'interview'")->fetchColumn();
$summary['offered'] = (int) $conn->query("SELECT COUNT(*) FROM jobs WHERE status = 'offered'")->fetchColumn();
$summary['rejected'] = (int) $conn->query("SELECT COUNT(*) FROM jobs WHERE status = 'rejected'")->fetchColumn();

$usersStmt = $conn->query('SELECT id, username, email, is_admin, created_at FROM users ORDER BY created_at DESC');
$users = $usersStmt->fetchAll(PDO::FETCH_ASSOC);

$jobsStmt = $conn->query('SELECT j.id, u.username, j.company, j.position, j.status, j.last_action, j.created_at, j.updated_at FROM jobs j INNER JOIN users u ON u.id = j.user_id ORDER BY j.created_at DESC LIMIT 400');
$jobs = $jobsStmt->fetchAll(PDO::FETCH_ASSOC);

$tablesStmt = $conn->prepare(
    'SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME'
);
$tablesStmt->execute();
$tables = $tablesStmt->fetchAll(PDO::FETCH_COLUMN);

$mailSettings = get_mail_settings($conn);

$tableRows = [];
foreach($tables as $tableName) {
    $safeName = preg_replace('/[^a-zA-Z0-9_]/', '', (string) $tableName);
    if($safeName === '') {
        continue;
    }
    $count = (int) $conn->query("SELECT COUNT(*) FROM `{$safeName}`")->fetchColumn();
    $tableRows[] = ['table' => $safeName, 'rows' => $count];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="style/admin.css">
</head>
<body>
    <div class="admin-shell">
        <header class="admin-top">
            <div>
                <h1>Admin Dashboard</h1>
                <p>View all users, all jobs, and quick database statistics.</p>
            </div>
            <div class="actions">
                <a href="index.php?logout=1">Log Out</a>
            </div>
        </header>

        <?php if($flashMessage !== ''): ?>
            <div class="flash <?php echo $flashType === 'error' ? 'flash-error' : 'flash-success'; ?>">
                <?php echo htmlspecialchars($flashMessage, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <section class="cards">
            <article><h3>Total Users</h3><p><?php echo $summary['users']; ?></p></article>
            <article><h3>Total Jobs</h3><p><?php echo $summary['jobs']; ?></p></article>
            <article><h3>Applied</h3><p><?php echo $summary['applied']; ?></p></article>
            <article><h3>Interview</h3><p><?php echo $summary['interview']; ?></p></article>
            <article><h3>Offered</h3><p><?php echo $summary['offered']; ?></p></article>
            <article><h3>Rejected</h3><p><?php echo $summary['rejected']; ?></p></article>
        </section>

        <section class="panel">
            <h2>Email Settings</h2>
            <p class="panel-note">Configure the sender once here. Users can then request reset codes without editing any files.</p>
            <form method="POST" action="admin.php" class="mail-settings-form">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
                <div class="settings-grid">
                    <label>
                        <span>SMTP Host</span>
                        <input type="text" name="smtp_host" value="<?php echo htmlspecialchars($mailSettings['smtp_host'], ENT_QUOTES, 'UTF-8'); ?>" placeholder="smtp.gmail.com" required>
                    </label>
                    <label>
                        <span>SMTP Port</span>
                        <input type="number" name="smtp_port" value="<?php echo (int) $mailSettings['smtp_port']; ?>" min="1" max="65535" required>
                    </label>
                    <label>
                        <span>Encryption</span>
                        <select name="smtp_encryption">
                            <option value="tls" <?php echo $mailSettings['smtp_encryption'] === 'tls' ? 'selected' : ''; ?>>TLS</option>
                            <option value="ssl" <?php echo $mailSettings['smtp_encryption'] === 'ssl' ? 'selected' : ''; ?>>SSL</option>
                            <option value="none" <?php echo $mailSettings['smtp_encryption'] === 'none' ? 'selected' : ''; ?>>None</option>
                        </select>
                    </label>
                    <label>
                        <span>SMTP Username</span>
                        <input type="text" name="smtp_username" value="<?php echo htmlspecialchars($mailSettings['smtp_username'], ENT_QUOTES, 'UTF-8'); ?>" placeholder="your-email@gmail.com" required>
                    </label>
                    <label>
                        <span>SMTP Password or App Password</span>
                        <input type="password" name="smtp_password" value="<?php echo htmlspecialchars($mailSettings['smtp_password'], ENT_QUOTES, 'UTF-8'); ?>" required>
                    </label>
                    <label>
                        <span>From Email</span>
                        <input type="email" name="from_email" value="<?php echo htmlspecialchars($mailSettings['from_email'], ENT_QUOTES, 'UTF-8'); ?>" required>
                    </label>
                    <label>
                        <span>From Name</span>
                        <input type="text" name="from_name" value="<?php echo htmlspecialchars($mailSettings['from_name'], ENT_QUOTES, 'UTF-8'); ?>" placeholder="JobTracker">
                    </label>
                </div>
                <button type="submit" name="save-mail-settings-btn">Save Email Settings</button>
            </form>
        </section>

        <section class="panel">
            <h2>Database Tables</h2>
            <table>
                <thead><tr><th>Table</th><th>Rows</th></tr></thead>
                <tbody>
                    <?php foreach($tableRows as $table): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($table['table'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo (int) $table['rows']; ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </section>

        <section class="panel">
            <h2>All Users</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th><th>Username</th><th>Email</th><th>Admin</th><th>Created</th><th>Role Action</th><th>Delete</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach($users as $user): ?>
                        <tr>
                            <td><?php echo (int) $user['id']; ?></td>
                            <td><?php echo htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars((string) ($user['email'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo (int) $user['is_admin'] === 1 ? 'Yes' : 'No'; ?></td>
                            <td><?php echo htmlspecialchars($user['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td>
                                <form method="POST" action="admin.php" class="inline-form">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
                                    <input type="hidden" name="target_user_id" value="<?php echo (int) $user['id']; ?>">
                                    <input type="hidden" name="next_admin_value" value="<?php echo (int) $user['is_admin'] === 1 ? 0 : 1; ?>">
                                    <button type="submit" name="toggle-admin-btn">
                                        <?php echo (int) $user['is_admin'] === 1 ? 'Remove Admin' : 'Make Admin'; ?>
                                    </button>
                                </form>
                            </td>
                            <td>
                                <form method="POST" action="admin.php" class="inline-form confirm-delete" data-confirm-message="Delete this user and all their jobs?">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
                                    <input type="hidden" name="target_user_id" value="<?php echo (int) $user['id']; ?>">
                                    <button type="submit" name="delete-user-btn" class="danger-btn" <?php echo (int) $user['id'] === (int) $_SESSION['user_id'] ? 'disabled' : ''; ?>>Delete User</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </section>

        <section class="panel">
            <h2>All Jobs (Latest 400)</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th><th>User</th><th>Company</th><th>Position</th><th>Status</th><th>Last Action</th><th>Created</th><th>Updated</th><th>Delete</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach($jobs as $job): ?>
                        <tr>
                            <td><?php echo (int) $job['id']; ?></td>
                            <td><?php echo htmlspecialchars($job['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars($job['company'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars($job['position'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars($job['status'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars($job['last_action'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars($job['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars($job['updated_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td>
                                <form method="POST" action="admin.php" class="inline-form confirm-delete" data-confirm-message="Delete this job permanently?">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
                                    <input type="hidden" name="target_job_id" value="<?php echo (int) $job['id']; ?>">
                                    <button type="submit" name="delete-job-btn" class="danger-btn">Delete Job</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </section>
    </div>

    <div class="confirm-modal" id="confirm-modal" aria-hidden="true">
        <div class="confirm-dialog">
            <h3>Confirm Action</h3>
            <p id="confirm-message">Are you sure?</p>
            <div class="confirm-actions">
                <button type="button" id="confirm-cancel">Cancel</button>
                <button type="button" id="confirm-accept" class="danger-btn">Delete</button>
            </div>
        </div>
    </div>

    <script>
        const modal = document.getElementById('confirm-modal');
        const confirmMessage = document.getElementById('confirm-message');
        const cancelBtn = document.getElementById('confirm-cancel');
        const acceptBtn = document.getElementById('confirm-accept');
        let pendingForm = null;

        document.querySelectorAll('form.confirm-delete').forEach((form) => {
            form.addEventListener('submit', (event) => {
                event.preventDefault();
                pendingForm = form;
                confirmMessage.textContent = form.dataset.confirmMessage || 'Are you sure?';
                modal.classList.add('show');
                modal.setAttribute('aria-hidden', 'false');
            });
        });

        cancelBtn.addEventListener('click', () => {
            modal.classList.remove('show');
            modal.setAttribute('aria-hidden', 'true');
            pendingForm = null;
        });

        acceptBtn.addEventListener('click', () => {
            if(pendingForm) {
                // Add a hidden input to mark that delete was confirmed
                const confirmInput = document.createElement('input');
                confirmInput.type = 'hidden';
                confirmInput.name = 'confirm_delete_action';
                confirmInput.value = '1';
                pendingForm.appendChild(confirmInput);
                pendingForm.submit();
            }
        });
    </script>
</body>
</html>
