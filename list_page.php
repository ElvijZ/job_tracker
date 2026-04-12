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
$showUserStats = true;
$search = trim($_GET['q'] ?? '');
$statusFilter = normalize_status($_GET['status'] ?? 'all');
if(($_GET['status'] ?? 'all') === 'all') {
    $statusFilter = 'all';
}
$page = max(1, (int) ($_GET['page'] ?? 1));
$perPage = 24;
$offset = ($page - 1) * $perPage;

$where = ' WHERE user_id = :user_id ';
$params = [':user_id' => (int) $_SESSION['user_id']];

if($search !== '') {
    $where .= ' AND (position LIKE :search OR company LIKE :search OR notes LIKE :search) ';
    $params[':search'] = '%' . $search . '%';
}

if($statusFilter !== 'all') {
    $where .= ' AND status = :status_filter ';
    $params[':status_filter'] = $statusFilter;
}

$countStmt = $conn->prepare('SELECT COUNT(*) FROM jobs ' . $where);
foreach($params as $key => $value) {
    $countStmt->bindValue($key, $value);
}
$countStmt->execute();
$totalJobs = (int) $countStmt->fetchColumn();
$totalPages = max(1, (int) ceil($totalJobs / $perPage));
if($page > $totalPages) {
    $page = $totalPages;
    $offset = ($page - 1) * $perPage;
}

$stats = [
    'total' => 0,
    'applied' => 0,
    'interview' => 0,
    'offered' => 0,
    'rejected' => 0,
    'recent' => 0,
    'active' => 0
];

if($showUserStats) {
    $statsStmt = $conn->prepare(
        "SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END) AS applied,
            SUM(CASE WHEN status = 'interview' THEN 1 ELSE 0 END) AS interview,
            SUM(CASE WHEN status = 'offered' THEN 1 ELSE 0 END) AS offered,
            SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected,
            SUM(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 ELSE 0 END) AS recent,
            SUM(CASE WHEN status IN ('applied', 'interview') THEN 1 ELSE 0 END) AS active
         FROM jobs
         WHERE user_id = :user_id"
    );
    $statsStmt->bindValue(':user_id', (int) $_SESSION['user_id'], PDO::PARAM_INT);
    $statsStmt->execute();
    $statsRow = $statsStmt->fetch(PDO::FETCH_ASSOC) ?: [];

    foreach($stats as $key => $value) {
        $stats[$key] = (int) ($statsRow[$key] ?? 0);
    }
}

$jobsStmt = $conn->prepare('SELECT id, position, company, status, notes, applied_date, created_at FROM jobs ' . $where . ' ORDER BY created_at DESC LIMIT :limit OFFSET :offset');
foreach($params as $key => $value) {
    $jobsStmt->bindValue($key, $value);
}
$jobsStmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
$jobsStmt->bindValue(':offset', $offset, PDO::PARAM_INT);
$jobsStmt->execute();
$jobs = $jobsStmt->fetchAll(PDO::FETCH_ASSOC);

$columns = [
    'applied' => 'Applied',
    'interview' => 'Interview',
    'offered' => 'Offered',
    'rejected' => 'Rejected'
];

$jobsByStatus = [
    'applied' => [],
    'interview' => [],
    'offered' => [],
    'rejected' => []
];

foreach($jobs as $job) {
    $statusKey = normalize_status($job['status'] ?? 'applied');
    $jobsByStatus[$statusKey][] = $job;
}

$flashMessage = trim($_GET['message'] ?? '');
$flashType = ($_GET['type'] ?? '') === 'error' ? 'error' : 'success';

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Job Tracker - List Page</title>
    <link rel="stylesheet" href="style/list_page.css">
</head>
<body>
    <div class="page-shell">
        <header class="topbar">
            <div>
                <h1>Job Applications Board</h1>
                <p>Drag a job card and drop it into another column to update its status.</p>
            </div>
            <div class="topbar-actions">
                <a class="btn" href="insert_jobs.php">Insert New Job</a>
                <?php if(is_admin_user()): ?>
                    <a class="btn" href="admin.php">Admin Page</a>
                <?php endif; ?>
                <a class="btn btn-secondary" href="index.php?logout=1">Log Out</a>
            </div>
        </header>

        <?php if($showUserStats): ?>
            <section class="user-stats" aria-label="Your job statistics">
                <article class="stat-card stat-total">
                    <span class="stat-label">Total Jobs</span>
                    <strong><?php echo $stats['total']; ?></strong>
                </article>
                <article class="stat-card stat-applied">
                    <span class="stat-label">Applied</span>
                    <strong><?php echo $stats['applied']; ?></strong>
                </article>
                <article class="stat-card stat-interview">
                    <span class="stat-label">Interview</span>
                    <strong><?php echo $stats['interview']; ?></strong>
                </article>
                <article class="stat-card stat-offered">
                    <span class="stat-label">Offered</span>
                    <strong><?php echo $stats['offered']; ?></strong>
                </article>
                <article class="stat-card stat-rejected">
                    <span class="stat-label">Rejected</span>
                    <strong><?php echo $stats['rejected']; ?></strong>
                </article>
                <article class="stat-card stat-active">
                    <span class="stat-label">Active Pipeline</span>
                    <strong><?php echo $stats['active']; ?></strong>
                    <small><?php echo $stats['recent']; ?> added in last 30 days</small>
                </article>
            </section>
        <?php endif; ?>

        <form class="board-filters" method="GET" action="list_page.php">
            <input type="text" name="q" placeholder="Search position, company, notes" value="<?php echo htmlspecialchars($search, ENT_QUOTES, 'UTF-8'); ?>">
            <select name="status">
                <option value="all" <?php echo $statusFilter === 'all' ? 'selected' : ''; ?>>All Statuses</option>
                <option value="applied" <?php echo $statusFilter === 'applied' ? 'selected' : ''; ?>>Applied</option>
                <option value="interview" <?php echo $statusFilter === 'interview' ? 'selected' : ''; ?>>Interview</option>
                <option value="offered" <?php echo $statusFilter === 'offered' ? 'selected' : ''; ?>>Offered</option>
                <option value="rejected" <?php echo $statusFilter === 'rejected' ? 'selected' : ''; ?>>Rejected</option>
            </select>
            <button type="submit">Apply</button>
        </form>

        <?php if($flashMessage !== ''): ?>
            <div class="flash-message <?php echo $flashType === 'error' ? 'flash-error' : 'flash-success'; ?>">
                <?php echo htmlspecialchars($flashMessage, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <?php if(empty($jobs)): ?>
            <p class="empty-state">No jobs found yet. Add your first one.</p>
        <?php else: ?>
            <section class="board" id="job-board">
                <?php foreach($columns as $statusKey => $label): ?>
                    <article class="board-column" data-status="<?php echo htmlspecialchars($statusKey, ENT_QUOTES, 'UTF-8'); ?>">
                        <h2><?php echo htmlspecialchars($label, ENT_QUOTES, 'UTF-8'); ?></h2>
                        <p class="column-count"><?php echo count($jobsByStatus[$statusKey]); ?> job(s)</p>

                        <div class="dropzone" data-status="<?php echo htmlspecialchars($statusKey, ENT_QUOTES, 'UTF-8'); ?>">
                            <?php foreach($jobsByStatus[$statusKey] as $job): ?>
                                <div
                                    class="job-card"
                                    draggable="true"
                                    data-job-id="<?php echo (int) $job['id']; ?>"
                                    data-current-status="<?php echo htmlspecialchars($statusKey, ENT_QUOTES, 'UTF-8'); ?>"
                                >
                                    <h3><?php echo htmlspecialchars($job['position'] ?? '', ENT_QUOTES, 'UTF-8'); ?></h3>
                                    <p class="company"><?php echo htmlspecialchars($job['company'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p class="meta">Applied: <?php echo htmlspecialchars($job['applied_date'] ?: date('Y-m-d', strtotime($job['created_at'] ?? 'now')), ENT_QUOTES, 'UTF-8'); ?></p>
                                    <?php if(!empty($job['notes'])): ?>
                                        <p class="notes"><?php echo htmlspecialchars($job['notes'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <?php endif; ?>

                                    <details class="manual-update" draggable="false">
                                        <summary>Manual Update</summary>
                                        <form class="manual-update-form" method="POST" action="backend/update_job_details.php" draggable="false">
                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
                                            <input type="hidden" name="job_id" value="<?php echo (int) $job['id']; ?>">

                                            <label for="position-<?php echo (int) $job['id']; ?>">Position</label>
                                            <input id="position-<?php echo (int) $job['id']; ?>" type="text" name="position" value="<?php echo htmlspecialchars($job['position'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>

                                            <label for="company-<?php echo (int) $job['id']; ?>">Company</label>
                                            <input id="company-<?php echo (int) $job['id']; ?>" type="text" name="company" value="<?php echo htmlspecialchars($job['company'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>

                                            <label for="status-<?php echo (int) $job['id']; ?>">Status</label>
                                            <select id="status-<?php echo (int) $job['id']; ?>" name="status" required>
                                                <option value="applied" <?php echo $statusKey === 'applied' ? 'selected' : ''; ?>>Applied</option>
                                                <option value="interview" <?php echo $statusKey === 'interview' ? 'selected' : ''; ?>>Interview</option>
                                                <option value="offered" <?php echo $statusKey === 'offered' ? 'selected' : ''; ?>>Offered</option>
                                                <option value="rejected" <?php echo $statusKey === 'rejected' ? 'selected' : ''; ?>>Rejected</option>
                                            </select>

                                            <label for="applied-date-<?php echo (int) $job['id']; ?>">Applied Date</label>
                                            <input id="applied-date-<?php echo (int) $job['id']; ?>" type="date" name="applied_date" value="<?php echo htmlspecialchars($job['applied_date'] ?: date('Y-m-d', strtotime($job['created_at'] ?? 'now')), ENT_QUOTES, 'UTF-8'); ?>" required>

                                            <label for="notes-<?php echo (int) $job['id']; ?>">Notes</label>
                                            <textarea id="notes-<?php echo (int) $job['id']; ?>" name="notes" rows="3"><?php echo htmlspecialchars($job['notes'] ?? '', ENT_QUOTES, 'UTF-8'); ?></textarea>

                                            <button type="submit">Save Changes</button>
                                        </form>
                                    </details>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </article>
                <?php endforeach; ?>
            </section>
        <?php endif; ?>

        <?php if($totalPages > 1): ?>
            <nav class="pagination" aria-label="Board pagination">
                <?php for($i = 1; $i <= $totalPages; $i++): ?>
                    <a class="<?php echo $i === $page ? 'active' : ''; ?>" href="list_page.php?page=<?php echo $i; ?>&amp;q=<?php echo urlencode($search); ?>&amp;status=<?php echo urlencode($statusFilter); ?>"><?php echo $i; ?></a>
                <?php endfor; ?>
            </nav>
        <?php endif; ?>
    </div>

    <div id="toast" class="toast" aria-live="polite"></div>

    <script>
        const cards = document.querySelectorAll('.job-card');
        const dropzones = document.querySelectorAll('.dropzone');
        const csrfToken = '<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>';
        let draggingCard = null;
        let sourceDropzone = null;

        const toast = document.getElementById('toast');
        const showToast = (message, isError = false) => {
            toast.textContent = message;
            toast.classList.toggle('error', isError);
            toast.classList.add('show');
            window.setTimeout(() => {
                toast.classList.remove('show');
            }, 2600);
        };

        cards.forEach((card) => {
            card.addEventListener('dragstart', () => {
                if(document.activeElement && ['INPUT', 'TEXTAREA', 'SELECT', 'BUTTON'].includes(document.activeElement.tagName)) {
                    return;
                }
                draggingCard = card;
                sourceDropzone = card.parentElement;
                card.classList.add('is-dragging');
            });

            card.addEventListener('dragend', () => {
                card.classList.remove('is-dragging');
            });
        });

        dropzones.forEach((zone) => {
            zone.addEventListener('dragover', (event) => {
                event.preventDefault();
                zone.classList.add('is-active');
            });

            zone.addEventListener('dragleave', () => {
                zone.classList.remove('is-active');
            });

            zone.addEventListener('drop', async (event) => {
                event.preventDefault();
                zone.classList.remove('is-active');

                if(!draggingCard) {
                    return;
                }

                const newStatus = zone.dataset.status;
                const oldStatus = draggingCard.dataset.currentStatus;

                if(newStatus === oldStatus) {
                    return;
                }

                zone.appendChild(draggingCard);

                const formData = new FormData();
                formData.append('job_id', draggingCard.dataset.jobId);
                formData.append('status', newStatus);
                formData.append('csrf_token', csrfToken);

                try {
                    const response = await fetch('backend/update_job_status.php', {
                        method: 'POST',
                        body: formData
                    });

                    const result = await response.json();
                    if(!response.ok || !result.success) {
                        throw new Error(result.message || 'Unable to update status.');
                    }

                    draggingCard.dataset.currentStatus = newStatus;
                    showToast('Status updated');
                } catch(error) {
                    if(sourceDropzone) {
                        sourceDropzone.appendChild(draggingCard);
                    }
                    showToast(error.message, true);
                }
            });
        });
    </script>
</body>
</html>