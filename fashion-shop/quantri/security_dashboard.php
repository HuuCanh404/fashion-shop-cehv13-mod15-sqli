<?php
define('SECURITY_DASHBOARD_CONTEXT', true);
require_once __DIR__ . '/includes/header.php';
require_once __DIR__ . '/../database/dbhelper.php';

if (empty($_SESSION['sec_csrf'])) {
    $_SESSION['sec_csrf'] = bin2hex(random_bytes(16));
}
$csrfToken = $_SESSION['sec_csrf'];

$feedbackMsg = '';
$feedbackType = 'info';
$sandboxOutput = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!hash_equals($csrfToken, $submittedToken)) {
        $feedbackMsg = 'Mã CSRF không hợp lệ, vui lòng tải lại trang.';
        $feedbackType = 'danger';
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'save_config') {
            $newCfg = [
                'lab_mode' => ($_POST['lab_mode'] ?? 'hardened') === 'vulnerable' ? 'vulnerable' : 'hardened',
                'enforce_admin_auth' => isset($_POST['enforce_admin_auth']),
                'rate_limit_enabled' => isset($_POST['rate_limit_enabled']),
                'rate_limit_window_sec' => (int)($_POST['rate_limit_window_sec'] ?? 60),
                'rate_limit_max_requests' => (int)($_POST['rate_limit_max_requests'] ?? 10),
                'rate_limit_cooldown_sec' => (int)($_POST['rate_limit_cooldown_sec'] ?? 600),
                'otp_enabled' => isset($_POST['otp_enabled']),
                'deception_enabled' => isset($_POST['deception_enabled']),
                'cloudflare_mode' => isset($_POST['cloudflare_mode'])
            ];
            SecurityDefense::saveConfig($newCfg);
            SecurityDefense::logSecurityIncident(
                SecurityDefense::getClientIp(),
                'ADMIN_POLICY_UPDATE: Cập nhật lab_mode=' . $newCfg['lab_mode']
                . ', auth_guard=' . ($newCfg['enforce_admin_auth'] ? 'ON' : 'OFF')
                . ', rate=' . $newCfg['rate_limit_max_requests'] . '/' . $newCfg['rate_limit_window_sec'] . 's'
            );
            $feedbackMsg = 'Đã lưu cấu hình bảo mật mới vào defense_config.json.';
            $feedbackType = 'success';
        } elseif ($action === 'preset_vulnerable') {
            SecurityDefense::saveConfig([
                'lab_mode' => 'vulnerable',
                'enforce_admin_auth' => false,
                'rate_limit_enabled' => false,
                'otp_enabled' => false,
                'deception_enabled' => false,
                'cloudflare_mode' => true,
                'rate_limit_window_sec' => 60,
                'rate_limit_max_requests' => 10,
                'rate_limit_cooldown_sec' => 600
            ]);
            SecurityDefense::logSecurityIncident(SecurityDefense::getClientIp(), 'DEMO_MODE: Chuyển hệ thống sang trạng thái VULNERABLE để minh họa.');
            $feedbackMsg = 'Đã bật chế độ VULNERABLE DEMO (tắt tường bảo vệ & tắt Auth Guard để tái hiện lỗi tại lớp).';
            $feedbackType = 'warning';
        } elseif ($action === 'preset_hardened') {
            SecurityDefense::saveConfig(SecurityDefense::defaultConfig());
            SecurityDefense::logSecurityIncident(SecurityDefense::getClientIp(), 'DEMO_MODE: Kích hoạt đầy đủ phòng thủ 4 lớp (10 req/60s -> chặn 600s, OTP, HTTP 200 Decoy).');
            $feedbackMsg = 'Đã kích hoạt chuẩn Phòng thủ 4 lớp (10 req/1 phút -> chặn 10 phút, OTP, Nghi binh HTTP 200 OK).';
            $feedbackType = 'success';
        } elseif ($action === 'unblock_ip') {
            $ipTarget = trim($_POST['ip_target'] ?? '');
            if ($ipTarget !== '' && SecurityDefense::unblockIp($ipTarget)) {
                $feedbackMsg = "Đã gỡ chặn IP {$ipTarget}.";
                $feedbackType = 'success';
            }
        } elseif ($action === 'clear_rate_limits') {
            $removed = SecurityDefense::clearAllRateLimits();
            $feedbackMsg = "Đã đặt lại bộ đếm Rate Limit ({$removed} tệp).";
            $feedbackType = 'success';
        } elseif ($action === 'clear_logs') {
            SecurityDefense::clearAuditLog();
            $feedbackMsg = 'Đã xóa nhật ký security_audit.log.';
            $feedbackType = 'info';
        } elseif ($action === 'issue_test_otp') {
            $otpInfo = SecurityDefense::issueOtpChallenge($_SESSION['user_name'] ?? 'admin_demo', SecurityDefense::getClientIp());
            $feedbackMsg = 'Đã tạo mã OTP mô phỏng mới: ' . $otpInfo['code_for_lab_preview'] . ' (lưu trong otp_mailbox.log).';
            $feedbackType = 'info';
        } elseif ($action === 'run_sandbox') {
            $term = $_POST['sandbox_term'] ?? '';
            $cfgNow = SecurityDefense::getConfig(true);
            $conn = createConnection();
            if (($cfgNow['lab_mode'] ?? 'hardened') === 'vulnerable') {
                $rawSql = "SELECT id, username, email, role FROM users WHERE username LIKE '%$term%' OR email LIKE '%$term%'";
                $rows = [];
                $sqlErr = '';
                try {
                    $res = $conn->query($rawSql);
                    if ($res instanceof mysqli_result) {
                        while ($r = $res->fetch_assoc()) {
                            $rows[] = $r;
                        }
                    }
                } catch (mysqli_sql_exception $e) {
                    $sqlErr = $e->getMessage();
                }
                $sandboxOutput = [
                    'mode' => 'vulnerable',
                    'layer' => 'KHÔNG BẢO VỆ (Ghép chuỗi SQL trực tiếp)',
                    'sql' => $rawSql,
                    'error' => $sqlErr,
                    'rows' => $rows,
                    'decoy' => false
                ];
            } else {
                $matched = !empty($cfgNow['deception_enabled']) ? SecurityDefense::matchSqliPattern($term) : null;
                if ($matched !== null) {
                    SecurityDefense::logSecurityIncident(
                        SecurityDefense::getClientIp(),
                        "SQLI_DECEPTION (Admin Sandbox): Phát hiện mẫu nghi ngờ ({$matched}) -> Trả phản hồi giả HTTP 200 OK."
                    );
                    $sandboxOutput = [
                        'mode' => 'hardened',
                        'layer' => 'Lớp 3: Nghi binh HTTP 200 OK (Không chạm tới CSDL thật)',
                        'sql' => 'BỊ CHẶN TẠI TẦNG KIỂM SOÁT TRƯỚC KHI TRUY VẤN',
                        'error' => '',
                        'rows' => [
                            ['id' => 101, 'username' => 'sample_guest_1', 'email' => 'guest1@demo.local', 'role' => 'user'],
                            ['id' => 102, 'username' => 'sample_guest_2', 'email' => 'guest2@demo.local', 'role' => 'user']
                        ],
                        'decoy' => true,
                        'matched_pattern' => $matched
                    ];
                } else {
                    $sqlSafe = "SELECT id, username, email, role FROM users WHERE username LIKE ? OR email LIKE ?";
                    $likeVal = '%' . $term . '%';
                    $rows = executePrepared($conn, $sqlSafe, [$likeVal, $likeVal]);
                    $sandboxOutput = [
                        'mode' => 'hardened',
                        'layer' => 'Lớp 1: Truy vấn tham số hóa (Prepared Statement)',
                        'sql' => $sqlSafe . '  [Tham số tách biệt khỏi cấu trúc lệnh]',
                        'error' => '',
                        'rows' => is_array($rows) ? $rows : [],
                        'decoy' => false
                    ];
                }
            }
            $conn->close();
        }
    }
}

$cfg = SecurityDefense::getConfig(true);
$summary = SecurityDefense::getSecuritySummary();
$rateStates = SecurityDefense::listRateLimitStates();
$auditLogs = SecurityDefense::readAuditLog(40);
$otpLines = SecurityDefense::readOtpMailbox(10);
$isVuln = ($cfg['lab_mode'] === 'vulnerable');
?>

<div class="container-fluid py-2">
    <div class="dashboard-header d-flex justify-content-between align-items-center flex-wrap gap-2 mb-4">
        <div>
            <h2 class="dashboard-title mb-1"><i class="fas fa-shield-alt me-2"></i>Trung tâm Quản lý An ninh & Demo Module 15</h2>
            <p class="dashboard-subtitle mb-0">Giám sát SQL Injection, giới hạn tần suất (10 req/1 phút), xác minh OTP, nghi binh HTTP 200 OK & mô hình Cloudflare</p>
        </div>
        <div class="d-flex gap-2">
            <form method="POST" class="d-inline">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                <input type="hidden" name="action" value="preset_vulnerable">
                <button type="submit" class="btn btn-outline-danger"><i class="fas fa-bug me-1"></i>Bật Demo Lỗi (Vulnerable)</button>
            </form>
            <form method="POST" class="d-inline">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                <input type="hidden" name="action" value="preset_hardened">
                <button type="submit" class="btn btn-success"><i class="fas fa-lock me-1"></i>Bật Chuẩn Phòng Thủ 4 Lớp</button>
            </form>
        </div>
    </div>

    <?php if ($feedbackMsg): ?>
        <div class="alert alert-<?= htmlspecialchars($feedbackType) ?> alert-dismissible fade show" role="alert">
            <?= htmlspecialchars($feedbackMsg) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <!-- KPI Cards -->
    <div class="row g-3 mb-4">
        <div class="col-md-3">
            <div class="card border-0 shadow-sm h-100 <?= $isVuln ? 'border-start border-danger border-4' : 'border-start border-success border-4' ?>">
                <div class="card-body">
                    <div class="small text-muted">Trạng thái Lab hiện tại</div>
                    <h4 class="fw-bold mt-1 <?= $isVuln ? 'text-danger' : 'text-success' ?>">
                        <?= $isVuln ? 'VULNERABLE' : 'HARDENED' ?>
                    </h4>
                    <div class="small">Auth Guard: <strong><?= $cfg['enforce_admin_auth'] ? 'BẬT' : 'TẮT' ?></strong></div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-0 shadow-sm h-100 border-start border-primary border-4">
                <div class="card-body">
                    <div class="small text-muted">Phản hồi Nghi binh HTTP 200 OK</div>
                    <h4 class="fw-bold mt-1 text-primary"><?= (int)$summary['deception_hits'] ?></h4>
                    <div class="small">Đánh lừa công cụ quét tự động</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-0 shadow-sm h-100 border-start border-warning border-4">
                <div class="card-body">
                    <div class="small text-muted">IP đang bị khóa Rate Limit</div>
                    <h4 class="fw-bold mt-1 text-warning"><?= (int)$summary['active_blocked_ips'] ?></h4>
                    <div class="small">Ngưỡng: <?= (int)$cfg['rate_limit_max_requests'] ?> req / <?= (int)$cfg['rate_limit_window_sec'] ?>s</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-0 shadow-sm h-100 border-start border-dark border-4">
                <div class="card-body">
                    <div class="small text-muted">Tổng sự kiện ghi nhận</div>
                    <h4 class="fw-bold mt-1"><?= (int)$summary['total_events'] ?></h4>
                    <div class="small">Từ chối truy cập: <?= (int)$summary['auth_denied'] ?> | OTP: <?= (int)$summary['otp_events'] ?></div>
                </div>
            </div>
        </div>
    </div>

    <div class="row g-4 mb-4">
        <!-- Policy Control -->
        <div class="col-lg-5">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white fw-bold">
                    <i class="fas fa-sliders-h me-2 text-primary"></i>Cấu hình Chính sách Bảo vệ
                </div>
                <div class="card-body">
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <input type="hidden" name="action" value="save_config">

                        <div class="mb-3">
                            <label class="form-label fw-semibold">Chế độ vận hành (Lab Mode)</label>
                            <select name="lab_mode" class="form-select">
                                <option value="hardened" <?= !$isVuln ? 'selected' : '' ?>>Hardened — Bật đầy đủ các lớp phòng thủ</option>
                                <option value="vulnerable" <?= $isVuln ? 'selected' : '' ?>>Vulnerable — Mở lỗi SQLi để demo tại lớp</option>
                            </select>
                        </div>

                        <div class="row g-2 mb-3">
                            <div class="col-4">
                                <label class="form-label small">Số request tối đa</label>
                                <input type="number" name="rate_limit_max_requests" class="form-control" min="1" value="<?= (int)$cfg['rate_limit_max_requests'] ?>">
                            </div>
                            <div class="col-4">
                                <label class="form-label small">Cửa sổ (giây)</label>
                                <input type="number" name="rate_limit_window_sec" class="form-control" min="5" value="<?= (int)$cfg['rate_limit_window_sec'] ?>">
                            </div>
                            <div class="col-4">
                                <label class="form-label small">Khóa (giây)</label>
                                <input type="number" name="rate_limit_cooldown_sec" class="form-control" min="5" value="<?= (int)$cfg['rate_limit_cooldown_sec'] ?>">
                            </div>
                        </div>

                        <div class="form-check form-switch mb-2">
                            <input class="form-check-input" type="checkbox" name="enforce_admin_auth" id="swAuth" <?= $cfg['enforce_admin_auth'] ? 'checked' : '' ?>>
                            <label class="form-check-label" for="swAuth">Bật kiểm tra đăng nhập Admin (Chống vào thẳng URL quản trị)</label>
                        </div>
                        <div class="form-check form-switch mb-2">
                            <input class="form-check-input" type="checkbox" name="rate_limit_enabled" id="swRate" <?= $cfg['rate_limit_enabled'] ? 'checked' : '' ?>>
                            <label class="form-check-label" for="swRate">Bật giới hạn tần suất (Mặc định: 10 lần/1 phút → khóa 10 phút)</label>
                        </div>
                        <div class="form-check form-switch mb-2">
                            <input class="form-check-input" type="checkbox" name="otp_enabled" id="swOtp" <?= $cfg['otp_enabled'] ? 'checked' : '' ?>>
                            <label class="form-check-label" for="swOtp">Bật xác minh OTP bước 2 khi đăng nhập Admin</label>
                        </div>
                        <div class="form-check form-switch mb-2">
                            <input class="form-check-input" type="checkbox" name="deception_enabled" id="swDecoy" <?= $cfg['deception_enabled'] ? 'checked' : '' ?>>
                            <label class="form-check-label" for="swDecoy">Bật phản hồi giả HTTP 200 OK (Nghi binh thay vì báo lỗi)</label>
                        </div>
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" name="cloudflare_mode" id="swCf" <?= $cfg['cloudflare_mode'] ? 'checked' : '' ?>>
                            <label class="form-check-label" for="swCf">Đọc IP thật qua Cloudflare (<code>CF-Connecting-IP</code>)</label>
                        </div>

                        <button type="submit" class="btn btn-primary w-100"><i class="fas fa-save me-1"></i>Lưu chính sách</button>
                    </form>
                </div>
            </div>
        </div>

        <!-- Admin SQLi Lab Sandbox -->
        <div class="col-lg-7">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white fw-bold d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-flask me-2 text-danger"></i>Sandbox Demo SQL Injection & Phòng thủ ngay trên Admin</span>
                    <span class="badge <?= $isVuln ? 'bg-danger' : 'bg-success' ?>"><?= $isVuln ? 'Đang mở lỗi' : 'Đang bảo vệ' ?></span>
                </div>
                <div class="card-body">
                    <p class="small text-muted">
                        Nhập từ khóa tìm kiếm tài khoản để quan sát cách câu lệnh SQL được tạo ở chế độ <strong>Vulnerable</strong> (ghép chuỗi trực tiếp) so với chế độ <strong>Hardened</strong> (Prepared Statement &amp; Phản hồi giả HTTP 200 OK).
                    </p>
                    <form method="POST" class="row g-2 mb-3">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <input type="hidden" name="action" value="run_sandbox">
                        <div class="col-md-9">
                            <input type="text" name="sandbox_term" class="form-control" placeholder="Nhập tên tài khoản (VD: Huyền) hoặc chuỗi kiểm thử logic SQL..." value="<?= htmlspecialchars($_POST['sandbox_term'] ?? '') ?>">
                        </div>
                        <div class="col-md-3">
                            <button type="submit" class="btn btn-dark w-100">Chạy thử</button>
                        </div>
                    </form>

                    <?php if ($sandboxOutput !== null): ?>
                        <div class="border rounded p-3 bg-light mb-3">
                            <div class="fw-bold mb-1 <?= $sandboxOutput['decoy'] ? 'text-primary' : ($sandboxOutput['mode'] === 'vulnerable' ? 'text-danger' : 'text-success') ?>">
                                Cơ chế áp dụng: <?= htmlspecialchars($sandboxOutput['layer']) ?>
                            </div>
                            <div class="small mb-2"><strong>SQL:</strong> <code><?= htmlspecialchars($sandboxOutput['sql']) ?></code></div>
                            <?php if (!empty($sandboxOutput['error'])): ?>
                                <div class="alert alert-danger py-1 px-2 small mb-2"><strong>Lỗi CSDL rò rỉ:</strong> <?= htmlspecialchars($sandboxOutput['error']) ?></div>
                            <?php endif; ?>
                            <?php if (!empty($sandboxOutput['decoy'])): ?>
                                <div class="alert alert-info py-1 px-2 small mb-2">
                                    <strong>Chú thích:</strong> Hệ thống đã trả về <strong>HTTP 200 OK</strong> với dữ liệu giả lập bên dưới để đối phương tưởng đã lấy được kết quả và dừng dò quét, trong khi CSDL thật không hề bị chạm tới.
                                </div>
                            <?php endif; ?>
                            <div class="table-responsive">
                                <table class="table table-sm table-bordered bg-white mb-0">
                                    <thead><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr></thead>
                                    <tbody>
                                        <?php if (empty($sandboxOutput['rows'])): ?>
                                            <tr><td colspan="4" class="text-center text-muted">Không có bản ghi trả về</td></tr>
                                        <?php else: ?>
                                            <?php foreach ($sandboxOutput['rows'] as $row): ?>
                                                <tr>
                                                    <td><?= htmlspecialchars((string)($row['id'] ?? '')) ?></td>
                                                    <td><?= htmlspecialchars((string)($row['username'] ?? '')) ?></td>
                                                    <td><?= htmlspecialchars((string)($row['email'] ?? '')) ?></td>
                                                    <td><?= htmlspecialchars((string)($row['role'] ?? '')) ?></td>
                                                </tr>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    <?php endif; ?>

                    <div class="small fw-semibold mb-1">Các điểm Demo trực tiếp khác trên hệ thống:</div>
                    <div class="d-flex flex-wrap gap-2">
                        <a href="/shopweb/quantri/admin_login.php" target="_blank" class="btn btn-sm btn-outline-dark">Cổng Login Admin (+ OTP)</a>
                        <a href="/shopweb/xacthuc/login.php" target="_blank" class="btn btn-sm btn-outline-danger">Cổng Login Khách -> Leo thang Admin</a>
                        <a href="/shopweb/quantri/user_management/admin_management.php" target="_blank" class="btn btn-sm btn-outline-dark">Tìm kiếm Người dùng Admin</a>
                        <a href="/shopweb/quantri/editsp.php?id=3" target="_blank" class="btn btn-sm btn-outline-dark">Sửa sản phẩm theo ID</a>
                        <a href="/shopweb/fontend/search_results.php?q=ao" target="_blank" class="btn btn-sm btn-outline-dark">Tìm kiếm Trang chủ (HTML)</a>
                        <a href="/shopweb/xacthuc/login_demo.php" target="_blank" class="btn btn-sm btn-outline-dark">Demo Login Khách</a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Rate Limit + OTP + Cloudflare -->
    <div class="row g-4 mb-4">
        <div class="col-lg-6">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white fw-bold d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-ban me-2 text-warning"></i>Danh sách IP & Trạng thái Rate Limit</span>
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <input type="hidden" name="action" value="clear_rate_limits">
                        <button type="submit" class="btn btn-sm btn-outline-secondary">Xóa toàn bộ bộ đếm</button>
                    </form>
                </div>
                <div class="card-body p-0">
                    <div class="table-responsive">
                        <table class="table table-sm mb-0">
                            <thead><tr><th>Địa chỉ IP</th><th>Request (cửa sổ)</th><th>Vi phạm</th><th>Trạng thái</th><th>Thao tác</th></tr></thead>
                            <tbody>
                                <?php if (empty($rateStates)): ?>
                                    <tr><td colspan="5" class="text-center text-muted py-3">Chưa có IP nào trong bộ đếm</td></tr>
                                <?php else: ?>
                                    <?php foreach ($rateStates as $st): ?>
                                        <tr>
                                            <td><code><?= htmlspecialchars($st['ip']) ?></code></td>
                                            <td><?= (int)$st['requests_in_window'] ?> / <?= (int)$cfg['rate_limit_max_requests'] ?></td>
                                            <td><?= (int)$st['violations'] ?></td>
                                            <td>
                                                <?php if ($st['quarantined']): ?>
                                                    <span class="badge bg-danger">Đang khóa (<?= (int)$st['remaining_sec'] ?>s)</span>
                                                <?php else: ?>
                                                    <span class="badge bg-success">Bình thường</span>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <form method="POST" class="d-inline">
                                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                                    <input type="hidden" name="action" value="unblock_ip">
                                                    <input type="hidden" name="ip_target" value="<?= htmlspecialchars($st['ip']) ?>">
                                                    <button type="submit" class="btn btn-xs btn-outline-primary py-0 px-2">Gỡ khóa</button>
                                                </form>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div class="col-lg-6">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white fw-bold d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-envelope-open-text me-2 text-info"></i>Hộp thư OTP Mô phỏng &amp; Hạ tầng Cloudflare / Nhà mạng</span>
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <input type="hidden" name="action" value="issue_test_otp">
                        <button type="submit" class="btn btn-sm btn-outline-info">Phát thử OTP</button>
                    </form>
                </div>
                <div class="card-body">
                    <div class="small fw-semibold mb-1">Mã OTP gần nhất (<code>quantri/logs/otp_mailbox.log</code>):</div>
                    <pre class="bg-dark text-light p-2 rounded small" style="max-height:130px; overflow-y:auto;"><?= empty($otpLines) ? "Chưa có mã OTP nào được phát." : htmlspecialchars(implode("\n", $otpLines)) ?></pre>
                    <div class="small border-top pt-2 mt-2">
                        <strong>Mô hình tích hợp Cloudflare + Đổi IP Nhà mạng:</strong>
                        <ul class="mb-0 ps-3">
                            <li><strong>Cloudflare WAF:</strong> Chặn yêu cầu chứa chữ ký SQL bất thường ngay tại lớp biên (Edge) trước khi tới máy chủ PHP.</li>
                            <li><strong>Header <code>CF-Connecting-IP</code>:</strong> Giúp Rate Limit xác định đúng IP thật của người gửi thay vì chặn nhầm IP Cloudflare.</li>
                            <li><strong>Phối hợp Nhà mạng đổi IP:</strong> Khi IP gốc (Origin IP) bị lộ và chịu lưu lượng dò quét kéo dài, đổi IP public kết hợp chỉ cho phép dải IP Cloudflare truy cập máy chủ.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Audit Logs -->
    <div class="card shadow-sm mb-4">
        <div class="card-header bg-white fw-bold d-flex justify-content-between align-items-center">
            <span><i class="fas fa-clipboard-list me-2 text-secondary"></i>Nhật ký Sự cố An ninh (<code>quantri/logs/security_audit.log</code>)</span>
            <div class="d-flex gap-2">
                <a href="security_dashboard.php" class="btn btn-sm btn-outline-primary">Làm mới</a>
                <form method="POST" class="d-inline">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    <input type="hidden" name="action" value="clear_logs">
                    <button type="submit" class="btn btn-sm btn-outline-danger">Xóa nhật ký</button>
                </form>
            </div>
        </div>
        <div class="card-body">
            <pre class="bg-light border p-3 rounded small mb-0" style="max-height:260px; overflow-y:auto;"><?= empty($auditLogs) ? "Nhật ký đang trống." : htmlspecialchars(implode("\n", $auditLogs)) ?></pre>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
