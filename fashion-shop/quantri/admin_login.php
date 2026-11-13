<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/../database/dbhelper.php';

$cfg = SecurityDefense::getConfig();
$mode = $_GET['mode'] ?? ($cfg['lab_mode'] ?? 'hardened');
$mode = ($mode === 'vulnerable') ? 'vulnerable' : 'hardened';

$conn = createConnection();
$error = '';
$info = '';
$debugSql = '';
$debugSqlError = '';
$pendingOtpUser = $_SESSION['pending_admin_otp_user'] ?? null;

// Handle OTP step-up submission in hardened mode
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'verify_otp') {
    $otpInput = trim($_POST['otp_code'] ?? '');
    if ($pendingOtpUser && SecurityDefense::verifyOtpChallenge($pendingOtpUser['username'], $otpInput)) {
        $_SESSION['user_id'] = $pendingOtpUser['id'];
        $_SESSION['user_name'] = $pendingOtpUser['username'];
        $_SESSION['admin_name'] = $pendingOtpUser['username'];
        $_SESSION['role'] = $pendingOtpUser['role'];
        unset($_SESSION['pending_admin_otp_user'], $_SESSION['pending_admin_otp_preview']);
        header('Location: /shopweb/quantri/security_dashboard.php');
        exit;
    } else {
        $error = 'Mã OTP không chính xác hoặc đã hết hạn. Vui lòng kiểm tra lại OTP.';
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'cancel_otp') {
    unset($_SESSION['pending_admin_otp_user'], $_SESSION['pending_admin_otp_preview']);
    $pendingOtpUser = null;
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $loginInput = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if ($mode === 'vulnerable') {
        // INTENTIONALLY VULNERABLE FOR CEH MODULE 15 CLASSROOM DEMO:
        // Direct string interpolation allows SQL logic manipulation
        $debugSql = "SELECT id, username, email, role FROM users WHERE role = 'admin' AND username = '$loginInput' AND password = '$password'";
        try {
            $res = $conn->query($debugSql);
            if ($res && $res->num_rows > 0) {
                $user = $res->fetch_assoc();
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['username'];
                $_SESSION['admin_name'] = $user['username'];
                $_SESSION['role'] = $user['role'] ?? 'admin';
                SecurityDefense::logSecurityIncident(
                    SecurityDefense::getClientIp(),
                    "DEMO_VULNERABLE_ADMIN_LOGIN: Đăng nhập thành công qua chế độ không bảo vệ với tài khoản '{$user['username']}'."
                );
                if (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
                    header('Content-Type: application/json; charset=utf-8');
                    echo json_encode([
                        'status' => 'success',
                        'authenticated' => true,
                        'mode' => 'vulnerable',
                        'user' => $user,
                        'executed_sql' => $debugSql
                    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
                    exit;
                }
                header('Location: /shopweb/quantri/security_dashboard.php?demo_login=vulnerable');
                exit;
            } else {
                $debugSqlError = $conn->error ?: 'Không tìm thấy tài khoản quản trị phù hợp.';
                $error = 'Đăng nhập thất bại (Chế độ Vulnerable).';
            }
        } catch (mysqli_sql_exception $e) {
            $debugSqlError = $e->getMessage();
            $error = 'Lỗi cú pháp SQL lộ ra ngoài (In-Band Error Leak)!';
        }
    } else {
        // HARDENED MODE: Parameterized Query + password_verify + Optional Step-up OTP
        $sql = "SELECT id, username, password, email, role FROM users WHERE (username = ? OR email = ?) AND role = 'admin'";
        $debugSql = $sql . "  [Tham số gắn an toàn qua bind_param]";
        $user = executePrepared($conn, $sql, [$loginInput, $loginInput])[0] ?? null;

        if ($user && password_verify($password, $user['password'])) {
            if (!empty($cfg['otp_enabled'])) {
                $otpMeta = SecurityDefense::issueOtpChallenge($user['username'], SecurityDefense::getClientIp());
                $_SESSION['pending_admin_otp_user'] = [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'role' => $user['role']
                ];
                $_SESSION['pending_admin_otp_preview'] = $otpMeta['code_for_lab_preview'];
                $pendingOtpUser = $_SESSION['pending_admin_otp_user'];
                $info = 'Tài khoản hợp lệ! Hệ thống yêu cầu xác minh bước 2 (OTP). Vui lòng kiểm tra lại OTP trong hộp thư mô phỏng.';
            } else {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['username'];
                $_SESSION['admin_name'] = $user['username'];
                $_SESSION['role'] = $user['role'];
                header('Location: /shopweb/quantri/security_dashboard.php');
                exit;
            }
        } else {
            SecurityDefense::logSecurityIncident(
                SecurityDefense::getClientIp(),
                "ADMIN_LOGIN_FAILED: Sai thông tin đăng nhập cho '{$loginInput}'."
            );
            $error = 'Tên đăng nhập hoặc mật khẩu quản trị không đúng.';
        }

        if (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'status' => $pendingOtpUser ? 'otp_required' : 'failed',
                'authenticated' => false,
                'mode' => 'hardened',
                'otp_required' => (bool)$pendingOtpUser,
                'message' => $info ?: $error
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
            exit;
        }
    }
}
$conn->close();
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Đăng nhập Quản trị (Admin) - Fashion Shop Security Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
</head>
<body class="bg-light">
<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-md-7 col-lg-6">
            <div class="card shadow-lg border-0">
                <div class="card-header text-white d-flex justify-content-between align-items-center <?= $mode === 'vulnerable' ? 'bg-danger' : 'bg-dark' ?>">
                    <div>
                        <h5 class="mb-0"><i class="fas fa-user-shield me-2"></i>Cổng Quản trị Admin (CEH Module 15)</h5>
                        <small>Chế độ hiện tại: <strong><?= $mode === 'vulnerable' ? 'TRƯỚC KHI VÁ (Vulnerable)' : 'ĐÃ BẢO VỆ (Hardened + OTP)' ?></strong></small>
                    </div>
                    <span class="badge bg-light text-dark"><?= strtoupper($mode) ?></span>
                </div>
                <div class="card-body p-4">
                    <?php if (isset($_GET['auth_required'])): ?>
                        <div class="alert alert-warning">
                            <i class="fas fa-lock me-1"></i>Khu vực <code>/quantri/</code> đang được bảo vệ bởi <strong>Auth Guard</strong>. Vui lòng đăng nhập quyền Admin (hoặc chuyển sang chế độ Vulnerable để demo).
                        </div>
                    <?php endif; ?>

                    <?php if ($mode === 'vulnerable'): ?>
                        <div class="alert alert-warning small">
                            <div><strong>Mẹo Demo trên MariaDB (Tránh lỗi mất dấu cách):</strong></div>
                            <div>• Vào thẳng Admin: nhập <code>' OR '1'='1' #</code> (mật khẩu gõ bất kỳ) — dùng dấu <code>#</code> sẽ không bị lỗi khi thiếu dấu cách cuối như <code>--</code>.</div>
                            <div>• Minh họa rò rỉ lỗi SQL: nhập chỉ 1 dấu <code>'</code> rồi bấm Đăng nhập.</div>
                            <div class="mt-2 d-flex flex-wrap gap-1">
                                <button type="button" class="btn btn-xs btn-outline-danger btn-sm" onclick="document.querySelector('[name=username]').value=&quot;' OR '1'='1' #&quot;; document.querySelector('[name=password]').value='123456';">Điền mẫu vào Admin (#)</button>
                                <button type="button" class="btn btn-xs btn-outline-secondary btn-sm" onclick="document.querySelector('[name=username]').value=&quot;'&quot;; document.querySelector('[name=password]').value='123456';">Điền mẫu gây lỗi (')</button>
                            </div>
                        </div>
                    <?php endif; ?>

                    <?php if ($error): ?>
                        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                    <?php endif; ?>
                    <?php if ($info): ?>
                        <div class="alert alert-info"><?= htmlspecialchars($info) ?></div>
                    <?php endif; ?>

                    <?php if ($debugSql): ?>
                        <div class="alert alert-secondary small">
                            <div><strong>Câu lệnh SQL thực thi:</strong></div>
                            <code><?= htmlspecialchars($debugSql) ?></code>
                            <?php if ($debugSqlError): ?>
                                <div class="text-danger mt-2"><strong>Phản hồi lỗi từ CSDL:</strong> <?= htmlspecialchars($debugSqlError) ?></div>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>

                    <?php if ($mode === 'hardened' && $pendingOtpUser): ?>
                        <form method="POST" action="admin_login.php?mode=hardened">
                            <input type="hidden" name="action" value="verify_otp">
                            <div class="mb-3">
                                <label class="form-label fw-bold">Xác minh OTP bước 2 cho tài khoản: <?= htmlspecialchars($pendingOtpUser['username']) ?></label>
                                <input type="text" name="otp_code" class="form-control form-control-lg text-center" maxlength="6" placeholder="Nhập 6 chữ số OTP" required autofocus>
                                <?php if (!empty($_SESSION['pending_admin_otp_preview'])): ?>
                                    <div class="form-text text-primary">
                                        [Mô phỏng hộp thư OTP tại lớp] Mã OTP vừa cấp: <strong><?= htmlspecialchars($_SESSION['pending_admin_otp_preview']) ?></strong>
                                        (cũng được lưu tại <code>quantri/logs/otp_mailbox.log</code>)
                                    </div>
                                <?php endif; ?>
                            </div>
                            <button type="submit" class="btn btn-success w-100 mb-2"><i class="fas fa-key me-1"></i>Xác nhận OTP & Vào Admin</button>
                        </form>
                        <form method="POST" action="admin_login.php?mode=hardened">
                            <input type="hidden" name="action" value="cancel_otp">
                            <button type="submit" class="btn btn-outline-secondary w-100 btn-sm">Quay lại bước nhập mật khẩu</button>
                        </form>
                    <?php else: ?>
                        <form method="POST" action="admin_login.php?mode=<?= htmlspecialchars($mode) ?>">
                            <div class="mb-3">
                                <label class="form-label">Tên đăng nhập Admin / Email</label>
                                <input type="text" name="username" class="form-control" placeholder="<?= $mode === 'vulnerable' ? "Ví dụ dữ liệu kiểm thử logic SQL..." : "admin_demo" ?>" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Mật khẩu</label>
                                <input type="password" name="password" class="form-control" placeholder="Nhập mật khẩu">
                            </div>
                            <button type="submit" class="btn <?= $mode === 'vulnerable' ? 'btn-danger' : 'btn-primary' ?> w-100">
                                <i class="fas fa-sign-in-alt me-1"></i>Đăng nhập Admin (<?= htmlspecialchars($mode) ?>)
                            </button>
                        </form>
                    <?php endif; ?>

                    <hr>
                    <div class="d-flex justify-content-between align-items-center flex-wrap gap-2">
                        <div>
                            <a href="?mode=vulnerable" class="btn btn-sm btn-outline-danger <?= $mode === 'vulnerable' ? 'active' : '' ?>">Chế độ Trước khi vá</a>
                            <a href="?mode=hardened" class="btn btn-sm btn-outline-success <?= $mode === 'hardened' ? 'active' : '' ?>">Chế độ Đã bảo vệ</a>
                        </div>
                        <a href="/shopweb/index.php" class="btn btn-sm btn-link">Về trang chủ cửa hàng</a>
                    </div>
                    <div class="mt-3 p-2 bg-white border rounded small text-muted">
                        <strong>Tài khoản Admin thử nghiệm hợp lệ:</strong> <code>admin_demo</code> / <code>Admin@123</code><br>
                        <strong>Chính sách Rate Limit hiện hành:</strong> Tối đa <strong><?= (int)$cfg['rate_limit_max_requests'] ?></strong> request / <strong><?= (int)$cfg['rate_limit_window_sec'] ?>s</strong> (vượt ngưỡng khóa <strong><?= (int)$cfg['rate_limit_cooldown_sec'] ?>s</strong>).
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
