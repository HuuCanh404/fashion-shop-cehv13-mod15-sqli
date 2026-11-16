<?php
if (ini_get("session.auto_start") == 0) {
    ini_set('session.gc_maxlifetime', 86400);
    session_set_cookie_params(86400);
}
session_start();
require_once __DIR__ . '/../database/dbhelper.php';

$conn = createConnection();
$cfg = SecurityDefense::getConfig();
$isVulnerable = (($cfg['lab_mode'] ?? 'hardened') === 'vulnerable');

if (empty($_SESSION['user_login_csrf'])) {
    $_SESSION['user_login_csrf'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['user_login_csrf'];

function fashionShopCookieSecret(): string {
    return getenv('APP_COOKIE_SECRET') ?: hash('sha256', __DIR__ . '|FashionShopRememberSecret2026');
}

function buildSignedRememberCookie(string $username, int $expiresAt): string {
    $payload = $username . '|' . $expiresAt;
    $sig = hash_hmac('sha256', $payload, fashionShopCookieSecret());
    return base64_encode($payload . '|' . $sig);
}

function verifySignedRememberCookie(string $cookieVal): ?string {
    $decoded = base64_decode($cookieVal, true);
    if ($decoded === false) {
        return null;
    }
    $parts = explode('|', $decoded, 3);
    if (count($parts) !== 3) {
        return null;
    }
    [$username, $expStr, $sig] = $parts;
    if (!ctype_digit($expStr) || (int)$expStr < time()) {
        return null;
    }
    $expected = hash_hmac('sha256', $username . '|' . $expStr, fashionShopCookieSecret());
    if (!hash_equals($expected, $sig)) {
        return null;
    }
    return $username;
}

$error = '';
$debugSql = '';
$debugSqlError = '';

// Cookie Remember-Me Auto-Login
if (!isset($_SESSION['user_id']) && isset($_COOKIE['remember_user'])) {
    if ($isVulnerable) {
        // VULNERABLE LAB: trusts raw unsigned cookie value and allows admin escalation
        $login_input = trim((string)$_COOKIE['remember_user']);
        $sql = "SELECT id, username, role FROM users WHERE username = ? OR email = ?";
        $user = executePrepared($conn, $sql, [$login_input, $login_input])[0] ?? null;
        if ($user) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_name'] = $user['username'];
            $_SESSION['role'] = $user['role'] ?? 'user';
            if (($_SESSION['role']) === 'admin') {
                $_SESSION['admin_name'] = $user['username'];
                SecurityDefense::logSecurityIncident(
                    SecurityDefense::getClientIp(),
                    "DEMO_VULNERABLE_COOKIE_TO_ADMIN: Cookie remember_user='{$user['username']}' nâng quyền thẳng vào Admin."
                );
            }
            $redirect = ($user['role'] === 'admin') ? '/shopweb/quantri/index.php' : '/shopweb/index.php';
            header("Location: $redirect");
            exit;
        }
    } else {
        // HARDENED: requires valid HMAC-signed cookie and strictly denies admin auto-login
        $verifiedUsername = verifySignedRememberCookie((string)$_COOKIE['remember_user']);
        if ($verifiedUsername !== null) {
            $sql = "SELECT id, username, role FROM users WHERE username = ? AND role = 'user'";
            $user = executePrepared($conn, $sql, [$verifiedUsername])[0] ?? null;
            if ($user) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['username'];
                $_SESSION['role'] = 'user';
                header("Location: /shopweb/index.php");
                exit;
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $rawUsername = (string)($_POST['username'] ?? '');
    $login_input = $isVulnerable ? $rawUsername : trim($rawUsername);
    $password = (string)($_POST['password'] ?? '');
    $remember_me = isset($_POST['remember_me']);

    if ($isVulnerable) {
        // INTENTIONALLY VULNERABLE FOR LAB DEMO (User Login -> Admin Escalation):
        // Unparameterized concatenation allows SQL logic manipulation to match an admin row
        $debugSql = "SELECT id, username, email, role FROM users WHERE username = '$login_input' AND password = '$password'";
        try {
            $res = $conn->query($debugSql);
            if ($res && $res->num_rows > 0) {
                $user = $res->fetch_assoc();
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['username'];
                $_SESSION['role'] = $user['role'] ?? 'user';
                if ($_SESSION['role'] === 'admin') {
                    $_SESSION['admin_name'] = $user['username'];
                    SecurityDefense::logSecurityIncident(
                        SecurityDefense::getClientIp(),
                        "DEMO_VULNERABLE_USER_TO_ADMIN: Leo thang từ cổng User Login vào Admin với tài khoản '{$user['username']}'."
                    );
                }
                if ($remember_me) {
                    setcookie('remember_user', $user['username'], time() + (30 * 24 * 60 * 60), "/");
                }
                $redirect = ($user['role'] === 'admin') ? '/shopweb/quantri/index.php' : '/shopweb/index.php';
                header("Location: $redirect");
                exit;
            } else {
                $debugSqlError = $conn->error ?: 'Không tìm thấy bản ghi khớp điều kiện truy vấn.';
                $error = "<div class='alert alert-danger text-center'>Tên đăng nhập hoặc mật khẩu không đúng (Chế độ Vulnerable Lab)!</div>";
            }
        } catch (mysqli_sql_exception $e) {
            $debugSqlError = $e->getMessage();
            $error = "<div class='alert alert-danger text-center'>Lỗi cú pháp SQL bị lộ ra ngoài từ câu truy vấn ghép chuỗi!</div>";
        }
    } else {
        // HARDENED MODE: CSRF verification + Prepared Statement + password_verify + Portal Role Separation
        $postedCsrf = (string)($_POST['csrf_token'] ?? '');
        if (!hash_equals($csrfToken, $postedCsrf)) {
            $error = "<div class='alert alert-danger text-center'>Phiên biểu mẫu không hợp lệ (CSRF check). Vui lòng tải lại trang!</div>";
        } else {
            $sql = "SELECT id, username, password, role FROM users WHERE username = ? OR email = ?";
            $user = executePrepared($conn, $sql, [$login_input, $login_input])[0] ?? null;

            if ($user && password_verify($password, $user['password'])) {
                if (($user['role'] ?? 'user') === 'admin') {
                    SecurityDefense::logSecurityIncident(
                        SecurityDefense::getClientIp(),
                        "USER_PORTAL_ADMIN_BLOCKED: Chặn đăng nhập quyền Admin '{$user['username']}' qua cổng khách hàng."
                    );
                    $error = "<div class='alert alert-warning text-center'>Tài khoản Quản trị không được phép đăng nhập tại cổng Khách hàng. Vui lòng dùng <strong>Cổng Admin riêng (+ xác minh OTP)</strong>.</div>";
                } else {
                    session_regenerate_id(true);
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_name'] = $user['username'];
                    $_SESSION['role'] = 'user';
                    if ($remember_me) {
                        $exp = time() + (30 * 24 * 60 * 60);
                        setcookie(
                            'remember_user',
                            buildSignedRememberCookie($user['username'], $exp),
                            [
                                'expires' => $exp,
                                'path' => '/',
                                'httponly' => true,
                                'samesite' => 'Lax',
                            ]
                        );
                    }
                    header("Location: /shopweb/index.php");
                    exit;
                }
            } else {
                $error = "<div class='alert alert-danger text-center'>Tên đăng nhập, email hoặc mật khẩu không đúng!</div>";
            }
        }
    }
}
$conn->close();
?>

<!DOCTYPE html>
<html lang="vi">
<head>
    <title>Đăng nhập - Streetwear Shop</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="/shopweb/css/global.css">
    <link rel="stylesheet" href="/shopweb/css/user.css">
</head>
<body class="user-page">
    <?php include '../fontend/header.php'; ?>
    <section class="login-container">
        <h2 class="text-center mb-3">Đăng Nhập Khách Hàng</h2>

        <?php if ($isVulnerable): ?>
            <div style="background:#fdedec;border:1px solid #e74c3c;color:#922b21;padding:10px 12px;border-radius:6px;margin-bottom:14px;font-size:13px;">
                <strong>[CHẾ ĐỘ VULNERABLE LAB ĐANG BẬT]</strong> Cổng đăng nhập khách hàng đang dùng truy vấn SQL ghép chuỗi &amp; không tách quyền Admin.
                Dùng dấu <code>#</code> (không cần dấu cách cuối như <code>--</code>) với mẫu <code>' OR role='admin' #</code> và mật khẩu bất kỳ để vào thẳng Admin!
                <div style="margin-top:6px;">
                    <button type="button" onclick="document.getElementById('username').value=&quot;' OR role='admin' #&quot;; document.getElementById('password').value='123456';" style="background:#c0392b;color:#fff;border:none;padding:4px 10px;border-radius:4px;font-size:12px;cursor:pointer;">Điền nhanh mẫu vào Admin (#)</button>
                </div>
            </div>
        <?php else: ?>
            <div style="background:#eafaf1;border:1px solid #27ae60;color:#145a32;padding:8px 12px;border-radius:6px;margin-bottom:14px;font-size:12.5px;">
                <strong>[HARDENED]</strong> Bảo vệ bởi Prepared Statement, CSRF Token, Cookie ký HMAC-SHA256 &amp; tách biệt cổng Admin.
            </div>
        <?php endif; ?>

        <?php if ($error) echo $error; ?>

        <?php if ($debugSql !== ''): ?>
            <div style="background:#f8f9fa;border-left:4px solid #c0392b;padding:8px 10px;margin-bottom:14px;font-size:12px;word-break:break-all;">
                <strong>SQL đã thực thi (Lab):</strong><br>
                <code><?= htmlspecialchars($debugSql) ?></code>
                <?php if ($debugSqlError !== ''): ?>
                    <div style="color:#922b21;margin-top:4px;"><strong>Chi tiết lỗi:</strong> <?= htmlspecialchars($debugSqlError) ?></div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <form method="post" class="login-form">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <div class="form-group">
                <label for="username">Email hoặc Tên đăng nhập</label>
                <input type="text" id="username" name="username" required placeholder="Nhập email hoặc tên đăng nhập">
            </div>
            <div class="form-group">
                <label for="password">Mật khẩu</label>
                <input type="password" id="password" name="password" required placeholder="Nhập mật khẩu">
            </div>
            <div class="checkbox-group">
                <input type="checkbox" id="remember_me" name="remember_me">
                <label for="remember_me">Ghi nhớ đăng nhập</label>
            </div>
            <button type="submit" class="btn-login">Đăng nhập</button>
            <div class="link-group">
                <a href="/shopweb/xacthuc/recover.php">Quên mật khẩu?</a>
                <a href="/shopweb/xacthuc/register.php">Tạo tài khoản mới!</a>
            </div>
        </form>
    </section>
    <?php include '../fontend/footer.php'; ?>
</body>
</html>
