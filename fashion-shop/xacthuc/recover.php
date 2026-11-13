<?php
session_start();
include '../database/dbhelper.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
require '../vendor/autoload.php';

$conn = createConnection();
if (!$conn) {
    die("<div class='alert alert-danger text-center'>Lỗi kết nối cơ sở dữ liệu!</div>");
}

$message = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
    $sql = "SELECT id FROM users WHERE email = ?";
    $user = executePrepared($conn, $sql, [$email])[0] ?? null;

    if ($user) {
        $token = bin2hex(random_bytes(32));
        $expires_at = date("Y-m-d H:i:s", time() + 1800); 

        executePrepared($conn, "DELETE FROM password_resets WHERE email = ?", [$email]);
        $result = executePrepared($conn, "INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)", [$email, $token, $expires_at]);

        if ($result) {
            $smtpUser = getenv('SMTP_USER') ?: '';
            $smtpPass = getenv('SMTP_PASS') ?: '';
            $smtpHost = getenv('SMTP_HOST') ?: 'smtp.gmail.com';
            $resetLink = "http://localhost/shopweb/xacthuc/reset_password.php?token=" . $token;

            if ($smtpUser !== '' && $smtpPass !== '') {
                $mail = new PHPMailer(true);
                try {
                    $mail->isSMTP();
                    $mail->Host = $smtpHost;
                    $mail->SMTPAuth = true;
                    $mail->Username = $smtpUser;
                    $mail->Password = $smtpPass;
                    $mail->SMTPSecure = 'tls';
                    $mail->Port = 587;

                    $mail->setFrom($smtpUser, 'Streetwear Shop');
                    $mail->addAddress($email);
                    $mail->isHTML(true);
                    $mail->CharSet = 'UTF-8';
                    $mail->Subject = 'Đặt lại mật khẩu - Streetwear Shop';
                    $mail->Body = '
                        <html>
                            <head><meta charset="UTF-8"></head>
                            <body style="font-family: Arial, sans-serif; color: #333;">
                                <p>Xin chào,</p>
                                <p>Bạn vừa yêu cầu khôi phục mật khẩu từ <strong>Streetwear Shop</strong>.</p>
                                <p>Nhấn vào nút bên dưới để đặt lại mật khẩu:</p>
                                <p><a href="' . htmlspecialchars($resetLink) . '" 
                                      style="background: #007bff; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                                      Đặt lại mật khẩu</a></p>
                                <p>Liên kết sẽ hết hạn sau 30 phút.</p>
                            </body>
                        </html>';

                    $mail->send();
                    $message = "<div class='alert alert-success text-center'>Nếu email tồn tại, liên kết khôi phục đã được gửi!</div>";
                } catch (Exception $e) {
                    $message = "<div class='alert alert-danger text-center'>Không thể gửi email khôi phục lúc này.</div>";
                }
            } else {
                // Local demo fallback: log simulated recovery notice without storing hardcoded SMTP secrets
                $logDir = __DIR__ . '/../quantri/logs';
                if (!is_dir($logDir)) {
                    @mkdir($logDir, 0777, true);
                }
                $entry = sprintf("[%s] [PasswordReset] [Email: %s] Link: %s\n", date('Y-m-d H:i:s'), $email, $resetLink);
                @file_put_contents($logDir . '/otp_mailbox.log', $entry, FILE_APPEND | LOCK_EX);
                $message = "<div class='alert alert-success text-center'>Yêu cầu khôi phục đã được ghi nhận trong hộp thư mô phỏng nội bộ (<code>quantri/logs/otp_mailbox.log</code>).</div>";
            }
        } else {
            $message = "<div class='alert alert-danger text-center'>Lỗi lưu token, vui lòng thử lại!</div>";
        }
    } else {
        $message = "<div class='alert alert-success text-center'>Nếu email tồn tại trong hệ thống, hướng dẫn khôi phục đã được xử lý.</div>";
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Khôi phục mật khẩu</title>
    <link rel="stylesheet" href="/shopweb/css/global.css">
    <link rel="stylesheet" href="/shopweb/css/user.css">
</head>
<body class="user-page">
<?php include '../fontend/header.php'; ?>

<section class="recover-container">
    <h2 class="text-center">KHÔI PHỤC MẬT KHẨU</h2>
    <?= $message ?>
    <form method="post" class="recover-form">
        <div class="form-group">
            <label for="email">Email</label>
            <input type="email" name="email" id="email" required placeholder="Nhập email đã đăng ký">
        </div>
        <button type="submit" class="btn-recover">Gửi liên kết đặt lại</button>
        <div class="link-group">
            <a href="/shopweb/xacthuc/login.php">← Trở về đăng nhập</a>
        </div>
    </form>
</section>

<?php include '../fontend/footer.php'; ?>
</body>
</html>