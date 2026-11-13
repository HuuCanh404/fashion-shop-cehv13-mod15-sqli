<?php
/**
 * security_defense.php - Defense-in-Depth Middleware for fashion-shop
 *
 * Layer 1: Parameterized Query Helpers & Strict Input Casting
 * Layer 2: Sliding-Window Rate Limiting (Default: 10 requests / 60s -> 600s cooldown)
 * Layer 2b: Step-up OTP Challenge Simulation & Verification
 * Layer 3: Deceptive HTTP 200 OK Response Handling against Automated Scanners
 * Layer 4: Cloudflare Edge IP Resolution (CF-Connecting-IP) & Audit Telemetry
 */

class SecurityDefense {
    private const CONFIG_PATH = __DIR__ . '/defense_config.json';
    private const STORAGE_SUBDIR = '/fashion_security';
    private const OTP_TTL_SECONDS = 120;

    private static bool $enforced_for_request = false;
    private static ?array $cached_config = null;

    // Suspicious SQL Injection signatures for Layer 3 detection
    private static array $sqli_patterns = [
        '/\b(union\s+(all\s+)?select)\b/i',
        '/\b(extractvalue|updatexml)\s*\(/i',
        '/\b(sleep|benchmark)\s*\(/i',
        '/\b(information_schema|load_file|into\s+outfile|into\s+dumpfile)\b/i',
        '/(--(\s|$)|#|\/\*)/',
        '/\b(or|and)\s+[\'"]?(\d+|true)[\'"]?\s*=\s*[\'"]?(\d+|true)[\'"]?/i',
        '/\b(or|and)\s+[\'"]?[a-zA-Z0-9_]+[\'"]?\s*=\s*[\'"]?[a-zA-Z0-9_]+[\'"]?\s*(--|#)/i',
        '/\border\s+by\s+\d+\b/i',
        '/\bgroup_concat\s*\(/i'
    ];

    public static function defaultConfig(): array {
        return [
            'lab_mode' => 'hardened',
            'enforce_admin_auth' => true,
            'rate_limit_enabled' => true,
            'rate_limit_window_sec' => 60,
            'rate_limit_max_requests' => 10,
            'rate_limit_cooldown_sec' => 600,
            'otp_enabled' => true,
            'deception_enabled' => true,
            'cloudflare_mode' => true
        ];
    }

    public static function getConfig(bool $reload = false): array {
        if (self::$cached_config !== null && !$reload) {
            return self::$cached_config;
        }
        $defaults = self::defaultConfig();
        if (file_exists(self::CONFIG_PATH)) {
            $raw = @file_get_contents(self::CONFIG_PATH);
            $parsed = json_decode((string)$raw, true);
            if (is_array($parsed)) {
                self::$cached_config = array_merge($defaults, $parsed);
                return self::$cached_config;
            }
        }
        self::$cached_config = $defaults;
        return self::$cached_config;
    }

    public static function saveConfig(array $newConfig): bool {
        $merged = array_merge(self::defaultConfig(), $newConfig);
        $merged['lab_mode'] = ($merged['lab_mode'] === 'vulnerable') ? 'vulnerable' : 'hardened';
        $merged['enforce_admin_auth'] = (bool)$merged['enforce_admin_auth'];
        $merged['rate_limit_enabled'] = (bool)$merged['rate_limit_enabled'];
        $merged['rate_limit_window_sec'] = max(5, (int)$merged['rate_limit_window_sec']);
        $merged['rate_limit_max_requests'] = max(1, (int)$merged['rate_limit_max_requests']);
        $merged['rate_limit_cooldown_sec'] = max(5, (int)$merged['rate_limit_cooldown_sec']);
        $merged['otp_enabled'] = (bool)$merged['otp_enabled'];
        $merged['deception_enabled'] = (bool)$merged['deception_enabled'];
        $merged['cloudflare_mode'] = (bool)$merged['cloudflare_mode'];

        $encoded = json_encode($merged, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
        $ok = @file_put_contents(self::CONFIG_PATH, $encoded, LOCK_EX) !== false;
        if ($ok) {
            self::$cached_config = $merged;
        }
        return $ok;
    }

    public static function isVulnerableLabMode(): bool {
        $cfg = self::getConfig();
        if (($cfg['lab_mode'] ?? 'hardened') === 'vulnerable') {
            return true;
        }
        if (isset($_GET['mode']) && $_GET['mode'] === 'vulnerable') {
            return true;
        }
        return false;
    }

    private static function getStorageDir(): string {
        $dir = sys_get_temp_dir() . self::STORAGE_SUBDIR;
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        return $dir;
    }

    /**
     * Entry point: run defense suite on incoming HTTP request
     */
    public static function enforce(): void {
        if (self::$enforced_for_request) {
            return;
        }
        self::$enforced_for_request = true;

        if (defined('SECURITY_DASHBOARD_CONTEXT') && SECURITY_DASHBOARD_CONTEXT === true) {
            return;
        }

        if (PHP_SAPI === 'cli') {
            return;
        }

        $cfg = self::getConfig();
        $script = basename($_SERVER['SCRIPT_NAME'] ?? '');

        // Dedicated educational comparison endpoints honor explicit ?mode=vulnerable
        $demoScripts = ['login_demo.php', 'admin_login.php'];
        if (in_array($script, $demoScripts, true) && isset($_GET['mode']) && $_GET['mode'] === 'vulnerable') {
            return;
        }

        // Global vulnerable mode skips automated middleware so classroom demos can reproduce flaws
        if (($cfg['lab_mode'] ?? 'hardened') === 'vulnerable') {
            return;
        }

        $client_ip = self::getClientIp();

        // Layer 2: Sliding-Window Rate Limiting (default 10 requests / 60s -> 600s block)
        if (!empty($cfg['rate_limit_enabled'])) {
            $rate_check = self::checkRateLimit($client_ip);
            if (!$rate_check['allowed']) {
                self::emitRateLimitResponse($client_ip, $rate_check);
                exit;
            }
        }

        // Layer 3: Deceptive HTTP 200 Scanner Neutralization
        if (!empty($cfg['deception_enabled'])) {
            self::inspectAndDeceive();
        }
    }

    private static function emitRateLimitResponse(string $client_ip, array $rate_check): void {
        $retry_after = (int)($rate_check['retry_after'] ?? 600);
        $minutes = ceil($retry_after / 60);
        http_response_code(429);
        header("Retry-After: " . $retry_after);

        $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
        $isAjax = (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest')
            || strpos($accept, 'application/json') !== false;

        if ($isAjax) {
            header("Content-Type: application/json; charset=utf-8");
            echo json_encode([
                "status" => "blocked",
                "code" => 429,
                "message" => "Vượt quá giới hạn truy cập (tối đa {$rate_check['max_requests']} lần/{$rate_check['window_sec']} giây). Hệ thống tạm khóa {$retry_after} giây (~{$minutes} phút). Vui lòng thử lại sau hoặc xác minh OTP.",
                "retry_after_sec" => $retry_after,
                "client_ip" => $client_ip,
                "otp_required" => true
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
            return;
        }

        header("Content-Type: text/html; charset=UTF-8");
        echo '<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><title>429 - Tạm khóa truy cập</title>'
            . '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>'
            . '<body class="bg-light d-flex align-items-center justify-content-center" style="min-height:100vh;">'
            . '<div class="card shadow border-danger" style="max-width:540px;"><div class="card-header bg-danger text-white">'
            . '<h5 class="mb-0">Cảnh báo Giới hạn Tần suất (HTTP 429)</h5></div><div class="card-body">'
            . '<p>Địa chỉ IP <strong>' . htmlspecialchars($client_ip) . '</strong> đã vượt quá ngưỡng cho phép ('
            . (int)$rate_check['max_requests'] . ' yêu cầu / ' . (int)$rate_check['window_sec'] . ' giây).</p>'
            . '<p class="text-danger fw-bold">Vui lòng chờ ' . $retry_after . ' giây (~' . $minutes . ' phút) trước khi gửi yêu cầu tiếp theo hoặc kiểm tra xác minh OTP.</p>'
            . '<a href="/shopweb/quantri/admin_login.php" class="btn btn-outline-primary btn-sm">Quay lại trang đăng nhập</a> '
            . '<a href="/shopweb/quantri/security_dashboard.php" class="btn btn-outline-secondary btn-sm">Mở Admin An ninh</a>'
            . '</div></div></body></html>';
    }

    /**
     * Layer 2: Sliding-window rate limiter with configurable window & cooldown
     */
    public static function checkRateLimit(string $ip): array {
        $cfg = self::getConfig();
        $window_sec = (int)($cfg['rate_limit_window_sec'] ?? 60);
        $max_requests = (int)($cfg['rate_limit_max_requests'] ?? 10);
        $cooldown_sec = (int)($cfg['rate_limit_cooldown_sec'] ?? 600);

        $file = self::getStorageDir() . '/rate_' . md5($ip) . '.json';
        $now = time();
        $fp = fopen($file, 'c+');
        if (!$fp) {
            return [
                'allowed' => true,
                'retry_after' => 0,
                'max_requests' => $max_requests,
                'window_sec' => $window_sec
            ];
        }

        flock($fp, LOCK_EX);
        clearstatcache(true, $file);
        $fstat = fstat($fp);
        $size = $fstat ? $fstat['size'] : 0;
        $content = $size > 0 ? fread($fp, $size) : '';
        $data = !empty($content) ? json_decode($content, true) : null;
        if (!is_array($data)) {
            $data = [
                'ip' => $ip,
                'requests' => [],
                'quarantine_until' => 0,
                'violations' => 0
            ];
        }
        $data['ip'] = $ip;

        // Check active quarantine
        if (($data['quarantine_until'] ?? 0) > $now) {
            $remaining = $data['quarantine_until'] - $now;
            flock($fp, LOCK_UN);
            fclose($fp);
            return [
                'allowed' => false,
                'retry_after' => $remaining,
                'status' => 'quarantined',
                'max_requests' => $max_requests,
                'window_sec' => $window_sec
            ];
        }

        // Prune timestamps outside sliding window
        $window_start = $now - $window_sec;
        $data['requests'] = array_values(array_filter($data['requests'] ?? [], function ($ts) use ($window_start) {
            return $ts >= $window_start;
        }));

        if (count($data['requests']) >= $max_requests) {
            $data['violations'] = ($data['violations'] ?? 0) + 1;
            $penalty = $cooldown_sec;
            $data['quarantine_until'] = $now + $penalty;
            $data['requests'] = [];

            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($data));
            fflush($fp);
            flock($fp, LOCK_UN);
            fclose($fp);

            self::logSecurityIncident(
                $ip,
                "RATE_LIMIT: Vượt {$max_requests} req/{$window_sec}s (lần {$data['violations']}). Chặn {$penalty}s."
            );

            return [
                'allowed' => false,
                'retry_after' => $penalty,
                'status' => 'threshold_exceeded',
                'max_requests' => $max_requests,
                'window_sec' => $window_sec
            ];
        }

        $data['requests'][] = $now;
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($data));
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);

        return [
            'allowed' => true,
            'retry_after' => 0,
            'status' => 'ok',
            'current_count' => count($data['requests']),
            'max_requests' => $max_requests,
            'window_sec' => $window_sec
        ];
    }

    public static function listRateLimitStates(): array {
        $dir = self::getStorageDir();
        $files = glob($dir . '/rate_*.json') ?: [];
        $now = time();
        $states = [];
        foreach ($files as $file) {
            $raw = @file_get_contents($file);
            $data = json_decode((string)$raw, true);
            if (!is_array($data)) {
                continue;
            }
            $quarantine_until = (int)($data['quarantine_until'] ?? 0);
            $remaining = max(0, $quarantine_until - $now);
            $states[] = [
                'file' => basename($file),
                'ip' => $data['ip'] ?? 'unknown',
                'requests_in_window' => count($data['requests'] ?? []),
                'violations' => (int)($data['violations'] ?? 0),
                'quarantined' => $remaining > 0,
                'remaining_sec' => $remaining
            ];
        }
        return $states;
    }

    public static function unblockIp(string $ip): bool {
        $file = self::getStorageDir() . '/rate_' . md5($ip) . '.json';
        if (file_exists($file)) {
            $ok = @unlink($file);
            if ($ok) {
                self::logSecurityIncident($ip, "ADMIN_ACTION: Gỡ chặn IP thủ công từ bảng quản trị.");
            }
            return $ok;
        }
        return false;
    }

    public static function clearAllRateLimits(): int {
        $files = glob(self::getStorageDir() . '/rate_*.json') ?: [];
        $count = 0;
        foreach ($files as $file) {
            if (@unlink($file)) {
                $count++;
            }
        }
        if ($count > 0) {
            self::logSecurityIncident(self::getClientIp(), "ADMIN_ACTION: Xóa toàn bộ bộ đếm Rate Limit ({$count} bản ghi).");
        }
        return $count;
    }

    /**
     * Check arbitrary string for SQLi pattern (also usable by Admin Lab UI)
     */
    public static function matchSqliPattern(string $val): ?string {
        foreach (self::$sqli_patterns as $pattern) {
            if (preg_match($pattern, $val)) {
                return $pattern;
            }
        }
        return null;
    }

    /**
     * Layer 3: Deceptive HTTP 200 Scanner Neutralization
     */
    public static function inspectAndDeceive(): void {
        $raw_uri = $_SERVER['REQUEST_URI'] ?? '';
        $query_string = $_SERVER['QUERY_STRING'] ?? '';
        $post_body = @file_get_contents('php://input') ?: '';

        $inputs_to_check = [
            'uri' => urldecode($raw_uri),
            'query' => urldecode($query_string),
            'post' => urldecode($post_body)
        ];

        foreach ($_GET as $k => $v) {
            if (is_string($v)) {
                $inputs_to_check["get_$k"] = $v;
            }
        }
        foreach ($_POST as $k => $v) {
            if (is_string($v)) {
                $inputs_to_check["post_$k"] = $v;
            }
        }

        $matched_pattern = null;
        foreach ($inputs_to_check as $val) {
            $pattern = self::matchSqliPattern((string)$val);
            if ($pattern !== null) {
                $matched_pattern = $pattern;
                break;
            }
        }

        if ($matched_pattern !== null) {
            $client_ip = self::getClientIp();
            self::logSecurityIncident(
                $client_ip,
                "SQLI_DECEPTION: Phát hiện mẫu nghi ngờ ({$matched_pattern}) -> Trả phản hồi giả HTTP 200 OK."
            );

            // Synthetic timing jitter: 50ms - 80ms
            usleep(rand(50000, 80000));

            http_response_code(200);
            header("X-Content-Type-Options: nosniff");
            header("X-Protection-System: Deceptive-Decoy-Active");

            $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
            if (strpos($accept, 'application/json') !== false) {
                header("Content-Type: application/json; charset=utf-8");
                echo json_encode([
                    "status" => "success",
                    "authenticated" => false,
                    "records" => [
                        ["id" => 101, "name" => "SWE Sample Tee", "status" => "verified"],
                        ["id" => 102, "name" => "SWE Standard Hoodie", "status" => "verified"]
                    ],
                    "message" => "Yêu cầu đã được ghi nhận và xử lý thành công."
                ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
                exit;
            }

            header("Content-Type: text/html; charset=UTF-8");
            echo self::generateDecoyHtml();
            exit;
        }
    }

    public static function generateDecoyHtml(): string {
        return '<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Fashion Shop - Hệ thống quản lý</title>
    <link href="/shopweb/quantri/css/styles.css" rel="stylesheet">
    <style>
        body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;margin:0;padding:32px;color:#2c3e50}
        .card{max-width:680px;margin:0 auto;background:#fff;border:1px solid #d5dbdb;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,.06);overflow:hidden}
        .card-header{padding:14px 20px;border-bottom:1px solid #e5e8e8;background:#f8f9fa;font-weight:700;color:#1b4f72}
        .card-body{padding:20px}
        .alert-success{background:#eafaf1;border:1px solid #a9dfbf;color:#145a32;padding:10px 14px;border-radius:6px;margin-bottom:16px}
        table{width:100%;border-collapse:collapse;margin-bottom:16px}
        th,td{border:1px solid #d5dbdb;padding:9px 12px;text-align:left;font-size:14px}
        th{background:#f2f4f4;font-weight:600}
        .btn-secondary{display:inline-block;padding:8px 14px;background:#5d6d7e;color:#fff;text-decoration:none;border-radius:5px;font-size:13px}
    </style>
</head>
<body class="bg-light">
    <div class="container-fluid py-4">
        <div class="card shadow mb-4">
            <div class="card-header py-3 bg-white">Thông tin hệ thống</div>
            <div class="card-body">
                <div class="alert alert-success">Truy vấn hoàn tất. Hệ thống đã ghi nhận dữ liệu hợp lệ.</div>
                <table class="table table-bordered">
                    <thead><tr><th>Mã</th><th>Danh mục</th><th>Trạng thái</th></tr></thead>
                    <tbody>
                        <tr><td>101</td><td>Sản phẩm tiêu chuẩn</td><td>Hoàn tất</td></tr>
                        <tr><td>102</td><td>Tài khoản khách mẫu</td><td>Đã xác nhận</td></tr>
                    </tbody>
                </table>
                <a href="/shopweb/index.php" class="btn btn-secondary">Quay lại trang chủ</a>
            </div>
        </div>
    </div>
</body>
</html>';
    }

    /**
     * Step-up OTP Challenge helpers
     */
    public static function issueOtpChallenge(string $identifier, string $ip): array {
        $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $expires = time() + self::OTP_TTL_SECONDS;
        $file = self::getStorageDir() . '/otp_' . md5(strtolower(trim($identifier))) . '.json';
        $payload = [
            'identifier' => $identifier,
            'code_hash' => password_hash($code, PASSWORD_DEFAULT),
            'expires_at' => $expires,
            'verified' => false
        ];
        @file_put_contents($file, json_encode($payload), LOCK_EX);

        $log_dir = __DIR__ . '/../quantri/logs';
        if (!is_dir($log_dir)) {
            @mkdir($log_dir, 0777, true);
        }
        $otp_line = sprintf("[%s] [User: %s] [IP: %s] Mã OTP xác minh: %s (hết hạn sau %ds)\n", date('Y-m-d H:i:s'), $identifier, $ip, $code, self::OTP_TTL_SECONDS);
        @file_put_contents($log_dir . '/otp_mailbox.log', $otp_line, FILE_APPEND | LOCK_EX);
        self::logSecurityIncident($ip, "OTP_CHALLENGE: Cấp mã xác minh OTP cho tài khoản '{$identifier}'.");

        return ['code_for_lab_preview' => $code, 'expires_at' => $expires];
    }

    public static function verifyOtpChallenge(string $identifier, string $submittedCode): bool {
        $file = self::getStorageDir() . '/otp_' . md5(strtolower(trim($identifier))) . '.json';
        if (!file_exists($file)) {
            return false;
        }
        $data = json_decode((string)@file_get_contents($file), true);
        if (!is_array($data) || time() > (int)($data['expires_at'] ?? 0)) {
            return false;
        }
        if (password_verify(trim($submittedCode), (string)($data['code_hash'] ?? ''))) {
            @unlink($file);
            self::logSecurityIncident(self::getClientIp(), "OTP_VERIFIED: Xác minh OTP thành công cho '{$identifier}'.");
            return true;
        }
        self::logSecurityIncident(self::getClientIp(), "OTP_FAILED: Nhập sai mã OTP cho '{$identifier}'.");
        return false;
    }

    public static function readOtpMailbox(int $limit = 15): array {
        $file = __DIR__ . '/../quantri/logs/otp_mailbox.log';
        if (!file_exists($file)) {
            return [];
        }
        $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        return array_slice(array_reverse($lines), 0, $limit);
    }

    public static function readAuditLog(int $limit = 50): array {
        $file = __DIR__ . '/../quantri/logs/security_audit.log';
        if (!file_exists($file)) {
            return [];
        }
        $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        return array_slice(array_reverse($lines), 0, $limit);
    }

    public static function clearAuditLog(): void {
        $file = __DIR__ . '/../quantri/logs/security_audit.log';
        if (file_exists($file)) {
            @file_put_contents($file, '', LOCK_EX);
        }
    }

    public static function getSecuritySummary(): array {
        $file = __DIR__ . '/../quantri/logs/security_audit.log';
        $lines = file_exists($file) ? (@file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []) : [];
        $deception = 0;
        $rate_blocks = 0;
        $otp_events = 0;
        $auth_denied = 0;
        foreach ($lines as $line) {
            if (strpos($line, 'SQLI_DECEPTION') !== false || strpos($line, 'Deceptive HTTP 200') !== false) {
                $deception++;
            }
            if (strpos($line, 'RATE_LIMIT') !== false || strpos($line, 'Rate limit') !== false) {
                $rate_blocks++;
            }
            if (strpos($line, 'OTP_') !== false) {
                $otp_events++;
            }
            if (strpos($line, 'AUTH_DENIED') !== false) {
                $auth_denied++;
            }
        }
        $states = self::listRateLimitStates();
        $active_blocks = count(array_filter($states, fn($s) => $s['quarantined']));
        return [
            'total_events' => count($lines),
            'deception_hits' => $deception,
            'rate_limit_hits' => $rate_blocks,
            'otp_events' => $otp_events,
            'auth_denied' => $auth_denied,
            'active_blocked_ips' => $active_blocks
        ];
    }

    /**
     * Retrieve remote IP accurately, prioritizing Cloudflare edge header when enabled
     */
    public static function getClientIp(): string {
        $cfg = self::getConfig();
        if (!empty($cfg['cloudflare_mode']) && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return trim($_SERVER['HTTP_CF_CONNECTING_IP']);
        }
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            return trim($_SERVER['HTTP_CLIENT_IP']);
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            return trim($parts[0]);
        }
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    /**
     * Audit logger for security telemetry
     */
    public static function logSecurityIncident(string $ip, string $message): void {
        $log_dir = __DIR__ . '/../quantri/logs';
        if (!is_dir($log_dir)) {
            @mkdir($log_dir, 0777, true);
        }
        $log_file = $log_dir . '/security_audit.log';
        $entry = sprintf("[%s] [IP: %s] %s\n", date('Y-m-d H:i:s'), $ip, $message);
        @file_put_contents($log_file, $entry, FILE_APPEND | LOCK_EX);
    }
}
