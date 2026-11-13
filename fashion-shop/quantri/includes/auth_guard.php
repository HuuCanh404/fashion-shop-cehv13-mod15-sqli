<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/../../database/security_defense.php';
SecurityDefense::enforce();

$__defenseCfg = SecurityDefense::getConfig();
$__isVulnerableDemo = (($__defenseCfg['lab_mode'] ?? 'hardened') === 'vulnerable');
$__enforceAuth = !empty($__defenseCfg['enforce_admin_auth']) && !$__isVulnerableDemo;

if ($__enforceAuth) {
    $isAdmin = isset($_SESSION['user_id']) && (($_SESSION['role'] ?? '') === 'admin');
    if (!$isAdmin) {
        SecurityDefense::logSecurityIncident(
            SecurityDefense::getClientIp(),
            'AUTH_DENIED: Truy cập trái phép vào khu vực quản trị (' . ($_SERVER['REQUEST_URI'] ?? 'unknown') . ').'
        );
        header('Location: /shopweb/quantri/admin_login.php?auth_required=1');
        exit;
    }
}
