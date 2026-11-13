<?php
require_once __DIR__ . '/auth_guard.php';
$__secCfg = SecurityDefense::getConfig();
$__secVuln = (($__secCfg['lab_mode'] ?? 'hardened') === 'vulnerable');
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShopWeb - Admin Dashboard & Security Center</title>
    <link rel="stylesheet" href="/shopweb/quantri/css/styles.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div id="wrapper">
        <?php include 'sidebar.php'; ?>
        <div id="content-wrapper">
            <?php include 'topbar.php'; ?>
            <?php if ($__secVuln || empty($__secCfg['enforce_admin_auth'])): ?>
                <div class="alert alert-warning border-warning mb-3 d-flex justify-content-between align-items-center" role="alert">
                    <div>
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        <strong>Cảnh báo Demo Lab:</strong>
                        <?= $__secVuln ? 'Hệ thống đang ở chế độ <strong>VULNERABLE</strong> (tắt tường bảo vệ để minh họa lỗ hổng CEH Module 15).' : '' ?>
                        <?= empty($__secCfg['enforce_admin_auth']) ? ' <strong>Auth Guard đang tắt</strong> (cho phép vào thẳng Admin không cần đăng nhập).' : '' ?>
                    </div>
                    <a href="/shopweb/quantri/security_dashboard.php" class="btn btn-sm btn-dark">Mở Bảng An ninh</a>
                </div>
            <?php endif; ?>
