<?php
$adminName = $_SESSION['admin_name'] ?? $_SESSION['user_name'] ?? 'Khách (Chưa đăng nhập)';
$__topCfg = class_exists('SecurityDefense') ? SecurityDefense::getConfig() : ['lab_mode' => 'hardened'];
$__isVulnTop = (($__topCfg['lab_mode'] ?? 'hardened') === 'vulnerable');
?>

<div id="topbar" class="d-flex justify-content-between align-items-center">
    <div class="d-flex align-items-center">
        <button class="btn btn-gradient d-md-none me-3" id="sidebarToggle">
            <i class="fas fa-bars"></i>
        </button>
        <form class="search-form d-flex align-items-center" method="GET" action="/shopweb/quantri/user_management/admin_management.php">
            <input type="text" name="search" class="form-control" placeholder="Tìm tài khoản quản trị...">
            <button type="submit" class="btn ms-2"><i class="fas fa-search"></i></button>
        </form>
    </div>
    <div class="d-flex align-items-center gap-2">
        <a href="/shopweb/quantri/security_dashboard.php" class="badge text-decoration-none p-2 <?= $__isVulnTop ? 'bg-danger' : 'bg-success' ?>">
            <i class="fas fa-shield-alt me-1"></i>
            <?= $__isVulnTop ? 'MODE: VULNERABLE LAB' : 'MODE: HARDENED 4 LỚP' ?>
        </a>
        <span class="small text-muted d-none d-md-inline">
            <i class="fas fa-user-circle me-1"></i><?= htmlspecialchars($adminName) ?>
        </span>
        <a href="/shopweb/quantri/logout.php" class="btn btn-sm btn-outline-secondary" title="Đăng xuất">
            <i class="fas fa-sign-out-alt"></i>
        </a>
    </div>
</div>
