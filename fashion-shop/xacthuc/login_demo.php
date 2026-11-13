<?php
// Educational demonstration endpoint for CEH Module 15: Authentication Bypass
session_start();
require_once __DIR__ . '/../database/dbhelper.php';

$conn = createConnection();
$mode = $_GET['mode'] ?? 'vulnerable'; // 'vulnerable' or 'hardened'
$error = '';
$result_data = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $login_input = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if ($mode === 'hardened') {
        // Hardened: Parameterized query + password_verify
        $sql = "SELECT id, username, password, role FROM users WHERE username = ? OR email = ?";
        $user = executePrepared($conn, $sql, [$login_input, $login_input])[0] ?? null;
        if ($user && password_verify($password, $user['password'])) {
            $result_data = [
                'status' => 'success',
                'authenticated' => true,
                'user' => [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'role' => $user['role']
                ],
                'mode' => 'hardened',
                'message' => 'Authentication successful via prepared statement and password_verify'
            ];
        } else {
            $result_data = [
                'status' => 'failed',
                'authenticated' => false,
                'mode' => 'hardened',
                'message' => 'Invalid username, email, or password'
            ];
        }
    } else {
        // Vulnerable (CEH Module 15 classic dynamic SQL injection sink)
        // Direct string concatenation susceptible to ' OR '1'='1' -- 
        $sql = "SELECT id, username, role FROM users WHERE username = '$login_input' AND password = '$password'";
        $query_res = $conn->query($sql);
        
        if ($query_res && $query_res->num_rows > 0) {
            $user = $query_res->fetch_assoc();
            $result_data = [
                'status' => 'success',
                'authenticated' => true,
                'user' => [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'role' => $user['role']
                ],
                'mode' => 'vulnerable',
                'injected_sql' => $sql,
                'message' => 'Authentication bypass successful! Injected logic evaluated to TRUE.'
            ];
        } else {
            $result_data = [
                'status' => 'failed',
                'authenticated' => false,
                'mode' => 'vulnerable',
                'injected_sql' => $sql,
                'sql_error' => $conn->error,
                'message' => 'Authentication failed'
            ];
        }
    }

    if (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($result_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>CEH Module 15 - Educational Authentication Demonstration</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card shadow">
                <div class="card-header bg-dark text-white">
                    <h5 class="mb-0">CEH Module 15: Authentication Bypass Demo</h5>
                    <small>Current Mode: <span class="badge bg-<?= $mode === 'hardened' ? 'success' : 'danger' ?>"><?= htmlspecialchars($mode) ?></span></small>
                </div>
                <div class="card-body">
                    <?php if ($result_data): ?>
                        <div class="alert alert-<?= $result_data['authenticated'] ? 'success' : 'danger' ?>">
                            <h6><?= htmlspecialchars($result_data['message']) ?></h6>
                            <?php if ($result_data['authenticated']): ?>
                                <p class="mb-0">Logged in as: <strong><?= htmlspecialchars($result_data['user']['username']) ?></strong> (Role: <?= htmlspecialchars($result_data['user']['role']) ?>)</p>
                            <?php endif; ?>
                            <?php if (isset($result_data['injected_sql'])): ?>
                                <hr>
                                <small><strong>Executed SQL:</strong> <code><?= htmlspecialchars($result_data['injected_sql']) ?></code></small>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>

                    <form method="POST" action="login_demo.php?mode=<?= htmlspecialchars($mode) ?>">
                        <div class="mb-3">
                            <label class="form-label">Username / Payload</label>
                            <input type="text" name="username" class="form-control" placeholder="admin' OR '1'='1' -- " required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" name="password" class="form-control" placeholder="anything">
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Submit Login</button>
                    </form>
                    <hr>
                    <div class="d-flex justify-content-between">
                        <a href="login_demo.php?mode=vulnerable" class="btn btn-sm btn-outline-danger">Switch to Vulnerable Mode</a>
                        <a href="login_demo.php?mode=hardened" class="btn btn-sm btn-outline-success">Switch to Hardened Mode</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
