<?php
require_once(__DIR__ . '/includes/auth_guard.php');
// Defense Layer 1: Strict input type casting and parameterized query execution
$delid = isset($_GET['id']) ? intval($_GET['id']) : 0;

require_once('../database/dbhelper.php');

$conn = createConnection();

if ($delid > 0) {
    $sql_str = "DELETE FROM products WHERE id = ?";
    executePrepared($conn, $sql_str, [$delid]);
}

header("location:listsanpham.php");
$conn->close();
exit;