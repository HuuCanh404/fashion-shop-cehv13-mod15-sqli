<?php
require_once(__DIR__ . '/includes/auth_guard.php');
require_once('../database/dbhelper.php');

$conn = createConnection();
$cfg = SecurityDefense::getConfig();
$isVulnerableMode = (($cfg['lab_mode'] ?? 'hardened') === 'vulnerable');

$product = null;
$editid = 0;

if ($isVulnerableMode) {
    // Educational Lab Mode ONLY (when toggled from Admin Security Dashboard):
    $raw_id = $_GET['id'] ?? '0';
    $sql_select = "SELECT * FROM products WHERE id = $raw_id";
    try {
        $res = $conn->query($sql_select);
        if ($res instanceof mysqli_result && $res->num_rows > 0) {
            $product = $res->fetch_assoc();
            $editid = intval($product['id'] ?? 0);
        }
    } catch (mysqli_sql_exception $e) {
        die("SQL Error (Vulnerable Lab Mode): " . htmlspecialchars($e->getMessage()));
    }
    if (!$product) {
        header("location:listsanpham.php");
        exit;
    }
} else {
    // Defense Layer 1: Strict input type casting and universal parameterization
    $editid = isset($_GET['id']) ? intval($_GET['id']) : 0;
    if ($editid <= 0) {
        header("location:listsanpham.php");
        exit;
    }
    $sql_select = "SELECT * FROM products WHERE id = ?";
    $result = executePrepared($conn, $sql_select, [$editid]);
    $product = (!empty($result) && is_array($result)) ? $result[0] : null;
    if (!$product) {
        header("location:listsanpham.php");
        exit;
    }
}

// Xử lý form khi submit (cập nhật sản phẩm)
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Lấy dữ liệu từ form
    $name = mysqli_real_escape_string($conn, $_POST['name']);
    $price = floatval($_POST['price']);
    $description = mysqli_real_escape_string($conn, $_POST['description']);

    // Xử lý upload hình ảnh
    $image = $product['image']; 
    if (isset($_FILES['image']) && $_FILES['image']['error'] == 0) {
        $target_dir = "../images/";
        $image_name = time() . "_" . basename($_FILES['image']['name']);
        $target_file = $target_dir . $image_name;

        // Kiểm tra loại file (chỉ cho phép hình ảnh)
        $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
        $allowed_types = ['jpg', 'jpeg', 'png', 'gif'];
        if (in_array($imageFileType, $allowed_types)) {
            if (move_uploaded_file($_FILES['image']['tmp_name'], $target_file)) {
                $image = $image_name; 
            }
        }
    }

    $sql_update = "UPDATE products SET name = ?, price = ?, description = ?, image = ? WHERE id = ?";
    $update_success = executePrepared($conn, $sql_update, [$name, $price, $description, $image, $editid]);

    header("location:listsanpham.php");
    $conn->close();
    exit;
}
?>

<?php require('includes/header.php'); ?>

<div class="container-fluid">
    <h3 class="mb-4">Chỉnh sửa sản phẩm</h3>

    <div class="card shadow mb-4">
        <div class="card-body">
            <form method="POST" enctype="multipart/form-data">
                <div class="form-group">
                    <label>Tên sản phẩm</label>
                    <input type="text" class="form-control" name="name" value="<?= htmlspecialchars($product['name']) ?>" required>
                </div>
                <div class="form-group">
                    <label>Giá</label>
                    <input type="number" class="form-control" name="price" value="<?= $product['price'] ?>" required>
                </div>
                <div class="form-group">
                    <label>Mô tả</label>
                    <textarea class="form-control" name="description"><?= htmlspecialchars($product['description']) ?></textarea>
                </div>
                <div class="form-group">
                    <label class="form-label">Hình ảnh:</label>
                    <input type="file" class="form-control-file" id="image" name="image" accept="image/*">
                    <small>Hình ảnh hiện tại: <img src="../images/<?= htmlspecialchars($product['image']) ?>" width="100" alt="Current Image"></small>
                </div>
                <button type="submit" class="btn btn-primary">Cập nhật</button>
                <a href="listsanpham.php" class="btn btn-secondary">Hủy</a>
            </form>
        </div>
    </div>
</div>

<?php require('includes/footer.php'); ?>