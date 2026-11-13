<?php
session_start();
require_once __DIR__ . '/../database/dbhelper.php';

$conn = createConnection();
$secCfg = SecurityDefense::getConfig();
$isVulnerableLab = (($secCfg['lab_mode'] ?? 'hardened') === 'vulnerable');

// Số sản phẩm mỗi trang
$productsPerPage = 20;

// Lấy trang hiện tại từ query string, mặc định là 1
$page = isset($_GET['page']) && is_numeric($_GET['page']) ? (int)$_GET['page'] : 1;
if ($page < 1) $page = 1;

// Lấy từ khóa tìm kiếm
$query = isset($_GET['q']) ? trim($_GET['q']) : '';
$labExecutedSql = '';
$labSqlError = '';
$totalProducts = 0;

if ($query !== '') {
    if ($isVulnerableLab) {
        $labCountSql = "SELECT COUNT(*) as total FROM products WHERE name LIKE '%$query%'";
        try {
            $cr = $conn->query($labCountSql);
            if ($cr instanceof mysqli_result) {
                $totalProducts = (int)($cr->fetch_assoc()['total'] ?? 0);
            }
        } catch (mysqli_sql_exception $e) {
            $labSqlError = $e->getMessage();
        }
    } else {
        $countStmt = $conn->prepare("SELECT COUNT(*) as total FROM products WHERE name LIKE CONCAT('%', ?, '%')");
        $countStmt->bind_param("s", $query);
        $countStmt->execute();
        $countResult = $countStmt->get_result();
        $totalProducts = (int)($countResult->fetch_assoc()['total'] ?? 0);
        $countStmt->close();
    }
}

$totalPages = $totalProducts > 0 ? ceil($totalProducts / $productsPerPage) : 1;
if ($page > $totalPages) $page = $totalPages;

include $_SERVER['DOCUMENT_ROOT'].'/shopweb/fontend/header.php';
?>
<link rel="stylesheet" href="/shopweb/css/search_results.css">

<div class="search-container">
    <h1>Kết quả tìm kiếm cho: "<?php echo htmlspecialchars($query); ?>"</h1>

    <?php if ($isVulnerableLab): ?>
        <div style="background:#fdedec;border:1px solid #e74c3c;color:#922b21;padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:13px;">
            <strong>[VULNERABLE LAB - TRANG KHÁCH HÀNG]</strong> Thanh tìm kiếm đang nối trực tiếp từ khóa vào câu lệnh SQL (có thể thử chèn mẫu để quan sát sự khác biệt so với chế độ Hardened).
        </div>
    <?php endif; ?>

    <?php
    if ($query === '') {
        echo "<p>Vui lòng nhập từ khóa tìm kiếm.</p>";
    } else {
        $offset = ($page - 1) * $productsPerPage;
        $rows = [];
        if ($isVulnerableLab) {
            $labExecutedSql = "SELECT p.id, p.name, p.price, p.image, IFNULL(AVG(r.rating), 0) AS rating, COUNT(r.id) AS review_count FROM products p LEFT JOIN product_reviews r ON p.id = r.product_id WHERE p.name LIKE '%$query%' GROUP BY p.id LIMIT $productsPerPage OFFSET $offset";
            try {
                $res = $conn->query($labExecutedSql);
                if ($res instanceof mysqli_result) {
                    $rows = $res->fetch_all(MYSQLI_ASSOC);
                }
            } catch (mysqli_sql_exception $e) {
                $labSqlError = $e->getMessage();
            }
            echo "<div style='background:#f8f9fa;border-left:4px solid #c0392b;padding:8px 10px;margin-bottom:14px;font-size:12px;word-break:break-all;'>";
            echo "<strong>SQL đã thực thi (Lab):</strong> <code>" . htmlspecialchars($labExecutedSql) . "</code>";
            if ($labSqlError !== '') {
                echo "<div style='color:#922b21;margin-top:4px;'><strong>Lỗi SQL:</strong> " . htmlspecialchars($labSqlError) . "</div>";
            }
            echo "</div>";
        } else {
            $stmt = $conn->prepare("
                SELECT p.id, p.name, p.price, p.image,
                    IFNULL(AVG(r.rating), 0) AS rating,
                    COUNT(r.id) AS review_count
                FROM products p
                LEFT JOIN product_reviews r ON p.id = r.product_id
                WHERE p.name LIKE CONCAT('%', ?, '%')
                GROUP BY p.id
                LIMIT ? OFFSET ?
            ");
            $stmt->bind_param("sii", $query, $productsPerPage, $offset);
            $stmt->execute();
            $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
            $stmt->close();
        }

        if (count($rows) > 0) {
            echo "<div class='product-list'>";
            foreach ($rows as $product) {
                // Dữ liệu giả lập cho demo
                $rating = isset($product['rating']) ? $product['rating'] : 0;
                $reviewCount = isset($product['review_count']) ? $product['review_count'] : 0;
                $priceOriginal = isset($product['price_original']) ? $product['price_original'] : 0;

                echo "<div class='product-item'>
                        <a href='/shopweb/fontend/product_detail.php?id=" . htmlspecialchars($product['id']) . "'>
                            <div class='product-content'>
                                <div class='product-image-container'>
                                    <img src='/shopweb/images/" . htmlspecialchars($product['image']) . "' alt='" . htmlspecialchars($product['name']) . "'>
                                </div>
                                <h3>" . htmlspecialchars($product['name']) . "</h3>
                                <div class='product-rating'>
                                    <div class='rating-stars'>";
                for ($i = 1; $i <= 5; $i++) {
                    if ($i <= round($rating)) {
                        echo '<svg class="star filled" viewBox="0 0 24 24" fill="#FFD700" xmlns="http://www.w3.org/2000/svg">
                                <path d="M12 2l2.834 6.036L22 9.27l-5 4.73L18.668 22 12 18.26 5.332 22 7 14 2 9.27l7.166-1.234L12 2z"/>
                              </svg>';
                    } else {
                        echo '<svg class="star empty" viewBox="0 0 24 24" fill="none" stroke="#FFD700" stroke-width="2" xmlns="http://www.w3.org/2000/svg">
                                <path d="M12 2l2.834 6.036L22 9.27l-5 4.73L18.668 22 12 18.26 5.332 22 7 14 2 9.27l7.166-1.234L12 2z"/>
                              </svg>';
                    }
                }
                echo "          </div>
                                <span class='rating-count'>(" . htmlspecialchars($reviewCount) . " đánh giá)</span>
                            </div>
                            <div class='product-prices'>
                                <span class='price'>" . number_format($product['price'], 0, ',', '.') . "đ</span>
                                <svg class='cart-icon' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'>
                                    <path d='M6.29977 5H21L19 12H7.37671M20 16H8L6 3H3M9 20C9 20.5523 8.55228 21 8 21C7.44772 21 7 20.5523 7 20C7 19.4477 7.44772 19 8 19C8.55228 19 9 19.4477 9 20ZM20 20C20 20.5523 19.5523 21 19 21C18.4477 21 18 20.5523 18 20C18 19.4477 18.4477 19 19 19C19.5523 19 20 19.4477 20 20Z'
                                        stroke-width='2' stroke-linecap='round' stroke-linejoin='round' />
                                </svg>";
                if (!empty($priceOriginal) && $priceOriginal > $product['price']) {
                    echo "<span class='product-price-original'>" . number_format($priceOriginal, 0, ',', '.') . "đ</span>";
                }
                echo "      </div>
                        </div>
                    </a>
                </div>";
            }
            echo "</div>";

            // Phân trang
            echo "<div class='pagination'>";
            // Nút quay về đầu
            if ($page > 1) {
                echo '<a class="page-btn" href="?page=1&q=' . urlencode($query) . '">«</a>';
            } else {
                echo '<span class="page-btn disabled">«</span>';
            }

            // Nút Prev
            if ($page > 1) {
                echo '<a class="page-btn" href="?page=' . ($page - 1) . '&q=' . urlencode($query) . '">‹</a>';
            } else {
                echo '<span class="page-btn disabled">‹</span>';
            }

            // Logic hiển thị trang
            if ($page > 2) {
                echo '<a class="page-btn" href="?page=1&q=' . urlencode($query) . '">1</a>';
                if ($page > 3) echo '<span class="dots">...</span>';
            }

            $start = max(1, $page - 1);
            $end = min($totalPages, $page + 1);

            for ($i = $start; $i <= $end; $i++) {
                if ($i == $page) {
                    echo '<span class="page-btn active">' . $i . '</span>';
                } else {
                    echo '<a class="page-btn" href="?page=' . $i . '&q=' . urlencode($query) . '">' . $i . '</a>';
                }
            }

            if ($page < $totalPages - 1) {
                if ($page < $totalPages - 2) echo '<span class="dots">...</span>';
                echo '<a class="page-btn" href="?page=' . $totalPages . '&q=' . urlencode($query) . '">' . $totalPages . '</a>';
            }

            // Nút Next
            if ($page < $totalPages) {
                echo '<a class="page-btn" href="?page=' . ($page + 1) . '&q=' . urlencode($query) . '">›</a>';
            } else {
                echo '<span class="page-btn disabled">›</span>';
            }

            // Nút đến trang cuối
            if ($page < $totalPages) {
                echo '<a class="page-btn" href="?page=' . $totalPages . '&q=' . urlencode($query) . '">»</a>';
            } else {
                echo '<span class="page-btn disabled">»</span>';
            }
            echo "</div>";
        } else {
            echo "<p>Không có sản phẩm nào.</p>";
        }
    }

    $conn->close();
    ?>
</div>
<?php include $_SERVER['DOCUMENT_ROOT'].'/shopweb/fontend/footer.php'; ?>