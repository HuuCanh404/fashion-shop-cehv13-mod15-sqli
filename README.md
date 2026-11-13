# Fashion-Shop — CEHv13 Module 15: SQL Injection Lab & Kiến trúc Phòng thủ 4 Lớp

> **Bài tập lớn môn An ninh mạng** — Trường Đại học Giao thông Vận tải TP. HCM (UTH)  
> **Đề tài:** `MODULE 15 — SQL INJECTION (CEHv13)` | **Nhóm thực hiện:** Nhóm 2

Kho mã nguồn thực nghiệm xây dựng trên ứng dụng thương mại điện tử **Fashion-Shop** (PHP 8.2 / MariaDB 13.0, dựa trên mã nguồn gốc `thhuyn25/fashion-shop`), cho phép chuyển đổi linh hoạt giữa hai chế độ **Vulnerable Lab (trước khi vá)** và **Hardened 4-Layer (sau khi bảo vệ)** để mô phỏng, rà soát và kiểm chứng phòng thủ SQL Injection.

---

## 1. Cấu trúc kho mã nguồn

```text
fashion-shop-cehv13-mod15-sqli/
├── fashion-shop/                          # Ứng dụng Web PHP/MariaDB hoàn chỉnh (87 tệp .php)
│   ├── database/
│   │   ├── config.php                     # Cấu hình kết nối MariaDB (shopdb)
│   │   ├── dbhelper.php                   # Hàm executePrepared() & hook SecurityDefense::enforce()
│   │   ├── defense_config.json            # Trạng thái cấu hình Lab / Hardened toàn cục
│   │   └── security_defense.php           # Bộ phòng thủ 4 lớp + Rate Limit + OTP + Nghi binh 200 OK
│   ├── quantri/
│   │   ├── admin_login.php                # Cổng đăng nhập Admin (hỗ trợ ?mode=vulnerable / hardened + OTP)
│   │   ├── security_dashboard.php         # Trung tâm Quản lý An ninh (bật/tắt chế độ, IP lock, Sandbox, OTP Inbox)
│   │   └── includes/auth_guard.php        # Bộ kiểm tra phiên $_SESSION['role'] === 'admin'
│   ├── xacthuc/
│   │   ├── login.php                      # Cổng khách hàng (mô phỏng leo thang -> tách cổng + HMAC Cookie)
│   │   ├── register.php, recover.php, reset_password.php
│   ├── fontend/
│   │   ├── search_results.php             # Trang tìm kiếm sản phẩm (Lab SQLi vs Hardened)
│   │   ├── product_detail.php, header.php, cart.php, checkout.php
│   ├── router.php                         # Bộ định tuyến cho PHP Built-in Server (/shopweb/)
│   ├── start_demo.ps1                     # Khởi chạy demo đa máy (PHP + MariaDB trên PATH)
│   └── shopdb.sql                         # Cơ sở dữ liệu mẫu kèm tài khoản admin_demo
├── tests/
│   ├── verify_admin_security.py           # Bộ kiểm thử HTTP tự động 10 kịch bản
│   └── admin_security_verification.json   # Bằng chứng kết quả đạt 10/10 kịch bản
└── docs/
    ├── academic_report_fashion_shop.docx  # Báo cáo Word chuẩn mẫu UTH (28 trang, Times New Roman)
    └── presentation_fashion_shop.pptx     # Slide thuyết trình (14 trang)
```

---

## 2. Nhóm thực hiện (Nhóm 2 — CNTT, UTH)

| STT | Họ và Tên | MSSV | Vai trò chính |
|:---:|---|:---:|---|
| 1 | Nguyễn Thanh Khiêm | `054204001759` | Thiết kế Lab, kiểm thử cổng Admin (`admin_login.php`) & Auth Guard |
| 2 | Đặng Duy Khánh | `052205011731` | Xây dựng Trung tâm An ninh (`security_dashboard.php`) & Rate Limit |
| 3 | Đặng Huỳnh Trà My | `052305011719` | Lỗ hổng cổng Khách hàng (`xacthuc/login.php`), Tìm kiếm & HMAC Cookie |
| 4 | Nguyễn Hữu Cảnh | `051205012841` | Cloudflare `CF-Connecting-IP`, xác thực OTP 6 số & Nghi binh `HTTP 200 OK` |
| 5 | Nguyễn Văn Phú | `02251120039` | Bộ kiểm thử tự động (`22/22` lint, `10/10` HTTP) & Tổng hợp tài liệu |

---

## 3. Các lỗ hổng mô phỏng & Kiến trúc phòng thủ 4 lớp

### Chế độ `Vulnerable Lab` (Phục vụ minh họa CEHv13 Module 15)
- **`quantri/admin_login.php`**: Chấp nhận chuỗi điều kiện `' OR '1'='1' #` hoặc `' OR 1=1 -- `, phơi bày câu truy vấn SQL và lỗi cú pháp MariaDB (In-Band Error Leak).
- **`quantri/includes/auth_guard.php`**: Tạm tắt kiểm tra `$_SESSION['role'] === 'admin'` khi `enforce_admin_auth = false`.
- **`xacthuc/login.php`**: Minh họa lỗ hổng leo thang từ cổng khách hàng sang trang quản trị bằng `' OR role='admin' #` (chuyển thẳng về `/shopweb/quantri/index.php`) và Cookie `remember_user` chưa ký.
- **`fontend/search_results.php` & `quantri/editsp.php`**: Truy vấn ghép chuỗi phục vụ kiểm thử đọc dữ liệu bảng khác (`UNION SELECT`) và đo trễ (`SLEEP`).

### Chế độ `Hardened 4-Layer` (Khiên bảo vệ kích hoạt đồng bộ)
1. **Lớp 1 — Vá tận gốc mã nguồn**: Chuẩn hóa `executePrepared()` (`mysqli_prepare` + `bind_param`), mật khẩu `password_verify()`, `AuthGuard` bắt buộc `role === 'admin'`, tách cổng chặn `admin` ở `xacthuc/login.php`, ký `remember_user` bằng `HMAC-SHA256` (`HttpOnly`), đóng token hết hạn tại `reset_password.php`, ẩn lỗi SQL `$conn->error`.
2. **Lớp 2 — Giới hạn tốc độ & OTP 6 chữ số**: Cửa sổ trượt tối đa `10 yêu cầu / 60 giây` theo IP; vi phạm trả `HTTP 429 Too Many Requests` (`Retry-After: 600`, khóa 10 phút). Đăng nhập Admin yêu cầu thêm mã OTP 6 chữ số dùng một lần.
3. **Lớp 3 — Nhận diện IP thực sau Cloudflare WAF (`CF-Connecting-IP`)**: Bật `cloudflare_mode` ưu tiên đọc `HTTP_CF_CONNECTING_IP` để tránh khóa nhầm IP nút Proxy và hỗ trợ đối chiếu chặn dải IP ở tầng mạng/ISP.
4. **Lớp 4 — Chiến thuật Nghi binh `HTTP 200 OK`**: Khi phát hiện dấu hiệu SQLi (`UNION SELECT`, `' OR`, `--`, `#`, `SLEEP(`, `BENCHMARK(`...), ngắt xử lý trước khi tới MariaDB và trả về trang giả mạo `HTTP 200 OK` sạch kèm header `X-Protection-System: Deceptive-Decoy-Active` trong `< 0.1s`.

---

## 4. Hướng dẫn cài đặt & Chạy thử nhanh (Localhost)

### Yêu cầu môi trường
- PHP 8.2+ (đã bật extension `mysqli`)
- MariaDB / MySQL 10.4+ hoặc 13.0+
- Python 3.10+ (nếu chạy bộ kiểm thử tự động `tests/verify_admin_security.py`)

### Bước 1: Tạo cơ sở dữ liệu
Tạo database tên `shopdb` trên MySQL/MariaDB và nạp tệp `fashion-shop/shopdb.sql`:
```sql
CREATE DATABASE IF NOT EXISTS shopdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```
```bash
mysql -u root shopdb < fashion-shop/shopdb.sql
```

### Bước 2: Chạy PHP Server
Từ thư mục gốc của kho (`fashion-shop-cehv13-mod15-sqli`), chạy script hỗ trợ hoặc lệnh PHP Built-in Server:
```powershell
php -S 127.0.0.1:8080 -t fashion-shop fashion-shop/router.php
```
Hoặc chạy trực tiếp bằng PowerShell:
```powershell
.\fashion-shop\start_demo.ps1
```

### Bước 3: Truy cập các đường dẫn chính
- **Trang chủ bán hàng**: `http://127.0.0.1:8080/shopweb/`
- **Đăng nhập Khách hàng**: `http://127.0.0.1:8080/shopweb/xacthuc/login.php`
- **Đăng nhập Quản trị (Admin)**: `http://127.0.0.1:8080/shopweb/quantri/admin_login.php`
- **Trung tâm Quản lý An ninh**: `http://127.0.0.1:8080/shopweb/quantri/security_dashboard.php`
- **Tài khoản Admin demo**: `admin_demo` / `Admin@123` (ở chế độ Hardened, xem mã OTP 6 số tại Hộp thư mô phỏng hoặc `quantri/logs/otp_mailbox.log`).

---

## 5. Kết quả kiểm chứng tự động

- **Kiểm tra cú pháp PHP (`php -l`)**: `22/22` tệp lõi không lỗi cú pháp.
- **Kiểm thử HTTP trực tiếp (`tests/verify_admin_security.py`)**: **`10/10` kịch bản đạt** (`passed_count: 10`, `total_count: 10`, `all_passed: true`, xem chi tiết trong `tests/admin_security_verification.json`).
