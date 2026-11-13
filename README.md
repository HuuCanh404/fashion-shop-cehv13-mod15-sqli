# Fashion-Shop — CEHv13 Module 15: SQL Injection Lab & Kiến trúc Phòng thủ 4 Lớp

> **Đề tài:** `MODULE 15 — SQL INJECTION (CEHv13)` trên ứng dụng Web PHP 8.2 / MariaDB 13.0

Kho mã nguồn thực nghiệm xây dựng trên ứng dụng thương mại điện tử **Fashion-Shop** (dựa trên mã nguồn gốc `thhuyn25/fashion-shop`), cho phép chuyển đổi linh hoạt giữa hai chế độ **Vulnerable Lab (trước khi vá)** và **Hardened 4-Layer (sau khi bảo vệ)** để mô phỏng, rà soát và kiểm chứng phòng thủ SQL Injection.

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
│   ├── start_demo.ps1                     # Khởi chạy demo đa máy (tự tìm PHP WinGet / PATH)
│   └── shopdb.sql                         # Cơ sở dữ liệu mẫu kèm tài khoản admin_demo
├── tests/
│   ├── verify_admin_security.py           # Bộ kiểm thử HTTP tự động 10 kịch bản
│   └── admin_security_verification.json   # Bằng chứng kết quả đạt 10/10 kịch bản
└── docs/
    ├── academic_report_fashion_shop.docx  # Báo cáo Word tham khảo (28 trang, Times New Roman)
    └── presentation_fashion_shop.pptx     # Slide thuyết trình (14 trang)
```

---

## 2. Các lỗ hổng mô phỏng & Kiến trúc phòng thủ 4 lớp

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

## 3. Hướng dẫn cài đặt ứng dụng & Chạy bài bằng CMD (Windows)

### Bước 1: Cài đặt toàn bộ phần mềm cần thiết bằng CMD (`winget`)
Mở **Command Prompt (`cmd`)** (nên chạy bằng quyền Administrator nếu cài MariaDB dịch vụ hệ thống) và chạy lần lượt các lệnh sau:

```bat
winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements
winget install --id PHP.PHP.8.2 -e --accept-source-agreements --accept-package-agreements
winget install --id MariaDB.Server -e --accept-source-agreements --accept-package-agreements
winget install --id Python.Python.3.12 -e --accept-source-agreements --accept-package-agreements
```

*(Ghi chú: Sau khi cài xong, **đóng cửa sổ CMD cũ và mở cửa sổ CMD mới** để Windows nạp lại biến môi trường `PATH`. Nếu chỉ cần chạy web demo mà không chạy script kiểm thử tự động, có thể bỏ qua bước cài Python 3.12; hoặc thay PHP + MariaDB bằng bộ XAMPP nếu máy bạn đã cài sẵn XAMPP.)*

### Bước 2: Kiểm tra nhanh môi trường & Extension PHP bằng CMD
Chạy lệnh sau trong **CMD mới** để kiểm tra `git`, `php`, `python` và đảm bảo các module `mysqli`, `mbstring`, `openssl` đã sẵn sàng:

```bat
git --version
php -v
php -m | findstr /I "mysqli mbstring openssl"
python --version
```

*(Nếu `php -m` chưa thấy `mysqli`, kiểm tra vị trí tệp cấu hình bằng `php --ini`, mở tệp `php.ini` tương ứng hoặc chép từ `php.ini-development` sang `php.ini` rồi bỏ dấu `;` trước các dòng `extension=mysqli`, `extension=mbstring`, `extension=openssl`.)*

### Bước 3: Tải mã nguồn về máy bằng CMD

```bat
git clone https://github.com/HuuCanh404/fashion-shop-cehv13-mod15-sqli.git
cd fashion-shop-cehv13-mod15-sqli
```

### Bước 4: Khởi động MariaDB, tạo CSDL `shopdb` và nạp dữ liệu mẫu bằng CMD
Chạy các lệnh sau ngay trong thư mục gốc `fashion-shop-cehv13-mod15-sqli` của **CMD**:

```bat
net start MariaDB
"C:\Program Files\MariaDB 13.0\bin\mysql.exe" -u root -e "CREATE DATABASE IF NOT EXISTS shopdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
"C:\Program Files\MariaDB 13.0\bin\mysql.exe" -u root shopdb < fashion-shop\shopdb.sql
```

*(Lưu ý: Nếu khi cài MariaDB bạn có đặt mật khẩu cho tài khoản `root` thay vì để trống, thêm cờ `-p` sau `-u root` khi chạy lệnh `mysql.exe` và cập nhật hằng số `DB_PASS` trong `fashion-shop\database\config.php` cho khớp.)*

### Bước 5: Chạy Web Server bằng CMD
Tại thư mục `fashion-shop-cehv13-mod15-sqli`, chạy lệnh sau để mở máy chủ web nội bộ:

```bat
php -S 127.0.0.1:8080 -t fashion-shop fashion-shop\router.php
```

Hoặc dùng script tự động tìm `php.exe`:

```bat
powershell -ExecutionPolicy Bypass -File .\fashion-shop\start_demo.ps1
```

### Bước 6: Truy cập trình duyệt & Tài khoản thử nghiệm
- **Trang chủ bán hàng**: `http://127.0.0.1:8080/shopweb/`
- **Đăng nhập Khách hàng**: `http://127.0.0.1:8080/shopweb/xacthuc/login.php`
- **Đăng nhập Quản trị (Admin)**: `http://127.0.0.1:8080/shopweb/quantri/admin_login.php`
- **Trung tâm Quản lý An ninh**: `http://127.0.0.1:8080/shopweb/quantri/security_dashboard.php`
- **Tài khoản Admin demo**: `admin_demo` / `Admin@123` (ở chế độ `Hardened`, xem mã OTP 6 chữ số tại Hộp thư mô phỏng trên giao diện hoặc trong `fashion-shop\quantri\logs\otp_mailbox.log`).

### Bước 7: Chạy bộ kiểm thử tự động bằng CMD (tuỳ chọn)
Mở thêm một cửa sổ **CMD thứ hai** (trong lúc Web Server đang chạy ở cửa sổ thứ nhất) tại thư mục dự án và chạy:

```bat
python tests\verify_admin_security.py
```

---

## 4. Kết quả kiểm chứng tự động

- **Kiểm tra cú pháp PHP (`php -l`)**: `22/22` tệp lõi không lỗi cú pháp.
- **Kiểm thử HTTP trực tiếp (`tests/verify_admin_security.py`)**: **`10/10` kịch bản đạt** (`passed_count: 10`, `total_count: 10`, `all_passed: true`, xem chi tiết trong `tests/admin_security_verification.json`).
