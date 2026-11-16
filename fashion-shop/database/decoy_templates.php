<?php
/**
 * decoy_templates.php - Realistic Deceptive HTTP 200 OK Templates & Synthetic Export Dumps
 *
 * Used by SecurityDefense (Layer 3 / 4) to neutralize SQLi probes with a believable
 * internal database & admin console UI and downloadable synthetic datasets.
 * All records below are 100% synthetic honeytoken/decoy fixtures.
 */

class SecurityDecoyTemplates {

    public static function getDataset(): array {
        return [
            'meta' => [
                'database' => 'shopdb',
                'engine' => 'MariaDB 10.11.6-MariaDB',
                'host' => '10.24.8.15:3306',
                'charset' => 'utf8mb4_unicode_ci',
                'total_users' => 1482,
                'total_orders' => 8940,
                'backup_file' => 'shopdb_production_backup_2026.sql',
                'backup_size' => '42.8 MB',
                'generated_at' => date('Y-m-d H:i:s'),
            ],
            'users' => [
                [
                    'id' => 1,
                    'username' => 'sys_root_adm',
                    'full_name' => 'Nguyễn Minh Quân',
                    'email' => 'quan.nm@fashionshop-corp.vn',
                    'phone' => '0908124578',
                    'role' => 'super_admin',
                    'password_hash' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
                    'last_login' => '2026-11-16 09:14:22',
                    'ip_address' => '14.161.28.94',
                    'status' => 'active',
                ],
                [
                    'id' => 2,
                    'username' => 'ketoan_hcm',
                    'full_name' => 'Trần Thị Bích Ngọc',
                    'email' => 'ngoc.ttb@fashionshop-corp.vn',
                    'phone' => '0912445890',
                    'role' => 'finance_admin',
                    'password_hash' => '$2y$10$TKh8H1.PfQx37YgCzwiKb.KjNyWgaHb9cbcoQgdIVFlYg7B77UdFm',
                    'last_login' => '2026-11-16 08:47:10',
                    'ip_address' => '113.161.72.19',
                    'status' => 'active',
                ],
                [
                    'id' => 3,
                    'username' => 'vanhanh_kho',
                    'full_name' => 'Lê Hoàng Nam',
                    'email' => 'nam.lh@fashionshop-corp.vn',
                    'phone' => '0983771204',
                    'role' => 'warehouse_mgr',
                    'password_hash' => '$2y$10$K4W8x0uJ1n6V7mR2pQ9sFe8aZ3cT5yL1bN0dH6jM2kP4rS7vW9xYe',
                    'last_login' => '2026-11-15 17:52:03',
                    'ip_address' => '27.72.104.51',
                    'status' => 'active',
                ],
                [
                    'id' => 4,
                    'username' => 'devops_vn',
                    'full_name' => 'Phạm Tuấn Kiệt',
                    'email' => 'kiet.pt@fashionshop-corp.vn',
                    'phone' => '0934882190',
                    'role' => 'admin',
                    'password_hash' => '$2y$10$mN8bV2cX5zL9kJ3hG7fD1sA4pQ6wE0rT8yU2iO5pL9kM3nB7vC1xZ',
                    'last_login' => '2026-11-16 07:30:45',
                    'ip_address' => '171.244.14.88',
                    'status' => 'active',
                ],
                [
                    'id' => 104,
                    'username' => 'minhanh_vip',
                    'full_name' => 'Đặng Minh Anh',
                    'email' => 'minhanh.dang97@mail-vn.example',
                    'phone' => '0903556712',
                    'role' => 'vip_customer',
                    'password_hash' => '$2y$10$a1B2c3D4e5F6g7H8i9J0kL1mN2oP3qR4sT5uV6wX7yZ8aB9cD0eF1',
                    'last_login' => '2026-11-15 21:18:11',
                    'ip_address' => '42.116.84.203',
                    'status' => 'active',
                ],
                [
                    'id' => 105,
                    'username' => 'thanhtung_95',
                    'full_name' => 'Võ Thanh Tùng',
                    'email' => 'tung.vo95@mail-vn.example',
                    'phone' => '0909334112',
                    'role' => 'vip_customer',
                    'password_hash' => '$2y$10$qW9eR8tY7uI6oP5aS4dF3gH2jK1lZ0xC9vB8nM7mN6bV5cX4zL3kJ',
                    'last_login' => '2026-11-16 10:05:39',
                    'ip_address' => '115.79.31.140',
                    'status' => 'active',
                ],
                [
                    'id' => 106,
                    'username' => 'thaovy_2001',
                    'full_name' => 'Nguyễn Thảo Vy',
                    'email' => 'thaovy.2001@mail-vn.example',
                    'phone' => '0977218934',
                    'role' => 'customer',
                    'password_hash' => '$2y$10$zX1cV2bN3mK4lJ5hG6fD7sA8pQ9wE0rT1yU2iO3pL4kM5nB6vC7xZ',
                    'last_login' => '2026-11-14 19:42:55',
                    'ip_address' => '1.55.198.76',
                    'status' => 'active',
                ],
                [
                    'id' => 107,
                    'username' => 'duchuy_saigon',
                    'full_name' => 'Huỳnh Đức Huy',
                    'email' => 'huy.huynh99@mail-vn.example',
                    'phone' => '0918663421',
                    'role' => 'customer',
                    'password_hash' => '$2y$10$pO9iU8yT7rE6wQ5aS4dF3gH2jK1lM0nB9vC8xZ7aS6dF5gH4jK3lM',
                    'last_login' => '2026-11-15 13:11:04',
                    'ip_address' => '14.241.67.192',
                    'status' => 'active',
                ],
                [
                    'id' => 108,
                    'username' => 'khanhlinh_style',
                    'full_name' => 'Bùi Khánh Linh',
                    'email' => 'linh.bui@mail-vn.example',
                    'phone' => '0938119205',
                    'role' => 'vip_customer',
                    'password_hash' => '$2y$10$lK9jH8gF7dS6aP5oI4uY3tR2eW1qA0zX9cV8bN7mM6nB5vC4xZ3aS',
                    'last_login' => '2026-11-16 11:27:18',
                    'ip_address' => '116.108.45.67',
                    'status' => 'active',
                ],
                [
                    'id' => 109,
                    'username' => 'quocbao_hn',
                    'full_name' => 'Trương Quốc Bảo',
                    'email' => 'bao.truong@mail-vn.example',
                    'phone' => '0964509812',
                    'role' => 'customer',
                    'password_hash' => '$2y$10$vB8nM7mN6bV5cX4zL3kJ2hG1fD0sA9pQ8wE7rT6yU5iO4pL3kM2nB',
                    'last_login' => '2026-11-13 20:09:41',
                    'ip_address' => '123.24.118.44',
                    'status' => 'active',
                ],
                [
                    'id' => 110,
                    'username' => 'myduyen_shop',
                    'full_name' => 'Phan Mỹ Duyên',
                    'email' => 'duyen.phan@mail-vn.example',
                    'phone' => '0945778231',
                    'role' => 'customer',
                    'password_hash' => '$2y$10$cX4zL3kJ2hG1fD0sA9pQ8wE7rT6yU5iO4pL3kM2nB1vC0xZ9aS8dF',
                    'last_login' => '2026-11-16 06:51:29',
                    'ip_address' => '171.233.90.15',
                    'status' => 'active',
                ],
                [
                    'id' => 111,
                    'username' => 'anhkhoa_2026',
                    'full_name' => 'Ngô Anh Khoa',
                    'email' => 'khoa.ngo@mail-vn.example',
                    'phone' => '0989412765',
                    'role' => 'staff',
                    'password_hash' => '$2y$10$eR8tY7uI6oP5aS4dF3gH2jK1lZ0xC9vB8nM7mN6bV5cX4zL3kJ2hG',
                    'last_login' => '2026-11-16 12:04:02',
                    'ip_address' => '27.67.55.109',
                    'status' => 'active',
                ],
            ],
            'orders' => [
                [
                    'order_code' => 'FS-2026-98412',
                    'customer_name' => 'Võ Thanh Tùng',
                    'phone' => '0909334112',
                    'email' => 'tung.vo95@mail-vn.example',
                    'shipping_address' => '128 Nguyễn Trãi, P. Bến Thành, Q.1, TP.HCM',
                    'payment_method' => 'VNPAY / Visa',
                    'card_masked' => '4111 •••• •••• 8824',
                    'total_amount' => 3290000,
                    'status' => 'Đã thanh toán',
                    'created_at' => '2026-11-16 14:22:08',
                ],
                [
                    'order_code' => 'FS-2026-98411',
                    'customer_name' => 'Đặng Minh Anh',
                    'phone' => '0903556712',
                    'email' => 'minhanh.dang97@mail-vn.example',
                    'shipping_address' => '45 Phố Huế, Q. Hai Bà Trưng, Hà Nội',
                    'payment_method' => 'MoMo Wallet',
                    'card_masked' => 'MOMO-****6712',
                    'total_amount' => 1850000,
                    'status' => 'Đang giao hàng',
                    'created_at' => '2026-11-16 13:49:17',
                ],
                [
                    'order_code' => 'FS-2026-98409',
                    'customer_name' => 'Bùi Khánh Linh',
                    'phone' => '0938119205',
                    'email' => 'linh.bui@mail-vn.example',
                    'shipping_address' => '210 Lê Lợi, Q. Hải Châu, Đà Nẵng',
                    'payment_method' => 'Mastercard',
                    'card_masked' => '5425 •••• •••• 3109',
                    'total_amount' => 4620000,
                    'status' => 'Đã thanh toán',
                    'created_at' => '2026-11-16 11:38:51',
                ],
                [
                    'order_code' => 'FS-2026-98405',
                    'customer_name' => 'Huỳnh Đức Huy',
                    'phone' => '0918663421',
                    'email' => 'huy.huynh99@mail-vn.example',
                    'shipping_address' => '72 Điện Biên Phủ, Q. Bình Thạnh, TP.HCM',
                    'payment_method' => 'Chuyển khoản Vietcombank',
                    'card_masked' => 'VCB **** 4912',
                    'total_amount' => 1240000,
                    'status' => 'Hoàn tất',
                    'created_at' => '2026-11-15 20:15:30',
                ],
                [
                    'order_code' => 'FS-2026-98398',
                    'customer_name' => 'Nguyễn Thảo Vy',
                    'phone' => '0977218934',
                    'email' => 'thaovy.2001@mail-vn.example',
                    'shipping_address' => '19 Cầu Giấy, Q. Cầu Giấy, Hà Nội',
                    'payment_method' => 'COD',
                    'card_masked' => 'Thanh toán khi nhận',
                    'total_amount' => 890000,
                    'status' => 'Đang xử lý',
                    'created_at' => '2026-11-15 16:40:12',
                ],
                [
                    'order_code' => 'FS-2026-98391',
                    'customer_name' => 'Trương Quốc Bảo',
                    'phone' => '0964509812',
                    'email' => 'bao.truong@mail-vn.example',
                    'shipping_address' => '88 Trần Phú, TP. Nha Trang, Khánh Hòa',
                    'payment_method' => 'VNPAY / JCB',
                    'card_masked' => '3528 •••• •••• 1140',
                    'total_amount' => 2750000,
                    'status' => 'Hoàn tất',
                    'created_at' => '2026-11-15 10:12:44',
                ],
                [
                    'order_code' => 'FS-2026-98384',
                    'customer_name' => 'Phan Mỹ Duyên',
                    'phone' => '0945778231',
                    'email' => 'duyen.phan@mail-vn.example',
                    'shipping_address' => '304 Cách Mạng Tháng 8, Q.10, TP.HCM',
                    'payment_method' => 'Techcombank QR',
                    'card_masked' => 'TCB **** 7781',
                    'total_amount' => 1990000,
                    'status' => 'Đã thanh toán',
                    'created_at' => '2026-11-14 21:05:19',
                ],
                [
                    'order_code' => 'FS-2026-98377',
                    'customer_name' => 'Lê Hoàng Nam',
                    'phone' => '0983771204',
                    'email' => 'nam.lh@fashionshop-corp.vn',
                    'shipping_address' => '15 Võ Văn Tần, Q.3, TP.HCM',
                    'payment_method' => 'Visa Corporate',
                    'card_masked' => '4532 •••• •••• 6019',
                    'total_amount' => 5400000,
                    'status' => 'Hoàn tất',
                    'created_at' => '2026-11-14 14:33:07',
                ],
            ],
            'system_config' => [
                [
                    'config_key' => 'VNPAY_TMN_SECRET',
                    'environment' => 'production',
                    'secret_value' => 'VNP_LIVE_9f8e7d6c5b4a3210fedcba9876543210',
                    'endpoint_note' => 'https://pay.vnpay.vn/vpcpay.html (Merchant ID: FSHOP2026)',
                    'updated_at' => '2026-11-10 08:00:00',
                ],
                [
                    'config_key' => 'JWT_AUTH_MASTER_KEY',
                    'environment' => 'production',
                    'secret_value' => 'fsh_live_91a8c4d2e7b0f31a6c5d4e2a8891bc34',
                    'endpoint_note' => 'Internal SSO & Admin Session Signer (HS256)',
                    'updated_at' => '2026-11-12 11:30:00',
                ],
                [
                    'config_key' => 'AWS_S3_BACKUP_KEY',
                    'environment' => 'backup',
                    'secret_value' => 'AKIA5F92B4C1E8A07721 / sK9mPq2xV7nR4wL8zB3cT6yH',
                    'endpoint_note' => 's3://fashionshop-db-backups-vn/daily-snapshots/',
                    'updated_at' => '2026-11-15 02:00:00',
                ],
                [
                    'config_key' => 'SMTP_MAIL_RELAY_PASS',
                    'environment' => 'mail',
                    'secret_value' => 'FShopMail#2026!Relay99',
                    'endpoint_note' => 'smtp.fashionshop-corp.vn:587 (noreply@fashionshop-corp.vn)',
                    'updated_at' => '2026-11-01 10:15:00',
                ],
                [
                    'config_key' => 'REDIS_SESSION_AUTH',
                    'environment' => 'cache',
                    'secret_value' => 'rd_prod_4482a91f7e6c0d3b2a19',
                    'endpoint_note' => 'redis://10.24.8.18:6379/0',
                    'updated_at' => '2026-11-14 09:45:00',
                ],
                [
                    'config_key' => 'MOMO_PARTNER_ACCESS_KEY',
                    'environment' => 'production',
                    'secret_value' => 'MOMO_PK_81729304abcdEFGH5678',
                    'endpoint_note' => 'https://payment.momo.vn/v2/gateway/api/create',
                    'updated_at' => '2026-11-08 15:20:00',
                ],
            ],
            'products' => [
                ['id' => 1, 'sku' => 'FS-TEE-001', 'name' => 'Áo Thun Oversize Heavyweight Signature', 'category' => 'Áo thun', 'price' => 390000, 'stock' => 142],
                ['id' => 2, 'sku' => 'FS-HD-014', 'name' => 'Áo Hoodie Nỉ Bông Essential Zip', 'category' => 'Hoodie & Sweater', 'price' => 680000, 'stock' => 64],
                ['id' => 3, 'sku' => 'FS-JKT-008', 'name' => 'Áo Khoác Bomber Varsity Limited', 'category' => 'Áo khoác', 'price' => 1150000, 'stock' => 28],
                ['id' => 4, 'sku' => 'FS-PNT-021', 'name' => 'Quần Cargo Túi Hộp Ripstop', 'category' => 'Quần dài', 'price' => 590000, 'stock' => 91],
                ['id' => 5, 'sku' => 'FS-SH-005', 'name' => 'Áo Sơ Mi Oxford Regular Fit', 'category' => 'Áo sơ mi', 'price' => 490000, 'stock' => 115],
                ['id' => 6, 'sku' => 'FS-CAP-011', 'name' => 'Mũ Lưỡi Trai Cotton Wash Logo', 'category' => 'Phụ kiện', 'price' => 260000, 'stock' => 210],
            ],
        ];
    }

    public static function renderSqlDump(): string {
        $ds = self::getDataset();
        $now = $ds['meta']['generated_at'];
        $sql = "-- FashionShop Production Database Snapshot\n"
            . "-- Host: {$ds['meta']['host']}    Database: {$ds['meta']['database']}\n"
            . "-- Server version: {$ds['meta']['engine']}\n"
            . "-- Generated: {$now}\n"
            . "-- ------------------------------------------------------\n\n"
            . "SET NAMES utf8mb4;\n"
            . "SET FOREIGN_KEY_CHECKS = 0;\n\n"
            . "CREATE DATABASE IF NOT EXISTS `shopdb` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
            . "USE `shopdb`;\n\n"
            . "-- ----------------------------\n"
            . "-- Table structure for `users`\n"
            . "-- ----------------------------\n"
            . "DROP TABLE IF EXISTS `users`;\n"
            . "CREATE TABLE `users` (\n"
            . "  `id` int(11) NOT NULL AUTO_INCREMENT,\n"
            . "  `username` varchar(100) NOT NULL,\n"
            . "  `full_name` varchar(150) NOT NULL,\n"
            . "  `email` varchar(150) NOT NULL,\n"
            . "  `phone` varchar(20) DEFAULT NULL,\n"
            . "  `role` varchar(40) NOT NULL DEFAULT 'customer',\n"
            . "  `password` varchar(255) NOT NULL,\n"
            . "  `last_login` datetime DEFAULT NULL,\n"
            . "  `ip_address` varchar(45) DEFAULT NULL,\n"
            . "  `status` varchar(20) NOT NULL DEFAULT 'active',\n"
            . "  PRIMARY KEY (`id`),\n"
            . "  UNIQUE KEY `uniq_username` (`username`)\n"
            . ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n";

        $esc = static function ($val): string {
            return str_replace(["\\", "'", "\r", "\n"], ["\\\\", "\\'", "\\r", "\\n"], (string)$val);
        };

        $sql .= "INSERT INTO `users` (`id`, `username`, `full_name`, `email`, `phone`, `role`, `password`, `last_login`, `ip_address`, `status`) VALUES\n";
        $userLines = [];
        foreach ($ds['users'] as $u) {
            $userLines[] = sprintf(
                "(%d, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')",
                (int)$u['id'],
                $esc($u['username']),
                $esc($u['full_name']),
                $esc($u['email']),
                $esc($u['phone']),
                $esc($u['role']),
                $esc($u['password_hash']),
                $esc($u['last_login']),
                $esc($u['ip_address']),
                $esc($u['status'])
            );
        }
        $sql .= implode(",\n", $userLines) . ";\n\n";

        $sql .= "-- ----------------------------\n"
            . "-- Table structure for `orders`\n"
            . "-- ----------------------------\n"
            . "DROP TABLE IF EXISTS `orders`;\n"
            . "CREATE TABLE `orders` (\n"
            . "  `order_code` varchar(32) NOT NULL,\n"
            . "  `customer_name` varchar(150) NOT NULL,\n"
            . "  `phone` varchar(20) NOT NULL,\n"
            . "  `email` varchar(150) NOT NULL,\n"
            . "  `shipping_address` varchar(255) NOT NULL,\n"
            . "  `payment_method` varchar(60) NOT NULL,\n"
            . "  `card_masked` varchar(60) DEFAULT NULL,\n"
            . "  `total_amount` bigint(20) NOT NULL,\n"
            . "  `status` varchar(50) NOT NULL,\n"
            . "  `created_at` datetime NOT NULL,\n"
            . "  PRIMARY KEY (`order_code`)\n"
            . ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n";

        $sql .= "INSERT INTO `orders` (`order_code`, `customer_name`, `phone`, `email`, `shipping_address`, `payment_method`, `card_masked`, `total_amount`, `status`, `created_at`) VALUES\n";
        $orderLines = [];
        foreach ($ds['orders'] as $o) {
            $orderLines[] = sprintf(
                "('%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, '%s', '%s')",
                $esc($o['order_code']),
                $esc($o['customer_name']),
                $esc($o['phone']),
                $esc($o['email']),
                $esc($o['shipping_address']),
                $esc($o['payment_method']),
                $esc($o['card_masked']),
                (int)$o['total_amount'],
                $esc($o['status']),
                $esc($o['created_at'])
            );
        }
        $sql .= implode(",\n", $orderLines) . ";\n\n";

        $sql .= "-- ----------------------------\n"
            . "-- Table structure for `system_config`\n"
            . "-- ----------------------------\n"
            . "DROP TABLE IF EXISTS `system_config`;\n"
            . "CREATE TABLE `system_config` (\n"
            . "  `config_key` varchar(100) NOT NULL,\n"
            . "  `environment` varchar(40) NOT NULL,\n"
            . "  `secret_value` varchar(255) NOT NULL,\n"
            . "  `endpoint_note` varchar(255) DEFAULT NULL,\n"
            . "  `updated_at` datetime NOT NULL,\n"
            . "  PRIMARY KEY (`config_key`)\n"
            . ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n";

        $sql .= "INSERT INTO `system_config` (`config_key`, `environment`, `secret_value`, `endpoint_note`, `updated_at`) VALUES\n";
        $cfgLines = [];
        foreach ($ds['system_config'] as $c) {
            $cfgLines[] = sprintf(
                "('%s', '%s', '%s', '%s', '%s')",
                $esc($c['config_key']),
                $esc($c['environment']),
                $esc($c['secret_value']),
                $esc($c['endpoint_note']),
                $esc($c['updated_at'])
            );
        }
        $sql .= implode(",\n", $cfgLines) . ";\n\nSET FOREIGN_KEY_CHECKS = 1;\n";

        return $sql;
    }

    public static function renderCsvDump(): string {
        $ds = self::getDataset();
        $out = "\xEF\xBB\xBF";
        $csvCell = static function ($val): string {
            $s = str_replace('"', '""', (string)$val);
            return '"' . $s . '"';
        };
        $headers = ['id', 'username', 'full_name', 'email', 'phone', 'role', 'password_hash', 'last_login', 'ip_address', 'status'];
        $out .= implode(',', array_map($csvCell, $headers)) . "\r\n";
        foreach ($ds['users'] as $u) {
            $row = [
                $u['id'],
                $u['username'],
                $u['full_name'],
                $u['email'],
                $u['phone'],
                $u['role'],
                $u['password_hash'],
                $u['last_login'],
                $u['ip_address'],
                $u['status'],
            ];
            $out .= implode(',', array_map($csvCell, $row)) . "\r\n";
        }
        return $out;
    }

    public static function renderJsonDump(): string {
        $ds = self::getDataset();
        $payload = [
            'status' => 'success',
            'database' => $ds['meta']['database'],
            'engine' => $ds['meta']['engine'],
            'host' => $ds['meta']['host'],
            'exported_at' => $ds['meta']['generated_at'],
            'summary' => [
                'users_total' => $ds['meta']['total_users'],
                'orders_total' => $ds['meta']['total_orders'],
                'exported_users' => count($ds['users']),
                'exported_orders' => count($ds['orders']),
                'exported_configs' => count($ds['system_config']),
            ],
            'tables' => [
                'users' => $ds['users'],
                'orders' => $ds['orders'],
                'system_config' => $ds['system_config'],
                'products' => $ds['products'],
            ],
        ];
        return json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    }

    public static function renderHtml(string $matchedInput = '', string $requestUri = ''): string {
        $ds = self::getDataset();
        $safeInput = htmlspecialchars($matchedInput !== '' ? $matchedInput : "SELECT * FROM users WHERE status='active'", ENT_QUOTES, 'UTF-8');
        $safeUri = htmlspecialchars($requestUri !== '' ? $requestUri : '/shopweb/quantri/index.php', ENT_QUOTES, 'UTF-8');
        $usersJson = json_encode($ds['users'], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        $ordersJson = json_encode($ds['orders'], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        $configJson = json_encode($ds['system_config'], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        $productsJson = json_encode($ds['products'], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

        $userRowsHtml = '';
        foreach ($ds['users'] as $u) {
            $roleClass = 'badge-user';
            if ($u['role'] === 'super_admin' || $u['role'] === 'admin') {
                $roleClass = 'badge-admin';
            } elseif ($u['role'] === 'finance_admin' || $u['role'] === 'warehouse_mgr' || $u['role'] === 'staff') {
                $roleClass = 'badge-staff';
            } elseif ($u['role'] === 'vip_customer') {
                $roleClass = 'badge-vip';
            }
            $shortHash = htmlspecialchars(substr($u['password_hash'], 0, 26) . '...', ENT_QUOTES, 'UTF-8');
            $fullHash = htmlspecialchars($u['password_hash'], ENT_QUOTES, 'UTF-8');
            $userRowsHtml .= '<tr data-search="' . htmlspecialchars(strtolower($u['username'] . ' ' . $u['full_name'] . ' ' . $u['email'] . ' ' . $u['role']), ENT_QUOTES, 'UTF-8') . '">'
                . '<td class="mono muted">#' . (int)$u['id'] . '</td>'
                . '<td><div class="user-cell"><strong>' . htmlspecialchars($u['username'], ENT_QUOTES, 'UTF-8') . '</strong><span class="sub">' . htmlspecialchars($u['full_name'], ENT_QUOTES, 'UTF-8') . '</span></div></td>'
                . '<td><div>' . htmlspecialchars($u['email'], ENT_QUOTES, 'UTF-8') . '</div><span class="sub mono">' . htmlspecialchars($u['phone'], ENT_QUOTES, 'UTF-8') . '</span></td>'
                . '<td><span class="role-badge ' . $roleClass . '">' . htmlspecialchars($u['role'], ENT_QUOTES, 'UTF-8') . '</span></td>'
                . '<td><div class="hash-box"><code title="' . $fullHash . '">' . $shortHash . '</code><button type="button" class="copy-btn" data-copy="' . $fullHash . '">Copy</button></div></td>'
                . '<td class="mono sub">' . htmlspecialchars($u['last_login'], ENT_QUOTES, 'UTF-8') . '<br>' . htmlspecialchars($u['ip_address'], ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td><span class="status-dot"></span>Active</td>'
                . '</tr>';
        }

        $orderRowsHtml = '';
        foreach ($ds['orders'] as $o) {
            $amt = number_format((int)$o['total_amount'], 0, ',', '.') . '₫';
            $orderRowsHtml .= '<tr>'
                . '<td class="mono"><strong>' . htmlspecialchars($o['order_code'], ENT_QUOTES, 'UTF-8') . '</strong></td>'
                . '<td><div>' . htmlspecialchars($o['customer_name'], ENT_QUOTES, 'UTF-8') . '</div><span class="sub mono">' . htmlspecialchars($o['phone'], ENT_QUOTES, 'UTF-8') . '</span></td>'
                . '<td class="sub">' . htmlspecialchars($o['shipping_address'], ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td><div>' . htmlspecialchars($o['payment_method'], ENT_QUOTES, 'UTF-8') . '</div><span class="sub mono">' . htmlspecialchars($o['card_masked'], ENT_QUOTES, 'UTF-8') . '</span></td>'
                . '<td class="mono"><strong>' . htmlspecialchars($amt, ENT_QUOTES, 'UTF-8') . '</strong></td>'
                . '<td><span class="role-badge badge-staff">' . htmlspecialchars($o['status'], ENT_QUOTES, 'UTF-8') . '</span></td>'
                . '<td class="mono sub">' . htmlspecialchars($o['created_at'], ENT_QUOTES, 'UTF-8') . '</td>'
                . '</tr>';
        }

        $cfgRowsHtml = '';
        foreach ($ds['system_config'] as $c) {
            $valEsc = htmlspecialchars($c['secret_value'], ENT_QUOTES, 'UTF-8');
            $cfgRowsHtml .= '<tr>'
                . '<td class="mono"><strong>' . htmlspecialchars($c['config_key'], ENT_QUOTES, 'UTF-8') . '</strong></td>'
                . '<td><span class="role-badge badge-admin">' . htmlspecialchars($c['environment'], ENT_QUOTES, 'UTF-8') . '</span></td>'
                . '<td><div class="hash-box"><code>' . $valEsc . '</code><button type="button" class="copy-btn" data-copy="' . $valEsc . '">Copy</button></div></td>'
                . '<td class="sub">' . htmlspecialchars($c['endpoint_note'], ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td class="mono sub">' . htmlspecialchars($c['updated_at'], ENT_QUOTES, 'UTF-8') . '</td>'
                . '</tr>';
        }

        return <<<HTML
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FashionShop Internal Console — Database &amp; Admin Manager (shopdb)</title>
    <style>
        :root {
            --bg: #ffffff;
            --panel: #ffffff;
            --panel-2: #f8fafc;
            --border: #e2e8f0;
            --text: #0f172a;
            --muted: #64748b;
            --accent: #0284c7;
            --green: #059669;
            --amber: #d97706;
            --purple: #7c3aed;
            --red: #dc2626;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
        }
        .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
        .sub { font-size: 12px; color: var(--muted); display: block; }
        .muted { color: var(--muted); }
        .layout { display: grid; grid-template-columns: 260px 1fr; min-height: 100vh; background: #ffffff; }
        .sidebar {
            background: #f8fafc;
            border-right: 1px solid var(--border);
            padding: 20px 16px;
            display: flex;
            flex-direction: column;
            gap: 18px;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 10px;
            padding-bottom: 14px;
            border-bottom: 1px solid var(--border);
        }
        .brand-logo {
            width: 36px; height: 36px; border-radius: 10px;
            background: linear-gradient(135deg, #0284c7, #4f46e5);
            display: grid; place-items: center; font-weight: 800; color: #fff; font-size: 15px;
        }
        .brand-title { font-weight: 700; font-size: 15px; line-height: 1.2; color: #0f172a; }
        .brand-ver { font-size: 11px; color: var(--accent); font-weight: 600; }
        .conn-card {
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 12px;
            font-size: 12px;
            line-height: 1.65;
            color: #334155;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
        }
        .conn-card .ok { color: var(--green); font-weight: 700; }
        .nav-group-title { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin-bottom: 6px; font-weight: 600; }
        .nav-btn {
            width: 100%; text-align: left; background: transparent; color: #334155;
            border: 1px solid transparent; border-radius: 8px; padding: 9px 12px;
            cursor: pointer; font-size: 13px; display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 4px; transition: .15s;
        }
        .nav-btn:hover { background: #e2e8f0; color: #0f172a; }
        .nav-btn.active { background: #e0f2fe; border-color: #7dd3fc; color: #0369a1; font-weight: 600; }
        .nav-count { background: #ffffff; border: 1px solid var(--border); color: var(--accent); padding: 2px 7px; border-radius: 99px; font-size: 11px; font-weight: 600; }
        .main { padding: 24px 28px; overflow-x: hidden; background: #ffffff; }
        .topbar {
            display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
            margin-bottom: 18px;
        }
        .session-pill {
            display: inline-flex; align-items: center; gap: 8px;
            background: #ecfdf5; border: 1px solid #a7f3d0;
            color: #047857; padding: 6px 12px; border-radius: 99px; font-size: 12px; font-weight: 600;
        }
        .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--green); margin-right: 6px; }
        .query-banner {
            background: #ffffff; border: 1px solid var(--border); border-left: 4px solid var(--green);
            border-radius: 10px; padding: 14px 16px; margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
        }
        .query-banner-head { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; font-size: 13px; margin-bottom: 8px; color: #0f172a; }
        .query-code {
            background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px;
            padding: 9px 12px; font-size: 12px; color: #0369a1; overflow-x: auto; white-space: pre-wrap; word-break: break-all;
        }
        .kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 20px; }
        .kpi {
            background: #ffffff; border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px;
            box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
        }
        .kpi-label { font-size: 12px; color: var(--muted); font-weight: 500; }
        .kpi-val { font-size: 22px; font-weight: 700; margin: 4px 0; color: #0f172a; }
        .kpi-sub { font-size: 11px; color: var(--accent); font-weight: 500; }
        .export-box {
            background: #f0f9ff;
            border: 1px solid #bae6fd;
            border-radius: 12px; padding: 16px 18px; margin-bottom: 20px;
            display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px;
        }
        .export-actions { display: flex; flex-wrap: wrap; gap: 10px; }
        .dl-btn {
            display: inline-flex; align-items: center; gap: 8px; padding: 9px 14px;
            border-radius: 8px; font-size: 13px; font-weight: 600; text-decoration: none;
            cursor: pointer; border: 1px solid transparent; transition: .15s;
        }
        .dl-sql { background: #0284c7; color: #fff; }
        .dl-sql:hover { background: #0369a1; }
        .dl-csv { background: #059669; color: #fff; }
        .dl-csv:hover { background: #047857; }
        .dl-json { background: #4f46e5; color: #fff; }
        .dl-json:hover { background: #4338ca; }
        .panel {
            background: #ffffff; border: 1px solid var(--border); border-radius: 12px; overflow: hidden;
            box-shadow: 0 1px 3px rgba(15, 23, 42, 0.05);
        }
        .panel-head {
            padding: 14px 18px; border-bottom: 1px solid var(--border);
            display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;
            background: #f8fafc;
        }
        .search-input {
            background: #ffffff; border: 1px solid #cbd5e1; color: var(--text);
            padding: 7px 12px; border-radius: 8px; font-size: 13px; min-width: 240px;
        }
        .search-input:focus { outline: 2px solid #bae6fd; border-color: #0284c7; }
        .table-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; background: #ffffff; }
        th, td { padding: 11px 14px; text-align: left; border-bottom: 1px solid #e2e8f0; vertical-align: middle; }
        th { font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: #475569; background: #f8fafc; font-weight: 700; }
        tr:hover td { background: #f8fafc; }
        .role-badge { padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; display: inline-block; }
        .badge-admin { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }
        .badge-staff { background: #fffbeb; color: #b45309; border: 1px solid #fde68a; }
        .badge-vip { background: #f5f3ff; color: #6d28d9; border: 1px solid #ddd6fe; }
        .badge-user { background: #f0f9ff; color: #0369a1; border: 1px solid #bae6fd; }
        .hash-box { display: flex; align-items: center; gap: 6px; }
        .hash-box code { background: #f1f5f9; border: 1px solid #e2e8f0; padding: 3px 7px; border-radius: 5px; font-size: 12px; color: #0f172a; }
        .copy-btn {
            background: #ffffff; color: #334155; border: 1px solid #cbd5e1;
            border-radius: 5px; padding: 3px 8px; font-size: 11px; cursor: pointer; font-weight: 500;
        }
        .copy-btn:hover { background: #f1f5f9; color: #0f172a; }
        .tab-pane { display: none; }
        .tab-pane.active { display: block; }
        .sql-editor {
            width: 100%; min-height: 92px; background: #f8fafc; color: #0f172a;
            border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px; font-size: 13px;
            resize: vertical;
        }
        .toast {
            position: fixed; right: 20px; bottom: 20px; background: #ffffff; color: #047857;
            border: 1px solid #10b981; padding: 11px 16px; border-radius: 10px;
            font-size: 13px; font-weight: 600; box-shadow: 0 10px 25px rgba(15, 23, 42, .12); display: none; z-index: 99;
        }
        @media (max-width: 960px) {
            .layout { grid-template-columns: 1fr; }
            .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        }
    </style>
</head>
<body>
<div class="layout">
    <aside class="sidebar">
        <div class="brand">
            <div class="brand-logo">FS</div>
            <div>
                <div class="brand-title">FashionShop DB</div>
                <div class="brand-ver">Internal Console v4.2</div>
            </div>
        </div>
        <div class="conn-card mono">
            <div>Status: <span class="ok">CONNECTED</span></div>
            <div>Host: 10.24.8.15:3306</div>
            <div>DB: <strong>shopdb</strong></div>
            <div>User: root@localhost</div>
            <div>Privileges: ALL GRANT</div>
        </div>
        <div>
            <div class="nav-group-title">Bảng dữ liệu (shopdb)</div>
            <button class="nav-btn active" data-tab="users"><span>users</span><span class="nav-count">1,482</span></button>
            <button class="nav-btn" data-tab="orders"><span>orders &amp; payments</span><span class="nav-count">8,940</span></button>
            <button class="nav-btn" data-tab="config"><span>system_config</span><span class="nav-count">6</span></button>
            <button class="nav-btn" data-tab="console"><span>SQL Query Console</span><span class="nav-count">CLI</span></button>
        </div>
        <div style="margin-top:auto; font-size:12px; color:var(--muted); border-top:1px solid var(--border); padding-top:12px;">
            <div>Endpoint: <span class="mono">{$safeUri}</span></div>
            <div style="margin-top:6px;"><a href="/shopweb/index.php" style="color:var(--accent); text-decoration:none;">← Về trang cửa hàng</a></div>
        </div>
    </aside>

    <main class="main">
        <div class="topbar">
            <div>
                <h1 style="margin:0; font-size:20px;">Trung tâm Quản trị Cơ sở Dữ liệu &amp; Xuất Sao lưu</h1>
                <span class="sub">MariaDB 10.11.6-MariaDB • utf8mb4_unicode_ci • Phiên truy cập đặc quyền</span>
            </div>
            <div class="session-pill"><span class="status-dot"></span>HTTP 200 OK • Truy vấn hợp lệ (0.041s)</div>
        </div>

        <div class="query-banner">
            <div class="query-banner-head">
                <strong>✓ Truy vấn hoàn tất — Trả về tập kết quả từ bảng <code class="mono">shopdb.users</code></strong>
                <span class="mono muted">Rows matched: 12 / 1,482 (cached snapshot)</span>
            </div>
            <div class="query-code mono">Input Context: {$safeInput}
Executed: SELECT id, username, full_name, email, phone, role, password, last_login, ip_address FROM shopdb.users ORDER BY id ASC LIMIT 12;</div>
        </div>

        <div class="kpis">
            <div class="kpi">
                <div class="kpi-label">Tài khoản hệ thống (users)</div>
                <div class="kpi-val">1,482</div>
                <div class="kpi-sub">4 Admin • 14 Nhân viên • 1,464 Khách</div>
            </div>
            <div class="kpi">
                <div class="kpi-label">Đơn hàng &amp; Giao dịch (orders)</div>
                <div class="kpi-val">8,940</div>
                <div class="kpi-sub">Đồng bộ VNPAY / MoMo / Visa</div>
            </div>
            <div class="kpi">
                <div class="kpi-label">Khóa bí mật &amp; API (system_config)</div>
                <div class="kpi-val">6</div>
                <div class="kpi-sub">Payment, JWT, AWS S3, SMTP</div>
            </div>
            <div class="kpi">
                <div class="kpi-label">Bản sao lưu CSDL gần nhất</div>
                <div class="kpi-val">42.8 MB</div>
                <div class="kpi-sub">shopdb_production_backup_2026.sql</div>
            </div>
        </div>

        <div class="export-box">
            <div>
                <div style="font-weight:700; font-size:15px;">Gói Dữ liệu Trích xuất &amp; Sao lưu Hệ thống (Sẵn sàng tải về)</div>
                <div class="sub">Tải trực tiếp toàn bộ cấu trúc bảng, danh sách tài khoản, hash mật khẩu, đơn hàng và khóa cấu hình.</div>
            </div>
            <div class="export-actions">
                <a class="dl-btn dl-sql" href="?sys_export=sql" data-dl-label="shopdb_production_backup_2026.sql">⬇ Tải Full SQL Dump (.sql)</a>
                <a class="dl-btn dl-csv" href="?sys_export=csv" data-dl-label="users_admin_credentials_export.csv">⬇ Tải Tài khoản &amp; Hash (.csv)</a>
                <a class="dl-btn dl-json" href="?sys_export=json" data-dl-label="customers_orders_secrets_dump.json">⬇ Tải Full JSON Export (.json)</a>
            </div>
        </div>

        <!-- TAB: USERS -->
        <section class="panel tab-pane active" id="tab-users">
            <div class="panel-head">
                <div><strong>Bảng `shopdb`.`users`</strong> <span class="sub">Hiển thị 12 bản ghi ưu tiên (Quản trị &amp; Khách hàng VIP)</span></div>
                <input type="text" id="userSearch" class="search-input" placeholder="Lọc theo username, email, role...">
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Tài khoản</th>
                            <th>Liên hệ</th>
                            <th>Phân quyền</th>
                            <th>Password Hash (bcrypt)</th>
                            <th>Đăng nhập cuối</th>
                            <th>Trạng thái</th>
                        </tr>
                    </thead>
                    <tbody id="userTbody">{$userRowsHtml}</tbody>
                </table>
            </div>
        </section>

        <!-- TAB: ORDERS -->
        <section class="panel tab-pane" id="tab-orders">
            <div class="panel-head">
                <div><strong>Bảng `shopdb`.`orders`</strong> <span class="sub">Giao dịch thanh toán &amp; địa chỉ giao nhận gần nhất</span></div>
                <a class="dl-btn dl-json" style="padding:6px 12px; font-size:12px;" href="?sys_export=json">Xuất JSON</a>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Mã đơn</th>
                            <th>Khách hàng</th>
                            <th>Địa chỉ giao hàng</th>
                            <th>Thanh toán</th>
                            <th>Tổng tiền</th>
                            <th>Trạng thái</th>
                            <th>Thời gian</th>
                        </tr>
                    </thead>
                    <tbody>{$orderRowsHtml}</tbody>
                </table>
            </div>
        </section>

        <!-- TAB: CONFIG -->
        <section class="panel tab-pane" id="tab-config">
            <div class="panel-head">
                <div><strong>Bảng `shopdb`.`system_config`</strong> <span class="sub">Thông số tích hợp thanh toán, lưu trữ S3 &amp; khóa xác thực</span></div>
                <a class="dl-btn dl-sql" style="padding:6px 12px; font-size:12px;" href="?sys_export=sql">Bao gồm trong .sql</a>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Config Key</th>
                            <th>Môi trường</th>
                            <th>Secret / Token</th>
                            <th>Ghi chú Endpoint</th>
                            <th>Cập nhật</th>
                        </tr>
                    </thead>
                    <tbody>{$cfgRowsHtml}</tbody>
                </table>
            </div>
        </section>

        <!-- TAB: SQL CONSOLE -->
        <section class="panel tab-pane" id="tab-console">
            <div class="panel-head">
                <div><strong>SQL Query Console — `shopdb`</strong> <span class="sub">Thực thi truy vấn trực tiếp trên kết nối MariaDB hiện tại</span></div>
                <div style="display:flex; gap:6px; flex-wrap:wrap;">
                    <button type="button" class="copy-btn" onclick="setSql('SHOW TABLES;')">SHOW TABLES;</button>
                    <button type="button" class="copy-btn" onclick="setSql('SELECT id, username, email, role, password FROM users;')">SELECT * FROM users;</button>
                    <button type="button" class="copy-btn" onclick="setSql('SELECT * FROM orders;')">SELECT * FROM orders;</button>
                    <button type="button" class="copy-btn" onclick="setSql('SELECT * FROM system_config;')">SELECT * FROM system_config;</button>
                </div>
            </div>
            <div style="padding:16px;">
                <textarea id="sqlInput" class="sql-editor mono">SELECT id, username, email, role, password FROM users ORDER BY id ASC;</textarea>
                <div style="margin-top:10px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                    <button type="button" class="dl-btn dl-sql" onclick="runSimulatedSql()">▶ Thực thi truy vấn</button>
                    <span id="sqlMeta" class="mono sub">Sẵn sàng</span>
                </div>
                <div id="sqlResultWrap" class="table-wrap" style="margin-top:14px;"></div>
            </div>
        </section>
    </main>
</div>
<div id="toast" class="toast"></div>
<script>
const DB_DATA = {
    users: {$usersJson},
    orders: {$ordersJson},
    system_config: {$configJson},
    products: {$productsJson}
};

function showToast(msg) {
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.style.display = 'block';
    clearTimeout(window.__toastTimer);
    window.__toastTimer = setTimeout(() => { el.style.display = 'none'; }, 2800);
}

document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const target = document.getElementById('tab-' + btn.dataset.tab);
        if (target) target.classList.add('active');
    });
});

document.getElementById('userSearch').addEventListener('input', function() {
    const q = this.value.trim().toLowerCase();
    document.querySelectorAll('#userTbody tr').forEach(tr => {
        const hay = tr.dataset.search || '';
        tr.style.display = hay.includes(q) ? '' : 'none';
    });
});

document.querySelectorAll('.copy-btn[data-copy]').forEach(btn => {
    btn.addEventListener('click', () => {
        const val = btn.dataset.copy;
        if (navigator.clipboard) {
            navigator.clipboard.writeText(val).catch(() => {});
        }
        showToast('Đã sao chép giá trị vào clipboard.');
    });
});

document.querySelectorAll('a[data-dl-label]').forEach(link => {
    link.addEventListener('click', () => {
        showToast('Đang trích xuất & tải xuống ' + link.dataset.dlLabel + '...');
    });
});

function setSql(q) {
    document.getElementById('sqlInput').value = q;
    runSimulatedSql();
}

function escHtml(v) {
    return String(v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function runSimulatedSql() {
    const raw = (document.getElementById('sqlInput').value || '').trim();
    const low = raw.toLowerCase();
    let rows = [];
    if (low.includes('show tables')) {
        rows = [
            {Tables_in_shopdb: 'users', Engine: 'InnoDB', Rows: 1482},
            {Tables_in_shopdb: 'orders', Engine: 'InnoDB', Rows: 8940},
            {Tables_in_shopdb: 'customers', Engine: 'InnoDB', Rows: 1464},
            {Tables_in_shopdb: 'products', Engine: 'InnoDB', Rows: 128},
            {Tables_in_shopdb: 'system_config', Engine: 'InnoDB', Rows: 6}
        ];
    } else if (low.includes('orders')) {
        rows = DB_DATA.orders;
    } else if (low.includes('system_config') || low.includes('config')) {
        rows = DB_DATA.system_config;
    } else if (low.includes('products')) {
        rows = DB_DATA.products;
    } else {
        rows = DB_DATA.users;
    }
    const meta = document.getElementById('sqlMeta');
    meta.textContent = rows.length + ' rows in set (0.029 sec)';
    const wrap = document.getElementById('sqlResultWrap');
    if (!rows.length) {
        wrap.innerHTML = '<div class="sub">Empty set (0.012 sec)</div>';
        return;
    }
    const cols = Object.keys(rows[0]);
    let html = '<table><thead><tr>' + cols.map(c => '<th>' + escHtml(c) + '</th>').join('') + '</tr></thead><tbody>';
    rows.forEach(r => {
        html += '<tr>' + cols.map(c => '<td class="mono">' + escHtml(r[c]) + '</td>').join('') + '</tr>';
    });
    html += '</tbody></table>';
    wrap.innerHTML = html;
}
</script>
</body>
</html>
HTML;
    }
}
