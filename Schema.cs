namespace MobileStorePro;

public static class Schema
{
    public static readonly string[] Statements = new[]
    {
        @"CREATE TABLE IF NOT EXISTS stores (
            id INT AUTO_INCREMENT PRIMARY KEY,
            store_name VARCHAR(255) NOT NULL,
            owner_name VARCHAR(255) DEFAULT NULL,
            phone VARCHAR(50) DEFAULT NULL,
            address VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        @"CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            store_id INT DEFAULT NULL,
            username VARCHAR(100) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role ENUM('superadmin','storeowner','cashier','technician') NOT NULL DEFAULT 'cashier',
            name VARCHAR(255) DEFAULT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX(store_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        @"CREATE TABLE IF NOT EXISTS subscriptions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            store_id INT NOT NULL,
            plan VARCHAR(50) NOT NULL DEFAULT 'trial',
            expiry_date DATE NOT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX(store_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        @"CREATE TABLE IF NOT EXISTS products (
            id INT AUTO_INCREMENT PRIMARY KEY,
            store_id INT NOT NULL,
            name VARCHAR(255) NOT NULL,
            category VARCHAR(100) DEFAULT NULL,
            cost DECIMAL(12,2) NOT NULL DEFAULT 0,
            price DECIMAL(12,2) NOT NULL DEFAULT 0,
            stock INT NOT NULL DEFAULT 0,
            barcode VARCHAR(100) DEFAULT NULL,
            imei VARCHAR(100) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX(store_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        @"CREATE TABLE IF NOT EXISTS invoices (
            id INT AUTO_INCREMENT PRIMARY KEY,
            store_id INT NOT NULL,
            invoice_no VARCHAR(50) NOT NULL,
            customer_name VARCHAR(255) DEFAULT NULL,
            customer_phone VARCHAR(50) DEFAULT NULL,
            total DECIMAL(12,2) NOT NULL DEFAULT 0,
            seller_user_id INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX(store_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        @"CREATE TABLE IF NOT EXISTS invoice_items (
            id INT AUTO_INCREMENT PRIMARY KEY,
            invoice_id INT NOT NULL,
            product_id INT NOT NULL,
            product_name VARCHAR(255) DEFAULT NULL,
            unit_price DECIMAL(12,2) NOT NULL DEFAULT 0,
            quantity INT NOT NULL DEFAULT 1,
            line_total DECIMAL(12,2) NOT NULL DEFAULT 0,
            INDEX(invoice_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        @"CREATE TABLE IF NOT EXISTS repairs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            store_id INT NOT NULL,
            customer_name VARCHAR(255) NOT NULL,
            customer_phone VARCHAR(50) DEFAULT NULL,
            device VARCHAR(255) NOT NULL,
            issue TEXT,
            status ENUM('received','in_progress','repaired','delivered') NOT NULL DEFAULT 'received',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX(store_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    };
}