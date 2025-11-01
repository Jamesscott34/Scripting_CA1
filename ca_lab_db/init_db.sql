-- CA Lab Database Initialization Script
-- WARNING: This database contains intentionally vulnerable data for educational purposes only
-- DO NOT use these credentials or patterns in production environments

-- Drop and recreate database
DROP DATABASE IF EXISTS ca_vuln_db;
CREATE DATABASE ca_vuln_db;
USE ca_vuln_db;

-- Create users table with intentionally weak passwords for testing
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test users with intentionally weak passwords
INSERT INTO users (username, password, email, role) VALUES
('admin', 'admin123', 'admin@lab.local', 'admin'),
('john', 'password', 'john@lab.local', 'user'),
('jane', '123456', 'jane@lab.local', 'user'),
('test', 'test', 'test@lab.local', 'user'),
('demo', 'demo123', 'demo@lab.local', 'user');

-- Create products table for additional testing scenarios
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL
);

-- Insert sample products
INSERT INTO products (name, description, price) VALUES
('Laptop', 'High-performance laptop for development', 1299.99),
('Mouse', 'Wireless optical mouse', 29.99),
('Keyboard', 'Mechanical keyboard with RGB lighting', 89.99);

-- Create additional table for UNION-based injection testing
CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    product_id INT,
    quantity INT,
    total_amount DECIMAL(10,2),
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Insert sample orders
INSERT INTO orders (user_id, product_id, quantity, total_amount) VALUES
(1, 1, 1, 1299.99),
(2, 2, 2, 59.98),
(3, 3, 1, 89.99);
