#!/bin/bash
# MySQL Setup Script for SecureChat
# This script sets up the MySQL database and user for the SecureChat application

set -e

echo "=========================================="
echo "MySQL Setup for SecureChat"
echo "=========================================="
echo ""

# Read database configuration from .env
if [ ! -f .env ]; then
    echo "[✗] .env file not found! Please create it from .env.example"
    exit 1
fi

source .env

DB_NAME=${DB_NAME:-securechat}
DB_USER=${DB_USER:-securechat_user}
DB_PASSWORD=${DB_PASSWORD:-securechat_pass}
DB_HOST=${DB_HOST:-localhost}

echo "[*] Database Configuration:"
echo "    Database: $DB_NAME"
echo "    User: $DB_USER"
echo "    Host: $DB_HOST"
echo ""

# Prompt for MySQL root password
echo "[*] You need MySQL root access to create the database and user"
read -sp "Enter MySQL root password (or press Enter if using sudo): " ROOT_PASS
echo ""

if [ -z "$ROOT_PASS" ]; then
    MYSQL_CMD="sudo mysql"
else
    MYSQL_CMD="mysql -u root -p$ROOT_PASS"
fi

echo "[*] Creating database '$DB_NAME'..."
$MYSQL_CMD <<EOF
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
EOF

echo "[✓] Database created"

echo "[*] Creating user '$DB_USER'..."
$MYSQL_CMD <<EOF
CREATE USER IF NOT EXISTS '$DB_USER'@'$DB_HOST' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'$DB_HOST';
FLUSH PRIVILEGES;
EOF

echo "[✓] User created and privileges granted"
echo ""

echo "[*] Initializing database schema..."
python3 -m app.storage.db --init

echo ""
echo "=========================================="
echo "[✓] MySQL setup complete!"
echo "=========================================="
echo ""
echo "You can now run the server with:"
echo "  python -m app.server"
echo ""

