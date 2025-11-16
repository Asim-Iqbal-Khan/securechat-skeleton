# MySQL Setup Guide for SecureChat

This guide will help you set up MySQL for the SecureChat application.

## Option 1: Using Docker (Recommended - Easiest)

This is the simplest method and matches the README instructions:

```bash
# Start MySQL in Docker
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 \
  mysql:8

# Wait a few seconds for MySQL to start
sleep 5

# Update your .env file with these values:
# DB_HOST=localhost
# DB_PORT=3306
# DB_USER=scuser
# DB_PASSWORD=scpass
# DB_NAME=securechat
```

Then initialize the schema:
```bash
python -m app.storage.db --init
```

## Option 2: Using Local MySQL Installation

Since MySQL is already installed on your system, follow these steps:

### Step 1: Create Database and User

You have two options:

#### A. Using the setup script (easiest):
```bash
./setup_mysql.sh
```

This script will:
- Read your `.env` file
- Create the database
- Create the user with proper permissions
- Initialize the schema

#### B. Manual setup via MySQL command line:

```bash
# Connect to MySQL (use sudo if needed)
sudo mysql
# OR if you have root password:
mysql -u root -p
```

Then run these SQL commands (adjust values from your `.env` file):
```sql
CREATE DATABASE IF NOT EXISTS securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'securechat_user'@'localhost' IDENTIFIED BY 'your_password_here';
GRANT ALL PRIVILEGES ON securechat.* TO 'securechat_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Step 2: Update .env File

Make sure your `.env` file has the correct database credentials:

```bash
DB_HOST=localhost
DB_PORT=3306
DB_USER=securechat_user
DB_PASSWORD=your_password_here
DB_NAME=securechat
```

### Step 3: Initialize Database Schema

```bash
python -m app.storage.db --init
```

This will:
- Create the `users` table
- Set up indexes
- Verify the connection

## Option 3: Let the Script Create Everything

If your MySQL user has CREATE DATABASE privileges, you can skip manual setup:

```bash
# Just make sure .env has correct credentials
python -m app.storage.db --init
```

The script will automatically create the database if it doesn't exist.

## Verify Setup

Test the database connection:

```bash
# Connect to MySQL
mysql -u securechat_user -p securechat

# Check tables
SHOW TABLES;

# Should see: users
```

## Troubleshooting

### "Access denied" error
- Make sure MySQL root password is correct
- Try using `sudo mysql` instead
- Check if user exists: `SELECT User FROM mysql.user;`

### "Database connection failed"
- Verify MySQL service is running: `sudo systemctl status mysql`
- Check `.env` file has correct credentials
- Test connection: `mysql -u DB_USER -p -h DB_HOST`

### "Can't connect to MySQL server"
- Start MySQL service: `sudo systemctl start mysql`
- Check if port 3306 is open: `netstat -tlnp | grep 3306`

## Using Docker Commands

If using Docker:

```bash
# Stop the database
docker stop securechat-db

# Start the database
docker start securechat-db

# View logs
docker logs securechat-db

# Remove the database (WARNING: deletes all data)
docker rm -f securechat-db
```

