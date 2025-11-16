"""
MySQL user store with salted SHA-256 password hashing
Handles user registration and authentication
"""

import os
import mysql.connector
from mysql.connector import Error
from typing import Tuple, Optional
from app.common.utils import sha256_hex, constant_time_compare


class Database:
    """MySQL database manager for user credentials"""
    
    def __init__(self):
        self.host = os.getenv("DB_HOST", "localhost")
        self.port = int(os.getenv("DB_PORT", "3306"))
        self.user = os.getenv("DB_USER", "root")
        self.password = os.getenv("DB_PASSWORD", "")
        self.database = os.getenv("DB_NAME", "securechat")
        self.connection = None
    
    def connect(self) -> bool:
        """Establish database connection"""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password if self.password else None,
                database=self.database
            )
            return True
        except Error as e:
            print(f"[✗] Database connection error: {e}")
            return False
    
    def disconnect(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
    
    def init_schema(self):
        """Initialize database schema"""
        if not self.connection or not self.connection.is_connected():
            if not self.connect():
                raise Exception("Cannot connect to database")
        
        cursor = self.connection.cursor()
        
        # Create users table
        create_table_query = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) NOT NULL UNIQUE,
            username VARCHAR(255) NOT NULL UNIQUE,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_email (email),
            INDEX idx_username (username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
        
        cursor.execute(create_table_query)
        self.connection.commit()
        cursor.close()
        
        print("[✓] Database schema initialized")
    
    def register_user(self, email: str, username: str, salt: bytes, pwd_hash: str) -> Tuple[bool, str]:
        """
        Register a new user
        
        Args:
            email: User email
            username: Username
            salt: 16-byte random salt
            pwd_hash: Hex SHA-256 hash of (salt || password)
        
        Returns:
            Tuple of (success, message)
        """
        try:
            if not self.connection or not self.connection.is_connected():
                if not self.connect():
                    return False, "Database connection failed"
            
            cursor = self.connection.cursor()
            
            # Check if user exists
            cursor.execute(
                "SELECT email FROM users WHERE email = %s OR username = %s",
                (email, username)
            )
            if cursor.fetchone():
                cursor.close()
                return False, "User already exists"
            
            # Insert new user
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
            self.connection.commit()
            cursor.close()
            
            return True, "Registration successful"
            
        except Error as e:
            return False, f"Database error: {e}"
    
    def verify_login(self, email: str, password: str) -> Tuple[bool, str]:
        """
        Verify user credentials
        
        Args:
            email: User email
            password: Plaintext password
        
        Returns:
            Tuple of (success, username_or_error)
        """
        try:
            if not self.connection or not self.connection.is_connected():
                if not self.connect():
                    return False, "Database connection failed"
            
            cursor = self.connection.cursor()
            
            # Retrieve user data
            cursor.execute(
                "SELECT username, salt, pwd_hash FROM users WHERE email = %s",
                (email,)
            )
            result = cursor.fetchone()
            cursor.close()
            
            if not result:
                return False, "User not found"
            
            username, salt, stored_hash = result
            
            # Compute hash with provided password
            computed_hash = sha256_hex(salt, password.encode('utf-8'))
            
            # Constant-time comparison
            if constant_time_compare(computed_hash, stored_hash):
                return True, username
            else:
                return False, "Invalid password"
                
        except Error as e:
            return False, f"Database error: {e}"


# CLI for database initialization
if __name__ == "__main__":
    import sys
    
    if "--init" in sys.argv:
        from dotenv import load_dotenv
        load_dotenv()
        
        db = Database()
        
        # Connect to MySQL server without database
        try:
            conn = mysql.connector.connect(
                host=db.host,
                port=db.port,
                user=db.user,
                password=db.password if db.password else None
            )
            cursor = conn.cursor()
            
            # Create database
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db.database}")
            print(f"[✓] Database '{db.database}' created/verified")
            
            cursor.close()
            conn.close()
            
            # Initialize schema
            db.init_schema()
            db.disconnect()
            
        except Error as e:
            print(f"[✗] Error: {e}")
            sys.exit(1)
    else:
        print("Usage: python -m app.storage.db --init")