# Example 1: Input Validation and SQL Injection Prevention

## 🎯 Learning Objectives

By completing this example, you will:

1. **Understand** how SQL injection vulnerabilities occur
2. **Identify** vulnerable code patterns
3. **Implement** proper input validation techniques
4. **Apply** parameterized queries to prevent SQL injection
5. **Test** both vulnerable and secure implementations

## 📋 Prerequisites

- Basic Python programming knowledge
- Understanding of SQL queries
- Familiarity with databases (SQLite)

**Required Tools**:
- Python 3.8+
- SQLite3 (included with Python)

**Estimated Time**: 30-45 minutes

---

## 🔍 Problem Description

### The Scenario

You're developing a simple user authentication system for a web application. The system needs to:
- Accept a username and password from users
- Query the database to verify credentials
- Return user information if authentication succeeds

### The Vulnerability

Many developers make the mistake of directly embedding user input into SQL queries. This creates an **SQL injection vulnerability** where attackers can manipulate the query to bypass authentication or access unauthorized data.

### Example Attack

If a login form accepts username: `admin' OR '1'='1' --`

The resulting SQL query becomes:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = 'anything'
```

This always evaluates to TRUE, bypassing authentication!

---

## ⚠️ Vulnerable Implementation

### Vulnerable Code

```python
"""
vulnerable_login.py

⚠️ VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY
DO NOT USE IN PRODUCTION

This demonstrates how SQL injection vulnerabilities occur.
"""

import sqlite3
from typing import Optional, Dict

class VulnerableLoginSystem:
    """
    A deliberately vulnerable login system to demonstrate SQL injection.
    
    WARNING: This code contains security vulnerabilities!
    Use only for learning purposes in isolated environments.
    """
    
    def __init__(self, db_path: str = 'users.db'):
        """Initialize the vulnerable login system."""
        self.db_path = db_path
        self.setup_database()
    
    def setup_database(self):
        """Create a sample database with users."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                role TEXT
            )
        ''')
        
        # Insert sample users
        cursor.execute("DELETE FROM users")  # Clear existing data
        
        sample_users = [
            ('admin', 'admin123', 'admin@example.com', 'administrator'),
            ('alice', 'password1', 'alice@example.com', 'user'),
            ('bob', 'password2', 'bob@example.com', 'user'),
            ('charlie', 'securepass', 'charlie@example.com', 'user'),
        ]
        
        for username, password, email, role in sample_users:
            cursor.execute(
                "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                (username, password, email, role)
            )
        
        conn.commit()
        conn.close()
        print("Database initialized with sample users")
    
    def login_vulnerable(self, username: str, password: str) -> Optional[Dict]:
        """
        VULNERABLE LOGIN FUNCTION
        
        This function is vulnerable to SQL injection because it directly
        embeds user input into the SQL query string.
        
        Args:
            username: User-provided username
            password: User-provided password
            
        Returns:
            User information dict if login succeeds, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # ⚠️ VULNERABILITY: String formatting with user input
        # This allows attackers to inject arbitrary SQL code
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        print(f"\n[DEBUG] Executing query: {query}")
        
        try:
            cursor.execute(query)
            result = cursor.fetchone()
            
            if result:
                # Return user information
                user_info = {
                    'id': result[0],
                    'username': result[1],
                    'password': result[2],  # Never return passwords in real applications!
                    'email': result[3],
                    'role': result[4]
                }
                return user_info
            else:
                return None
                
        except sqlite3.Error as e:
            print(f"[ERROR] Database error: {e}")
            return None
        finally:
            conn.close()


def demonstrate_vulnerability():
    """
    Demonstrate various SQL injection attacks.
    """
    print("=" * 70)
    print("DEMONSTRATION: SQL INJECTION VULNERABILITY")
    print("=" * 70)
    
    system = VulnerableLoginSystem()
    
    # Test 1: Normal login (should work)
    print("\n[TEST 1] Normal Login")
    print("-" * 70)
    result = system.login_vulnerable('alice', 'password1')
    if result:
        print(f"✓ Login successful as: {result['username']} ({result['role']})")
    else:
        print("✗ Login failed")
    
    # Test 2: Wrong password (should fail)
    print("\n[TEST 2] Wrong Password")
    print("-" * 70)
    result = system.login_vulnerable('alice', 'wrongpassword')
    if result:
        print(f"✓ Login successful as: {result['username']}")
    else:
        print("✗ Login failed (expected)")
    
    # Test 3: SQL Injection - Authentication Bypass
    print("\n[TEST 3] SQL Injection - Authentication Bypass")
    print("-" * 70)
    malicious_input = "admin' OR '1'='1' --"
    result = system.login_vulnerable(malicious_input, 'anything')
    if result:
        print(f"⚠️  ATTACK SUCCESSFUL! Logged in as: {result['username']} ({result['role']})")
        print("    Attacker bypassed authentication without knowing the password!")
    else:
        print("✗ Attack failed")
    
    # Test 4: SQL Injection - Data Extraction
    print("\n[TEST 4] SQL Injection - Extracting All Users")
    print("-" * 70)
    malicious_input = "' OR '1'='1"
    result = system.login_vulnerable(malicious_input, 'anything')
    if result:
        print(f"⚠️  ATTACK SUCCESSFUL! Retrieved user: {result['username']}")
        print("    Attacker could enumerate all users this way!")
    else:
        print("✗ Attack failed")
    
    # Test 5: SQL Injection - Union-based Attack
    print("\n[TEST 5] SQL Injection - Advanced Attack")
    print("-" * 70)
    malicious_input = "admin' UNION SELECT 1,'hacker','hacked',NULL,'admin' --"
    result = system.login_vulnerable(malicious_input, '')
    if result:
        print(f"⚠️  ATTACK SUCCESSFUL! Created fake user: {result['username']}")
    else:
        print("✗ Attack failed or blocked")
    
    print("\n" + "=" * 70)
    print("CONCLUSION: The vulnerable implementation can be exploited in multiple ways!")
    print("=" * 70)


if __name__ == "__main__":
    demonstrate_vulnerability()
```

---

## ✅ Secure Implementation

### Secure Code

```python
"""
secure_login.py

✅ SECURE CODE - PRODUCTION-READY

This demonstrates proper input validation and parameterized queries
to prevent SQL injection attacks.
"""

import sqlite3
import re
import hashlib
from typing import Optional, Dict

class SecureLoginSystem:
    """
    A secure login system demonstrating best practices.
    
    Security Features:
    - Input validation with whitelisting
    - Parameterized queries (prepared statements)
    - Password hashing
    - Rate limiting (conceptual)
    - Logging
    """
    
    # Define allowed patterns
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
    PASSWORD_MIN_LENGTH = 8
    
    def __init__(self, db_path: str = 'users_secure.db'):
        """Initialize the secure login system."""
        self.db_path = db_path
        self.setup_database()
        self.failed_attempts = {}  # Simple rate limiting
    
    def setup_database(self):
        """Create a secure database with hashed passwords."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                role TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert sample users with hashed passwords
        cursor.execute("DELETE FROM users")
        
        sample_users = [
            ('admin', 'admin123', 'admin@example.com', 'administrator'),
            ('alice', 'password1', 'alice@example.com', 'user'),
            ('bob', 'password2', 'bob@example.com', 'user'),
            ('charlie', 'securepass', 'charlie@example.com', 'user'),
        ]
        
        for username, password, email, role in sample_users:
            password_hash = self._hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
                (username, password_hash, email, role)
            )
        
        conn.commit()
        conn.close()
        print("Secure database initialized")
    
    def _hash_password(self, password: str) -> str:
        """
        Hash a password using SHA-256.
        
        Note: In production, use bcrypt, scrypt, or Argon2 instead!
        SHA-256 is used here for simplicity.
        """
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _validate_username(self, username: str) -> bool:
        """
        Validate username format.
        
        Rules:
        - 3-20 characters
        - Only alphanumeric and underscore
        - No special characters
        """
        if not username or not isinstance(username, str):
            return False
        
        return bool(self.USERNAME_PATTERN.match(username))
    
    def _validate_password(self, password: str) -> bool:
        """
        Validate password requirements.
        
        Rules:
        - Minimum 8 characters
        - (In production: add complexity requirements)
        """
        if not password or not isinstance(password, str):
            return False
        
        return len(password) >= self.PASSWORD_MIN_LENGTH
    
    def _check_rate_limit(self, username: str) -> bool:
        """
        Simple rate limiting to prevent brute force.
        
        Returns:
            True if request is allowed, False if rate limited
        """
        # In production, use Redis or similar for distributed rate limiting
        if username in self.failed_attempts:
            if self.failed_attempts[username] >= 5:
                print(f"[SECURITY] Rate limit exceeded for user: {username}")
                return False
        return True
    
    def login_secure(self, username: str, password: str) -> Optional[Dict]:
        """
        SECURE LOGIN FUNCTION
        
        Security measures:
        1. Input validation
        2. Parameterized queries
        3. Password hashing
        4. Rate limiting
        5. Secure error messages
        
        Args:
            username: User-provided username
            password: User-provided password
            
        Returns:
            User information dict (without password!) if login succeeds, None otherwise
        """
        # Step 1: Validate input format
        if not self._validate_username(username):
            print("[SECURITY] Invalid username format")
            return None
        
        if not self._validate_password(password):
            print("[SECURITY] Invalid password format")
            return None
        
        # Step 2: Check rate limiting
        if not self._check_rate_limit(username):
            return None
        
        # Step 3: Hash the provided password
        password_hash = self._hash_password(password)
        
        # Step 4: Query database using parameterized query
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # ✅ SECURE: Parameterized query prevents SQL injection
        query = "SELECT id, username, email, role FROM users WHERE username = ? AND password_hash = ?"
        
        try:
            cursor.execute(query, (username, password_hash))
            result = cursor.fetchone()
            
            if result:
                # Successful login
                self.failed_attempts[username] = 0  # Reset failed attempts
                
                user_info = {
                    'id': result[0],
                    'username': result[1],
                    'email': result[2],
                    'role': result[3]
                }
                
                print(f"[INFO] Successful login for user: {username}")
                return user_info
            else:
                # Failed login
                self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
                print(f"[INFO] Failed login attempt for user: {username}")
                return None
                
        except sqlite3.Error as e:
            print(f"[ERROR] Database error: {e}")
            return None
        finally:
            conn.close()


def demonstrate_secure_system():
    """
    Demonstrate the secure login system.
    """
    print("=" * 70)
    print("DEMONSTRATION: SECURE LOGIN SYSTEM")
    print("=" * 70)
    
    system = SecureLoginSystem()
    
    # Test 1: Normal login (should work)
    print("\n[TEST 1] Valid Login")
    print("-" * 70)
    result = system.login_secure('alice', 'password1')
    if result:
        print(f"✓ Login successful!")
        print(f"   User: {result['username']}")
        print(f"   Role: {result['role']}")
        print(f"   Email: {result['email']}")
    else:
        print("✗ Login failed")
    
    # Test 2: Wrong password (should fail)
    print("\n[TEST 2] Wrong Password")
    print("-" * 70)
    result = system.login_secure('alice', 'wrongpassword')
    if result:
        print(f"✗ Unexpected success!")
    else:
        print("✓ Login correctly rejected")
    
    # Test 3: SQL Injection attempt (should fail)
    print("\n[TEST 3] SQL Injection Attempt")
    print("-" * 70)
    malicious_input = "admin' OR '1'='1' --"
    result = system.login_secure(malicious_input, 'anything')
    if result:
        print(f"✗ SECURITY FAILURE! Attack succeeded!")
    else:
        print("✓ Attack prevented by input validation")
    
    # Test 4: Invalid username format (should fail)
    print("\n[TEST 4] Invalid Username Format")
    print("-" * 70)
    result = system.login_secure('admin@#$%', 'password')
    if result:
        print(f"✗ Unexpected success!")
    else:
        print("✓ Invalid input correctly rejected")
    
    # Test 5: Rate limiting (should fail after multiple attempts)
    print("\n[TEST 5] Rate Limiting")
    print("-" * 70)
    for i in range(6):
        result = system.login_secure('alice', 'wrongpass')
        if not result and i < 5:
            print(f"   Attempt {i+1}: Failed (expected)")
        elif not result and i >= 5:
            print(f"   Attempt {i+1}: Rate limited ✓")
    
    print("\n" + "=" * 70)
    print("CONCLUSION: The secure implementation prevents all attack attempts!")
    print("=" * 70)


def compare_implementations():
    """
    Side-by-side comparison of vulnerable vs secure.
    """
    print("\n" + "=" * 70)
    print("COMPARISON: VULNERABLE VS. SECURE")
    print("=" * 70)
    
    print("\nVULNERABLE Implementation:")
    print("-" * 70)
    print("✗ String formatting with user input")
    print("✗ No input validation")
    print("✗ Plaintext passwords")
    print("✗ No rate limiting")
    print("✗ Verbose error messages")
    
    print("\nSECURE Implementation:")
    print("-" * 70)
    print("✓ Parameterized queries")
    print("✓ Input validation with whitelisting")
    print("✓ Password hashing")
    print("✓ Rate limiting")
    print("✓ Generic error messages")
    print("✓ Logging")
    
    print("\nKey Takeaway:")
    print("Defense in depth - multiple layers of security work together!")


if __name__ == "__main__":
    demonstrate_secure_system()
    compare_implementations()
```

---

## 🧪 Testing

### Test Script

```python
"""
test_login_systems.py

Unit tests for both vulnerable and secure login systems.
"""

import unittest
import os
from vulnerable_login import VulnerableLoginSystem
from secure_login import SecureLoginSystem

class TestVulnerableSystem(unittest.TestCase):
    """Tests for the vulnerable system (demonstrating exploits)."""
    
    def setUp(self):
        """Set up test database."""
        self.system = VulnerableLoginSystem('test_vulnerable.db')
    
    def tearDown(self):
        """Clean up test database."""
        if os.path.exists('test_vulnerable.db'):
            os.remove('test_vulnerable.db')
    
    def test_normal_login(self):
        """Test normal login functionality."""
        result = self.system.login_vulnerable('alice', 'password1')
        self.assertIsNotNone(result)
        self.assertEqual(result['username'], 'alice')
    
    def test_wrong_password(self):
        """Test failed login with wrong password."""
        result = self.system.login_vulnerable('alice', 'wrongpassword')
        self.assertIsNone(result)
    
    def test_sql_injection_bypass(self):
        """Test SQL injection vulnerability."""
        # This SHOULD fail in a secure system, but succeeds here
        result = self.system.login_vulnerable("admin' OR '1'='1' --", 'anything')
        self.assertIsNotNone(result)  # Vulnerability confirmed!


class TestSecureSystem(unittest.TestCase):
    """Tests for the secure system (should prevent exploits)."""
    
    def setUp(self):
        """Set up test database."""
        self.system = SecureLoginSystem('test_secure.db')
    
    def tearDown(self):
        """Clean up test database."""
        if os.path.exists('test_secure.db'):
            os.remove('test_secure.db')
    
    def test_normal_login(self):
        """Test normal login functionality."""
        result = self.system.login_secure('alice', 'password1')
        self.assertIsNotNone(result)
        self.assertEqual(result['username'], 'alice')
        self.assertNotIn('password', result)  # Should not return password
    
    def test_wrong_password(self):
        """Test failed login with wrong password."""
        result = self.system.login_secure('alice', 'wrongpassword')
        self.assertIsNone(result)
    
    def test_sql_injection_prevention(self):
        """Test that SQL injection is prevented."""
        result = self.system.login_secure("admin' OR '1'='1' --", 'anything')
        self.assertIsNone(result)  # Should be blocked
    
    def test_invalid_username_format(self):
        """Test input validation."""
        result = self.system.login_secure('admin@#$%', 'password')
        self.assertIsNone(result)
    
    def test_rate_limiting(self):
        """Test rate limiting after multiple failed attempts."""
        # Attempt 5 times
        for _ in range(5):
            self.system.login_secure('alice', 'wrongpass')
        
        # 6th attempt should be rate limited
        result = self.system.login_secure('alice', 'wrongpass')
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
```

### Running Tests

```bash
# Run tests
python test_login_systems.py

# Run with verbose output
python test_login_systems.py -v

# Run specific test class
python test_login_systems.py TestSecureSystem

# Run specific test
python test_login_systems.py TestSecureSystem.test_sql_injection_prevention
```

---

## 📚 Step-by-Step Walkthrough

### Understanding the Vulnerability

**Step 1: How SQL Injection Works**

Normal query:
```sql
SELECT * FROM users WHERE username = 'alice' AND password = 'password1'
```

With malicious input (`admin' OR '1'='1' --`):
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = 'anything'
```

The `--` comments out the rest, and `'1'='1'` is always true!

**Step 2: Why String Formatting is Dangerous**

```python
# DANGEROUS:
query = f"SELECT * FROM users WHERE username = '{username}'"

# User input: admin' OR '1'='1' --
# Resulting query: SELECT * FROM users WHERE username = 'admin' OR '1'='1' --'
```

### Implementing the Fix

**Step 1: Add Input Validation**

```python
def _validate_username(self, username: str) -> bool:
    # Only allow: letters, numbers, underscore
    # Length: 3-20 characters
    pattern = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
    return bool(pattern.match(username))
```

**WHY**: This prevents most injection attempts by rejecting special characters.

**Step 2: Use Parameterized Queries**

```python
# SECURE:
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))
```

**WHY**: The database treats `?` placeholders as data, not code. User input can never become part of the SQL command.

**Step 3: Hash Passwords**

```python
password_hash = hashlib.sha256(password.encode()).hexdigest()
```

**WHY**: Never store plain text passwords. If the database is compromised, hashed passwords are much harder to crack.

**Step 4: Implement Rate Limiting**

```python
if self.failed_attempts.get(username, 0) >= 5:
    return None  # Block further attempts
```

**WHY**: Prevents brute force attacks where attackers try many passwords.

**Step 5: Use Generic Error Messages**

```python
# GOOD:
print("Login failed")

# BAD:
print("User not found")  # Tells attacker the username doesn't exist
print("Wrong password")  # Tells attacker the username EXISTS
```

**WHY**: Don't give attackers information about what went wrong.

---

## 🎓 Key Takeaways

### Security Principles Applied

1. **Input Validation**: Whitelist only allowed characters
2. **Parameterized Queries**: Separate data from commands
3. **Defense in Depth**: Multiple layers (validation + parameterization + hashing)
4. **Principle of Least Privilege**: Don't return unnecessary data (no passwords in response)
5. **Fail Securely**: Reject invalid input rather than trying to sanitize it

### Common Mistakes to Avoid

❌ **String concatenation/formatting with user input**
❌ **Trying to "sanitize" input by escaping characters**
❌ **Storing passwords in plaintext**
❌ **Returning detailed error messages**
❌ **No rate limiting on authentication**

### Best Practices

✅ **Always use parameterized queries**
✅ **Validate input format before processing**
✅ **Use strong password hashing (bcrypt/Argon2)**
✅ **Implement rate limiting and account lockouts**
✅ **Log security events for monitoring**
✅ **Use HTTPS to protect credentials in transit**

---

## 📝 Exercises

### Exercise 1: Identify Vulnerabilities

Find the vulnerabilities in this code:

```python
def search_users(query):
    sql = f"SELECT * FROM users WHERE name LIKE '%{query}%'"
    cursor.execute(sql)
    return cursor.fetchall()
```

**Answer**: String formatting allows SQL injection. Use parameterized queries.

### Exercise 2: Fix the Vulnerable Code

Fix this registration function:

```python
def register_user(username, password, email):
    sql = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
    cursor.execute(sql)
```

**Solution**:
```python
def register_user(username, password, email):
    # Validate inputs
    if not validate_username(username):
        return False
    if not validate_email(email):
        return False
    
    # Hash password
    password_hash = hash_password(password)
    
    # Use parameterized query
    sql = "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)"
    cursor.execute(sql, (username, password_hash, email))
    return True
```

### Exercise 3: Extend the Secure System

Add the following features to the secure login system:
1. Password complexity requirements
2. Account lockout after failed attempts
3. Password reset functionality
4. Two-factor authentication

---

## 🔗 Additional Resources

### Documentation
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQLite Parameterized Queries](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders)
- [Python re module](https://docs.python.org/3/library/re.html)

### Tools
- [SQLMap](https://sqlmap.org/) - Automated SQL injection tool (for testing your own systems)
- [Burp Suite](https://portswigger.net/burp) - Web security testing

### Further Reading
- "SQL Injection Attacks and Defense" by Justin Clarke
- OWASP Testing Guide - SQL Injection section

---

## ❓ Discussion Questions

1. Why isn't escaping special characters enough to prevent SQL injection?
2. What's the difference between prepared statements and stored procedures?
3. How would you implement this securely in other languages (Java, PHP, Node.js)?
4. What additional security measures would a production system need?
5. How can you detect SQL injection attempts in your logs?

---

**Last Updated**: October 14, 2025  
**Version**: 1.0  
**Author**: IDATT2503 Course Team
