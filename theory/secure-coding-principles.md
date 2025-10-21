# Secure Coding Principles

## 📚 Overview

Secure coding is the practice of writing software that is resistant to security vulnerabilities and attacks. This document outlines fundamental principles, patterns, and practices that every developer should understand and apply.

---

## 🎯 Core Security Principles

### 1. Defense in Depth

**Concept**: Implement multiple layers of security controls so that if one layer fails, others provide protection.

**Example**:
```
Layer 1: Input validation (reject malformed data)
Layer 2: Parameterized queries (prevent SQL injection even if validation fails)
Layer 3: Least privilege database user (limit damage if SQL injection succeeds)
Layer 4: Monitoring and alerts (detect attacks in progress)
```

**Implementation**:
- Never rely on a single security control
- Combine preventive, detective, and corrective controls
- Assume any single control can fail

### 2. Principle of Least Privilege

**Concept**: Grant only the minimum permissions necessary to perform a task.

**Applications**:
- **User Accounts**: Regular users shouldn't have admin rights
- **Service Accounts**: Database users should have minimal permissions
- **File Permissions**: Code files should not be writable by web server
- **API Access**: Tokens should have scoped permissions

**Example**:
```python
# ❌ BAD: Database user with full access
DB_USER = 'root'  # Can DROP tables, create users, etc.

# ✅ GOOD: Limited permissions
DB_USER = 'webapp_reader'  # Only SELECT on specific tables
```

### 3. Fail Securely (Fail Safe)

**Concept**: When errors occur, fail in a way that maintains security rather than exposing vulnerabilities.

**Examples**:

**Access Control**:
```python
# ❌ BAD: Default to allowing access
def check_permission(user, resource):
    try:
        return database.check_permission(user, resource)
    except:
        return True  # Dangerous! Allows access on error

# ✅ GOOD: Default to denying access
def check_permission(user, resource):
    try:
        return database.check_permission(user, resource)
    except:
        log_error("Permission check failed")
        return False  # Safe default
```

**Error Messages**:
```python
# ❌ BAD: Revealing error message
except Exception as e:
    return f"Database error: {str(e)}"  # Leaks internal details

# ✅ GOOD: Generic error message
except Exception as e:
    log_error(f"Database error: {str(e)}")  # Log for admins
    return "An error occurred. Please try again."  # Safe for users
```

### 4. Complete Mediation

**Concept**: Check permissions on every access to every resource, not just the first access.

**Example**:
```python
# ❌ BAD: Check permission only on file open
file = open_file(filename)  # Permission checked here
if can_access(user, file):
    content = file.read()  # No check!

# ✅ GOOD: Check permission on every operation
if can_access(user, filename):
    with open_secure(filename) as file:
        if can_read(user, file):  # Check again
            content = file.read()
```

### 5. Separation of Duties

**Concept**: Critical operations should require multiple independent parties.

**Examples**:
- Code reviews: Developer writes code, another reviews
- Deployment: Developer cannot deploy to production alone
- Financial transactions: Initiation and approval by different people
- Cryptographic keys: Split into multiple parts held by different people

### 6. Economy of Mechanism (Keep It Simple)

**Concept**: Security mechanisms should be as simple as possible. Complex systems have more vulnerabilities.

**Guidelines**:
- Use proven libraries instead of custom implementations
- Prefer simple, well-understood algorithms
- Avoid unnecessary features that increase attack surface
- Clear, readable code is easier to audit

### 7. Open Design (No Security Through Obscurity)

**Concept**: Security should not depend on attackers not knowing the design. Assume attackers have full knowledge of the system.

**Applications**:
- Algorithms should be public (e.g., AES, RSA)
- Security through obscurity is not security
- Only secrets should be keys/credentials, not algorithms

**Example**:
```python
# ❌ BAD: Custom "encryption" algorithm
def encrypt(data):
    return ''.join([chr(ord(c) + 3) for c in data])  # Caesar cipher!

# ✅ GOOD: Standard, proven algorithm
from cryptography.fernet import Fernet
def encrypt(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode())
```

### 8. Psychological Acceptability

**Concept**: Security mechanisms should be easy to use correctly. If security is too difficult, users will bypass it.

**Examples**:
- Simple, clear authentication flows
- Reasonable password requirements (not overly complex)
- Single sign-on (SSO) to reduce password fatigue
- Good error messages that guide users

---

## 🛡️ Secure Coding Practices

### Input Validation

**Always validate input before processing.**

#### Validation Strategies

**1. Whitelisting (Preferred)**
```python
# ✅ Allow only expected characters
import re

def validate_username(username):
    # Only letters, numbers, underscore (3-20 chars)
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return bool(re.match(pattern, username))

def validate_email(email):
    # Simple email pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))
```

**2. Type Validation**
```python
# ✅ Ensure correct data types
def process_age(age):
    if not isinstance(age, int):
        raise ValueError("Age must be an integer")
    if age < 0 or age > 150:
        raise ValueError("Age must be between 0 and 150")
    return age
```

**3. Length Limits**
```python
# ✅ Prevent resource exhaustion
MAX_INPUT_LENGTH = 1000

def validate_comment(comment):
    if len(comment) > MAX_INPUT_LENGTH:
        raise ValueError(f"Comment exceeds maximum length of {MAX_INPUT_LENGTH}")
    return comment
```

**4. Context-Specific Validation**
```python
# Different validation for different contexts
def validate_for_sql(value):
    # For SQL: use parameterized queries (no need to escape)
    return value  # Let database driver handle it

def validate_for_html(value):
    # For HTML display: escape special characters
    from html import escape
    return escape(value)

def validate_for_url(value):
    # For URLs: URL encode
    from urllib.parse import quote
    return quote(value)
```

#### Input Validation Rules

✅ **DO**:
- Validate on the server side (never trust client-side validation)
- Reject unexpected input
- Use whitelisting over blacklisting
- Validate length, type, format, and range
- Validate early in the processing pipeline

❌ **DON'T**:
- Rely solely on client-side validation
- Try to "sanitize" dangerous input (reject it instead)
- Use blacklists (attackers find ways around them)
- Validate only at entry points (validate everywhere data crosses trust boundaries)

---

### Output Encoding

**Always encode output based on the context where it will be used.**

#### HTML Context
```python
from html import escape

# ✅ Escape for HTML
user_input = "<script>alert('XSS')</script>"
safe_output = escape(user_input)
# Result: &lt;script&gt;alert('XSS')&lt;/script&gt;
```

#### JavaScript Context
```python
import json

# ✅ Encode for JavaScript
user_data = {"name": "'; alert('XSS'); //"}
safe_json = json.dumps(user_data)
```

#### URL Context
```python
from urllib.parse import quote

# ✅ Encode for URLs
search_query = "hello world & special chars"
safe_url = f"/search?q={quote(search_query)}"
```

#### SQL Context
```python
# ✅ Use parameterized queries (encoding handled automatically)
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

---

### Authentication and Session Management

#### Secure Password Storage

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

def hash_password(password):
    """Hash password with PBKDF2-HMAC-SHA256."""
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000
    )
    hash = kdf.derive(password.encode())
    return {'hash': hash, 'salt': salt}
```

#### Session Management Best Practices

**1. Generate Strong Session IDs**
```python
import secrets

def create_session():
    session_id = secrets.token_urlsafe(32)  # 256 bits
    return session_id
```

**2. Set Secure Cookie Flags**
```python
response.set_cookie(
    'session_id',
    value=session_id,
    httponly=True,   # Prevent JavaScript access
    secure=True,     # HTTPS only
    samesite='Lax',  # CSRF protection
    max_age=3600     # 1 hour expiration
)
```

**3. Implement Session Timeout**
```python
from datetime import datetime, timedelta

def is_session_valid(session):
    if not session.get('last_activity'):
        return False
    
    timeout = timedelta(minutes=30)
    if datetime.now() - session['last_activity'] > timeout:
        return False
    
    session['last_activity'] = datetime.now()
    return True
```

---

### Error Handling and Logging

#### Secure Error Handling

```python
# ❌ BAD: Detailed error to user
try:
    db.execute(query)
except Exception as e:
    return f"Database error: {str(e)}"  # Leaks details!

# ✅ GOOD: Generic message to user, detailed log
import logging

try:
    db.execute(query)
except Exception as e:
    logging.error(f"Database error: {str(e)}", exc_info=True)
    return "An error occurred. Please try again."
```

#### Secure Logging

**What to Log**:
- Authentication attempts (success and failure)
- Authorization failures
- Input validation failures
- Security-relevant configuration changes
- Exceptions and errors

**What NOT to Log**:
- Passwords or password hashes
- Session tokens or API keys
- Credit card numbers or PII
- Cryptographic keys

```python
# ❌ BAD: Logging sensitive data
logger.info(f"User {username} logged in with password {password}")

# ✅ GOOD: Log without sensitive data
logger.info(f"User {username} logged in successfully from {ip_address}")
```

---

### Cryptography

#### Use Established Libraries

```python
# ✅ Use cryptography library
from cryptography.fernet import Fernet

key = Fernet.generate_key()
f = Fernet(key)
ciphertext = f.encrypt(b"Secret message")
plaintext = f.decrypt(ciphertext)
```

#### Never Roll Your Own Crypto

```python
# ❌ NEVER DO THIS: Custom encryption
def my_encrypt(data, key):
    return ''.join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data)])
```

#### Use Strong Random Values

```python
import secrets

# ✅ Cryptographically secure random
token = secrets.token_bytes(32)
session_id = secrets.token_urlsafe(32)

# ❌ NOT cryptographically secure
import random
weak_token = random.randint(0, 1000000)  # Predictable!
```

---

## 🔍 Common Vulnerabilities and Mitigations

### SQL Injection

**Vulnerability**: User input directly in SQL query
```python
# ❌ VULNERABLE
query = f"SELECT * FROM users WHERE username = '{username}'"
```

**Mitigation**: Parameterized queries
```python
# ✅ SECURE
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

### Cross-Site Scripting (XSS)

**Vulnerability**: Unescaped user input in HTML
```python
# ❌ VULNERABLE
return f"<p>Hello, {username}!</p>"
```

**Mitigation**: Output encoding
```python
# ✅ SECURE
from html import escape
return f"<p>Hello, {escape(username)}!</p>"
```

### Path Traversal

**Vulnerability**: User-controlled file paths
```python
# ❌ VULNERABLE
filename = request.args.get('file')
with open(f'/app/files/{filename}') as f:
    return f.read()
```

**Mitigation**: Path validation
```python
# ✅ SECURE
import os

filename = request.args.get('file')
filepath = os.path.join('/app/files', filename)
real_path = os.path.realpath(filepath)

if not real_path.startswith('/app/files/'):
    abort(403)

with open(real_path) as f:
    return f.read()
```

### Command Injection

**Vulnerability**: User input in system commands
```python
# ❌ VULNERABLE
os.system(f'ping {host}')
```

**Mitigation**: Use subprocess with list arguments
```python
# ✅ SECURE
import subprocess
result = subprocess.run(['ping', '-c', '1', host], capture_output=True)
```

---

## 📋 Secure Coding Checklist

### Input Handling
- [ ] All user input is validated on the server side
- [ ] Validation uses whitelisting where possible
- [ ] Length limits are enforced
- [ ] Type checking is performed
- [ ] Unexpected input is rejected, not sanitized

### Output Handling
- [ ] Output is encoded based on context (HTML, JS, URL, SQL)
- [ ] Content Security Policy headers are set
- [ ] Error messages don't leak sensitive information

### Authentication
- [ ] Passwords are hashed with strong KDF (PBKDF2, Argon2, bcrypt)
- [ ] Unique salts are used per password
- [ ] Multi-factor authentication is available
- [ ] Account lockout prevents brute force

### Session Management
- [ ] Session IDs are cryptographically random
- [ ] Secure cookie flags are set (HttpOnly, Secure, SameSite)
- [ ] Sessions timeout after inactivity
- [ ] Sessions are invalidated on logout

### Cryptography
- [ ] Established libraries are used (not custom implementations)
- [ ] Strong algorithms are used (AES-256, RSA-2048+, SHA-256)
- [ ] Keys are generated securely and stored safely
- [ ] Sensitive data is encrypted at rest and in transit

### Access Control
- [ ] Principle of least privilege is applied
- [ ] Authorization checks are performed on every request
- [ ] Direct object references are validated
- [ ] Sensitive operations require re-authentication

### Error Handling
- [ ] Errors are caught and handled gracefully
- [ ] Stack traces are not exposed to users
- [ ] Security events are logged
- [ ] Sensitive data is not logged

---

## 📚 Additional Resources

- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [CERT Secure Coding Standards](https://wiki.sei.cmu.edu/confluence/display/seccode)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf)

---

**Last Updated**: October 14, 2025  
**Version**: 1.0
