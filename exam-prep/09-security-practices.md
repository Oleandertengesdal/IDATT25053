# 9. Security Best Practices - Complete Guide

## Overview
Common sense security principles that appear in various exam questions. Know **why** each practice matters.

---

## 9.1 Principle of Least Privilege

### Definition
Users/processes should have only the minimum permissions needed to perform their tasks.

**Exam Question (2022 Q2 style):** "Why should you never run services as root?"

**Model Answer:**
"Running services as root violates the principle of least privilege. If a service has a vulnerability, an attacker exploiting it gains root privileges, allowing complete system compromise. A compromised root process can read/modify any file, install malware, create backdoor users, disable logging, and pivot to other systems. Instead, services should run as dedicated users with minimal permissions. For example, a web server only needs to read web files and bind to port 80/443, not access to entire system. If compromised, damage is limited to that service's capabilities. Modern systems use capabilities and containers to further restrict process permissions."

### Example 1: Service User Setup
```bash
# ❌ Bad: Run as root
$ sudo ./webserver

# If exploited:
- Attacker has root access
- Can read /etc/shadow
- Can install rootkits
- Can compromise entire system

# ✅ Good: Create dedicated user
$ sudo useradd -r -s /bin/false webserver
$ sudo chown -R webserver:webserver /var/www
$ sudo -u webserver ./webserver

# If exploited:
- Attacker has limited 'webserver' user access
- Cannot access other users' files
- Cannot modify system files
- Damage contained to web content
```

### Example 2: File Permissions
```bash
# ❌ Bad: World-readable secrets
$ chmod 644 /etc/mysql/password.conf
-rw-r--r-- password.conf
# Any user can read database password!

# ✅ Good: Restrictive permissions
$ chmod 600 /etc/mysql/password.conf
$ chown mysql:mysql /etc/mysql/password.conf
-rw------- 1 mysql mysql password.conf
# Only mysql user can read
```

---

## 9.2 Defense in Depth

### Definition
Multiple layers of security controls, so if one fails, others still protect.

**Layers:**
```
Layer 1: Network Perimeter
- Firewall
- IDS/IPS
- VPN

Layer 2: Host Security
- OS hardening
- Antivirus
- Host firewall

Layer 3: Application Security
- Input validation
- Authentication
- Encryption

Layer 4: Data Security
- Encryption at rest
- Access controls
- Backups

Layer 5: Physical Security
- Locked server rooms
- Security cameras
- Badge access
```

### Example 3: Web Application Defense
```
Single layer (❌):
Input validation only
→ If bypassed, complete compromise

Multiple layers (✅):
1. Input validation (prevent bad data)
2. Prepared statements (prevent SQL injection even if validation bypassed)
3. WAF (detect/block attack patterns)
4. Database permissions (limit damage if compromised)
5. Monitoring (detect ongoing attacks)
6. Backups (recover from successful attack)

Attacker must defeat ALL layers to fully succeed
```

---

## 9.3 Secure Password Handling

### Never Store Plaintext Passwords

**Exam Question (2022 Q5):** "Why should passwords not be stored in memory longer than necessary?"

**Model Answer:**
"Passwords in memory can be extracted via memory dumps, swap files, crash dumps, or debuggers even after the program ends. Attackers with local access or exploiting vulnerabilities (e.g., Heartbleed) can read process memory. Core dumps created during crashes may contain passwords and be world-readable. Passwords should be cleared from memory immediately after use using secure_zero_memory() or similar. In languages without memory management, use volatile pointers to prevent compiler optimization from removing clearing code. For password verification, compare hashes immediately and clear plaintext. This minimizes the window of vulnerability and reduces forensic traces."

### Example 4: Secure Password Handling
```c
// ❌ Bad: Password stays in memory
char password[128];
get_password(password);
if (check_password(password)) {
    login_user();
}
// password still in memory here!
// May persist even after program exits

// ✅ Good: Clear immediately
#include <string.h>
volatile char password[128];  // Volatile prevents optimization
get_password(password);
int valid = check_password(password);

// Clear password immediately
explicit_bzero(password, sizeof(password));  // or memset_s()
// Note: Don't use regular memset, compiler may optimize it away

if (valid) {
    login_user();
}
```

### Password Storage

```
❌ Never:
- Plaintext: passwords in cleartext
- Simple hash: MD5(password) - rainbow tables work
- Hash without salt: SHA256(password) - identical passwords = identical hashes

✅ Correct:
- Salted slow hash
- Example: Argon2id(password, salt, time=3, memory=64MB)

Why:
- Salt: Prevents rainbow tables, makes each hash unique
- Slow: Prevents brute force (Argon2 takes ~0.5 seconds vs SHA256's microseconds)
- Memory-hard: Prevents GPU cracking
```

**Example 5: Password Storage**
```python
# ❌ Bad
import hashlib
password_hash = hashlib.sha256(password.encode()).hexdigest()
# Fast to crack, no salt

# ✅ Good
import argon2
ph = argon2.PasswordHasher(
    time_cost=3,      # 3 iterations
    memory_cost=65536,  # 64 MB
    parallelism=4
)
password_hash = ph.hash(password)
# Slow, salted, memory-hard

# Verify
try:
    ph.verify(password_hash, password_attempt)
    print("Valid")
except argon2.exceptions.VerifyMismatchError:
    print("Invalid")
```

---

## 9.4 Multi-Factor Authentication (MFA)

### Three Factors

**Exam Question:** "What are the three authentication factors?"

**Answer:**
```
1. Something you KNOW
   - Password
   - PIN
   - Security questions
   - Weakness: Can be guessed, stolen, or phished

2. Something you HAVE
   - Hardware token (YubiKey)
   - Phone (SMS, authenticator app)
   - Smart card
   - Weakness: Can be lost or stolen (but attacker needs physical access)

3. Something you ARE
   - Fingerprint
   - Face recognition
   - Iris scan
   - Voice recognition
   - Weakness: Cannot be changed if compromised

MFA combines at least two different factors:
- Password + SMS code (know + have) ✅
- Password + fingerprint (know + are) ✅
- Password + security question (both "know") ❌ NOT MFA!
```

### Example 6: MFA Methods
```
Weakest to Strongest:

1. SMS codes (❌ Weak)
   - SIM swapping attacks
   - SS7 vulnerabilities
   - Still better than nothing

2. TOTP apps (✅ Better)
   - Google Authenticator, Authy
   - Time-based codes
   - Not vulnerable to phone network attacks

3. FIDO2/WebAuthn (✅ Best)
   - Hardware tokens (YubiKey)
   - Phishing-resistant
   - Cryptographic proof
```

---

## 9.5 Input Validation and Sanitization

### Whitelist vs Blacklist

**Exam Question:** "Why is whitelisting better than blacklisting for input validation?"

**Answer:**
"Whitelisting allows only known good inputs, while blacklisting blocks known bad inputs. Whitelisting is secure by default: anything not explicitly allowed is rejected. Blacklisting fails when attackers find bypasses not in the blocklist. Maintaining blacklists is impossible as new attack techniques constantly emerge. For example, blocking <script> doesn't prevent <img onerror=alert()>, <svg onload=alert()>, javascript: URLs, etc. Whitelisting defines acceptable input format (e.g., 'username must be 3-20 alphanumeric characters') and rejects everything else. This scales better and is more robust against novel attacks."

**Example 7: Validation Approaches**
```php
// ❌ Bad: Blacklist
function validate_username($username) {
    $blocked = ['<script>', 'DROP', 'SELECT', '../'];
    foreach ($blocked as $bad) {
        if (strpos($username, $bad) !== false) {
            return false;
        }
    }
    return true;
}
// Easily bypassed: <Script>, dr0p, sElEcT, ..%2f

// ✅ Good: Whitelist
function validate_username($username) {
    return preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username);
}
// Only allows: 3-20 alphanumeric + underscore
// Everything else rejected
```

---

## 9.6 Secure Communication

### TLS/HTTPS

**Requirements:**
```
✅ Always use HTTPS for:
- Authentication (login forms)
- Session management (cookies)
- Sensitive data
- API endpoints

Configuration:
- TLS 1.2 minimum (TLS 1.3 preferred)
- Strong cipher suites only
- Valid certificates from trusted CA
- HSTS header (force HTTPS)
- Certificate pinning (mobile apps)
```

**Example 8: HSTS Header**
```
HTTP header:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

Effect:
- Browser always uses HTTPS for this domain
- Even if user types http://
- For 1 year (31536000 seconds)
- Applies to all subdomains
- Prevents SSL stripping attacks
```

---

## 9.7 Error Handling and Logging

### Secure Error Messages

**Example 9: Error Messages**
```php
// ❌ Bad: Information disclosure
if (!authenticate($user, $pass)) {
    die("Invalid password for user $user");
}
// Reveals username exists!

// ✅ Good: Generic error
if (!authenticate($user, $pass)) {
    die("Invalid username or password");
}
// Doesn't reveal which was wrong

// ❌ Bad: Stack traces in production
try {
    query_database($sql);
} catch (Exception $e) {
    echo $e->getMessage();  
    echo $e->getTraceAsString();
}
// Reveals code structure, file paths, database schema

// ✅ Good: Log detail, show generic error
try {
    query_database($sql);
} catch (Exception $e) {
    error_log($e);  // Detailed log for admins
    echo "An error occurred. Please contact support.";  // Generic for users
}
```

### Logging Best Practices

```
✅ Log:
- Authentication attempts (success and failure)
- Access to sensitive data
- Changes to permissions/configuration
- Errors and exceptions
- Security events (blocked attacks)

❌ Never log:
- Passwords (even hashed)
- Credit card numbers
- Personal identifiable information (PII)
- Session tokens
- Encryption keys

Log format:
[2024-01-15 14:23:45] INFO: User 'admin' logged in from 192.168.1.100
[2024-01-15 14:24:12] WARN: Failed login attempt for user 'admin' from 10.0.0.50
[2024-01-15 14:24:15] ERROR: SQL query failed: [details]
```

---

## 9.8 Secure Defaults

### Security by Default

**Principle:** Systems should be secure out-of-the-box.

**Examples:**
```
✅ Secure defaults:
- Firewalls enabled by default
- Minimum password complexity enforced
- HTTPS enforced
- Unused services disabled
- Secure cookies (HttpOnly, Secure flags)
- Permissions restrictive by default (deny all, allow specific)

❌ Insecure defaults:
- No firewall
- Weak/no password requirements
- HTTP allowed
- All services running
- Permissive file permissions
```

---

## 9.9 Update and Patch Management

### Keep Systems Updated

**Why it matters:**
```
Security updates fix known vulnerabilities:
- 0-day → Known vulnerability → Patch released
- Systems not patched remain vulnerable
- Automated attacks scan for unpatched systems

Example: WannaCry ransomware (2017)
- Exploited Windows SMB vulnerability (CVE-2017-0144)
- Patch available 2 months before attack
- Infected 200,000+ systems that hadn't patched
- $4 billion in damages
```

**Best practices:**
```
✅ Do:
- Enable automatic security updates
- Subscribe to security mailing lists
- Test patches in staging before production
- Have rollback plan
- Document patch levels

❌ Don't:
- Run end-of-life (EOL) software
- Delay critical security patches
- Skip testing entirely (even for security patches)
```

---

## 🎯 Exam Tips for Security Practices

### Key Principles (Memorize)

```
1. Least Privilege
   - Minimum necessary permissions
   - Run services as non-root
   - Limit file access

2. Defense in Depth
   - Multiple security layers
   - Redundant controls
   - Assume breach, limit damage

3. Secure by Default
   - Start secure, opt into features
   - Fail closed, not open
   - Whitelist, not blacklist

4. Fail Securely
   - Errors don't bypass security
   - Generic error messages
   - Log failures

5. Keep It Simple
   - Complex = more vulnerabilities
   - Understand what you deploy
   - Remove unused features
```

### Common Question Patterns

**"Why not run as root?"**
→ Least privilege, limit compromise damage

**"Why clear passwords from memory?"**
→ Memory dumps, swap, core dumps can leak them

**"Whitelist vs blacklist?"**
→ Whitelist secure by default, blacklist has bypasses

**"What are the three factors?"**
→ Know (password), Have (token), Are (biometric)

---

## 📝 Quick Reference

```
PRINCIPLES:
- Least Privilege: Minimum permissions needed
- Defense in Depth: Multiple security layers
- Fail Securely: Errors don't bypass security
- Secure by Default: Opt-out of features, not opt-in

PASSWORDS:
- Never plaintext
- Use Argon2/bcrypt/PBKDF2
- Salt + slow hash
- Clear from memory immediately

MFA FACTORS:
1. Know: Password, PIN
2. Have: Token, phone
3. Are: Biometric

VALIDATION:
- Whitelist (allow known good)
- Not blacklist (block known bad)
- Server-side validation
- Escape output

LOGGING:
- Log security events
- Never log secrets
- Generic errors to users
- Detailed errors in logs
```

---

[← Previous: Pentest Methodology](./08-pentest-methodology.md) | [Back to Main →](../EXAM-PREP-README.md)
