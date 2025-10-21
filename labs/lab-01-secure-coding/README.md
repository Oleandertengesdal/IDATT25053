# Lab 1: Secure Coding Fundamentals

## 📋 Lab Information

**Duration**: 4 hours  
**Difficulty**: Beginner to Intermediate  
**Prerequisites**: Basic Python knowledge, understanding of web concepts  
**Learning Outcomes**: LO5, LO6, LO8

---

## 🎯 Learning Objectives

By completing this lab, you will be able to:

1. Identify common input validation vulnerabilities
2. Implement secure input validation using whitelisting
3. Apply parameterized queries to prevent SQL injection
4. Use output encoding to prevent XSS attacks
5. Test your implementation against common attack vectors

---

## 📚 Background

Input validation and output encoding are the first line of defense against injection attacks. In this lab, you'll work with a vulnerable web application and systematically secure it against:

- **SQL Injection**: Manipulating database queries
- **Cross-Site Scripting (XSS)**: Injecting malicious scripts
- **Path Traversal**: Accessing unauthorized files
- **Command Injection**: Executing system commands

---

## 🔧 Setup

### Prerequisites

Ensure you have the following installed:
- Python 3.8 or higher
- Docker Desktop (for running the lab environment)
- Git

### Installation

1. **Clone the repository** (if not already done):
```bash
cd /Users/oleandertengesdal/Documents/GitHub/IDATT25053
```

2. **Navigate to lab directory**:
```bash
cd labs/lab-01-secure-coding
```

3. **Create virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
```

4. **Install dependencies**:
```bash
pip install -r requirements.txt
```

5. **Start the lab environment**:
```bash
docker-compose up -d
```

This will start:
- Web application on `http://localhost:5001`
- Database (SQLite in container)

---

## 📝 Lab Tasks

### Task 1: SQL Injection Prevention (30 minutes)

**Objective**: Fix SQL injection vulnerabilities in the login system.

#### Step 1: Understand the Vulnerability

1. Open `vulnerable_app/auth.py`
2. Find the `login()` function
3. Identify the vulnerable SQL query

**Current vulnerable code**:
```python
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
```

#### Step 2: Exploit the Vulnerability (Educational Only!)

Test these attack vectors:

**Attack 1 - Authentication Bypass**:
```
Username: admin' OR '1'='1' --
Password: anything
```

**Attack 2 - UNION-based Injection**:
```
Username: admin' UNION SELECT 1,2,3 --
Password: anything
```

Document what happens in your lab report.

#### Step 3: Fix the Vulnerability

Implement the fix in `secure_app/auth.py`:

```python
def login_secure(username, password):
    # TODO: Implement parameterized query
    # Use ? placeholders and pass parameters as tuple
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
```

#### Step 4: Add Input Validation

Add validation before the query:

```python
def validate_username(username):
    """
    Validate username format.
    
    Rules:
    - 3-20 characters
    - Only alphanumeric and underscore
    """
    # TODO: Implement validation
    import re
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return bool(re.match(pattern, username))
```

#### Step 5: Test Your Implementation

Run the test suite:
```bash
pytest tests/test_auth.py
```

Expected output:
```
test_login_normal ... PASSED
test_login_sql_injection ... PASSED (attack prevented)
test_login_invalid_format ... PASSED (rejected)
```

---

### Task 2: Cross-Site Scripting (XSS) Prevention (30 minutes)

**Objective**: Secure the comment system against XSS attacks.

#### Step 1: Understand XSS

XSS occurs when user input is displayed without proper encoding.

**Vulnerable code** in `vulnerable_app/comments.py`:
```python
@app.route('/comment', methods=['POST'])
def post_comment():
    comment = request.form['comment']
    # Vulnerable: Direct rendering
    return render_template_string(f'<p>{comment}</p>')
```

#### Step 2: Test XSS Attacks

Try these payloads:

**Attack 1 - Alert Box**:
```html
<script>alert('XSS')</script>
```

**Attack 2 - Cookie Stealing**:
```html
<img src=x onerror="alert(document.cookie)">
```

**Attack 3 - Event Handler**:
```html
<div onmouseover="alert('XSS')">Hover me</div>
```

#### Step 3: Implement Output Encoding

Fix in `secure_app/comments.py`:

```python
from flask import escape
import bleach

def sanitize_comment(comment):
    """
    Sanitize user comment for safe display.
    
    Options:
    1. HTML escape (safest - no HTML allowed)
    2. HTML sanitization (allow safe tags only)
    """
    # TODO: Choose appropriate method
    
    # Method 1: Escape all HTML
    return escape(comment)
    
    # Method 2: Allow safe HTML tags
    # allowed_tags = ['b', 'i', 'u', 'p', 'br']
    # return bleach.clean(comment, tags=allowed_tags, strip=True)
```

#### Step 4: Add Content Security Policy

Add CSP header in `secure_app/__init__.py`:

```python
@app.after_request
def set_security_headers(response):
    # TODO: Add security headers
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response
```

#### Step 5: Test Your Implementation

```bash
pytest tests/test_xss.py
```

---

### Task 3: Path Traversal Prevention (20 minutes)

**Objective**: Prevent unauthorized file access.

#### Step 1: Understand Path Traversal

**Vulnerable code** in `vulnerable_app/files.py`:
```python
@app.route('/download/<filename>')
def download_file(filename):
    # Vulnerable: No path validation
    filepath = os.path.join('/app/files', filename)
    return send_file(filepath)
```

**Attack**:
```
GET /download/../../etc/passwd
```

#### Step 2: Implement Path Validation

Fix in `secure_app/files.py`:

```python
import os
from pathlib import Path

ALLOWED_DIR = '/app/files'

def download_file_secure(filename):
    # TODO: Validate path
    
    # Step 1: Validate filename format
    if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
        abort(400, "Invalid filename")
    
    # Step 2: Build path
    filepath = os.path.join(ALLOWED_DIR, filename)
    
    # Step 3: Resolve and validate path
    real_path = os.path.realpath(filepath)
    real_base = os.path.realpath(ALLOWED_DIR)
    
    if not real_path.startswith(real_base):
        abort(403, "Access denied")
    
    # Step 4: Check file exists
    if not os.path.exists(real_path):
        abort(404, "File not found")
    
    return send_file(real_path)
```

#### Step 3: Test Path Traversal Prevention

```bash
pytest tests/test_path_traversal.py
```

---

### Task 4: Command Injection Prevention (20 minutes)

**Objective**: Secure system command execution.

#### Step 1: Understand Command Injection

**Vulnerable code** in `vulnerable_app/utils.py`:
```python
import os

def ping_host(host):
    # Vulnerable: Direct command execution
    result = os.system(f'ping -c 1 {host}')
    return result
```

**Attack**:
```
host = "example.com; cat /etc/passwd"
```

#### Step 2: Implement Safe Command Execution

Fix in `secure_app/utils.py`:

```python
import subprocess
import shlex

def ping_host_secure(host):
    # TODO: Implement secure command execution
    
    # Step 1: Validate input
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        raise ValueError("Invalid host format")
    
    # Step 2: Use subprocess with list arguments
    try:
        result = subprocess.run(
            ['ping', '-c', '1', host],
            capture_output=True,
            timeout=5,
            check=True,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Ping failed: {e}"
    except subprocess.TimeoutExpired:
        return "Ping timed out"
```

#### Step 3: Test Command Injection Prevention

```bash
pytest tests/test_command_injection.py
```

---

### Task 5: Integration and Testing (20 minutes)

#### Step 1: Run Full Test Suite

```bash
pytest tests/ -v --cov=secure_app
```

**Expected Coverage**: Minimum 80%

#### Step 2: Manual Security Testing

Use the provided test scripts:

**Test SQL Injection**:
```bash
python test_scripts/test_sql_injection.py
```

**Test XSS**:
```bash
python test_scripts/test_xss.py
```

**Test Path Traversal**:
```bash
python test_scripts/test_path_traversal.py
```

#### Step 3: Security Scan

Run automated security scanner:
```bash
bandit -r secure_app/
```

Fix any HIGH or MEDIUM severity issues.

---

## 📊 Lab Report

### Requirements

Submit a lab report (PDF) covering:

1. **Vulnerability Analysis** (2 pages)
   - Description of each vulnerability
   - Proof of concept attacks
   - Impact assessment

2. **Implementation** (2 pages)
   - Security fixes implemented
   - Code snippets with explanations
   - Design decisions

3. **Testing Results** (1 page)
   - Test coverage report
   - Security scan results
   - Manual testing outcomes

4. **Reflection** (1 page)
   - Lessons learned
   - Challenges faced
   - Real-world applications

### Grading Rubric

| Criterion | Points | Description |
|-----------|--------|-------------|
| SQL Injection Fix | 25 | Parameterized queries + validation |
| XSS Prevention | 25 | Output encoding + CSP headers |
| Path Traversal Fix | 20 | Path validation + canonicalization |
| Command Injection Fix | 20 | Subprocess + input validation |
| Report Quality | 10 | Clear, complete, well-written |
| **Total** | **100** | |

**Pass Requirement**: Minimum 70 points

---

## 🔍 Testing Your Work

### Automated Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=secure_app --cov-report=html

# Run specific test category
pytest tests/test_auth.py -v
```

### Manual Testing Checklist

- [ ] SQL injection attacks fail with parameterized queries
- [ ] XSS payloads are escaped or sanitized
- [ ] Path traversal attempts are blocked
- [ ] Command injection is prevented
- [ ] Input validation rejects malformed data
- [ ] Security headers are present
- [ ] Error messages don't leak sensitive information

---

## 🎓 Learning Resources

### Required Reading
- OWASP Top 10: A03:2021 - Injection
- CWE-89: SQL Injection
- CWE-79: Cross-Site Scripting
- CWE-78: OS Command Injection

### Additional Resources
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Flask Security Documentation](https://flask.palletsprojects.com/en/2.3.x/security/)
- Python `subprocess` module documentation

---

## 🐛 Troubleshooting

### Common Issues

**Issue**: Database connection fails
```bash
# Solution: Restart Docker containers
docker-compose down
docker-compose up -d
```

**Issue**: Import errors
```bash
# Solution: Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

**Issue**: Tests fail with "module not found"
```bash
# Solution: Set PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
pytest tests/
```

---

## 📤 Submission

### Deliverables

1. **Source Code**:
   - Completed `secure_app/` directory
   - All fixes implemented
   - Comments explaining security measures

2. **Lab Report**:
   - PDF format
   - Maximum 6 pages
   - Include screenshots of test results

3. **Test Results**:
   - `pytest` output showing all tests pass
   - Coverage report (HTML)
   - Bandit security scan results

### Submission Instructions

1. Commit your code:
```bash
git add secure_app/ tests/ lab_report.pdf
git commit -m "Lab 1: Secure coding implementation"
git push origin lab-01-submission
```

2. Submit via Blackboard:
   - Upload lab_report.pdf
   - Include link to your Git branch
   - Submit by deadline (Week 6)

---

## ⚠️ Important Notes

### Academic Integrity

- All code must be your own work
- You may discuss concepts with peers, but not share code
- Properly cite any external resources used
- Using AI tools to generate solutions is prohibited

### Ethical Guidelines

- **ONLY** test on the provided lab environment
- **NEVER** scan or attack NTNU systems
- **DO NOT** use these techniques on unauthorized systems
- Violations will result in course failure and disciplinary action

---

## 🆘 Getting Help

### Office Hours
- **Instructor**: Tuesday & Thursday 14:00-16:00
- **TAs**: Friday during lab session

### Online Support
- Blackboard discussion forum
- Email: `course.coordinator@ntnu.no`
- Lab environment issues: `it.labs@ntnu.no`

---

**Lab Created**: October 14, 2025  
**Version**: 1.0  
**Estimated Completion Time**: 3-4 hours
