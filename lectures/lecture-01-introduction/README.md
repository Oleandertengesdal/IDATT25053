# Lecture 1: Introduction to Software Security

**Week**: 1  
**Duration**: 90 minutes  
**Date**: [To be scheduled]  
**Instructor**: [To be assigned]

---

## 📋 Learning Objectives

By the end of this lecture, students will be able to:

1. **Define** software security and its importance in modern computing
2. **Identify** the main threat actors and their motivations
3. **Explain** the CIA triad and its relevance to security
4. **Describe** the secure software development lifecycle (SSDLC)
5. **Recognize** common vulnerability types at a high level
6. **Understand** the ethical and legal framework for security research

---

## 📚 Prerequisites

- Basic programming knowledge (any language)
- Understanding of computer networks
- Familiarity with operating systems concepts

---

## 📖 Lecture Outline

### Part 1: Introduction (15 min)

#### 1.1 Welcome and Course Overview
- Course structure and expectations
- Assessment methods
- Resources and tools
- Lab environment setup

#### 1.2 Why Software Security Matters
- Real-world incidents and their impact
- Cost of security breaches
- Regulatory requirements (GDPR, etc.)
- Career opportunities in security

### Part 2: Fundamentals of Security (30 min)

#### 2.1 The CIA Triad
- **Confidentiality**: Protecting information from unauthorized access
- **Integrity**: Ensuring data hasn't been tampered with
- **Availability**: Ensuring systems and data are accessible when needed

#### 2.2 Security Principles
- **Least Privilege**: Minimum necessary access
- **Defense in Depth**: Multiple layers of security
- **Fail Securely**: Systems should fail in a secure state
- **Keep It Simple**: Complexity is the enemy of security
- **Don't Trust User Input**: Validate everything
- **Security by Design**: Build security in from the start

#### 2.3 Threat Modeling
- **Threat Actors**: Who are the attackers?
  - Script kiddies
  - Hacktivists
  - Organized crime
  - Nation-states
  - Insiders
- **Attack Vectors**: How do they attack?
  - Network attacks
  - Web application attacks
  - Social engineering
  - Physical access
- **Motivations**: Why do they attack?
  - Financial gain
  - Political goals
  - Espionage
  - Vandalism
  - Challenge/curiosity

### Part 3: Secure Software Development (25 min)

#### 3.1 Software Development Lifecycle (SDLC) Review
- Requirements
- Design
- Implementation
- Testing
- Deployment
- Maintenance

#### 3.2 Secure SDLC (SSDLC)
- **Security Requirements**:
  - Identify security needs early
  - Define security acceptance criteria
  
- **Threat Modeling in Design**:
  - STRIDE methodology
  - Attack trees
  - Security architecture review

- **Secure Coding Practices**:
  - Input validation
  - Output encoding
  - Authentication/authorization
  - Error handling
  - Logging

- **Security Testing**:
  - Static analysis (SAST)
  - Dynamic analysis (DAST)
  - Penetration testing
  - Code review

- **Secure Deployment**:
  - Configuration management
  - Patch management
  - Monitoring and logging

#### 3.3 Common Vulnerability Types (Overview)
- **Injection Flaws**: SQL, Command, LDAP injection
- **Broken Authentication**: Session management issues
- **Sensitive Data Exposure**: Inadequate encryption
- **XML External Entities (XXE)**: XML processing vulnerabilities
- **Broken Access Control**: Authorization failures
- **Security Misconfiguration**: Default settings, unnecessary features
- **Cross-Site Scripting (XSS)**: Injecting malicious scripts
- **Insecure Deserialization**: Untrusted data processing
- **Using Components with Known Vulnerabilities**: Outdated libraries
- **Insufficient Logging & Monitoring**: Lack of visibility

*Note: These will be covered in detail in future lectures*

### Part 4: Ethics and Legal Framework (15 min)

#### 4.1 Ethical Hacking
- What is ethical hacking?
- White hat vs. black hat vs. gray hat
- Responsible disclosure
- Professional certifications (CEH, OSCP, etc.)

#### 4.2 Legal Considerations
- **Norwegian Law**:
  - Straffeloven §§ 201-204 (Computer Crime)
  - GDPR compliance
  
- **International Law**:
  - Computer Fraud and Abuse Act (USA)
  - Convention on Cybercrime
  
- **NTNU Policies**:
  - Acceptable Use Policy
  - Research Ethics
  - Academic Integrity

#### 4.3 Rules of Engagement
- **Only test what you own** or have written permission to test
- Use **isolated lab environments**
- Follow **responsible disclosure** practices
- Never cause harm or disruption
- Document everything
- Know when to stop

### Part 5: Course Logistics & Q&A (5 min)

- Lab environment access
- Assignment overview
- Next week's preparation
- Questions and discussion

---

## 💻 Code Examples

### Example 1: Demonstrating the Importance of Input Validation

**Vulnerable Code** (Python):

```python
# ⚠️ VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY
# DO NOT USE IN PRODUCTION

def process_user_input_vulnerable(user_input):
    """
    This function demonstrates what NOT to do.
    It directly uses user input in a SQL query.
    """
    import sqlite3
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: User input directly in SQL query
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    
    result = cursor.fetchall()
    conn.close()
    
    return result

# If user_input = "admin' OR '1'='1", this would bypass authentication!
```

**Secure Code** (Python):

```python
# ✅ SECURE CODE - THIS IS THE CORRECT APPROACH

def process_user_input_secure(user_input):
    """
    This function demonstrates proper input validation and
    parameterized queries to prevent SQL injection.
    """
    import sqlite3
    import re
    
    # Step 1: Validate input format
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', user_input):
        raise ValueError("Invalid username format")
    
    # Step 2: Use parameterized queries
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # SECURE: Parameterized query prevents SQL injection
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (user_input,))
    
    result = cursor.fetchall()
    conn.close()
    
    return result

# This approach safely handles all input, including malicious attempts
```

**Key Takeaways**:
1. Never trust user input
2. Validate all input against expected patterns
3. Use parameterized queries or prepared statements
4. Apply defense in depth (multiple layers)

---

### Example 2: The CIA Triad in Practice

```python
"""
Demonstrating the CIA Triad with a simple file access control system.

Learning Objectives:
- Understand confidentiality through access control
- Understand integrity through checksums
- Understand availability through error handling
"""

import hashlib
import os
from typing import Optional

class SecureFileSystem:
    """
    A simple demonstration of CIA triad principles.
    """
    
    def __init__(self):
        self.authorized_users = {'alice', 'bob', 'charlie'}
        self.file_hashes = {}  # Store file integrity checksums
    
    def read_file(self, filename: str, user: str) -> Optional[str]:
        """
        Read file with confidentiality and availability controls.
        
        Args:
            filename: Path to the file
            user: Username requesting access
            
        Returns:
            File contents if authorized, None otherwise
        """
        # CONFIDENTIALITY: Check authorization
        if user not in self.authorized_users:
            print(f"Access denied for user: {user}")
            return None
        
        # AVAILABILITY: Handle errors gracefully
        try:
            with open(filename, 'r') as f:
                content = f.read()
            
            # INTEGRITY: Verify file hasn't been tampered with
            current_hash = hashlib.sha256(content.encode()).hexdigest()
            
            if filename in self.file_hashes:
                if current_hash != self.file_hashes[filename]:
                    print("WARNING: File integrity check failed!")
                    print("File may have been tampered with.")
                    return None
            else:
                # First time reading, store the hash
                self.file_hashes[filename] = current_hash
            
            return content
            
        except FileNotFoundError:
            print(f"File not found: {filename}")
            return None
        except PermissionError:
            print(f"Permission denied: {filename}")
            return None
        except Exception as e:
            print(f"Error reading file: {e}")
            return None
    
    def write_file(self, filename: str, content: str, user: str) -> bool:
        """
        Write file with authorization and integrity tracking.
        
        Args:
            filename: Path to the file
            content: Content to write
            user: Username requesting access
            
        Returns:
            True if successful, False otherwise
        """
        # CONFIDENTIALITY: Check authorization
        if user not in self.authorized_users:
            print(f"Access denied for user: {user}")
            return False
        
        # AVAILABILITY: Handle errors
        try:
            with open(filename, 'w') as f:
                f.write(content)
            
            # INTEGRITY: Update hash after write
            file_hash = hashlib.sha256(content.encode()).hexdigest()
            self.file_hashes[filename] = file_hash
            
            print(f"File written successfully. Hash: {file_hash[:16]}...")
            return True
            
        except Exception as e:
            print(f"Error writing file: {e}")
            return False


# Demonstration
if __name__ == "__main__":
    fs = SecureFileSystem()
    
    # CONFIDENTIALITY: Authorized access
    print("=== Testing Confidentiality ===")
    content = fs.read_file("test.txt", "alice")  # ✓ Authorized
    print(f"Content: {content}\n")
    
    content = fs.read_file("test.txt", "eve")    # ✗ Unauthorized
    print(f"Content: {content}\n")
    
    # INTEGRITY: Detect tampering
    print("=== Testing Integrity ===")
    fs.write_file("secure.txt", "Important data", "bob")
    fs.read_file("secure.txt", "bob")  # ✓ Integrity check passes
    
    # AVAILABILITY: Graceful error handling
    print("\n=== Testing Availability ===")
    fs.read_file("nonexistent.txt", "alice")  # Handles error gracefully
```

**Discussion Points**:
- How does this demonstrate confidentiality?
- What would happen if we didn't check file integrity?
- How could we improve availability (e.g., redundancy)?

---

## 📊 Slides

Slides are available in multiple formats:

- **PDF**: [`lecture-01-slides.pdf`](./lecture-01-slides.pdf)
- **PowerPoint**: [`lecture-01-slides.pptx`](./lecture-01-slides.pptx)
- **Markdown** (reveal.js): [`lecture-01-slides.md`](./lecture-01-slides.md)

### Key Slide Topics:

1. Title & Course Overview
2. Why Security Matters (Statistics & Case Studies)
3. The CIA Triad (Diagram)
4. Security Principles (List with examples)
5. Threat Actors (Categories with characteristics)
6. SDLC vs. SSDLC (Comparison diagram)
7. OWASP Top 10 Overview
8. Ethics & Legal Framework
9. Lab Environment Setup
10. Next Steps & Resources

---

## 🎯 In-Class Activities

### Activity 1: Threat Modeling Exercise (10 min)

**Scenario**: A university student portal where students can:
- View grades
- Register for courses
- Update personal information
- Submit assignments

**Task**: In groups of 3-4, identify:
1. **Assets**: What needs protection?
2. **Threats**: What could go wrong?
3. **Vulnerabilities**: What weaknesses exist?
4. **Attack Vectors**: How could attackers exploit them?

**Discussion**: Share findings with the class

### Activity 2: CIA Triad Application (5 min)

**Scenarios**: For each scenario, identify which aspect of CIA is violated:

1. A student changes another student's grade in the database
2. An attacker obtains a list of all students' email addresses
3. The course registration system crashes during registration period
4. A hacker modifies course descriptions on the university website

**Answers**:
1. Integrity
2. Confidentiality
3. Availability
4. Integrity

---

## 📝 Homework/Preparation for Next Lecture

### Required Reading:
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Chapter 1 of course textbook
- Review Python/Java basics (we'll be coding next week)

### Lab Setup:
1. Install VirtualBox or Docker
2. Download lab environment image (link on Blackboard)
3. Complete "Lab 0: Environment Setup"
4. Familiarize yourself with command line basics

### Reflection Questions (Submit on Blackboard):
1. What surprised you most about software security?
2. Think of an app you use daily. What security features does it have?
3. Have you ever experienced a security incident? What happened?

---

## 📚 Additional Resources

### Books:
- "The Web Application Hacker's Handbook" by Stuttard & Pinto
- "Security Engineering" by Ross Anderson (Free PDF available)
- "The Art of Software Security Assessment" by Dowd, McDonald & Schuh

### Online Resources:
- [OWASP](https://owasp.org/) - Open Web Application Security Project
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CWE Top 25](https://cwe.mitre.org/top25/) - Most dangerous software weaknesses

### Videos:
- [Computerphile - Secure Coding](https://www.youtube.com/watch?v=3kEfedtQVOY)
- [DEF CON Conference Talks](https://www.youtube.com/user/DEFCONConference)

### Tools (We'll explore these later):
- Burp Suite (Web security testing)
- OWASP ZAP (Free web scanner)
- Wireshark (Network analysis)
- Docker (Isolated environments)

---

## 🔍 Key Takeaways

1. **Security is everyone's responsibility**, not just the security team
2. **Build security in** from the beginning, don't bolt it on later
3. **Defense in depth** - use multiple layers of security
4. **Never trust user input** - validate everything
5. **Keep learning** - security is a constantly evolving field
6. **Act ethically** - only test what you're authorized to test
7. **Think like an attacker** to build better defenses

---

## ❓ Discussion Questions

1. Why is "security by obscurity" considered a bad practice?
2. Can a system ever be 100% secure? Why or why not?
3. What's the difference between vulnerability, threat, and risk?
4. How do you balance security with usability?
5. What role does security play in your future career?

---

## 📞 Contact & Office Hours

**Instructor**: [Name]  
**Email**: [email@ntnu.no]  
**Office Hours**: [Day/Time]  
**Location**: [Building/Room]

**TAs**:
- [TA1 Name]: [email]
- [TA2 Name]: [email]

**Course Forum**: Blackboard Discussion Board

---

## Next Lecture

**Lecture 2: Secure Coding Principles**
- Input validation techniques
- Output encoding
- Error handling and logging
- Hands-on coding exercises

**Preparation**: Review OWASP Secure Coding Practices Guide

---

**Last Updated**: October 14, 2025  
**Version**: 1.0
