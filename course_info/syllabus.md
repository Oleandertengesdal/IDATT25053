# IDATT2503 - Security in Software Systems
## Course Syllabus

**Academic Year**: 2025  
**Institution**: Norwegian University of Science and Technology (NTNU), Trondheim  
**Department**: Department of Computer Science  
**Course Code**: IDATT2503  
**Credits**: 7.5 ECTS  

---

## 📚 Course Overview

### Course Description

This course provides comprehensive education in security principles, secure software development, and defensive programming techniques. Students will learn to identify, analyze, and mitigate security vulnerabilities in software systems while developing practical skills in secure coding, cryptography, and security testing.

**Focus Areas**:
- Secure software development lifecycle (SSDLC)
- Common vulnerability patterns and defenses
- Cryptographic implementations
- Web and network security
- Penetration testing (ethical, defensive focus)
- Security tooling and automation

### Prerequisites

**Required**:
- IDATT2104 - Network Programming (or equivalent)
- IDATT2105 - Full-Stack Application Development
- Solid programming skills in at least one language (Python, Java, C/C++)

**Recommended**:
- Basic understanding of computer networks
- Experience with web development
- Familiarity with Linux/Unix systems

---

## 🎯 Learning Outcomes

Upon successful completion of this course, students will be able to:

### Knowledge
- **LO1**: Explain fundamental security principles (CIA triad, defense in depth, least privilege)
- **LO2**: Describe common vulnerability types (OWASP Top 10) and their exploitation mechanisms
- **LO3**: Understand cryptographic primitives and their appropriate applications
- **LO4**: Articulate legal and ethical frameworks for security research

### Skills
- **LO5**: Implement secure authentication and authorization systems
- **LO6**: Apply input validation and output encoding techniques to prevent injection attacks
- **LO7**: Use cryptographic libraries correctly for encryption, hashing, and signing
- **LO8**: Conduct security testing using automated tools (fuzzing, static analysis)
- **LO9**: Perform ethical penetration testing in controlled environments

### General Competence
- **LO10**: Adopt a security-first mindset in software development
- **LO11**: Evaluate trade-offs between security, usability, and performance
- **LO12**: Communicate security risks and recommendations to technical and non-technical audiences

---

## 📖 Course Content

### Module 1: Introduction to Software Security (Weeks 1-3)
- Security fundamentals and threat modeling
- Secure SDLC and DevSecOps
- Security principles (CIA triad, defense in depth)
- Risk assessment and management
- Legal and ethical frameworks (Norwegian Straffeloven, GDPR, responsible disclosure)

**Topics**:
- What is software security?
- Threat modeling (STRIDE, DREAD)
- Security vs. safety
- Attack surface analysis
- Security policies and standards

### Module 2: Input Validation and Injection Defenses (Weeks 4-6)
- SQL injection attacks and parameterized queries
- Cross-Site Scripting (XSS) and output encoding
- Command injection and path traversal
- XML/JSON injection
- Input validation strategies (whitelisting vs. blacklisting)

**Topics**:
- OWASP A03:2021 - Injection
- Context-specific encoding
- Content Security Policy (CSP)
- Server-side vs. client-side validation
- Prepared statements and ORM security

### Module 3: Authentication and Session Management (Weeks 7-9)
- Secure password storage (hashing, salting, key derivation)
- Multi-factor authentication (MFA)
- Session management and token-based authentication
- OAuth 2.0 and OpenID Connect
- JWT security

**Topics**:
- Password policies and credential storage
- Argon2, bcrypt, PBKDF2
- Session fixation and hijacking
- CSRF protection
- Cookie security flags (Secure, HttpOnly, SameSite)

### Module 4: Cryptography in Practice (Weeks 10-12)
- Symmetric encryption (AES, modes of operation)
- Asymmetric encryption (RSA, ECC)
- Cryptographic hashing (SHA-256, SHA-3)
- Digital signatures and certificates
- TLS/SSL and secure communications

**Topics**:
- When to use symmetric vs. asymmetric encryption
- Authenticated encryption (GCM, Poly1305)
- Key management and rotation
- Common cryptographic mistakes
- Perfect forward secrecy

### Module 5: Web and API Security (Weeks 13-15)
- HTTPS and certificate validation
- API security best practices
- Rate limiting and DoS prevention
- Security headers (HSTS, CSP, X-Frame-Options)
- CORS and same-origin policy

**Topics**:
- RESTful API security
- API authentication (API keys, OAuth)
- GraphQL security considerations
- WebSocket security
- Third-party dependency management

---

## 📅 Course Schedule

### Weekly Structure
- **Lectures**: 2 x 2 hours per week (Tuesday 10:15-12:00, Thursday 12:15-14:00)
- **Lab Sessions**: 1 x 4 hours per week (Friday 10:15-14:00)
- **Self-Study**: Approximately 20 hours per week (readings, assignments, projects)

### Important Dates

| Date | Event |
|------|-------|
| Week 1 | Course start, Lab 1 released |
| Week 3 | Assignment 1 released |
| Week 6 | Assignment 1 due, Lab 2 released |
| Week 9 | Midterm feedback session |
| Week 10 | Assignment 2 released |
| Week 13 | Assignment 2 due |
| Week 15 | Course wrap-up, final project presentations |
| Week 17 | Final written exam (3 hours) |

---

## 📊 Assessment Methods

### Grading Components

| Component | Weight | Type | Learning Outcomes |
|-----------|--------|------|-------------------|
| Lab Exercises | 30% | Pass/Fail (must pass all) | LO5-LO9 |
| Assignment 1 | 15% | Graded | LO2, LO5, LO6 |
| Assignment 2 | 15% | Graded | LO3, LO7, LO8 |
| Final Exam | 40% | Written exam (3 hours) | LO1-LO12 |

### Grading Scale
- **A**: 90-100% (Excellent)
- **B**: 80-89% (Very good)
- **C**: 70-79% (Good)
- **D**: 60-69% (Satisfactory)
- **E**: 50-59% (Sufficient)
- **F**: 0-49% (Fail)

### Lab Exercises (Pass/Fail)
**Requirements**:
- Complete all 8 lab exercises
- Submit lab reports demonstrating understanding
- Attend minimum 80% of lab sessions
- Pass all mandatory security checks (no unethical code submissions)

**Lab Topics**:
1. Secure coding fundamentals
2. SQL injection prevention
3. XSS defense mechanisms
4. Cryptographic implementations
5. Authentication systems
6. Fuzzing and vulnerability discovery
7. Static analysis tooling
8. Penetration testing (authorized targets only)

### Assignment 1: Secure Web Application (15%)
**Description**: Build a secure login and user management system that defends against common web vulnerabilities.

**Deliverables**:
- Source code with security annotations
- Security analysis report (3-5 pages)
- Demonstration video (5 minutes)

**Evaluation Criteria**:
- Input validation implementation (25%)
- SQL injection prevention (25%)
- XSS prevention (25%)
- Secure session management (15%)
- Code quality and documentation (10%)

### Assignment 2: Cryptographic Messaging System (15%)
**Description**: Implement an end-to-end encrypted messaging application using modern cryptographic libraries.

**Deliverables**:
- Working application with encryption
- Threat model document
- Security test suite
- Implementation report (4-6 pages)

**Evaluation Criteria**:
- Correct use of cryptography (30%)
- Key management implementation (25%)
- Authentication and integrity (20%)
- Security testing (15%)
- Documentation and code quality (10%)

### Final Exam (40%)
**Format**: Written exam, 3 hours, closed book

**Topics Covered**:
- Security principles and threat modeling (20%)
- Vulnerability identification and mitigation (30%)
- Cryptographic protocols (20%)
- Web and API security (20%)
- Legal and ethical considerations (10%)

**Question Types**:
- Multiple choice (20 questions, 20 points)
- Short answer (5 questions, 30 points)
- Long essay (2 questions, 30 points)
- Code analysis (2 scenarios, 20 points)

---

## 📚 Required Materials

### Textbooks

**Primary Text**:
- *Security Engineering* (3rd Edition) by Ross Anderson (2020)
  - Chapters 1-5, 18-21
  - Available online: https://www.cl.cam.ac.uk/~rja14/book.html

**Secondary Texts**:
- *The Web Application Hacker's Handbook* (2nd Edition) by Stuttard & Pinto (2011)
- *Cryptography Engineering* by Ferguson, Schneier & Kohno (2010)

### Online Resources

**Essential**:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) (2021)
- [CWE Top 25](https://cwe.mitre.org/top25/) Most Dangerous Software Weaknesses
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

**Tools Documentation**:
- Burp Suite Community Edition
- OWASP ZAP (Zed Attack Proxy)
- AFL++ (American Fuzzy Lop)
- SonarQube (static analysis)

### Software Requirements

**Required**:
- Python 3.8+ with `cryptography`, `flask`, `requests` libraries
- Docker Desktop (for safe lab environments)
- Git for version control
- Code editor (VS Code recommended)

**Optional**:
- Burp Suite Professional (free license available for students)
- Kali Linux VM (for optional advanced labs)

---

## 👨‍🏫 Teaching Methods

### Lecture Format
- Interactive lectures with live coding demonstrations
- Case studies of real-world security breaches
- Guest speakers from industry (2-3 sessions)
- Flipped classroom elements (pre-recorded theory, in-class practice)

### Lab Sessions
- Hands-on exercises in controlled environments
- Pair programming encouraged
- Teaching assistants available for guidance
- Safe, isolated Docker containers for all security testing

### Self-Study
- Weekly reading assignments
- Online quiz modules
- Discussion forums (Blackboard)
- Optional challenge exercises for advanced students

---

## ⚖️ Academic Integrity and Ethics

### Code of Conduct

**All students must**:
- Sign the course security pledge (Week 1)
- Conduct security research only on authorized systems
- Report any discovered vulnerabilities responsibly
- Never access systems without explicit permission
- Respect confidentiality of sensitive information

**Prohibited Activities**:
- Unauthorized scanning or testing of NTNU systems
- Sharing exploit code publicly
- Using course knowledge for malicious purposes
- Plagiarism or unauthorized collaboration on individual assignments

### Collaboration Policy

**Allowed**:
- Discussing concepts and approaches with peers
- Helping classmates debug general programming issues
- Sharing publicly available resources and tools

**Not Allowed**:
- Copying code solutions
- Sharing assignment answers
- Using AI tools to generate assignment code (must be your own work)
- Collaborative work on individual assignments

**Consequences**: Violations may result in:
- Grade penalties (0 on assignment, reduced course grade)
- Academic misconduct report
- Course failure
- Expulsion in severe cases

### Responsible Disclosure

If you discover a vulnerability in NTNU systems:
1. **STOP** further testing immediately
2. Document your findings (no screenshots of sensitive data)
3. Report to `security@ntnu.no` within 24 hours
4. Do not share findings with others
5. Wait for acknowledgment before disclosure

---

## ♿ Accessibility and Accommodations

NTNU is committed to providing equal access to education. Students requiring accommodations should:

1. Register with the Accessibility Services Office
2. Provide documentation to course coordinator within first two weeks
3. Discuss needs in confidential meeting

**Available Accommodations**:
- Extended exam time
- Alternative exam formats
- Assistive technologies
- Flexible attendance policies (with pre-approval)

Contact: `accessibility@ntnu.no`

---

## 📞 Contact Information

### Course Coordinator
**Name**: [To be assigned]  
**Email**: `course.coordinator@ntnu.no`  
**Office Hours**: Tuesday & Thursday 14:00-16:00 (Room IT-512)

### Teaching Assistants
- TA 1: `ta1@ntnu.no` (Lab sections 1-2)
- TA 2: `ta2@ntnu.no` (Lab sections 3-4)

### Technical Support
- Blackboard issues: `blackboard.support@ntnu.no`
- Lab environment: `it.labs@ntnu.no`

### Emergency Contact
For urgent security concerns: `security@ntnu.no` (24/7)

---

## 🔄 Changes and Updates

This syllabus is subject to change. Students will be notified of any modifications via:
- Blackboard announcement
- Email notification
- In-class announcement

**Last Updated**: October 14, 2025  
**Version**: 1.0

---

## 📖 Additional Policies

### Attendance
- Lectures: Recommended but not mandatory
- Labs: Minimum 80% attendance required for pass
- Excused absences must be documented

### Late Submissions
- 10% penalty per 24 hours late
- Maximum 3 days late (then 0 points)
- Extensions granted only for documented emergencies

### Re-examination
Students who fail may retake:
- Assignments: During designated re-submission period
- Exam: During official re-exam period (August)
- Labs: Must complete during next course offering

---

**Course Website**: [Blackboard Course Page]  
**Repository**: https://github.com/ntnu/idatt2503-security

---

*This syllabus is aligned with NTNU's academic policies and Norwegian national education standards.*
