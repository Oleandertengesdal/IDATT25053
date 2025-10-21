# IDATT2503 - Security in Software Systems
**Norwegian University of Science and Technology (NTNU), Trondheim**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Course Level](https://img.shields.io/badge/Level-Bachelor-blue)]()
[![Credits](https://img.shields.io/badge/Credits-7.5_ECTS-green)]()
[![Language](https://img.shields.io/badge/Language-English-red)]()

> **⚠️ EDUCATIONAL USE ONLY**: This repository is for lawful, educational purposes only. All materials are designed to teach defensive security concepts and responsible security research. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing security measures.

---

## 📚 Course Overview

IDATT2503 is a comprehensive course in software security covering:
- **Secure Software Development**: Principles, practices, and common vulnerabilities
- **Cryptography**: Symmetric/asymmetric encryption, hashing, digital signatures
- **Web Security**: OWASP Top 10, authentication, authorization, session management
- **System Security**: Buffer overflows, memory safety, privilege escalation concepts
- **Network Security**: Protocols, TLS/SSL, secure communications
- **Security Testing**: Static analysis, dynamic analysis, fuzzing concepts
- **Incident Response**: Detection, analysis, containment, recovery

**Course Metadata**:
- **Course Code**: IDATT2503
- **Credits**: 7.5 ECTS
- **Level**: Bachelor (3rd year)
- **Semester**: Autumn (example - update for actual term)
- **Prerequisites**: IDATT2104 (Network Programming) or equivalent
- **Language**: English

---

## 🗂️ Repository Structure

```
IDATT2503/
├── README.md                          # This file
├── LICENSE                            # MIT License
├── SECURITY.md                        # Security policy and responsible disclosure
├── CONTRIBUTING.md                    # Contribution guidelines
├── CODE_OF_CONDUCT.md                 # Community standards
│
├── course_info/                       # 📋 Official course information
│   ├── syllabus.md                    # Complete course syllabus
│   ├── learning_outcomes.md           # Learning objectives
│   ├── assessment_and_grading.md      # Grading criteria and exam info
│   ├── reading_list.md                # Required and recommended readings
│   ├── staff_and_contact.md           # Instructor and TA information
│   └── schedule.md                    # Weekly lecture schedule
│
├── lectures/                          # 🎓 Lecture materials
│   ├── lecture-01-introduction/       # Week 1: Course introduction
│   ├── lecture-02-secure-coding/      # Week 2: Secure coding principles
│   ├── lecture-03-cryptography/       # Week 3: Cryptography fundamentals
│   └── ...                            # Additional lectures
│
├── examples/                          # 💡 Practical examples
│   ├── binary-exploitation/           # Buffer overflow concepts
│   ├── cryptography/                  # Crypto examples
│   ├── fuzzing/                       # Fuzzing basics
│   └── system-programming/            # System security
│
├── labs/                              # 🔬 Hands-on lab exercises
│   ├── lab-01-secure-coding/          # Secure coding practices
│   ├── lab-02-cryptography/           # Implementing crypto
│   └── ...                            # Additional labs
│
├── assignments/                       # 📝 Graded assignments
│   ├── assignment-01/                 # Security audit project
│   ├── assignment-02/                 # Secure application development
│   └── ...                            # Additional assignments
│
├── theory/                            # 📖 Theoretical foundations
│   ├── secure-coding-principles.md    # Core security principles
│   ├── cryptography-fundamentals.md   # Crypto theory
│   ├── web-security-concepts.md       # Web security theory
│   ├── network-security.md            # Network protocols and security
│   └── glossary.md                    # Security terminology
│
├── cybersecurity_ethics/              # ⚖️ Ethics and legal framework
│   ├── legal-framework.md             # Norwegian and international law
│   ├── ethical-hacking.md             # Responsible security research
│   ├── responsible-disclosure.md      # Vulnerability reporting
│   ├── safe-lab-environments.md       # How to practice safely
│   └── case-studies/                  # Real-world incidents (sanitized)
│
├── resources/                         # 📚 Additional resources
│   ├── references.md                  # Academic references
│   ├── tools.md                       # Security tools (defensive)
│   ├── certifications.md              # Professional certifications
│   └── further-reading.md             # Books, papers, courses
│
├── infrastructure/                    # 🛠️ Repository infrastructure
│   ├── .github/                       # GitHub Actions and templates
│   │   ├── workflows/                 # CI/CD pipelines
│   │   ├── ISSUE_TEMPLATE.md          # Issue template
│   │   └── PULL_REQUEST_TEMPLATE.md   # PR template
│   ├── docker/                        # Safe lab Docker containers
│   └── docs/                          # Documentation site
│
└── cryptografi/                       # 🔐 Cryptography materials (existing)
    ├── CRYPTOGRAPHY_GUIDE.md          # Comprehensive crypto guide
    ├── EXERCISES.md                   # Crypto exercises
    ├── ATTACKS_AND_VULNERABILITIES.md # Security analysis
    └── examples/                      # Python crypto examples
```

---

## 🚀 Quick Start

### For Students

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Oleandertengesdal/IDATT2503.git
   cd IDATT2503
   ```

2. **Read the course information**:
   - Start with [`course_info/syllabus.md`](./course_info/syllabus.md)
   - Review [`course_info/learning_outcomes.md`](./course_info/learning_outcomes.md)

3. **Follow the weekly schedule**:
   - Check [`course_info/schedule.md`](./course_info/schedule.md) for topics
   - Read corresponding lecture materials in `lectures/`

4. **Work through examples and labs**:
   - Complete examples in `examples/` for understanding
   - Do hands-on labs in `labs/` for practice

5. **Study theory materials**:
   - Read `theory/` for in-depth understanding
   - Use `theory/glossary.md` for terminology

6. **Complete assignments**:
   - Follow instructions in `assignments/`
   - Submit via Blackboard (or as instructed)

### For Instructors

1. **Customize course information**:
   - Update `course_info/` with your specific term details
   - Modify `staff_and_contact.md` with your information

2. **Add or modify materials**:
   - Follow the structure in existing lectures/examples
   - Use templates in `infrastructure/`

3. **Set up autograding** (optional):
   - Configure GitHub Classroom integration
   - Use GitHub Actions workflows in `.github/workflows/`

4. **Deploy documentation site**:
   ```bash
   cd infrastructure/docs
   mkdocs serve  # Local preview
   mkdocs gh-deploy  # Deploy to GitHub Pages
   ```

### For Self-Learners

1. **Follow the learning path**:
   - Work through materials week by week
   - Complete all examples and labs

2. **Practice in safe environments**:
   - See [`cybersecurity_ethics/safe-lab-environments.md`](./cybersecurity_ethics/safe-lab-environments.md)
   - Use intentionally vulnerable applications (DVWA, Juice Shop)

3. **Join the community**:
   - Participate in educational CTF competitions
   - Follow responsible disclosure practices

---

## 📖 Course Content

### Module 1: Foundations (Weeks 1-3)
- Introduction to software security
- Secure software development lifecycle
- Common vulnerability types
- Cryptography fundamentals

### Module 2: Web Security (Weeks 4-6)
- OWASP Top 10
- Authentication and authorization
- Session management
- Input validation and output encoding

### Module 3: System Security (Weeks 7-9)
- Memory safety concepts
- Buffer overflow theory
- Privilege escalation concepts
- Secure system configuration

### Module 4: Network Security (Weeks 10-12)
- Network protocols and vulnerabilities
- TLS/SSL and PKI
- Secure communications
- Firewall and IDS concepts

### Module 5: Security in Practice (Weeks 13-15)
- Security testing methodologies
- Incident response
- Penetration testing ethics and process
- Final project presentations

---

## 🎯 Learning Outcomes

After completing this course, students will be able to:

1. **Analyze** software systems for common security vulnerabilities
2. **Design** and implement secure software applications
3. **Apply** cryptographic principles appropriately
4. **Evaluate** security risks and propose mitigations
5. **Conduct** ethical security assessments within legal boundaries
6. **Communicate** security findings responsibly

See [`course_info/learning_outcomes.md`](./course_info/learning_outcomes.md) for detailed outcomes.

---

## 📝 Assessment

- **Labs and Exercises**: 30% (continuous assessment)
- **Assignments**: 30% (2 major projects)
- **Final Exam**: 40% (written exam)

Passing grade: E (40%)

See [`course_info/assessment_and_grading.md`](./course_info/assessment_and_grading.md) for details.

---

## 🔐 Security and Ethics

**This repository is committed to responsible security education.**

- ✅ **Teaches**: Defensive security, secure coding, vulnerability mitigation
- ✅ **Promotes**: Ethical behavior, legal compliance, responsible disclosure
- ✅ **Provides**: Safe, isolated lab environments for learning

- ❌ **Does NOT include**: Exploit code, malware, attack tools
- ❌ **Does NOT teach**: Illegal hacking, unauthorized access
- ❌ **Does NOT support**: Unethical use of security knowledge

**Legal Notice**: Unauthorized access to computer systems is illegal in Norway and internationally. Students must:
- Only test systems they own or have explicit written permission to test
- Follow NTNU's acceptable use policies
- Comply with Norwegian Computer Crime Act (Straffeloven §§ 201-204)
- Practice responsible disclosure for any vulnerabilities discovered

See [`SECURITY.md`](./SECURITY.md) and [`cybersecurity_ethics/`](./cybersecurity_ethics/) for complete guidelines.

---

## 🤝 Contributing

We welcome contributions from students, instructors, and the security community!

**How to contribute**:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-example`)
3. Commit your changes (`git commit -m 'Add new secure coding example'`)
4. Push to the branch (`git push origin feature/new-example`)
5. Open a Pull Request

**Contribution guidelines**:
- Follow the existing structure and style
- Ensure all code is well-commented and tested
- Include only educational, non-malicious content
- Add appropriate documentation

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for detailed guidelines.

---

## 📜 License

This educational repository is licensed under the **MIT License** - see the [`LICENSE`](./LICENSE) file for details.

**Summary**: You may freely use, modify, and distribute this material for educational purposes, with attribution.

---

## 📞 Contact and Support

### Course Staff
- **Instructor**: [To be updated - see course_info/staff_and_contact.md]
- **Teaching Assistants**: [To be updated]
- **Course Forum**: Blackboard discussion board
- **Office Hours**: [To be updated]

### Technical Issues
- **Repository Issues**: Use [GitHub Issues](https://github.com/Oleandertengesdal/IDATT2503/issues)
- **Security Concerns**: See [`SECURITY.md`](./SECURITY.md)

### NTNU Resources
- **NTNU Security**: [security@ntnu.no](mailto:security@ntnu.no)
- **Student Support**: [innsida.ntnu.no](https://innsida.ntnu.no)
- **IT Help Desk**: [hjelp@ntnu.no](mailto:hjelp@ntnu.no)

---

## 🌟 Acknowledgments

This course builds upon:
- NTNU's Computer Science curriculum
- OWASP educational resources
- NIST cybersecurity framework
- Academic research in software security
- Contributions from students and instructors

Special thanks to the open-source security community for making education accessible.

---

## 🔗 Related Courses at NTNU

- **IDATT2104**: Network Programming (prerequisite)
- **IDATT2506**: Application Development
- **IDATT2502**: Applied Machine Learning (for security analytics)
- **TDT4237**: Software Security (advanced)

---

## 📚 Quick Links

### Getting Started
- [Course Syllabus](./course_info/syllabus.md)
- [Weekly Schedule](./course_info/schedule.md)
- [Reading List](./course_info/reading_list.md)

### Learning Materials
- [Lectures](./lectures/)
- [Examples](./examples/)
- [Labs](./labs/)
- [Theory](./theory/)

### Ethics and Safety
- [Legal Framework](./cybersecurity_ethics/legal-framework.md)
- [Ethical Hacking Guidelines](./cybersecurity_ethics/ethical-hacking.md)
- [Safe Lab Environments](./cybersecurity_ethics/safe-lab-environments.md)
- [Responsible Disclosure](./cybersecurity_ethics/responsible-disclosure.md)

### Resources
- [Tools and Software](./resources/tools.md)
- [References and Citations](./resources/references.md)
- [Certifications](./resources/certifications.md)

---

<div align="center">

**🔒 Stay Secure. Code Responsibly. Learn Ethically. 🔒**

*"Security is not a product, but a process." - Bruce Schneier*

</div>
