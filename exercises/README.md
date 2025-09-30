# Exercises

Hands-on practice exercises to develop ethical hacking and security skills.

## 📚 Available Exercise Sets

### [Web Security Exercises](web-security/)
Comprehensive web application security challenges covering:
- **SQL Injection** - 3 exercises (Basic, UNION-based, Blind)
- **Cross-Site Scripting (XSS)** - 3 exercises (Reflected, Stored, DOM-based)
- **Broken Access Control** - 3 exercises (IDOR, Privilege Escalation, Path Traversal)
- **CSRF** - Token bypass
- **Command Injection** - OS command execution
- **SSRF** - Server-side request forgery
- **XXE** - XML external entity attacks
- **JWT Authentication** - Token manipulation
- **Session Fixation** - Session security
- **API Security** - Rate limiting bypass

**Total: 16 exercises with detailed solutions**

Quick access:
- [Full Exercise Guide](web-security/README.md)
- [Quick Reference](web-security/QUICK-REFERENCE.md) - Fast payload lookup

## 🎯 How to Use These Exercises

### For Beginners
1. Start with **Exercise 1** (Basic SQL Injection)
2. Read the scenario carefully
3. Try to solve it yourself first
4. Use hints if you're stuck
5. Review the solution and understand the prevention

### For Intermediate Learners
1. Jump to exercises marked **(Medium)**
2. Try to solve without hints
3. Compare your solution with the provided one
4. Focus on understanding prevention techniques

### For Advanced Users
1. Tackle **(Hard)** exercises
2. Develop your own variations
3. Practice on real platforms (see [Practice Resources](#practice-resources))
4. Contribute additional exercises!

## 🔗 Related Resources

### Cheatsheets
- [Web Security Cheatsheet](../cheatsheets/web-security.md) - Comprehensive OWASP Top 10 reference
- [Binary Exploitation Cheatsheet](../cheatsheets/binary-exploitation.md)
- [Cryptography Cheatsheet](../cheatsheets/cryptography.md)

### Examples
- [Binary Exploitation Examples](../examples/binary-exploitation/)
- [Cryptography Examples](../examples/cryptography/)
- [System Programming Examples](../examples/system-programming/)

### Resources
- [Complete Resource List](../resources.md) - Platforms, books, courses, and tools

## 🌐 Practice Resources

### Beginner-Friendly Platforms
- **[Hacksplaining](https://www.hacksplaining.com/lessons)** - Interactive lessons
- **[OWASP WebGoat](https://owasp.org/www-project-webgoat/)** - Guided exercises
- **[DVWA](http://www.dvwa.co.uk/)** - Multiple difficulty levels
- **[picoCTF](https://picoctf.org/)** - CTF for beginners

### Intermediate Platforms
- **[PortSwigger Academy](https://portswigger.net/web-security)** - Free labs
- **[TryHackMe](https://tryhackme.com/)** - Guided rooms
- **[HackTheBox](https://www.hackthebox.eu/)** - Real-world scenarios

### Advanced Platforms
- **[PentesterLab](https://pentesterlab.com/)** - Professional exercises
- **Bug Bounty Programs** - Real applications (HackerOne, Bugcrowd)

## 🛠️ Required Tools

### Essential
- **Web Browser** with DevTools (Chrome/Firefox)
- **Burp Suite Community Edition** - Web proxy
- **Text Editor** - For crafting payloads

### Recommended
- **Python 3** - For automation scripts
- **SQLMap** - SQL injection automation
- **OWASP ZAP** - Free alternative to Burp
- **curl** or **Postman** - API testing

### Installation
```bash
# Burp Suite
# Download from: https://portswigger.net/burp/communitydownload

# Python tools
pip install requests pwntools

# SQLMap (if not included in Kali)
git clone https://github.com/sqlmapproject/sqlmap.git
```

## 📖 Learning Path

### Week 1-2: Injection Vulnerabilities
- [ ] Complete SQL Injection exercises 1-3
- [ ] Complete Command Injection exercise
- [ ] Read OWASP Injection documentation
- [ ] Practice on WebGoat

### Week 3-4: Client-Side Vulnerabilities
- [ ] Complete XSS exercises 4-6
- [ ] Complete CSRF exercise 10
- [ ] Complete Clickjacking section
- [ ] Practice on Juice Shop

### Week 5-6: Access Control & Authentication
- [ ] Complete Broken Access Control exercises 7-9
- [ ] Complete Session Fixation exercise 15
- [ ] Complete JWT exercise 14
- [ ] Study authentication best practices

### Week 7-8: Advanced Topics
- [ ] Complete XXE exercise 13
- [ ] Complete SSRF exercise 12
- [ ] Complete API security exercise 16
- [ ] Practice on HackTheBox

### Ongoing
- [ ] Participate in CTF competitions
- [ ] Read security blogs and writeups
- [ ] Practice on bug bounty platforms
- [ ] Build secure applications

## ⚠️ Ethical Guidelines

**CRITICAL REMINDERS:**

✅ **DO:**
- Practice on authorized platforms only
- Use knowledge to improve security
- Report vulnerabilities responsibly
- Learn prevention techniques
- Help others learn ethically

❌ **DON'T:**
- Attack systems without permission
- Use techniques maliciously
- Share zero-day exploits publicly
- Violate laws or regulations
- Harm systems or data

**Legal Notice**: Unauthorized computer access is illegal in most jurisdictions. Always obtain explicit permission before testing any system you don't own.

## 🤝 Contributing

Want to add more exercises? Great! Please:
1. Follow the existing format
2. Include clear objectives and scenarios
3. Provide progressive hints
4. Include detailed solutions
5. Add prevention techniques
6. Test your exercise thoroughly

Submit pull requests with new exercises or improvements!

## 📚 Additional Resources

- **Books**: "The Web Application Hacker's Handbook", "Real-World Bug Hunting"
- **Courses**: PortSwigger Academy, Offensive Security courses
- **Communities**: r/netsec, r/AskNetsec, security Discord servers
- **Certifications**: CEH, OSCP, eWPT

---

**Happy (Ethical) Hacking!** 🎩🔒
