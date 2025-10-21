# Security Policy

## Our Commitment

This repository is dedicated to **responsible security education**. We are committed to:

- Teaching defensive security practices and secure software development
- Promoting ethical behavior and legal compliance
- Providing safe learning environments
- Supporting responsible vulnerability disclosure
- Preventing misuse of security knowledge

## Scope and Purpose

### ✅ This Repository DOES Include:

- **Educational Content**: Theoretical explanations of security concepts
- **Defensive Techniques**: How to protect systems and write secure code
- **Vulnerability Mitigation**: How to fix and prevent security issues
- **Conceptual Overviews**: High-level descriptions of security testing methods
- **Safe Lab Environments**: Instructions for isolated, controlled practice environments
- **Case Studies**: Sanitized, academic analysis of past incidents (no exploit code)
- **Responsible Disclosure**: Guidelines for ethical vulnerability reporting

### ❌ This Repository Does NOT Include:

- **Exploit Code**: No working exploits, payloads, or attack tools
- **Malware**: No viruses, trojans, ransomware, or malicious software
- **Attack Tutorials**: No step-by-step instructions for unauthorized access
- **Credential Dumping**: No password cracking tools or stolen credentials
- **Illegal Content**: Nothing that violates Norwegian or international law

## Legal Framework

### Norwegian Law

Students and users of this repository must comply with Norwegian law, particularly:

**Straffeloven (Penal Code) §§ 201-204** - Computer Crime:
- § 201: Unauthorized access to data systems (up to 2 years imprisonment)
- § 202: Computer sabotage and data destruction
- § 203: Computer-related fraud
- § 204: Aggravated computer crime (up to 6 years imprisonment)

**Personopplysningsloven** - Personal Data Act (GDPR):
- Protects personal data and privacy
- Violations can result in significant fines

### International Law

- **Computer Fraud and Abuse Act (CFAA)** - USA
- **Computer Misuse Act** - UK
- **Convention on Cybercrime (Budapest Convention)** - Europe
- **EU Directive on Attacks against Information Systems**

### NTNU Acceptable Use Policy

All users must comply with:
- NTNU's IT Regulations
- Acceptable Use of IT Resources Policy
- Research Ethics Guidelines
- Student Code of Conduct

**Violations may result in**:
- Expulsion from the course
- Academic disciplinary action
- Referral to law enforcement
- Civil and criminal liability

## Authorized Security Testing

### When is Security Testing Legal?

Security testing is ONLY legal when you have:

1. **Explicit Written Permission**: From the system owner
2. **Clearly Defined Scope**: What systems and methods are authorized
3. **Time Constraints**: When testing is allowed
4. **Rules of Engagement**: What actions are prohibited
5. **Contact Information**: Emergency contacts if issues arise

### Examples of Authorized Testing

✅ **Authorized**:
- Testing your own systems and infrastructure
- Using intentionally vulnerable training platforms (DVWA, Juice Shop, HackTheBox)
- Participating in sanctioned CTF competitions
- Bug bounty programs with clear terms
- Academic research with ethics committee approval

❌ **Unauthorized** (ILLEGAL):
- Testing production systems without permission
- Scanning networks you don't own
- Accessing others' accounts or data
- Denial of service attacks
- Deploying tools on systems without authorization

## Safe Lab Environments

### Recommended Practice Platforms

**Intentionally Vulnerable Applications** (Legal to Test):
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [Damn Vulnerable Web Application (DVWA)](https://dvwa.co.uk/)
- [OWASP Mutillidae II](https://github.com/webpwnized/mutillidae)
- [bWAPP](http://www.itsecgames.com/)

**Virtual Machine Labs**:
- [VulnHub](https://www.vulnhub.com/) - Vulnerable VMs for practice
- [HackTheBox](https://www.hackthebox.com/) - Legal hacking challenges
- [TryHackMe](https://tryhackme.com/) - Guided security training

**CTF Platforms** (Educational):
- [OverTheWire](https://overthewire.org/wargames/) - Wargames
- [picoCTF](https://picoctf.org/) - Beginner-friendly CTF
- [CTFtime](https://ctftime.org/) - CTF event listings

### Setting Up Isolated Environments

**Local Isolated Networks**:
```bash
# Example: Create an isolated Docker network
docker network create --internal security-lab

# Run vulnerable app in isolated network
docker run -d --name dvwa --network security-lab vulnerables/web-dvwa
```

**Virtual Machines**:
- Use VirtualBox or VMware
- Configure host-only networking (no internet access)
- Take snapshots before testing
- Never connect to production networks

**Requirements for Safe Labs**:
- ✅ Isolated from production networks
- ✅ Air-gapped or firewalled
- ✅ Clear labeling as "lab" or "test" systems
- ✅ No real user data
- ✅ Documented and approved by instructors

## Responsible Vulnerability Disclosure

If you discover a real vulnerability, follow responsible disclosure:

### 1. Do NOT:
- Publicly disclose the vulnerability immediately
- Exploit the vulnerability beyond proof-of-concept
- Access or exfiltrate sensitive data
- Disrupt services or destroy data
- Demand payment or ransom

### 2. DO:
- Report to the affected organization privately
- Provide detailed technical information
- Allow reasonable time for patching (typically 90 days)
- Coordinate public disclosure with the vendor
- Follow the organization's security policy

### 3. Disclosure Process:

**Step 1 - Initial Contact** (Day 0):
```
Subject: Security Vulnerability Report - [Brief Description]

To: security@organization.com

I am a security researcher and have discovered a potential
vulnerability in your system. I am reporting this responsibly
and privately to allow you time to address the issue.

Vulnerability: [Type, e.g., SQL Injection]
Severity: [Critical/High/Medium/Low]
Component: [Affected system/application]
Discovery Date: [Date]

I am willing to provide technical details and assistance in
remediation. Please confirm receipt of this report.

Best regards,
[Your Name]
[Your Affiliation]
[Contact Information]
```

**Step 2 - Technical Details** (After acknowledgment):
- Detailed vulnerability description
- Proof-of-concept (non-destructive)
- Steps to reproduce
- Potential impact assessment
- Suggested remediation

**Step 3 - Coordinated Disclosure** (After patch):
- Agree on public disclosure date
- Review disclosure content with vendor
- Publish advisory (if appropriate)

### Reporting to NTNU

**NTNU Security Vulnerabilities**:
- Email: security@ntnu.no
- Use encrypted email if possible (PGP)
- Include: System, vulnerability type, impact, your contact info

**Course-Related Security Issues**:
- Report to course instructor privately
- Do not discuss in public forums
- Use secure communication channels

## Reporting Security Concerns in This Repository

### Vulnerability in Course Materials

If you find a security issue in example code or course materials:

1. **Open a Private Security Advisory**:
   - Go to Security → Advisories → New draft advisory
   - Provide detailed description
   - Suggest fixes if possible

2. **Or Email the Maintainers**:
   - [maintainer-email@example.com]
   - Include: File/section, issue description, suggested fix

### Inappropriate Content

If you find content that could be misused:

1. **Report via GitHub Issues** (for public, non-sensitive reports)
2. **Email maintainers privately** (for sensitive concerns)
3. **Contact NTNU** if it violates university policies

We will:
- Acknowledge your report within 48 hours
- Investigate and assess the issue
- Take appropriate action (remove, modify, or clarify content)
- Credit you for responsible disclosure (with permission)

## Ethical Use Agreement

By using this repository, you agree to:

1. **Legal Compliance**: Follow all applicable laws and regulations
2. **Authorized Testing Only**: Only test systems you own or have permission to test
3. **No Malicious Use**: Not use course materials for unauthorized access or harm
4. **Responsible Disclosure**: Report vulnerabilities responsibly
5. **Academic Integrity**: Follow NTNU's academic integrity policies
6. **Ethical Behavior**: Use knowledge to improve security, not to harm

## Consequences of Misuse

Misuse of this repository or its contents may result in:

### Academic Consequences:
- Failing grade in the course
- Academic misconduct proceedings
- Expulsion from NTNU
- Revocation of degree

### Legal Consequences:
- Criminal charges
- Fines and imprisonment
- Civil lawsuits
- Professional licensing issues

### Professional Consequences:
- Damage to reputation
- Blacklisting from security industry
- Difficulty obtaining employment
- Loss of security clearances

## Contact Information

### Security Issues in This Repository
- **GitHub Security Advisories**: [Repository → Security → Advisories]
- **Email**: [repository-security@example.com]

### NTNU Security Team
- **Email**: security@ntnu.no
- **Phone**: +47 73 59 50 00 (main switchboard)
- **Emergency**: [NTNU IT emergency contacts]

### Norwegian Authorities
- **Kripos (National Criminal Investigation Service)**: For cybercrime reports
- **NSM (National Security Authority)**: For critical infrastructure
- **Datatilsynet**: For data protection violations

### International CERT/CSIRT
- **CERT-EU**: European CERT
- **US-CERT**: United States CERT
- **FIRST**: Forum of Incident Response and Security Teams

## Resources

### Legal Resources
- [Norwegian Penal Code (English translation)](https://lovdata.no/dokument/NLE/lov/2005-05-20-28)
- [GDPR Official Text](https://gdpr-info.eu/)
- [Convention on Cybercrime](https://www.coe.int/en/web/conventions/full-list/-/conventions/treaty/185)

### Responsible Disclosure Guidelines
- [ISO/IEC 29147](https://www.iso.org/standard/72311.html) - Vulnerability disclosure
- [CERT Guide to Coordinated Vulnerability Disclosure](https://vuls.cert.org/confluence/display/CVD)
- [Google Project Zero Disclosure Policy](https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html)

### Ethics in Security Research
- [ACM Code of Ethics](https://www.acm.org/code-of-ethics)
- [IEEE Code of Ethics](https://www.ieee.org/about/corporate/governance/p7-8.html)
- [Menlo Report](https://www.dhs.gov/sites/default/files/publications/CSD-MenloPrinciplesCORE-20120803_1.pdf) - Ethical Principles for Computer Security Research

## Version History

- **v1.0** (2025-10-14): Initial security policy
- Updates will be logged here

## Acknowledgments

This security policy is inspired by:
- OWASP Security Policy guidelines
- GitHub Security Lab best practices
- Academic institution security policies
- Responsible disclosure frameworks

---

**Remember**: With great knowledge comes great responsibility. Use your security skills to make the digital world safer, not to cause harm.

**Last Updated**: October 14, 2025  
**Maintained by**: [Course Staff / Repository Maintainers]
