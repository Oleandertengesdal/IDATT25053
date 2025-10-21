# Contributing to IDATT2503

First off, thank you for considering contributing to IDATT2503! This course repository benefits from contributions by students, instructors, security researchers, and the broader community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Contribution Guidelines](#contribution-guidelines)
- [Style Guidelines](#style-guidelines)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Pull Request Process](#pull-request-process)
- [Legal and Ethical Considerations](#legal-and-ethical-considerations)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

### Our Pledge

We pledge to make participation in this project a harassment-free experience for everyone, regardless of:
- Age, body size, disability, ethnicity
- Gender identity and expression
- Level of experience, education
- Nationality, personal appearance, race, religion
- Sexual identity and orientation

## How Can I Contribute?

### Reporting Bugs or Issues

**Before submitting a bug report**:
- Check existing issues to avoid duplicates
- Collect relevant information (OS, browser, steps to reproduce)
- Verify it's not a security vulnerability (see [SECURITY.md](SECURITY.md))

**How to submit a bug report**:
1. Use the GitHub issue tracker
2. Use a clear, descriptive title
3. Provide detailed steps to reproduce
4. Include expected vs. actual behavior
5. Add screenshots if applicable
6. Mention your environment (OS, versions, etc.)

### Suggesting Enhancements

We welcome suggestions for:
- New examples or exercises
- Improved explanations
- Additional resources
- Better code samples
- Updated references

**How to suggest an enhancement**:
1. Open an issue with the label "enhancement"
2. Provide a clear use case
3. Explain why this would be useful
4. Suggest implementation if possible

### Contributing Content

You can contribute:

#### 1. **Examples and Exercises**
- Clear problem statements
- Well-commented code
- Step-by-step walkthroughs
- Test cases and expected outputs
- Learning objectives

#### 2. **Lecture Materials**
- Slide decks (PDF or Markdown)
- Lecture notes
- Code demos
- Additional references

#### 3. **Lab Exercises**
- Self-contained labs
- Safe, isolated environments
- Starter code and solutions
- Clear instructions
- Learning goals

#### 4. **Theory and Documentation**
- Conceptual explanations
- Diagrams and visualizations
- References to academic literature
- Glossary entries

#### 5. **Resources**
- Links to papers, books, courses
- Tool recommendations (defensive only)
- Certifications and career paths

## Contribution Guidelines

### General Principles

1. **Educational Focus**: All content must have clear educational value
2. **Safety First**: No exploit code, malware, or attack tools
3. **Legal Compliance**: Follow Norwegian and international law
4. **Ethical Standards**: Promote responsible security practices
5. **Quality**: Well-written, tested, and documented
6. **Accessibility**: Clear language, suitable for students

### Content Requirements

#### Code Contributions

✅ **DO**:
- Write clean, readable, well-commented code
- Include unit tests where applicable
- Provide runnable examples
- Use secure coding practices
- Add error handling
- Document dependencies
- Include usage examples

❌ **DON'T**:
- Submit exploit code or malware
- Include hardcoded credentials (even fake ones that look real)
- Use deprecated or vulnerable libraries without explanation
- Submit untested code
- Include malicious functionality

#### Example Code Template:

```python
"""
Module: [Module Name]
Purpose: [Educational purpose]
Author: [Your Name]
Date: [Date]
License: MIT

Description:
[Detailed description of what this example teaches]

Learning Objectives:
- [Objective 1]
- [Objective 2]

Prerequisites:
- [Required knowledge]
- [Required tools/libraries]

Usage:
$ python example.py
"""

# Required imports
import sys

def main():
    """
    Main function demonstrating [concept].
    
    This example shows how to [description] in a secure manner.
    """
    # Implementation with detailed comments
    pass

if __name__ == "__main__":
    main()
```

#### Documentation Contributions

✅ **DO**:
- Use clear, concise language
- Include examples and diagrams
- Cite sources and references
- Use proper Markdown formatting
- Check spelling and grammar
- Keep a professional tone

❌ **DON'T**:
- Copy content without attribution
- Use offensive or discriminatory language
- Make unsupported claims
- Include outdated information

#### Lecture Materials

**Structure**:
```markdown
# Lecture [Number]: [Title]

## Learning Objectives
- [Objective 1]
- [Objective 2]

## Prerequisites
- [Required knowledge]

## Lecture Outline
1. Introduction (10 min)
2. Main Concept 1 (20 min)
3. Example/Demo (15 min)
4. Main Concept 2 (20 min)
5. Q&A (10 min)

## Key Concepts
### Concept 1
[Explanation]

## Code Examples
[Well-commented examples]

## Exercises
[Practice problems]

## Additional Resources
- [Links to papers, videos, etc.]

## References
[Academic citations]
```

### Legal and Ethical Considerations

#### Acceptable Content

✅ **Approved**:
- Defensive security techniques
- Vulnerability mitigation strategies
- Secure coding practices
- Cryptographic implementations (standard algorithms)
- Network security concepts
- Authentication/authorization best practices
- Security testing methodologies (conceptual)
- Case studies (sanitized, no exploit code)

❌ **Prohibited**:
- Working exploits or attack code
- Malware (viruses, trojans, ransomware)
- Credential dumping tools
- DDoS attack tools
- Keyloggers or surveillance software
- Tools for unauthorized access
- Instructions for illegal activities
- Plagiarized content

#### Ethical Requirements

All contributors must:

1. **Respect Privacy**: No personal data without consent
2. **No Harm**: Don't contribute anything that could cause harm
3. **Legal Compliance**: Follow all applicable laws
4. **Academic Integrity**: Original work or properly cited
5. **Responsible Disclosure**: Report vulnerabilities privately first

#### Content Review

Contributions will be reviewed for:
- Educational value
- Legal compliance
- Ethical considerations
- Technical accuracy
- Code quality
- Documentation completeness

**Reviewers may**:
- Request changes
- Ask for clarification
- Suggest improvements
- Reject inappropriate content

## Style Guidelines

### Python Code Style

Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/):

```python
# Good
def calculate_hash(data: bytes) -> str:
    """Calculate SHA-256 hash of data."""
    return hashlib.sha256(data).hexdigest()

# Bad
def calc_hash(d):
    return hashlib.sha256(d).hexdigest()
```

### C/C++ Code Style

```c
// Good: Clear, commented, safe
void secure_copy(char *dest, const char *src, size_t size) {
    // Use safe string functions
    strncpy(dest, src, size - 1);
    dest[size - 1] = '\0';  // Ensure null termination
}

// Bad: No bounds checking, no comments
void copy(char *d, char *s) {
    strcpy(d, s);  // Unsafe!
}
```

### Markdown Style

- Use ATX-style headers (`#`, `##`, `###`)
- One blank line between sections
- Use code fences with language specification
- Use bullet points for lists
- Include alt text for images

### Commit Message Guidelines

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting changes
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples**:

```
feat(examples): add SQL injection prevention example

Added a comprehensive example showing proper input validation
and parameterized queries to prevent SQL injection.

Closes #42
```

```
docs(theory): update cryptography fundamentals

- Added section on post-quantum cryptography
- Updated references to latest NIST standards
- Fixed typos in RSA explanation
```

```
fix(labs): correct Docker configuration for lab 3

The previous configuration had port conflicts. Updated to use
host-only networking and corrected the port mappings.

Fixes #56
```

## Pull Request Process

### Before Submitting

1. **Update your fork**:
   ```bash
   git remote add upstream https://github.com/Oleandertengesdal/IDATT2503.git
   git fetch upstream
   git merge upstream/main
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**:
   - Follow style guidelines
   - Add tests if applicable
   - Update documentation
   - Commit with clear messages

4. **Test your changes**:
   - Run existing tests
   - Test code examples
   - Check links in documentation
   - Verify formatting

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

### Submitting the Pull Request

1. **Go to the original repository** on GitHub
2. **Click "New Pull Request"**
3. **Select your branch**
4. **Fill out the PR template**:

```markdown
## Description
[Brief description of changes]

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Code refactoring

## Related Issues
Closes #[issue number]

## Testing
- [ ] Code runs without errors
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Examples are runnable

## Checklist
- [ ] Code follows style guidelines
- [ ] Comments added for complex logic
- [ ] No security vulnerabilities introduced
- [ ] Content is educational and ethical
- [ ] All tests pass

## Screenshots (if applicable)
[Add screenshots]

## Additional Notes
[Any other relevant information]
```

### Review Process

1. **Automated Checks**: CI/CD will run tests and linters
2. **Maintainer Review**: A maintainer will review your PR
3. **Feedback**: You may be asked to make changes
4. **Approval**: Once approved, your PR will be merged

**Timeline**:
- Initial review: 2-5 days
- Follow-up reviews: 1-3 days
- Merge: After approval and passing checks

### After Merging

- Your contribution will be credited
- Update your fork to stay synchronized
- Consider contributing again!

## Recognition

Contributors will be recognized in:
- The repository's contributors list
- Course acknowledgments (for significant contributions)
- Academic citations (for substantial content)

## Questions?

- **General Questions**: Open a GitHub Discussion
- **Bug Reports**: Open an Issue
- **Security Concerns**: See [SECURITY.md](SECURITY.md)
- **Private Inquiries**: Email [maintainer@example.com]

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Resources for Contributors

### Documentation
- [GitHub Docs](https://docs.github.com/)
- [Markdown Guide](https://www.markdownguide.org/)
- [Git Tutorial](https://git-scm.com/doc)

### Code Quality
- [PEP 8](https://www.python.org/dev/peps/pep-0008/) - Python style guide
- [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html)
- [Clean Code](https://www.oreilly.com/library/view/clean-code-a/9780136083238/) by Robert C. Martin

### Security
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [CERT Secure Coding Standards](https://wiki.sei.cmu.edu/confluence/display/seccode)

---

Thank you for contributing to IDATT2503! Your efforts help make security education accessible and effective for everyone.

**Questions?** Don't hesitate to ask! We're here to help.
