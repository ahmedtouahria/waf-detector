# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of WAF Detector seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please Do Not

* Open a public GitHub issue for security vulnerabilities
* Discuss the vulnerability in public forums or social media

### Please Do

1. Email the security team with details about the vulnerability
2. Provide sufficient information to reproduce the issue
3. Allow reasonable time for us to address the issue before public disclosure

### What to Include

* Description of the vulnerability
* Steps to reproduce the issue
* Potential impact
* Any suggested fixes (if you have them)

### Response Timeline

* **Initial Response**: Within 48 hours
* **Status Update**: Within 7 days
* **Fix Timeline**: Varies based on severity and complexity

### Security Best Practices for Users

When using WAF Detector:

* Always use the latest version
* Be cautious when scanning targets you don't own
* Use authentication and rate limiting appropriately
* Don't store sensitive credentials in config files
* Review and sanitize all output before sharing
* Use secure connections (HTTPS) when possible
* Keep your Go version up to date

### Known Security Considerations

* This tool makes HTTP/HTTPS requests to target servers
* Response data may contain sensitive information
* Use responsibly and only on authorized targets
* Rate limiting is your responsibility

## Security Updates

Security updates will be released as soon as possible after a vulnerability is confirmed and fixed. Updates will be announced via:

* GitHub Security Advisories
* Release notes
* CHANGELOG.md

Thank you for helping keep WAF Detector and its users safe!
