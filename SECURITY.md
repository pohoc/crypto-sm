# Security Policy

## Reporting a Vulnerability

This is a cryptographic library — security vulnerabilities are taken very seriously.

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **po.hoc4@gmail.com**

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Time

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix timeline**: depends on severity, critical issues will be patched within 72 hours

### Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | :white_check_mark: |

## Security Considerations

- **SM4 ECB mode** is available but **not recommended** — CBC mode is the default
- **SM2** private keys are validated to be in range `[1, n-1]`
- **SM2 encryption** includes KDF zero-key retry protection (max 100 retries)
- Always use cryptographically secure random numbers for key generation
