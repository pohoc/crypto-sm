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

- **SM4 ECB mode** is available but **not recommended** — CBC mode is the default, GCM is the most recommended
- **SM2** private keys are validated to be in range `[1, n-1]`
- **SM2 encryption** includes KDF zero-key retry protection (max 100 retries)
- **SM2 signature** verification uses `hash_equals` for constant-time comparison to prevent timing attacks
- **SM2 DER auto-detection** correctly distinguishes plain (128 hex) vs DER signatures to avoid false positives
- **SM4-GCM** tag verification uses `hash_equals` for constant-time comparison; decryption only proceeds after tag validation
- **SM4-GCM** AAD (Additional Authenticated Data) is properly included in GHASH computation
- **PEM import** validates OID (1.2.156.10197.1.301) and DER boundary checks to prevent malformed input attacks
- Always use cryptographically secure random numbers for key generation (`gmp_random_range`, `random_bytes`)
- **SM4-GCM** IV must never be reused with the same key
