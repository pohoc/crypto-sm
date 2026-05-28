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
- **SM2 signature** final equality checks use `hash_equals`; PHP/GMP elliptic-curve arithmetic itself is not guaranteed constant-time
- **SM2 DER auto-detection** correctly distinguishes plain (128 hex) vs DER signatures to avoid false positives
- **SM4-GCM** tag verification uses `hash_equals` for constant-time comparison; decryption only proceeds after tag validation
- **SM4-GCM** AAD (Additional Authenticated Data) is properly included in GHASH computation
- **SM4 default CBC API** returns `iv_hex + ciphertext_hex` when no `Sm4Options` are provided; for production wrappers prefer `encryptPayload()` / `decryptPayload()`, which always carries IV/tag metadata and generates a fresh IV
- **SM4 zero padding** is deprecated for new code because it cannot preserve trailing null bytes; `encryptPayload()` rejects it
- **PEM import** validates OID (1.2.156.10197.1.301), DER canonical length forms, public-key curve membership, and private/public key consistency
- Always use cryptographically secure random numbers for key generation (`gmp_random_range`, `random_bytes`)
- **SM4-GCM** IV must never be reused with the same key

## Side-Channel Boundary

This library is implemented in PHP and GMP. It uses constant-time comparisons where practical, but scalar multiplication and big integer arithmetic are not guaranteed constant-time. For high-assurance deployments with local attackers or strict side-channel requirements, prefer a reviewed native implementation, HSM, or isolated signing/decryption service.
