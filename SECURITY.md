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
| 0.3.x   | :white_check_mark: |
| 0.0.x–0.2.x | :x:             |

The `0.3.x` line is the currently supported published release line. Unreleased branches are not release artifacts; fixes are delivered through a tagged release. Older `0.0.x`–`0.2.x` versions are unsupported and should be upgraded.

## Security Considerations

- **SM4-GCM** is the default for `Sm4::encrypt()` and `Sm4Options`; the no-options API uses a self-contained GCM format. CBC is an explicit compatibility mode and does not authenticate ciphertext.
- **SM4 mode key separation and IVs**: use a separate key for every mode, including CCM and GCM, and do not reuse a mode key for direct raw-block calls through `Sm4PurePhp::setKey()`. Automatically generated IVs use `random_bytes`; explicit IVs must be unpredictable and unique for CBC/CFB, unique for OFB, and must not produce repeated counter blocks for CTR. The library rejects repeated CBC key/IV pairs in-process (bounded to 65,536 pairs unless a shared `Sm4FeedbackIvTrackerInterface` is configured), and rejects cross-mode use of one key within a process when an operation consumes block-cipher inputs. Configure `Sm4KeyModeTrackerInterface` before the first cipher operation to enforce key-to-mode separation atomically across workers and restarts. Encryption claims the mode; decryption only checks an existing registration and never changes the registry based on unauthenticated input. Register decrypt-only keys from trusted configuration with `Sm4::registerKeyMode()` when using a shared tracker. An unregistered decrypt-only key has no inferred mode in the local guard, so the application must keep it confined to its trusted mode. Without a shared tracker, deployments spanning processes must enforce key separation themselves. Mode separation does not replace each mode's IV, nonce, counter, or usage tracking.
- **SM4-CBC padding checks** scan the full final block to reduce padding-length-dependent timing differences, but PHP does not guarantee constant-time execution. Do not expose unauthenticated CBC decryption to attacker-controlled ciphertext; use GCM or verify an Encrypt-then-MAC before decryption.
- **SM4-ECB** remains available for compatibility but is not recommended because repeated plaintext blocks produce repeated ciphertext blocks.
- **SM2** static private keys are validated to be in range `[1, n-2]` per GM/T 0003.2; key-exchange ephemeral scalars use `[1, n-1]`
- **SM2 key exchange ephemeral keys** must be freshly generated for each participant and each session; never reuse `rA`/`rB` across sessions, peers, or protocol roles. The API accepts caller-supplied scalars and cannot reliably detect reuse across processes or restarts, so callers must enforce one-session ownership.
- **SM2 encryption** includes KDF zero-key retry protection (max 100 retries)
- **SM2 secret-scalar operations** use PHP/GMP elliptic-curve arithmetic, which is not guaranteed constant-time. The current windowed scalar multiplication also performs scalar-dependent table lookups. Do not rely on this library to resist local timing/cache side-channel attackers; use a reviewed native implementation, HSM, or isolated cryptographic service where that threat applies.
- **SM4 pure-PHP fallback** uses secret-dependent S-box table lookups in both key expansion and block processing. If OpenSSL SM4 is unavailable, do not rely on the fallback to resist local timing/cache side-channel attackers; use a reviewed native implementation, HSM, or isolated cryptographic service where that threat applies. This affects all modes backed by `Sm4PurePhp`, including GCM and CCM.
- **SM4-GCM side channels**: when PHP can execute OpenSSL's native `SM4-GCM` AEAD, this library delegates the complete AEAD operation to it. Otherwise GHASH runs in PHP/GMP and branches on bits of its secret-derived field state (`H = E_K(0)`). OpenSSL's SM4 implementations may themselves use secret-dependent table lookups and are not guaranteed constant-time. Do not rely on either backend to resist local timing/cache side-channel attackers; use a reviewed constant-time native implementation, HSM, or isolated cryptographic service where that threat applies.
- **SM2 DER auto-detection** correctly distinguishes plain (128 hex) vs DER signatures to avoid false positives
- **SM3 streaming contexts** redact internal state in debug output and reject serialization; the pure-PHP backend temporarily retains the unprocessed input tail in memory.
- **SM4-GCM** on the PHP/GMP fallback compares tags with `hash_equals()` before decryption; when native OpenSSL `SM4-GCM` is executable, OpenSSL performs the authenticated operation
- **SM4-GCM/CCM failed authentication attempts**: the library does not impose a protocol-wide per-key limit on failed tag verifications. NIST SP 800-38D Appendix B says the implementing system or protocol should monitor and, when necessary, limit unsuccessful GCM verification attempts per key. Applications must rate-limit attacker-controlled decryption attempts per key across all workers and restarts, avoid distinguishable remote responses, and rotate the key when the configured budget is exhausted. `CcmBlockUsageTrackerInterface` accounts for CCM block-cipher work, including failed decryptions, but its `2^61` block limit is not a failed-verification-attempt budget.
- **SM4-GCM** AAD (Additional Authenticated Data) is properly included in GHASH computation
- **SM4 legacy CBC payloads** require the explicit unauthenticated `Sm4::decryptLegacyCbc()` migration API; new no-options encryption returns a self-contained GCM payload. `encryptPayload()` / `decryptPayload()` also default to GCM and carry IV/tag metadata.
- Structured payload decryption requires the expected mode from trusted configuration; non-GCM modes must be explicitly selected and do not authenticate ciphertext.
- **SM4 zero padding** is deprecated for new code because it cannot preserve trailing null bytes; `encryptPayload()` rejects it
- **PEM import** validates OID (1.2.156.10197.1.301), DER canonical length forms, public-key curve membership, and private/public key consistency
- For cryptographic key generation and nonces, use `random_bytes()` (or `random_int()` for ranges that fit a native integer). Never use GMP's `gmp_random_range()` or `gmp_random_bits()` for cryptographic purposes; PHP documents that these functions are not cryptographically secure. SM2 scalar generation in this library samples `random_bytes()` output with rejection sampling.
- **SM4-GCM** IV must never be reused with the same key
- **SM4-GCM** IV reuse is detected at runtime and rejected; this protection cannot be disabled. The explicit-IV tracking table is process-local and fails closed when its 65,536-entry capacity is reached. Internally generated IVs use a reserved 128-bit `SM4R || 96-bit CSPRNG output` format; caller-supplied encryption APIs reject this namespace so an exported IV cannot be reused through another library entry point. No-options encryption emits `SM4GCM2`; decryption remains compatible with `SM4GCM1`. All encryptions remain subject to the per-key invocation limit. Use shared `GcmIvTrackerInterface` and `GcmTagLengthTrackerInterface` implementations when coordinating workers or restarts; the tag tracker enforces the NIST fixed-tag-length profile per key.
- **SM4 decryption** with explicit `Sm4Options` requires the IV to be set; a missing IV throws `InvalidKeyException` instead of silently generating a random one (which would yield garbage plaintext)
- **SM4-GCM GHASH** correctness is anchored to RFC 8998 A.1 official vectors plus an independent NIST SP 800-38D reference-model differential test (`tests/GcmReferenceModelTest.php`)

## Side-Channel Boundary

This library is implemented in PHP and GMP. It uses constant-time comparisons where practical, but scalar multiplication and big integer arithmetic are not guaranteed constant-time. For high-assurance deployments with local attackers or strict side-channel requirements, prefer a reviewed native implementation, HSM, or isolated signing/decryption service.

## Key-Memory Boundary

Cipher contexts redact debug output and reject serialization, but PHP strings, GMP values, and copied/intermediate key material are managed by the runtime. Destroying a context does not guarantee that key bytes are immediately or securely erased from process memory. Applications requiring memory zeroization should use a reviewed native cryptographic provider or HSM and minimize the lifetime and copies of secrets in PHP.
