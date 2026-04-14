# Contributing

Thank you for your interest in contributing to `crypto-sm`!

## Development Setup

```bash
git clone https://github.com/pohoc/crypto-sm.git
cd crypto-sm
composer install
```

## Running Tests

```bash
# Run all tests
vendor/bin/phpunit

# Run without coverage (faster)
vendor/bin/phpunit --no-coverage

# Run specific test file
vendor/bin/phpunit tests/Sm2Test.php
```

## Code Style

This project uses [PHP-CS-Fixer](https://github.com/PHP-CS-Fixer/PHP-CS-Fixer) with PSR-12 rules defined in `.php-cs-fixer.php`.

```bash
# Check (dry-run)
vendor/bin/php-cs-fixer fix --dry-run --diff

# Auto-fix
vendor/bin/php-cs-fixer fix
```

## Static Analysis

This project uses [PHPStan](https://phpstan.org/) at **level 8** (maximum strictness).

```bash
vendor/bin/phpstan analyse
```

## One-Command Check

Run all checks before submitting a PR:

```bash
composer check
```

This runs: `cs-check` → `analyse` → `test`

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Ensure all checks pass (`composer check`)
5. Commit with a clear message
6. Open a pull request

### PR Requirements

- [ ] All tests pass (`vendor/bin/phpunit`)
- [ ] PHPStan level 8 passes (`vendor/bin/phpstan analyse`)
- [ ] Code style is consistent (`vendor/bin/php-cs-fixer fix --dry-run --diff`)
- [ ] New public methods have PHPDoc documentation
- [ ] New features include test cases

## Coding Standards

- PHP 8.0+ compatible (no 8.1+ only syntax features like enums, fibers, readonly properties)
- `declare(strict_types=1)` in every file
- PSR-4 autoloading
- PSR-12 coding style
- Add PHPDoc to all public methods
- Use type declarations for all parameters and return types

## Adding New Features

When adding a new cryptographic feature:

1. **Follow the standard**: Reference the relevant GM/T standard document
2. **Add standard test vectors**: Include official test vectors from the standard
3. **Add round-trip tests**: Encrypt → Decrypt, Sign → Verify
4. **Update SmCrypto facade**: Add a proxy method to the facade class
5. **Update documentation**: Add usage examples to `docs/` and `README.md`

## Security

If you discover a security vulnerability, please follow the instructions in [SECURITY.md](SECURITY.md). **Do not** open a public issue.
