<?php

declare(strict_types=1);

/** Reads public Packagist metadata without credentials. */
final class PackagistReleaseCheck
{
    public static function matches(string $metadataJson, string $tag, string $expectedSha): bool
    {
        $metadata = json_decode($metadataJson, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($metadata) || !is_array($metadata['packages'] ?? null)) {
            return false;
        }
        $versions = $metadata['packages']['pohoc/crypto-sm'] ?? null;
        if (!is_array($versions)) {
            return false;
        }
        foreach ($versions as $version) {
            if (!is_array($version)) {
                continue;
            }
            if (($version['version'] ?? null) === $tag) {
                $dist = $version['dist'] ?? null;
                $reference = is_array($dist) ? ($dist['reference'] ?? null) : null;
                return is_string($reference) && hash_equals(strtolower($expectedSha), strtolower($reference));
            }
        }
        return false;
    }
}

if (isset($_SERVER['SCRIPT_FILENAME']) && is_string($_SERVER['SCRIPT_FILENAME'])
    && realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    if (($argv[1] ?? null) === '--lock') {
        if ($argc !== 4 || preg_match('/\A[0-9a-f]{40}\z/i', $argv[3]) !== 1) {
            fwrite(STDERR, "Usage: php scripts/PackagistReleaseCheck.php --lock <version> <commit-sha>\n");
            exit(2);
        }
        try {
            $lock = json_decode((string) file_get_contents('composer.lock'), true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($lock)) {
                throw new RuntimeException('Composer lock is invalid.');
            }
            $packages = array_merge(
                is_array($lock['packages'] ?? null) ? $lock['packages'] : [],
                is_array($lock['packages-dev'] ?? null) ? $lock['packages-dev'] : []
            );
            foreach ($packages as $package) {
                if (!is_array($package) || ($package['name'] ?? null) !== 'pohoc/crypto-sm') {
                    continue;
                }
                $dist = $package['dist'] ?? null;
                $reference = is_array($dist) ? ($dist['reference'] ?? null) : null;
                if (($package['version'] ?? null) !== $argv[2]
                    || !is_string($reference)
                    || !hash_equals(strtolower($argv[3]), strtolower($reference))) {
                    throw new RuntimeException('Composer lock resolved an unexpected package version or commit.');
                }
                fwrite(STDOUT, "Composer lock resolves {$argv[2]} to the expected commit.\n");
                exit(0);
            }
            throw new RuntimeException('Composer lock does not contain pohoc/crypto-sm.');
        } catch (Throwable $exception) {
            fwrite(STDERR, $exception->getMessage() . PHP_EOL);
            exit(1);
        }
    }
    if ($argc !== 3 || preg_match('/\A[0-9a-f]{40}\z/i', $argv[2]) !== 1) {
        fwrite(STDERR, "Usage: php scripts/PackagistReleaseCheck.php <v-tag> <commit-sha>\n");
        exit(2);
    }

    $context = stream_context_create(['http' => [
        'timeout' => 15,
        'ignore_errors' => true,
        'header' => "User-Agent: crypto-sm-release-check\r\nAccept: application/json\r\n",
    ]]);
    $tag = $argv[1];
    $expectedSha = strtolower($argv[2]);
    for ($attempt = 1; $attempt <= 6; $attempt++) {
        $metadata = @file_get_contents('https://repo.packagist.org/p2/pohoc/crypto-sm.json', false, $context);
        if (is_string($metadata)) {
            try {
                if (PackagistReleaseCheck::matches($metadata, $tag, $expectedSha)) {
                    fwrite(STDOUT, "Packagist resolves $tag to $expectedSha.\n");
                    exit(0);
                }
            } catch (\JsonException) {
                // A partial or invalid response is treated as not synchronized yet.
            }
        }

        if ($attempt < 6) {
            fwrite(STDOUT, "Packagist has not synchronized $tag (attempt $attempt/6); retrying.\n");
            sleep(10);
        }
    }

    fwrite(STDERR, "Packagist did not resolve $tag to the expected commit after 6 attempts. Check the Packagist webhook or update the package manually.\n");
    exit(1);
}
