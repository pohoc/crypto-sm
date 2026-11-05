<?php

declare(strict_types=1);

/** Small, dependency-free SemVer 2.0 helper used by the release workflow and tests. */
final class ReleaseVersion
{
    /** @return array{major:string,minor:string,patch:string,prerelease:list<string>,build:list<string>} */
    public static function parse(string $version): array
    {
        $identifier = '(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)';
        $pattern = '/\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
            . '(?:-(' . $identifier . '(?:\.' . $identifier . ')*))?'
            . '(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\z/D';

        if (preg_match($pattern, $version, $matches, PREG_UNMATCHED_AS_NULL) !== 1) {
            throw new InvalidArgumentException("Invalid SemVer 2.0.0 version: $version");
        }

        return [
            'major' => $matches[1],
            'minor' => $matches[2],
            'patch' => $matches[3],
            'prerelease' => $matches[4] === null ? [] : explode('.', $matches[4]),
            'build' => $matches[5] === null ? [] : explode('.', $matches[5]),
        ];
    }

    public static function compare(string $left, string $right): int
    {
        $a = self::parse($left);
        $b = self::parse($right);
        foreach (['major', 'minor', 'patch'] as $field) {
            $comparison = self::compareNumeric($a[$field], $b[$field]);
            if ($comparison !== 0) {
                return $comparison;
            }
        }

        if ($a['prerelease'] === [] || $b['prerelease'] === []) {
            if ($a['prerelease'] === [] && $b['prerelease'] === []) {
                return 0;
            }
            return $a['prerelease'] === [] ? 1 : -1;
        }
        for ($index = 0, $length = min(count($a['prerelease']), count($b['prerelease'])); $index < $length; $index++) {
            $leftId = $a['prerelease'][$index];
            $rightId = $b['prerelease'][$index];
            $leftNumeric = ctype_digit($leftId);
            $rightNumeric = ctype_digit($rightId);
            if ($leftNumeric && $rightNumeric) {
                $comparison = self::compareNumeric($leftId, $rightId);
            } elseif ($leftNumeric !== $rightNumeric) {
                $comparison = $leftNumeric ? -1 : 1;
            } else {
                $comparison = strcmp($leftId, $rightId) <=> 0;
            }
            if ($comparison !== 0) {
                return $comparison;
            }
        }

        return count($a['prerelease']) <=> count($b['prerelease']);
    }

    /** @param list<string> $tags */
    public static function validateInput(string $version, array $tags, bool $allowExisting = false): string
    {
        if (str_starts_with($version, 'v')) {
            throw new InvalidArgumentException('Enter the version without the v prefix.');
        }
        self::parse($version);

        $highest = null;
        $targetExists = false;
        foreach ($tags as $tag) {
            if (!str_starts_with($tag, 'v')) {
                throw new InvalidArgumentException("Invalid release tag: $tag");
            }
            $tagVersion = substr($tag, 1);
            self::parse($tagVersion);
            if ($tag === 'v' . $version) {
                $targetExists = true;
            }
            if ($highest === null || self::compare($tagVersion, $highest) > 0) {
                $highest = $tagVersion;
            }
        }

        if ($targetExists) {
            if ($allowExisting) {
                return $version;
            }
            throw new InvalidArgumentException('The release tag already exists; use the Release workflow to resume it.');
        }

        if ($highest !== null && self::compare($version, $highest) <= 0) {
            throw new InvalidArgumentException("Version $version must be greater than the highest release $highest.");
        }

        return $version;
    }

    /** @param array<string, mixed> $results */
    public static function ciGatePassed(array $results): bool
    {
        foreach (['composer', 'tests', 'quality', 'security'] as $job) {
            if (($results[$job] ?? null) !== 'success') {
                return false;
            }
        }

        return true;
    }

    /** @param array<string, mixed>|null $release */
    public static function releaseAction(string $tag, string $expectedSha, ?string $tagSha, ?array $release): string
    {
        $version = substr($tag, 1);
        $parsed = self::parse($version);
        if (!str_starts_with($tag, 'v')) {
            throw new InvalidArgumentException('Release tag must start with v.');
        }
        if ($tagSha === null && $release !== null) {
            throw new InvalidArgumentException('A GitHub Release exists without its Git tag.');
        }
        if ($tagSha !== null && !hash_equals(strtolower($expectedSha), strtolower($tagSha))) {
            throw new InvalidArgumentException('Existing tag points to a different commit.');
        }
        if ($release === null) {
            return $tagSha === null ? 'create-tag' : 'resume-release';
        }
        if (($release['tag_name'] ?? null) !== $tag || !is_bool($release['draft'] ?? null)) {
            throw new InvalidArgumentException('GitHub Release state does not match the requested tag.');
        }
        $expectedPrerelease = $parsed['prerelease'] !== [];
        if (($release['prerelease'] ?? null) !== $expectedPrerelease) {
            throw new InvalidArgumentException('GitHub Release prerelease state does not match its SemVer tag.');
        }
        $target = $release['target_commitish'] ?? null;
        if (is_string($target) && preg_match('/\A[0-9a-f]{40}\z/i', $target) === 1
            && !hash_equals(strtolower($expectedSha), strtolower($target))) {
            throw new InvalidArgumentException('GitHub Release targets a different commit.');
        }

        return $release['draft'] ? 'draft-exists' : 'published-exists';
    }

    private static function compareNumeric(string $left, string $right): int
    {
        $lengthComparison = strlen($left) <=> strlen($right);
        return $lengthComparison !== 0 ? $lengthComparison : (strcmp($left, $right) <=> 0);
    }
}

if (isset($_SERVER['SCRIPT_FILENAME']) && is_string($_SERVER['SCRIPT_FILENAME'])
    && realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    $arguments = array_slice($argv, 1);
    if (($arguments[0] ?? null) === '--ci-gate') {
        try {
            $results = json_decode($arguments[1] ?? '', true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($results) || !array_is_list($results) && array_filter(array_keys($results), 'is_string') !== array_keys($results)
                || !ReleaseVersion::ciGatePassed($results)) {
                fwrite(STDERR, "CI Gate blocked: every required job must conclude success.\n");
                exit(1);
            }
            fwrite(STDOUT, "All required CI jobs succeeded.\n");
            exit(0);
        } catch (Throwable $exception) {
            fwrite(STDERR, "CI Gate input is invalid: {$exception->getMessage()}\n");
            exit(1);
        }
    }
    if (($arguments[0] ?? null) === '--release-state') {
        try {
            if (count($arguments) !== 5) {
                throw new InvalidArgumentException('Release-state mode expects tag, expected SHA, tag SHA or -, and Release JSON file or -.');
            }
            $tagSha = $arguments[3] === '-' ? null : $arguments[3];
            $release = $arguments[4] === '-'
                ? null
                : json_decode((string) file_get_contents($arguments[4]), true, 512, JSON_THROW_ON_ERROR);
            if ($release !== null && (!is_array($release) || array_filter(array_keys($release), 'is_string') !== array_keys($release))) {
                throw new InvalidArgumentException('GitHub Release data is invalid.');
            }
            /** @var array<string, mixed>|null $releaseState */
            $releaseState = $release;
            fwrite(STDOUT, ReleaseVersion::releaseAction($arguments[1], $arguments[2], $tagSha, $releaseState) . PHP_EOL);
            exit(0);
        } catch (Throwable $exception) {
            fwrite(STDERR, $exception->getMessage() . PHP_EOL);
            exit(1);
        }
    }
    $allowExisting = in_array('--allow-existing', $arguments, true);
    $arguments = array_values(array_filter($arguments, static fn (string $arg): bool => $arg !== '--allow-existing'));
    if ($arguments === []) {
        fwrite(STDERR, "Usage: php scripts/ReleaseVersion.php <version-without-v> [existing-v-tags...] [--allow-existing]\n");
        exit(2);
    }
    try {
        fwrite(STDOUT, ReleaseVersion::validateInput($arguments[0], array_slice($arguments, 1), $allowExisting) . PHP_EOL);
    } catch (Throwable $exception) {
        fwrite(STDERR, $exception->getMessage() . PHP_EOL);
        exit(1);
    }
}
