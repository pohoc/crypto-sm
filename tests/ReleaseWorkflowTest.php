<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../scripts/ReleaseVersion.php';
require_once __DIR__ . '/../scripts/PackagistReleaseCheck.php';

final class ReleaseWorkflowTest extends TestCase
{
    public function testStrictSemVerAcceptsStablePrereleaseAndBuildMetadata(): void
    {
        foreach (['1.2.3', '1.2.3-rc.1', '0.0.0-alpha+build.01'] as $version) {
            self::assertSame($version, self::render(\ReleaseVersion::parse($version)));
        }
    }

    public function testStrictSemVerRejectsLeadingZeroAndMalformedIdentifiers(): void
    {
        foreach ([
            '01.2.3', '1.02.3', '1.2.03', 'v1.2.3', '1.2.3-', '1.2.3+',
            '1.2.3-01', '1.2.3-a..b', '1.2.3-a_b', '1.2.3+meta..x',
        ] as $version) {
            try {
                \ReleaseVersion::parse($version);
                self::fail("Invalid SemVer accepted: $version");
            } catch (InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testSemVerPrecedenceOrdersNumericAndTextPrereleaseIdentifiers(): void
    {
        $ordered = [
            '1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta',
            '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0',
        ];
        for ($index = 1; $index < count($ordered); $index++) {
            self::assertLessThan(0, \ReleaseVersion::compare($ordered[$index - 1], $ordered[$index]));
        }
        self::assertSame(0, \ReleaseVersion::compare('1.2.3+one', '1.2.3+two'));
    }

    public function testVersionMustAdvanceAndExistingTagCanBeResumed(): void
    {
        self::assertSame('1.2.4', \ReleaseVersion::validateInput('1.2.4', ['v1.2.3']));
        self::assertSame('1.2.3-rc.2', \ReleaseVersion::validateInput('1.2.3-rc.2', ['v1.2.3-rc.1']));
        self::assertSame('1.2.3', \ReleaseVersion::validateInput('1.2.3', ['v1.2.3'], true));

        foreach ([['1.2.2', ['v1.2.3']], ['1.2.3', ['v1.2.3']]] as [$version, $tags]) {
            try {
                \ReleaseVersion::validateInput($version, $tags);
                self::fail('Version regression or duplicate must be rejected.');
            } catch (InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testReleaseStateSupportsCreateResumeAndIdempotentDraftOrPublishedRelease(): void
    {
        $sha = str_repeat('a', 40);
        self::assertSame('create-tag', \ReleaseVersion::releaseAction('v1.2.3', $sha, null, null));
        self::assertSame('resume-release', \ReleaseVersion::releaseAction('v1.2.3', $sha, $sha, null));
        self::assertSame('draft-exists', \ReleaseVersion::releaseAction('v1.2.3', $sha, $sha, [
            'tag_name' => 'v1.2.3', 'draft' => true, 'prerelease' => false, 'target_commitish' => $sha,
        ]));
        self::assertSame('published-exists', \ReleaseVersion::releaseAction('v1.2.3', $sha, $sha, [
            'tag_name' => 'v1.2.3', 'draft' => false, 'prerelease' => false, 'target_commitish' => $sha,
        ]));
    }

    public function testReleaseStateRejectsShaTagAndPrereleaseMismatches(): void
    {
        $sha = str_repeat('a', 40);
        $badStates = [
            static fn () => \ReleaseVersion::releaseAction('v1.2.3', $sha, str_repeat('b', 40), null),
            static fn () => \ReleaseVersion::releaseAction('v1.2.3', $sha, null, [
                'tag_name' => 'v1.2.3', 'draft' => false, 'prerelease' => false,
            ]),
            static fn () => \ReleaseVersion::releaseAction('v1.2.3', $sha, $sha, [
                'tag_name' => 'v1.2.2', 'draft' => false, 'prerelease' => false,
            ]),
            static fn () => \ReleaseVersion::releaseAction('v1.2.3-rc.1', $sha, $sha, [
                'tag_name' => 'v1.2.3-rc.1', 'draft' => true, 'prerelease' => false,
            ]),
            static fn () => \ReleaseVersion::releaseAction('v1.2.3', $sha, $sha, [
                'tag_name' => 'v1.2.3', 'draft' => true, 'prerelease' => false, 'target_commitish' => str_repeat('b', 40),
            ]),
        ];
        foreach ($badStates as $badState) {
            try {
                $badState();
                self::fail('Inconsistent GitHub state must be rejected.');
            } catch (InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testCiGateRejectsFailedCancelledSkippedAndMissingJobs(): void
    {
        self::assertTrue(\ReleaseVersion::ciGatePassed([
            'composer' => 'success', 'tests' => 'success', 'quality' => 'success', 'security' => 'success',
        ]));
        foreach (['failure', 'cancelled', 'skipped', null] as $result) {
            self::assertFalse(\ReleaseVersion::ciGatePassed([
                'composer' => 'success', 'tests' => $result, 'quality' => 'success', 'security' => 'success',
            ]));
        }
        self::assertFalse(\ReleaseVersion::ciGatePassed(['composer' => 'success']));
    }

    public function testPackagistMustResolveVersionToTheReleaseCommit(): void
    {
        $sha = str_repeat('a', 40);
        $metadata = json_encode(['packages' => ['pohoc/crypto-sm' => [[
            'version' => 'v1.2.3', 'dist' => ['reference' => $sha],
        ]]]], JSON_THROW_ON_ERROR);

        self::assertTrue(\PackagistReleaseCheck::matches($metadata, 'v1.2.3', $sha));
        self::assertFalse(\PackagistReleaseCheck::matches($metadata, 'v1.2.4', $sha));
        self::assertFalse(\PackagistReleaseCheck::matches(
            json_encode(['packages' => ['pohoc/crypto-sm' => [[
                'version' => 'v1.2.3', 'dist' => ['reference' => str_repeat('b', 40)],
            ]]]], JSON_THROW_ON_ERROR),
            'v1.2.3',
            $sha
        ));
    }

    /** @param array{major:string,minor:string,patch:string,prerelease:list<string>,build:list<string>} $version */
    private static function render(array $version): string
    {
        return $version['major'] . '.' . $version['minor'] . '.' . $version['patch']
            . ($version['prerelease'] === [] ? '' : '-' . implode('.', $version['prerelease']))
            . ($version['build'] === [] ? '' : '+' . implode('.', $version['build']));
    }
}
