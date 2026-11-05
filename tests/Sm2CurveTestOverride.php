<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\SM2\Sm2;

/** Test-only access to alternate curves used by published SM2 conformance vectors. */
final class Sm2CurveTestOverride
{
    /** @var array<string, string>|null */
    private static ?array $original = null;

    /** @param array<string, string> $params */
    public static function use(array $params): void
    {
        $property = new \ReflectionProperty(Sm2::class, 'eccTable');
        $property->setAccessible(true);
        $original = $property->getValue();
        if (!is_array($original)) {
            throw new \LogicException('SM2 curve parameter table is unavailable');
        }
        foreach ($original as $name => $value) {
            if (!is_string($name) || !is_string($value)) {
                throw new \LogicException('SM2 curve parameter table has an invalid shape');
            }
        }
        self::$original ??= $original;
        $property->setValue(null, array_map('strtolower', $params));
        self::clearCaches();
    }

    public static function reset(): void
    {
        if (self::$original !== null) {
            $property = new \ReflectionProperty(Sm2::class, 'eccTable');
            $property->setAccessible(true);
            $property->setValue(null, self::$original);
            self::$original = null;
        }
        self::clearCaches();
    }

    private static function clearCaches(): void
    {
        foreach (['gmpCache', 'basePointTable', 'windowTableCache'] as $cacheName) {
            $property = new \ReflectionProperty(Sm2::class, $cacheName);
            $property->setAccessible(true);
            $property->setValue(null, null);
        }
    }
}
