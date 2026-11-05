<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Crypto\Asn1;
use CryptoSm\Exception\CryptoException;
use PHPUnit\Framework\TestCase;

final class Asn1SignatureEncodingTest extends TestCase
{
    public function testEncodedSm2SignatureRoundTripsValidScalars(): void
    {
        $r = str_pad('1', 64, '0', STR_PAD_LEFT);
        $s = str_pad('2', 64, '0', STR_PAD_LEFT);

        $der = Asn1::encodeDerSignature($r, $s);

        $this->assertSame([$r, $s], Asn1::decodeDerSignature($der));
    }

    public function testEncoderRejectsComponentsOutsideSm2SignatureRangeOrWidth(): void
    {
        $one = str_pad('1', 64, '0', STR_PAD_LEFT);
        $zero = str_repeat('0', 64);
        $order = 'fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123';
        $invalidPairs = [
            [$zero, $one],
            [$order, $one],
            [$one, $zero],
            [$one, $order],
            [str_repeat('f', 66), $one],
            [$one, str_repeat('g', 64)],
        ];

        foreach ($invalidPairs as [$r, $s]) {
            try {
                Asn1::encodeDerSignatureBinary($r, $s);
                $this->fail('SM2 signature DER encoder accepted an invalid component');
            } catch (CryptoException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testDerSignatureDecodersRejectComponentsOutsideSm2Range(): void
    {
        $one = str_pad('1', 64, '0', STR_PAD_LEFT);
        $order = 'fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123';
        $invalidPairs = [
            [str_repeat('0', 64), $one],
            [$order, $one],
            [$one, str_repeat('0', 64)],
            [$one, $order],
        ];

        foreach ($invalidPairs as [$r, $s]) {
            $der = Asn1::encodeSequence(Asn1::encodeInteger($r) . Asn1::encodeInteger($s));

            try {
                Asn1::decodeDerSignatureBinary($der);
                $this->fail('SM2 DER decoder accepted a component outside [1, n-1]');
            } catch (CryptoException) {
                $this->addToAssertionCount(1);
            }

            try {
                Asn1::decodeDerSignature(bin2hex($der));
                $this->fail('Hex SM2 DER decoder accepted a component outside [1, n-1]');
            } catch (CryptoException) {
                $this->addToAssertionCount(1);
            }
        }
    }
}
