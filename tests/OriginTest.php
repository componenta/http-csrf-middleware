<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Csrf\Tests;

use Componenta\Http\Middleware\Csrf\Origin;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class OriginTest extends TestCase
{
    #[DataProvider('serializedOriginNormalizations')]
    public function testSerializedOriginNormalizesHttpOrigin(string $input, string $expected): void
    {
        $origin = Origin::fromSerialized($input);

        self::assertNotNull($origin);
        self::assertFalse($origin->opaque);
        self::assertSame($expected, (string) $origin);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function serializedOriginNormalizations(): iterable
    {
        yield 'https default port' => ['HTTPS://Example.COM:443', 'https://example.com'];
        yield 'http default port' => ['HTTP://Example.COM:80', 'http://example.com'];
        yield 'https non-default port' => ['https://Example.COM:8443', 'https://example.com:8443'];
        yield 'http non-default port' => ['http://Example.COM:443', 'http://example.com:443'];
        yield 'https port 80 remains explicit' => ['https://Example.COM:80', 'https://example.com:80'];
    }

    public function testSerializedNullOriginIsExplicitlyOpaque(): void
    {
        $origin = Origin::fromSerialized('null');

        self::assertNotNull($origin);
        self::assertTrue($origin->opaque);
        self::assertSame('null', (string) $origin);
    }

    #[DataProvider('invalidSerializedOrigins')]
    public function testSerializedOriginRejectsNonOriginValues(string $value): void
    {
        self::assertNull(Origin::fromSerialized($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidSerializedOrigins(): iterable
    {
        yield 'empty' => [''];
        yield 'leading whitespace' => [' https://example.test'];
        yield 'trailing whitespace' => ['https://example.test '];
        yield 'path' => ['https://example.test/path'];
        yield 'query' => ['https://example.test?x=1'];
        yield 'fragment' => ['https://example.test#fragment'];
        yield 'userinfo' => ['https://user@example.test'];
        yield 'userinfo password' => ['https://user:pass@example.test'];
        yield 'unsupported scheme' => ['file://example.test'];
        yield 'missing host' => ['https://'];
        yield 'host whitespace' => ['https://exa mple.test'];
        yield 'zero port' => ['https://example.test:0'];
    }

    #[DataProvider('refererUris')]
    public function testUriOriginAcceptsResourceUriAndExtractsOnlyOrigin(string $uri, string $expected): void
    {
        $origin = Origin::fromUri($uri);

        self::assertNotNull($origin);
        self::assertFalse($origin->opaque);
        self::assertSame($expected, (string) $origin);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function refererUris(): iterable
    {
        yield 'path and query' => [
            'https://Example.TEST:443/forms/edit?id=1#section',
            'https://example.test',
        ];
        yield 'non-default port' => [
            'https://Example.TEST:8443/forms/edit',
            'https://example.test:8443',
        ];
    }

    #[DataProvider('invalidRefererUris')]
    public function testUriOriginRejectsUntrustedAuthority(string $uri): void
    {
        self::assertNull(Origin::fromUri($uri));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidRefererUris(): iterable
    {
        yield 'userinfo' => ['https://user@example.test/path'];
        yield 'unsupported scheme' => ['file://example.test/path'];
        yield 'missing host' => ['/local/path'];
        yield 'zero port' => ['https://example.test:0/path'];
    }

    public function testRequestOriginUsesNormalizedPsrUriAuthority(): void
    {
        $request = new ServerRequest('POST', 'HTTPS://Example.TEST:443/change');

        $origin = Origin::fromRequest($request);

        self::assertNotNull($origin);
        self::assertSame('https://example.test', (string) $origin);
    }

    public function testRelativeRequestUriHasNoTrustworthyOrigin(): void
    {
        self::assertNull(Origin::fromRequest(new ServerRequest('POST', '/change')));
    }

    public function testOriginEqualityIncludesSchemeHostAndEffectivePort(): void
    {
        $origin = Origin::fromSerialized('https://example.test');
        $same = Origin::fromSerialized('HTTPS://EXAMPLE.TEST:443');
        $otherScheme = Origin::fromSerialized('http://example.test');
        $otherPort = Origin::fromSerialized('https://example.test:8443');

        self::assertNotNull($origin);
        self::assertNotNull($same);
        self::assertNotNull($otherScheme);
        self::assertNotNull($otherPort);
        self::assertTrue($origin->equals($same));
        self::assertFalse($origin->equals($otherScheme));
        self::assertFalse($origin->equals($otherPort));
    }
}
