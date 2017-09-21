<?php

namespace ChadicusTest\Psr\Http\ServerMiddleware;

use Chadicus\Psr\Http\ServerMiddleware\Token;

/**
 * @coversDefaultClass \Chadicus\Psr\Http\ServerMiddleware\Token
 * @covers ::__construct
 */
final class TokenTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Verify basic behavior of getPublicKey().
     *
     * @test
     * @covers ::getPublicKey
     *
     * @return void
     */
    public function getPublicKey()
    {
        $token = new Token('a public key', 'not under test', 'not under test', time());
        $this->assertSame('a public key', $token->getPublicKey());
    }

    /**
     * Verify basic behavior of getSignature().
     *
     * @test
     * @covers ::getSignature
     *
     * @return void
     */
    public function getSignature()
    {
        $token = new Token('not under test', 'a signature', 'not under test', time());
        $this->assertSame('a signature', $token->getSignature());
    }

    /**
     * Verify basic behavior of getNonce().
     *
     * @test
     * @covers ::getNonce
     *
     * @return void
     */
    public function getNonce()
    {
        $token = new Token('not under test', 'not under test', '12345', time());
        $this->assertSame('12345', $token->getNonce());
    }

    /**
     * Verify basic behavior of getTimestamp().
     *
     * @test
     * @covers ::getTimestamp
     *
     * @return void
     */
    public function getTimestamp()
    {
        $time = 1464053940;
        $token = new Token('not under test', 'not under test', 'not under test', $time);
        $this->assertSame(1464053940, $token->getTimestamp());
    }
}
