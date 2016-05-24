<?php

namespace ChadicusTest\Hmac;

use Chadicus\Hmac\Token;

/**
 * @coversDefaultClass \Chadicus\Hmac\Token
 * @covers ::__construct
 */
final class TokenTest extends \PHPUnit_Framework_TestCase
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
}
