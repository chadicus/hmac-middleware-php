<?php

namespace ChadicusTest\Hmac;

use Chadicus\Hmac\AuthenticationException;

/**
 * @coversDefaultClass \Chadicus\Hmac\AuthenticationException
 * @covers ::__construct
 */
final class AuthenticationExceptionTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Verify basic behavior of getStatusCode().
     *
     * @test
     * @covers ::getStatusCode
     *
     * @return void
     */
    public function getStatusCode()
    {
        $exception = new AuthenticationException(200, 'A Reason');
        $this->assertSame(200, $exception->getStatusCode());
    }

    /**
     * Verify basic behavior of getReasonPhrase().
     *
     * @test
     * @covers ::getReasonPhrase
     *
     * @return void
     */
    public function getReasonPhrase()
    {
        $exception = new AuthenticationException(200, 'A Reason');
        $this->assertSame('A Reason', $exception->getReasonPhrase());
    }
}
