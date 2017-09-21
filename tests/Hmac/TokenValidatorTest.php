<?php

namespace ChadicusTest\Psr\Http\ServerMiddleware\Hmac;

use Chadicus\Psr\Http\ServerMiddleware\AuthenticationException;
use Chadicus\Psr\Http\ServerMiddleware\Token;
use Chadicus\Psr\Http\ServerMiddleware\Hmac\TokenValidator;
use PHPUnit\Framework\TestCase;
use Zend\Diactoros\ServerRequest;
use Zend\Diactoros\Stream;

/**
 * @coversDefaultClass \Chadicus\Psr\Http\ServerMiddleware\Hmac\TokenValidator
 */
final class TokenValidatorTest extends TestCase
{
    /**
     * @test
     * @covers ::validate
     *
     * @return void
     */
    public function validate()
    {
        $json = json_encode(['foo' => 'bar', 'abc' => '123']);
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $json);
        rewind($stream);

        $privateKey = md5(microtime(true));
        $uri = 'https://example.com/foos';
        $now = time();
        $nonce = rand();
        $base64 = base64_encode($json);
        $data = "{$privateKey}POST{$uri}{$now}{$nonce}{$base64}";
        $signature = hash('sha256', $data);
        $publicKey = md5(microtime());
        $token = new Token($publicKey, $signature, $nonce, $now);

        $request = new ServerRequest([], [], $uri, 'POST', $stream);

        $validator = new TokenValidator();
        $this->assertTrue($validator->validate($privateKey, $token, $request));
    }

    /**
     * @test
     * @covers ::validate
     *
     * @return void
     */
    public function validateFails()
    {
        $json = json_encode(['foo' => 'bar', 'abc' => '123']);
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $json);
        rewind($stream);

        $privateKey = md5(microtime(true));
        $uri = 'https://example.com/foos';
        $now = time();
        $nonce = rand();
        $base64 = base64_encode($json);
        //encode data with GET method not expected POST
        $data = "{$privateKey}GET{$uri}{$now}{$nonce}{$base64}";
        $signature = hash('sha256', $data);
        $publicKey = md5(microtime());
        $token = new Token($publicKey, $signature, $nonce, $now);

        $request = new ServerRequest([], [], $uri, 'POST', $stream);

        $validator = new TokenValidator();
        try {
            $validator->validate($privateKey, $token, $request);
            $this->fail('No exception thrown');
        } catch (AuthenticationException $e) {
            $this->assertSame(401, $e->getStatusCode());
            $this->assertSame('Invalid Hash', $e->getReasonPhrase());
        }
    }
}
