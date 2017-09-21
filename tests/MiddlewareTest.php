<?php

namespace ChadicusTest\Psr\Http\ServerMiddleware;

use ArrayObject;
use Chadicus\Psr\Http\ServerMiddleware\AuthenticationException;
use Chadicus\Psr\Http\ServerMiddleware\Middleware;
use Chadicus\Psr\Http\ServerMiddleware\Token;
use Chadicus\Psr\Http\ServerMiddleware;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

/**
 * @coversDefaultClass \Chadicus\Psr\Http\ServerMiddleware\Middleware
 * @covers ::__construct
 */
final class MiddlewareTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Verify basic behavior of __invoke().
     *
     * @test
     * @covers ::__invoke
     *
     * @return void
     */
    public function invoke()
    {
        $privateKey = md5(microtime(true));
        $publicKey = md5(microtime());
        $nonce = rand();
        $time = time();
        $signature = md5("{$privateKey}{$nonce}{$time}{$publicKey}");

        $token = new Token($publicKey, $signature, $nonce, $time);

        $provider = $this->getMockBuilder('\\Chadicus\\Psr\\Http\\ServerMiddleware\\KeyProviderInterface')->getMock();
        $provider->method('findPrivateKey')->willReturn($privateKey);

        $extractor = $this->getMockBuilder('\\Chadicus\\Psr\\Http\\ServerMiddleware\\TokenExtractorInterface')->getMock();
        $extractor->method('extract')->willReturn($token);

        $validator = $this->getMockBuilder('\\Chadicus\\Psr\\Http\\ServerMiddleware\\TokenValidatorInterface')->getMock();
        $validator->method('validate')->willReturn(true);

        $container = new ArrayObject();

        $middleware = new Middleware($provider, $extractor, $validator, $container);

        $headers = [
            'X-Hmac-Auth' => ["{$publicKey}:{$signature}:{$nonce}:{$time}"],
        ];

        $next = function ($request, $response) {
            return $response;
        };

        $psr7Request = new ServerRequest([], [], 'http://localhost', 'GET', 'php://input', $headers);

        $middleware($psr7Request, new Response(), $next);

        $this->assertSame($privateKey, $container['privateKey']);
    }

    /**
     * Verify behavior of __invoke() when AuthenticationException is thrown.
     *
     * @test
     * @covers ::__invoke
     *
     * @return void
     *
     * @throws \Exception Thrown if the $next callable passed to the middleware is called.
     */
    public function invokeExceptionThrown()
    {
        $privateKey = md5(microtime(true));
        $publicKey = md5(microtime());
        $nonce = rand();
        $time = time();
        $signature = md5("{$privateKey}{$nonce}{$time}{$publicKey}");

        $token = new Token($publicKey, $signature, $nonce, $time);

        $provider = $this->getMockBuilder('\\Chadicus\\Psr\\Http\\ServerMiddleware\\KeyProviderInterface')->getMock();
        $provider->method('findPrivateKey')->willReturn($privateKey);

        $extractor = $this->getMockBuilder('\\Chadicus\\Psr\\Http\\ServerMiddleware\\TokenExtractorInterface')->getMock();
        $extractor->method('extract')->willReturn($token);

        $exception = new AuthenticationException(400, 'Bad Request');

        $validator = $this->getMockBuilder('\\Chadicus\\Psr\\Http\\ServerMiddleware\\TokenValidatorInterface')->getMock();
        $validator->method('validate')->will($this->throwException($exception));

        $container = new ArrayObject();

        $middleware = new Middleware($provider, $extractor, $validator, $container);

        $headers = [
            'X-Hmac-Auth' => ["{$publicKey}:{$signature}:{$nonce}:{$time}"],
        ];

        $next = function ($request, $response) {
            throw new \Exception('This should not have been called!!');
        };

        $psr7Request = new ServerRequest([], [], 'http://localhost', 'GET', 'php://input', $headers);

        $response = $middleware($psr7Request, new Response(), $next);

        $this->assertFalse(isset($container['privateKey']));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('Bad Request', $response->getReasonPhrase());
    }
}
