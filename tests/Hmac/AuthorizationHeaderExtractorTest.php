<?php

namespace ChadicusTest\Psr\Http\ServerMiddleware\Hmac;

use Chadicus\Psr\Http\ServerMiddleware\AuthenticationException;
use Chadicus\Psr\Http\ServerMiddleware\Hmac\AuthorizationHeaderExtractor;
use PHPUnit\Framework\TestCase;
use Zend\Diactoros\ServerRequest;
use Zend\Diactoros\Stream;

/**
 * @coversDefaultClass \Chadicus\Psr\Http\ServerMiddleware\Hmac\AuthorizationHeaderExtractor
 * @covers ::__construct
 */
final class AuthorizationHeaderExtractorTest extends TestCase
{
    /**
     * @test
     * @covers ::extract
     *
     * @return void
     */
    public function extract()
    {
        $json = json_encode(['foo' => 'bar', 'abc' => '123']);
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $json);
        rewind($stream);

        $privateKey = md5(microtime(true));
        $uri = 'https://example.com/foos';
        $now = time();
        $nonce = (string)rand();
        $base64 = base64_encode($json);
        $data = "{$privateKey}POST{$uri}{$now}{$nonce}{$base64}";
        $signature = hash('sha256', $data);
        $publicKey = md5(microtime());

        $headers = ['Authorization' => "hmac {$publicKey}:{$signature}:{$nonce}:{$now}"];

        $request = new ServerRequest([], [], $uri, 'POST', $stream, $headers);

        $extractor = new AuthorizationHeaderExtractor();

        $token = $extractor->extract($request);

        $this->assertSame($publicKey, $token->getPublicKey());
        $this->assertSame($signature, $token->getSignature());
        $this->assertSame($nonce, $token->getNonce());
        $this->assertSame($now, $token->getTimestamp());
    }

    /**
     * @test
     * @covers ::extract
     *
     * @return void
     */
    public function extractInvalidHeader()
    {
        $headers = ['Authorization' => 'This isnt:exactly:right'];
        $request = new ServerRequest([], [], 'http://localhost', 'POST', 'php://input', $headers);

        $extractor = new AuthorizationHeaderExtractor();
        try {
            $extractor->extract($request);
            $this->fail('No exception thrown');
        } catch (AuthenticationException $e) {
            $this->assertSame(400, $e->getStatusCode());
            $this->assertSame('Bad Request', $e->getReasonPhrase());
        }
    }
}
