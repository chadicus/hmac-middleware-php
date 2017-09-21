<?php

namespace Chadicus\Psr\Http\ServerMiddleware\Hmac;

use Chadicus\Psr\Http\ServerMiddleware\AuthenticationException;
use Chadicus\Psr\Http\ServerMiddleware\Token;
use Chadicus\Psr\Http\ServerMiddleware\TokenExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Token extractor to obtain a token from an authorization header.
 */
final class AuthorizationHeaderExtractor implements TokenExtractorInterface
{
    /**
     * A custom scheme expected in the Authorization header.
     *
     * @var string
     */
    private $scheme;

    /**
     * Construct a new instance of this extractor
     *
     * @param string $scheme A custom scheme expected in the Authorization header.
     */
    public function __construct(string $scheme = 'hmac')
    {
        $this->scheme = 'hmac';
    }

    /**
     * Extracts the HMAC authentication Token from the given PSR-7 $request.
     *
     * @param ServerRequestInterface $request The request containing the HMAC token data.
     *
     * @return Token
     *
     * @throws AuthenticationException 400 Thrown if any required data is missing.
     */
    public function extract(ServerRequestInterface $request) : Token
    {
        $authorizationHeader = $request->getHeaderLine('Authorization');

        //Authorization: schema PublicKey:Signature:Nonce:Timestamp

        $pattern = "^{$this->scheme}\s(?P<publicKey>[a-zA-z0-9]*):(?P<signature>[a-zA-Z0-9]*):"
                 . '(?P<nonce>[a-zA-Z0-9]*):(?P<timestamp>[0-9]*)$';
        $matches = [];
        $matched = preg_match("/{$pattern}/", $authorizationHeader, $matches);
        if (!$matched) {
            throw new AuthenticationException(400, 'Bad Request');
        }

        return new Token($matches['publicKey'], $matches['signature'], $matches['nonce'], $matches['timestamp']);
    }
}
