<?php

namespace Chadicus\Psr\Http\ServerMiddleware\Hmac;

use Chadicus\Psr\Http\ServerMiddleware\AuthenticationException;
use Chadicus\Psr\Http\ServerMiddleware\Token;
use Chadicus\Psr\Http\ServerMiddleware\TokenValidatorInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Interface for validating token data.
 */
final class TokenValidator implements TokenValidatorInterface
{
    /**
     * Validates the given token against the private key and incoming request.
     *
     * @param string                 $privateKey The private API key.
     * @param Token                  $token      The token extracted from the request.
     * @param ServerRequestInterface $request    The incoming PSR-7 request.
     *
     * @return boolean
     *
     * @throws AuthenticationException 401 Thrown hash is not valid.
     */
    public function validate(string $privateKey, Token $token, ServerRequestInterface $request) : bool
    {
        $method = $request->getMethod();
        $uri = (string)$request->getUri();
        $base64 = base64_encode((string)$request->getBody());
        $data = "{$privateKey}{$method}{$uri}{$token->getTimeStamp()}{$token->getNonce()}{$base64}";

        if (hash('sha256', $data) !== $token->getSignature()) {
            throw new AuthenticationException(401, 'Invalid Hash');
        }

        return true;
    }
}
