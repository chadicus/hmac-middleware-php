<?php

namespace Chadicus\Hmac;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Interface for validating token data.
 */
interface TokenValidatorInterface
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
     * @throws AuthenticationException Thrown if the token cannot be validated or is missing data.
     */
    public function validate(string $privateKey, Token $token, ServerRequestInterface $request) : bool;
}
