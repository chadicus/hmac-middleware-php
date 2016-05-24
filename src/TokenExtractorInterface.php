<?php

namespace Chadicus\Hmac;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Interface for extracting token data from an incoming PSR-7 request.
 */
interface TokenExtractorInterface
{
    /**
     * Retrieves a token object from the given incoming PSR-7 request.
     *
     * @param ServerRequestInterface $request The incoming PSR-7 request.
     *
     * @return Token
     *
     * @throws AuthenticationException Thrown if the token cannot be extracted or is missing data.
     */
    public function extract(ServerRequestInterface $request);
}
