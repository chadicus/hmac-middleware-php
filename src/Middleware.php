<?php

namespace Chadicus\Hmac;

use ArrayAccess;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * PSR-7 Middleware for extracting and validating request via hmac cryptography.
 */
final class Middleware
{
    /**
     * Obtains private keys.
     *
     * @var KeyProviderInterface
     */
    private $keyProvider;

    /**
     * Extracts the token information from the incoming request.
     *
     * @var TokenExtractorInterface
     */
    private $tokenExtractor;

    /**
     * Validates the extracted token.
     *
     * @var TokenValidatorInterface
     */
    private $tokenValidator;

    /**
     * Container in which to store the private key.
     *
     * @var ArrayAccess
     */
    private $container;

    /**
     * Construct a new instance of this middleware.
     *
     * @param KeyProviderInterface    $provider  Obtains private keys.
     * @param TokenExtractorInterface $extractor Extracts the token information from the incoming request.
     * @param TokenValidatorInterface $validator Validates the extracted token.
     * @param ArrayAccess             $container Container in which to store the private key.
     */
    public function __construct(
        KeyProviderInterface $provider,
        TokenExtractorInterface $extractor,
        TokenValidatorInterface $validator,
        ArrayAccess $container
    ) {
        $this->keyProvider = $provider;
        $this->tokenExtractor = $extractor;
        $this->tokenValidator = $validator;
        $this->tokenContainer = $container;
    }

    /**
     * Execute this middleware.
     *
     * @param  ServerRequestInterface $request  The incoming PSR7 request.
     * @param  ResponseInterface      $response The outgoing PSR7 response.
     * @param  callable               $next     The next middleware.
     *
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, callable $next)
    {
        try {
            $token = $this->tokenExtractor->extract($request);
            $privateKey = $this->keyProvider->findPrivateKey($token->getPublicKey());
            $this->tokenValidator->validate($privateKey, $token, $request);

            //Authenticated! Set the private key and call the next middleware
            $this->tokenContainer['privateKey'] = $privateKey;

            return $next($request, $response);
        } catch (AuthenticationException $e) {
            return $response->withStatus($e->getStatusCode(), $e->getReasonPhrase());
        }
    }
}
