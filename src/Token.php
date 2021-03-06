<?php

namespace Chadicus\Psr\Http\ServerMiddleware;

/**
 * Immutable hmac authentication token.
 */
final class Token
{
    /**
     * The public api key.
     *
     * @var string
     */
    private $publicKey;

    /**
     * A unique hash for the request.
     *
     * @var string
     */
    private $signature;

    /**
     * An arbitrary string used only once.
     *
     * @var string
     */
    private $nonce;

    /**
     * The request timestamp.
     *
     * @var integer
     */
    private $timestamp;

    /**
     * Construct a new Token instance
     *
     * @param string  $publicKey The public api key.
     * @param string  $signature A unique hash for the request.
     * @param string  $nonce     An arbitrary string used only once.
     * @param integer $timestamp The request timestamp.
     *
     * @throws \InvalidArgumentException Thrown if any parameters are invalid.
     */
    public function __construct(string $publicKey, string $signature, string $nonce, int $timestamp)
    {
        $this->publicKey = $publicKey;
        $this->signature = $signature;
        $this->nonce = $nonce;
        $this->timestamp = $timestamp;
    }

    /**
     * The public api key found in the request.
     *
     * @return string
     */
    public function getPublicKey() : string
    {
        return $this->publicKey;
    }

    /**
     * Returns the signature of the request.
     *
     * @return string
     */
    public function getSignature() : string
    {
        return $this->signature;
    }

    /**
     * Returns the nonce value found in the request.
     *
     * @return string
     */
    public function getNonce() : string
    {
        return $this->nonce;
    }

    /**
     * Returns the timestamp of the request.
     *
     * @return integer
     */
    public function getTimestamp() : int
    {
        return $this->timestamp;
    }
}
