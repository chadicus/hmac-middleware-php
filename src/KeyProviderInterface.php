<?php

namespace Chadicus\Hmac;

/**
 * Interface for private key repositories.
 */
interface KeyProviderInterface
{
    /**
     * Returns the private key associated with the given public key.
     *
     * @param string $publicKey The public API key.
     *
     * @return string|null The private API key or null if none found.
     */
    public function findPrivateKey($publicKey);
}
