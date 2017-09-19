<?php

namespace Chadicus\Hmac;

/**
 * Exception to throw when authentication fails.
 */
class AuthenticationException extends \Exception
{
    /**
     * The 3-digit integer result code to set.
     *
     * @var integer
     */
    private $statusCode;

    /**
     * The reason phrase to use with the provided status code.
     *
     * @var string
     */
    private $reasonPhrase;

    /**
     * Construct a new instance of this exception.
     *
     * @param integer $statusCode   The 3-digit integer result code to set.
     * @param string  $reasonPhrase The reason phrase to use with the provided status code.
     */
    public function __construct($statusCode, $reasonPhrase)
    {
        parent::__construct();
        $this->statusCode = $statusCode;
        $this->reasonPhrase = $reasonPhrase;
    }

    /**
     * Gets the response status code.
     *
     * The status code is a 3-digit integer result code of the server's attempt
     * to understand and satisfy the request.
     *
     * @return integer Status code.
     */
    public function getStatusCode() : int
    {
        return $this->statusCode;
    }

    /**
     * Gets the response reason phrase associated with the status code.
     *
     * @return string Reason phrase
     */
    public function getReasonPhrase() : string
    {
        return $this->reasonPhrase;
    }
}
