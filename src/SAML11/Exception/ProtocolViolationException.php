<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML11\Exception;

use RuntimeException;

/**
 * This exception may be raised when a violation of the SAML 1.1 specification is detected
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */
class ProtocolViolationException extends RuntimeException
{
    /**
     * @param string $message
     */
    public function __construct(string $message = null)
    {
        if ($message === null) {
            if (defined('static::DEFAULT_MESSAGE')) {
                $message = static::DEFAULT_MESSAGE;
            } else {
                $message = 'A violation of the SAML 1.1 protocol occurred.';
            }
        }

        parent::__construct($message);
    }
}
