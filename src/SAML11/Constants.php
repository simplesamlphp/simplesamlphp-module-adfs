<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML11;

/**
 * Various SAML 1.1 constants.
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */
class Constants extends \SimpleSAML\XMLSecurity\Constants
{
    /**
     * The namespace for the SAML 1.1 assertions.
     */
    public const NS_SAML = 'urn:oasis:names:tc:SAML:1.0:assertion';

    /**
     * The namespace for the SAML 1.1 protocol.
     */
    public const NS_SAMLP = 'urn:oasis:names:tc:SAML:1.0:protocol';
}
