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
     * Password authentication context.
     */
    public const AC_PASSWORD = 'urn:oasis:names:tc:SAML:1.0:am:password';

    /**
     * Kerberos authentication context.
     */
    public const AC_KERBEROS = 'urn:ietf:rfc:1510';

    /**
     * Secure Remote Password authentication context.
     */
    public const AC_SECURE_REMOTE_PASSWORD = 'urn:ietf:rfc:2945';

    /**
     * Hardware token authentication context.
     */
    public const AC_HARDWARE_TOKEN = 'urn:oasis:names:tc:SAML:1.0:am:HardwareToken';

    /**
     * Certificate based client authentication authentication context.
     */
    public const AC_CERT_BASE_CLIENT_AUTHN = 'urn:ietf:rfc:2246';

    /**
     * X.509 Public key authentication context.
     */
    public const AC_X509_PUBLIC_KEY = 'urn:oasis:names:tc:SAML:1.0:am:X509-PKI';

    /**
     * PGP Public key authentication context.
     */
    public const AC_PGP_PUBLIC_KEY = 'urn:oasis:names:tc:SAML:1.0:am:PGP';

    /**
     * SPKI Public key authentication context.
     */
    public const AC_SPKI_PUBLIC_KEY = 'urn:oasis:names:tc:SAML:1.0:am:SPKI';

    /**
     * XKMS Public key authentication context.
     */
    public const AC_XMLS_PUBLIC_KEY = 'urn:oasis:names:tc:SAML:1.0:am:XKMS';

    /**
     * XML Digital Signature authentication context.
     */
    public const AC_XML_DSIG = 'urn:ietf:rfc:3075';

    /**
     * Unspecified authentication context.
     */
    public const AC_UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.0:am:unspecified';

    /**
     * The format to express a timestamp in SAML 1.1
     */
    public const DATETIME_FORMAT = 'Y-m-d\\TH:i:sp';

    /**
     * The namespace for the SAML 1.1 assertions.
     */
    public const NS_SAML = 'urn:oasis:names:tc:SAML:1.0:assertion';

    /**
     * The namespace for the SAML 1.1 protocol.
     */
    public const NS_SAMLP = 'urn:oasis:names:tc:SAML:1.0:protocol';
}
