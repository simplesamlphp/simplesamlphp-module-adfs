<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML11\XML\saml;

use SimpleSAML\Module\adfs\SAML11\Constants as C;
use SimpleSAML\XML\AbstractElement;

/**
 * Abstract class to be implemented by all the classes in this namespace
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */
abstract class AbstractSamlElement extends AbstractElement
{
    /** @var string */
    public const NS = C::NS_SAML;

    /** @var string */
    public const NS_PREFIX = 'saml';
}
