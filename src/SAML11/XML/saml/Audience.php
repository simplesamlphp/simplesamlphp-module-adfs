<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML11\XML\saml;

use SimpleSAML\XML\StringElementTrait;

/**
 * SAML Audience element.
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */

final class Audience extends AbstractSamlElement
{
    use StringElementTrait;


    /**
     * Initialize a saml:Action from scratch
     *
     * @param string $value
     */
    public function __construct(
        protected string $value
    ) {
        $this->setContent($value);
    }
}
