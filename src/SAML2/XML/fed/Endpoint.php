<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML2\XML\fed;

use DOMElement;
use SimpleSAML\WSSecurity\XML\wsa\Address;
use SimpleSAML\WSSecurity\XML\wsa\EndpointReference;

/**
 * Class representing fed Endpoint.
 *
 * @package SimpleSAMLphp
 */

class Endpoint
{
    /**
     * Add this endpoint to an XML element.
     *
     * @param \DOMElement $parent  The element we should append this endpoint to.
     * @param string $name  The name of the element we should create.
     * @param string $address
     * @return \DOMElement
     */
    public static function appendXML(DOMElement $parent, string $name, string $address): DOMElement
    {
        $e = $parent->ownerDocument->createElement($name);
        $parent->appendChild($e);

        $endpoint = new EndpointReference(new Address($address));
        $endpoint->toXML($parent);

        return $e;
    }
}
