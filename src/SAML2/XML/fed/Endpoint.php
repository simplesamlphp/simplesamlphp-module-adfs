<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML2\XML\fed;

use DOMElement;

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

        $endpoint = $parent->ownerDocument->createElementNS(Constants::NS_FED, 'fed:EndpointReference');
        $e->appendChild($endpoint);

        $address = $parent->ownerDocument->createElementNS('http://www.w3.org/2005/08/addressing', 'wsa:Address', $address);
        $endpoint->appendChild($address);

        return $e;
    }
}
