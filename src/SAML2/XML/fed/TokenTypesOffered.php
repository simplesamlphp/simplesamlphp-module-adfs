<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML2\XML\fed;

use DOMElement;
use SimpleSAML\WSSecurity\Constants as C;

/**
 * Class representing fed TokenTypesOffered.
 *
 * @package SimpleSAMLphp
 */
class TokenTypesOffered
{
    /**
     * Add tokentypesoffered to an XML element.
     *
     * @param \DOMElement $parent  The element we should append this endpoint to.
     * @return \DOMElement
     */
    public static function appendXML(DOMElement $parent): DOMElement
    {
        $e = $parent->ownerDocument->createElementNS(C::NS_FED, 'fed:TokenTypesOffered');
        $parent->appendChild($e);

        $tokentype = $parent->ownerDocument->createElementNS(C::NS_FED, 'fed:TokenType');
        $tokentype->setAttribute('Uri', 'urn:oasis:names:tc:SAML:1.0:assertion');
        $e->appendChild($tokentype);

        return $e;
    }
}
