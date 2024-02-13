<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML11\XML\saml;

use DOMElement;
use SimpleSAML\Assert\Assert;
use SimpleSAML\XML\Constants as C;
use SimpleSAML\XML\Exception\InvalidDOMElementException;

/**
 *  SAML AuthorityBindingType abstract data type.
 *
 * @package simplesaml/simplesamlphp-module-adfs
 */
abstract class AbstractAuthorityBindingType extends AbstractSamlElement
{
    /**
     * Initialize a saml:AuthorityBindingType from scratch
     *
     * @param string $AuthorityKind
     * @param string $Location
     * @param string $Binding
     */
    public function __construct(
        protected string $AuthorityKind,
        protected string $Location,
        protected string $Binding,
    ) {
        Assert::validQName($AuthorityKind);
        Assert::validURI($Location);
        Assert::validURI($Binding);
    }


    /**
     * Collect the value of the AuthorityKind-property
     *
     * @return string
     */
    public function getAuthorityKind(): string
    {
        return $this->AuthorityKind;
    }


    /**
     * Collect the value of the Location-property
     *
     * @return string
     */
    public function getLocation(): string
    {
        return $this->Location;
    }


    /**
     * Collect the value of the Binding-property
     *
     * @return string
     */
    public function getBinding(): string
    {
        return $this->Binding;
    }


    /**
     * Convert XML into an AuthorityBindingType
     *
     * @param \DOMElement $xml The XML element we should load
     * @return static
     *
     * @throws \SimpleSAML\XML\Exception\InvalidDOMElementException
     *   if the qualified name of the supplied element is wrong
     */
    public static function fromXML(DOMElement $xml): static
    {
        Assert::same($xml->localName, static::getLocalName(), InvalidDOMElementException::class);
        Assert::same($xml->namespaceURI, static::NS, InvalidDOMElementException::class);

        $AuthorityKind = self::getAttribute($xml, 'AuthorityKind');
        $Location = self::getAttribute($xml, 'Location');
        $Binding = self::getAttribute($xml, 'Binding');

        return new static($AuthorityKind, $Location, $Binding);
    }


    /**
     * Convert this AuthorityBindingType to XML.
     *
     * @param \DOMElement $parent The element we are converting to XML.
     * @return \DOMElement The XML element after adding the data corresponding to this AuthorityBindingType.
     */
    public function toXML(DOMElement $parent = null): DOMElement
    {
        $e = $this->instantiateParentElement($parent);

        $e->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:samlp', 'urn:oasis:names:tc:SAML:1.0:protocol');

        $e->setAttribute('AuthorityKind', $this->getAuthorityKind());
        $e->setAttribute('Location', $this->getLocation());
        $e->setAttribute('Binding', $this->getBinding());

        return $e;
    }
}
