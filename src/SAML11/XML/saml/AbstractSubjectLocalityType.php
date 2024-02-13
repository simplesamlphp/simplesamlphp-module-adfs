<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML11\XML\saml;

use DOMElement;
use SimpleSAML\Assert\Assert;
use SimpleSAML\XML\Exception\InvalidDOMElementException;

/**
 *  SAML SubjectLocalityType abstract data type.
 *
 * @package simplesaml/simplesamlphp-module-adfs
 */
abstract class AbstractSubjectLocalityType extends AbstractSamlElement
{
    /**
     * Initialize a saml:SubjectLocalityType from scratch
     *
     * @param string|null $IPAddress
     * @param string|null $DNSAddress
     */
    public function __construct(
        protected ?string $IPAddress = null,
        protected ?string $DNSAddress = null,
    ) {
        Assert::nullOrNotWhitespaceOnly($IPAddress);
        Assert::nullOrNotWhitespaceOnly($DNSAddress);
    }


    /**
     * Collect the value of the IPAddress-property
     *
     * @return string|null
     */
    public function getIPAddress(): ?string
    {
        return $this->IPAddress;
    }


    /**
     * Collect the value of the DNSAddress-property
     *
     * @return string|null
     */
    public function getDNSAddress(): string|null
    {
        return $this->DNSAddress;
    }


    /**
     * Test if an object, at the state it's in, would produce an empty XML-element
     *
     * @return bool
     */
    public function isEmptyElement(): bool
    {
        return empty($this->getIPAddress())
            && empty($this->getDNSAddress());
    }


    /**
     * Convert XML into an SubjectLocalityType
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

        $IPAddress = self::getOptionalAttribute($xml, 'IPAddress');
        $DNSAddress = self::getOptionalAttribute($xml, 'DNSAddress');

        return new static($IPAddress, $DNSAddress);
    }


    /**
     * Convert this SubjectLocalityType to XML.
     *
     * @param \DOMElement $parent The element we are converting to XML.
     * @return \DOMElement The XML element after adding the data corresponding to this SubjectLocalityType.
     */
    public function toXML(DOMElement $parent = null): DOMElement
    {
        $e = $this->instantiateParentElement($parent);

        if ($this->getIPAddress() !== null) {
            $e->setAttribute('IPAddress', $this->getIPAddress());
        }

        if ($this->getDNSAddress() !== null) {
            $e->setAttribute('DNSAddress', $this->getDNSAddress());
        }

        return $e;
    }
}
