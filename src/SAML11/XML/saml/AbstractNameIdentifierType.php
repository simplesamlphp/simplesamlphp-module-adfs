<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML11\XML\saml;

use DOMElement;
use SimpleSAML\Assert\Assert;
use SimpleSAML\XML\StringElementTrait;

/**
 * SAML NameIdentifierType abstract data type.
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */

abstract class AbstractNameIdentifierType extends AbstractSamlElement
{
    use StringElementTrait;


    /**
     * Initialize a saml:NameIdentifierType from scratch
     *
     * @param string $value
     * @param string|null $Format
     * @param string|null $NameQualifier
     */
    public function __construct(
        string $value,
        protected ?string $NameQualifier = null,
        protected ?string $Format = null,
    ) {
        Assert::nullOrNotWhitespaceOnly($NameQualifier);
        Assert::nullOrValidURI($Format); // Covers the empty string

        $this->setContent($value);
    }


    /**
     * Collect the value of the Format-property
     *
     * @return string|null
     */
    public function getFormat(): ?string
    {
        return $this->Format;
    }


    /**
     * Collect the value of the NameQualifier-property
     *
     * @return string|null
     */
    public function getNameQualifier(): ?string
    {
        return $this->NameQualifier;
    }


    /**
     * Convert XML into an NameIdentifier
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

        $NameQualifier = self::getOptionalAttribute($xml, 'NameQualifier', null);
        $Format = self::getOptionalAttribute($xml, 'Format', null);

        return new static($xml->textContent, $NameQualifier, $Format);
    }


    /**
     * Convert this NameIdentifierType to XML.
     *
     * @param \DOMElement $parent The element we are converting to XML.
     * @return \DOMElement The XML element after adding the data corresponding to this NameIdentifierType.
     */
    public function toXML(DOMElement $parent = null): DOMElement
    {
        $e = $this->instantiateParentElement($parent);
        $e->textContent = $this->getContent();

        if ($this->getNameQualifier() !== null) {
            $e->setAttribute('NameQualifier', $this->getNameQualifier());
        }

        if ($this->getFormat() !== null) {
            $e->setAttribute('Format', $this->getFormat());
        }

        return $e;
    }
}
