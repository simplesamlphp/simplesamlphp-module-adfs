<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML11\XML\saml;

use DOMElement;
use SimpleSAML\Assert\Assert;
use SimpleSAML\XML\Exception\InvalidDOMElementException;
use SimpleSAML\XML\Exception\SchemaViolationException;

/**
 * SAML AttributeType abstract data type.
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */

abstract class AbstractAttributeType extends AbstractSamlElement
{
    use AttributeDesignatorTypeTrait;


    /**
     * Initialize a saml:AttributeType from scratch
     *
     * @param string $AttributeName
     * @param string $AttributeNamespace
     * @param array<\SimpleSAML\Module\adfs\SAML11\XML\saml\AttributeValue> $attributeValue
     */
    public function __construct(
        protected string $AttributeName,
        protected string $AttributeNamespace,
        protected array $attributeValue,
    ) {
        Assert::nullOrNotWhitespaceOnly($AttributeName, SchemaViolationException::class);
        Assert::nullOrValidURI($AttributeNamespace, SchemaViolationException::class); // Covers the empty string
        Assert::allIsInstanceOf($attributeValue, AttributeValue::class, SchemaViolationException::class);
    }


    /**
     * Collect the value of the attributeValue-property
     *
     * @return array<\SimpleSAML\Module\adfs\SAML11\XML\saml\AttributeValue>
     */
    public function getAttributeValue(): array
    {
        return $this->attributeValue;
    }


    /**
     * Convert XML into an AttributeType
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

        $attributeValue = AttributeValue::getChildrenOfClass($xml);
        $AttributeName = self::getOptionalAttribute($xml, 'AttributeName');
        $AttributeNamespace = self::getOptionalAttribute($xml, 'AttributeNamespace');

        return new static($AttributeName, $AttributeNamespace, $attributeValue);
    }


    /**
     * Convert this AttributeType to XML.
     *
     * @param \DOMElement $parent The element we are converting to XML.
     * @return \DOMElement The XML element after adding the data corresponding to this AttributeType.
     */
    public function toXML(DOMElement $parent = null): DOMElement
    {
        $e = $this->instantiateParentElement($parent);

        if ($this->getAttributeName() !== null) {
            $e->setAttribute('AttributeName', $this->getAttributeName());
        }

        if ($this->getAttributeNamespace() !== null) {
            $e->setAttribute('AttributeNamespace', $this->getAttributeNamespace());
        }

        foreach ($this->getAttributeValue() as $av) {
            $av->toXML($e);
        }

        return $e;
    }
}
