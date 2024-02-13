<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML11\XML\saml;

use DOMElement;
use SimpleSAML\Assert\Assert;
use SimpleSAML\XML\Exception\InvalidDOMElementException;
use SimpleSAML\XML\Exception\SchemaViolationException;
use SimpleSAML\XML\StringElementTrait;

/**
 * SAML AttributeType abstract data type.
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */

abstract class AbstractActionType extends AbstractSamlElement
{
    use StringElementTrait;


    /**
     * Initialize a saml:AttributeActionType from scratch
     *
     * @param string $value
     * @param string|null $Namespace
     */
    final public function __construct(
        protected string $value,
        protected string|null $Namespace = null,
    ) {
        Assert::nullOrValidURI($Namespace, SchemaViolationException::class); // Covers the empty string
        $this->setContent($value);
    }


    /**
     * Collect the value of the Namespace-property
     *
     * @return string|null
     */
    public function getNamespace(): ?string
    {
        return $this->Namespace;
    }


    /**
     * Convert XML into an ActionType
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

        $Namespace = self::getOptionalAttribute($xml, 'Namespace');

        return new static($xml->textContent, $Namespace);
    }


    /**
     * Convert this ActionType to XML.
     *
     * @param \DOMElement $parent The element we are converting to XML.
     * @return \DOMElement The XML element after adding the data corresponding to this ActionType.
     */
    public function toXML(DOMElement $parent = null): DOMElement
    {
        $e = $this->instantiateParentElement($parent);
        $e->textContent = $this->getContent();

        if ($this->getNamespace() !== null) {
            $e->setAttribute('Namespace', $this->getNamespace());
        }

        return $e;
    }
}
