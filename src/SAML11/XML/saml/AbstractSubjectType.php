<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML11\XML\saml;

use DOMElement;
use SimpleSAML\Assert\Assert;
use SimpleSAML\XML\Exception\InvalidDOMElementException;
use SimpleSAML\XML\Exception\MissingElementException;
use SimpleSAML\XML\Exception\TooManyElementsException;

/**
 * SAML SubjectType abstract data type.
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */

abstract class AbstractSubjectType extends AbstractSamlElement
{
    /**
     * Initialize a saml:SubjectType from scratch
     *
     * @param \SimpleSAML\Module\adfs\SAML11\XML\saml\SubjectConfirmation|null $subjectConfirmation
     * @param \SimpleSAML\Module\adfs\SAML11\XML\saml\NameIdentifier|null $nameIdentifier
     */
    public function __construct(
        protected ?SubjectConfirmation $subjectConfirmation = null,
        protected ?NameIdentifier $nameIdentifier = null,
    ) {
        if ($nameIdentifier === null) {
            Assert::notNull($subjectConfirmation, MissingElementException::class);
        }
    }


    /**
     * Collect the value of the subjectConfirmation-property
     *
     * @return \SimpleSAML\Module\adfs\SAML11\XML\saml\SubjectConfirmation|null
     */
    public function getSubjectConfirmation(): ?SubjectConfirmation
    {
        return $this->subjectConfirmation;
    }


    /**
     * Collect the value of the nameIdentifier-property
     *
     * @return \SimpleSAML\Module\adfs\SAML11\XML\saml\NameIdentifier|null
     */
    public function getNameIdentifier(): ?NameIdentifier
    {
        return $this->nameIdentifier;
    }


    /**
     * Convert XML into an SubjectType
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

        $subjectConfirmation = SubjectConfirmation::getChildrenOfClass($xml);
        Assert::maxCount($subjectConfirmation, 1, TooManyElementsException::class);

        $nameIdentifier = NameIdentifier::getChildrenOfClass($xml);
        Assert::maxCount($nameIdentifier, 1, TooManyElementsException::class);

        return new static(
            array_pop($subjectConfirmation),
            array_pop($nameIdentifier),
        );
    }


    /**
     * Convert this SubjectType to XML.
     *
     * @param \DOMElement $parent The element we are converting to XML.
     * @return \DOMElement The XML element after adding the data corresponding to this SubjectType.
     */
    public function toXML(DOMElement $parent = null): DOMElement
    {
        $e = $this->instantiateParentElement($parent);

        $this->getNameIdentifier()?->toXML($e);
        $this->getSubjectConfirmation()?->toXML($e);

        return $e;
    }
}
