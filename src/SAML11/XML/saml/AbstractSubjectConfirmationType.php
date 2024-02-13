<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML11\XML\saml;

use DOMElement;
use SimpleSAML\Assert\Assert;
use SimpleSAML\XML\Exception\InvalidDOMElementException;
use SimpleSAML\XML\Exception\MissingElementException;
use SimpleSAML\XML\Exception\SchemaViolationException;
use SimpleSAML\XML\Exception\TooManyElementsException;
use SimpleSAML\XMLSecurity\XML\ds\KeyInfo;

/**
 * SAML SubjectConfirmationType abstract data type.
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */

abstract class AbstractSubjectConfirmationType extends AbstractSamlElement
{
    /**
     * Initialize a saml:SubjectConfirmationType from scratch
     *
     * @param array<\SimpleSAML\Module\adfs\SAML11\XML\saml\ConfirmationMethod> $confirmationMethod
     * @param \SimpleSAML\Module\adfs\SAML11\XML\saml\SubjectConfirmationData|null $subjectConfirmationData
     * @param \SimpleSAML\XMLSecurity\XML\ds\KeyInfo|null $keyInfo
     */
    public function __construct(
        protected array $confirmationMethod,
        protected ?SubjectConfirmationData $subjectConfirmationData = null,
        protected ?KeyInfo $keyInfo = null,
    ) {
        Assert::minCount($confirmationMethod, 1, MissingElementException::class);
        Assert::allIsInstanceOf($confirmationMethod, ConfirmationMethod::class, SchemaViolationException::class);
    }


    /**
     * Collect the value of the confirmationMethod-property
     *
     * @return array<\SimpleSAML\Module\adfs\SAML11\XML\saml\ConfirmationMethod>
     */
    public function getConfirmationMethod(): array
    {
        return $this->confirmationMethod;
    }


    /**
     * Collect the value of the subjectConfirmationData-property
     *
     * @return \SimpleSAML\Module\adfs\SAML11\XML\saml\SubjectConfirmationData|null
     */
    public function getSubjectConfirmationData(): ?SubjectConfirmationData
    {
        return $this->subjectConfirmationData;
    }


    /**
     * Collect the value of the keyInfo-property
     *
     * @return \SimpleSAML\XMLSecurity\XML\ds\KeyInfo|null
     */
    public function getKeyInfo(): ?KeyInfo
    {
        return $this->keyInfo;
    }


    /**
     * Convert XML into an SubjectConfirmationType
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

        $subjectConfirmationData = SubjectConfirmationData::getChildrenOfClass($xml);
        Assert::maxCount($subjectConfirmationData, 1, TooManyElementsException::class);

        $keyInfo = KeyInfo::getChildrenOfClass($xml);
        Assert::maxCount($keyInfo, 1, TooManyElementsException::class);

        return new static(
            ConfirmationMethod::getChildrenOfClass($xml),
            array_pop($subjectConfirmationData),
            array_pop($keyInfo),
        );
    }


    /**
     * Convert this SubjectConfirmationType to XML.
     *
     * @param \DOMElement $parent The element we are converting to XML.
     * @return \DOMElement The XML element after adding the data corresponding to this SubjectConfirmationType.
     */
    public function toXML(DOMElement $parent = null): DOMElement
    {
        $e = $this->instantiateParentElement($parent);

        foreach ($this->getConfirmationMethod() as $confirmationMethod) {
            $confirmationMethod->toXML($e);
        }

        $this->getSubjectConfirmationData()?->toXML($e);
        $this->getKeyInfo()?->toXML($e);

        return $e;
    }
}
