<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\SAML11\XML\saml;

use DateTimeImmutable;
use DOMElement;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Module\adfs\SAML11\Constants as C;
use SimpleSAML\Module\adfs\SAML11\Exception\ProtocolViolationException;
use SimpleSAML\XML\Exception\InvalidDOMElementException;
use SimpleSAML\XML\Exception\MissingElementException;
use SimpleSAML\XML\Exception\SchemaViolationException;
use SimpleSAML\XML\Exception\TooManyElementsException;

/**
 *  SAML AuthenticationStatementType abstract data type.
 *
 * @package simplesaml/simplesamlphp-module-adfs
 */
abstract class AbstractAuthenticationStatementType extends AbstractSubjectStatementType
{
    /**
     * Initialize a saml:AuthenticationStatementType from scratch
     *
     * @param string $authenticationMethod
     * @param \DateTimeImmutable $authenticationInstant
     * @param \SimpleSAML\Module\adfs\SAML11\XML\saml\Subject $subject
     * @param \SimpleSAML\Module\adfs\SAML11\XML\saml\SubjectLocality|null $subjectLocality
     * @param array<\SimpleSAML\Module\adfs\SAML11\XML\saml\AuthorityBinding> $authorityBinding
     */
    public function __construct(
        protected string $authenticationMethod,
        protected DateTimeImmutable $authenticationInstant,
        protected ?SubjectLocality $subjectLocality = null,
        protected array $authorityBinding = [],
    ) {
        Assert::validURI($authenticationMethod);
        Assert::allIsInstanceOf($authorityBinding, AuthorityBinding::class, SchemaViolationException::class);

        parent::__construct($subject);
    }


    /**
     * Collect the value of the authorityBinding-property
     *
     * @return array<\SimpleSAML\Module\adfs\SAML11\XML\saml\AuthorityBinding>
     */
    public function getAuthorityBinding(): array
    {
        return $this->authorityBinding;
    }


    /**
     * Collect the value of the subjectLocality-property
     *
     * @return \SimpleSAML\Module\adfs\SAML11\XML\saml\SubjectLocality|null
     */
    public function getSubjectLocality(): ?SubjectLocality
    {
        return $this->subjectLocality;
    }


    /**
     * Collect the value of the authenticationMethod-property
     *
     * @return string
     */
    public function getAuthenticationMethod(): string
    {
        return $this->authenticationMethod;
    }


    /**
     * Collect the value of the authenticationInstant-property
     *
     * @return \DateTimeImmutable
     */
    public function getAuthenticationInstant(): DateTimeImmutable
    {
        return $this->authenticationInstant;
    }


    /**
     * Convert XML into an AuthenticationStatementType
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

        $authenticationInstant = self::getAttribute($xml, 'AuthenticationInstant');
        // Strip sub-seconds - See paragraph 1.2.2 of SAML core specifications
        $authenticationInstant = preg_replace('/([.][0-9]+Z)$/', 'Z', $authenticationInstant, 1);

        Assert::validDateTimeZulu($authenticationInstant, ProtocolViolationException::class);
        $authenticationInstant = new DateTimeImmutable($authenticationInstant);

        $authorityBinding = AuthorityBinding::getChildrenOfClass($xml);
        $subjectLocality = SubjectLocality::getChildrenOfClass($xml);
        Assert::maxCount($subjectLocality, 1, TooManyElementsException::class);

        $subject = Subject::getChildrenOfClass($xml);
        Assert::minCount($subject, 1, MissingElementException::class);
        Assert::maxCount($subject, 1, TooManyElementsException::class);

        return new static(
            self::getAttribute($xml, 'AuthenticationMethod'),
            $authenticationInstant,
            array_pop($subject),
            array_pop($subjectLocality),
            $authorityBinding,
        );
    }


    /**
     * Convert this AuthenticationStatementType to XML.
     *
     * @param \DOMElement $parent The element we are converting to XML.
     * @return \DOMElement The XML element after adding the data corresponding to this AuthenticationStatementType.
     */
    public function toXML(DOMElement $parent = null): DOMElement
    {
        $e = parent::toXML($parent);

        $e->setAttribute('AuthenticationMethod', $this->getAuthenticationMethod());
        $e->setAttribute('AuthenticationInstant', $this->getAuthenticationInstant()->format(C::DATETIME_FORMAT));

        $this->getSubjectLocality()?->toXML($e);

        foreach ($this->getAuthorityBinding() as $ab) {
            $ab->toXML($e);
        }

        return $e;
    }
}
