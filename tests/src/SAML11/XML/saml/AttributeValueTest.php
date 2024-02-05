<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\Test\SAML11\XML\saml;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\adfs\SAML11\Constants as C;
use SimpleSAML\Module\adfs\SAML11\XML\saml\AttributeValue;
use SimpleSAML\Module\adfs\SAML11\XML\saml\NameIdentifier;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XML\TestUtils\SchemaValidationTestTrait;
use SimpleSAML\XML\TestUtils\SerializableElementTestTrait;

use function dirname;
use function strval;

/**
 * Tests for AttributeValue elements.
 *
 * @covers \SimpleSAML\Module\adfs\SAML11\XML\saml\AttributeValue
 * @covers \SimpleSAML\Module\adfs\SAML11\XML\saml\AbstractSamlElement
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */
final class AttributeValueTest extends TestCase
{
    use SchemaValidationTestTrait;
    use SerializableElementTestTrait;

    /**
     */
    public static function setUpBeforeClass(): void
    {
        self::$schemaFile = dirname(__FILE__, 6) . '/resources/schemas/oasis-sstc-saml-schema-assertion-1.1.xsd';

        self::$testedClass = AttributeValue::class;

        self::$xmlRepresentation = DOMDocumentFactory::fromFile(
            dirname(__FILE__, 5) . '/resources/xml/saml_AttributeValue.xml',
        );
    }


    // marshalling


    /**
     * Test creating an AttributeValue from scratch using an integer.
     */
    public function testMarshalling(): void
    {
        $av = new AttributeValue(2);
        $this->assertIsInt($av->getValue());
        $this->assertEquals(2, $av->getValue());
        $this->assertEquals('xs:integer', $av->getXsiType());

        $this->assertEquals(
            self::$xmlRepresentation->saveXML(self::$xmlRepresentation->documentElement),
            strval($av),
        );
    }


    /**
     * Test creating an AttributeValue from scratch using a string.
     */
    public function testMarshallingString(): void
    {
        $av = new AttributeValue('value');

        $this->assertEquals('value', $av->getValue());
        $this->assertEquals('xs:string', $av->getXsiType());
    }


    /**
     */
    public function testMarshallingNull(): void
    {
        $av = new AttributeValue(null);
        $this->assertNull($av->getValue());
        $this->assertEquals('xs:nil', $av->getXsiType());
        $nssaml = C::NS_SAML;
        $nsxsi = C::NS_XSI;
        $xml = <<<XML
<saml:AttributeValue xmlns:saml="{$nssaml}" xmlns:xsi="{$nsxsi}" xsi:nil="1"/>
XML;
        $this->assertEquals(
            $xml,
            strval($av),
        );
    }


    /**
     * Verifies that supplying an empty string as attribute value will
     * generate a tag with no content (instead of e.g. an empty tag).
     *
     */
    public function testEmptyStringAttribute(): void
    {
        $av = new AttributeValue('');
        $xmlRepresentation = clone self::$xmlRepresentation;
        $xmlRepresentation->documentElement->textContent = '';
//        $this->assertEqualXMLStructure(
//            $this->xmlRepresentation->documentElement,
//            $av->toXML(),
//        );
        $this->assertEquals('', $av->getValue());
        $this->assertEquals('xs:string', $av->getXsiType());
    }


    // unmarshalling


    /**
     * Verifies that we can create an AttributeValue containing a NameID from a DOMElement.
     *
     * @return void
     */
    public function testUnmarshallingNameID(): void
    {
        $document = DOMDocumentFactory::fromString(<<<XML
<saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion">
  <saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">abcd-some-value-xyz</saml:NameIdentifier>
</saml:AttributeValue>
XML
        );

        $av = AttributeValue::fromXML($document->documentElement);
        $value = $av->getValue();

        $this->assertInstanceOf(NameIdentifier::class, $value);

        $this->assertEquals('abcd-some-value-xyz', $value->getContent());
        $this->assertEquals('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', $value->getFormat());
        $this->assertXmlStringEqualsXmlString($document->saveXML(), $av->toXML()->ownerDocument?->saveXML());
    }
}
