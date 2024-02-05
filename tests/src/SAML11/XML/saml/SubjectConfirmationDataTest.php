<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\Test\SAML11\XML\saml;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\adfs\SAML11\Constants as C;
use SimpleSAML\Module\adfs\SAML11\XML\saml\Assertion;
use SimpleSAML\Module\adfs\SAML11\XML\saml\NameIdentifier;
use SimpleSAML\Module\adfs\SAML11\XML\saml\SubjectConfirmationData;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XML\TestUtils\SchemaValidationTestTrait;
use SimpleSAML\XML\TestUtils\SerializableElementTestTrait;

use function dirname;
use function strval;

/**
 * Tests for SubjectConfirmationData elements.
 *
 * @covers \SimpleSAML\Module\adfs\SAML11\XML\saml\SubjectConfirmationData
 * @covers \SimpleSAML\Module\adfs\SAML11\XML\saml\AbstractSamlElement
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */
final class SubjectConfirmationDataTest extends TestCase
{
    use SchemaValidationTestTrait;
    use SerializableElementTestTrait;

    /**
     */
    public static function setUpBeforeClass(): void
    {
        self::$schemaFile = dirname(__FILE__, 6) . '/resources/schemas/oasis-sstc-saml-schema-assertion-1.1.xsd';

        self::$testedClass = SubjectConfirmationData::class;

        self::$xmlRepresentation = DOMDocumentFactory::fromFile(
            dirname(__FILE__, 5) . '/resources/xml/saml_SubjectConfirmationData.xml',
        );
    }


    // marshalling


    /**
     * Test creating an SubjectConfirmationData from scratch using an integer.
     */
    public function testMarshalling(): void
    {
        $scd = new SubjectConfirmationData(2);
        $this->assertIsInt($scd->getValue());
        $this->assertEquals(2, $scd->getValue());
        $this->assertEquals('xs:integer', $scd->getXsiType());

        $this->assertEquals(
            self::$xmlRepresentation->saveXML(self::$xmlRepresentation->documentElement),
            strval($scd),
        );
    }


    /**
     * Test creating an SubjectConfirmationData from scratch using a string.
     */
    public function testMarshallingString(): void
    {
        $scd = new SubjectConfirmationData('value');

        $this->assertEquals('value', $scd->getValue());
        $this->assertEquals('xs:string', $scd->getXsiType());
    }


    /**
     */
    public function testMarshallingNull(): void
    {
        $scd = new SubjectConfirmationData(null);
        $this->assertNull($scd->getValue());
        $this->assertEquals('xs:nil', $scd->getXsiType());
        $nssaml = C::NS_SAML;
        $nsxsi = C::NS_XSI;
        $xml = <<<XML
<saml:SubjectConfirmationData xmlns:saml="{$nssaml}" xmlns:xsi="{$nsxsi}" xsi:nil="1"/>
XML;
        $this->assertEquals(
            $xml,
            strval($scd),
        );
    }


    /**
     * Verifies that supplying an empty string as subject confirmation data will
     * generate a tag with no content (instead of e.g. an empty tag).
     *
     */
    public function testEmptyStringAttribute(): void
    {
        $scd = new SubjectConfirmationData('');
        $xmlRepresentation = clone self::$xmlRepresentation;
        $xmlRepresentation->documentElement->textContent = '';
//        $this->assertEqualXMLStructure(
//            $this->xmlRepresentation->documentElement,
//            $scd->toXML(),
//        );
        $this->assertEquals('', $scd->getValue());
        $this->assertEquals('xs:string', $scd->getXsiType());
    }


    // unmarshalling


    /**
     * Verifies that we can create an SubjectConfirmationData containing a NameID from a DOMElement.
     *
     * @return void
     */
    public function testUnmarshallingNameID(): void
    {
        $document = DOMDocumentFactory::fromString(<<<XML
<saml:SubjectConfirmationData xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion">
  <saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">abcd-some-value-xyz</saml:NameIdentifier>
</saml:SubjectConfirmationData>
XML
        );

        $scd = SubjectConfirmationData::fromXML($document->documentElement);
        $value = $scd->getValue();

        $this->assertInstanceOf(NameIdentifier::class, $value);

        $this->assertEquals('abcd-some-value-xyz', $value->getContent());
        $this->assertEquals('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', $value->getFormat());
        $this->assertXmlStringEqualsXmlString($document->saveXML(), $scd->toXML()->ownerDocument?->saveXML());
    }
}
