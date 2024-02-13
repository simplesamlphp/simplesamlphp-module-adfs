<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\Test\SAML11\XML\saml;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\adfs\SAML11\XML\saml\SubjectLocality;
use SimpleSAML\XML\Chunk;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XML\TestUtils\SchemaValidationTestTrait;
use SimpleSAML\XML\TestUtils\SerializableElementTestTrait;

use function dirname;
use function strval;

/**
 * Tests for SubjectLocality elements.
 *
 * @covers \SimpleSAML\Module\adfs\SAML11\XML\saml\SubjectLocality
 * @covers \SimpleSAML\Module\adfs\SAML11\XML\saml\AbstractSubjectLocalityType
 * @covers \SimpleSAML\Module\adfs\SAML11\XML\saml\AbstractSamlElement
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */
final class SubjectLocalityTest extends TestCase
{
    use SchemaValidationTestTrait;
    use SerializableElementTestTrait;


    /**
     */
    public static function setUpBeforeClass(): void
    {
        self::$schemaFile = dirname(__FILE__, 6) . '/resources/schemas/oasis-sstc-saml-schema-assertion-1.1.xsd';

        self::$testedClass = SubjectLocality::class;

        self::$xmlRepresentation = DOMDocumentFactory::fromFile(
            dirname(__FILE__, 5) . '/resources/xml/saml_SubjectLocality.xml',
        );
    }


    // marshalling


    /**
     * Test creating an SubjectLocality from scratch
     */
    public function testMarshalling(): void
    {
        $sl = new SubjectLocality('127.0.0.1', 'simplesamlphp.org');

        $this->assertEquals(
            self::$xmlRepresentation->saveXML(self::$xmlRepresentation->documentElement),
            strval($sl),
        );
    }


    /**
     * Test creating an empty SubjectLocality from scratch
     */
    public function testMarshallingEmpty(): void
    {
        $sl = new SubjectLocality();
        $this->assertTrue($sl->isEmptyElement());
    }
}
