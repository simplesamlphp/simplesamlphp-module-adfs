<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\Test\SAML11\XML\saml;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\adfs\SAML11\XML\saml\Audience;
use SimpleSAML\XML\Chunk;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XML\TestUtils\SchemaValidationTestTrait;
use SimpleSAML\XML\TestUtils\SerializableElementTestTrait;

use function dirname;
use function strval;

/**
 * Tests for Audience elements.
 *
 * @covers \SimpleSAML\Module\adfs\SAML11\XML\saml\Audience
 * @covers \SimpleSAML\Module\adfs\SAML11\XML\saml\AbstractSamlElement
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */
final class AudienceTest extends TestCase
{
    use SchemaValidationTestTrait;
    use SerializableElementTestTrait;


    /**
     */
    public static function setUpBeforeClass(): void
    {
        self::$schemaFile = dirname(__FILE__, 6) . '/resources/schemas/oasis-sstc-saml-schema-assertion-1.1.xsd';

        self::$testedClass = Audience::class;

        self::$xmlRepresentation = DOMDocumentFactory::fromFile(
            dirname(__FILE__, 5) . '/resources/xml/saml_Audience.xml',
        );
    }


    // marshalling


    /**
     * Test creating an Audience from scratch
     */
    public function testMarshalling(): void
    {
        $audience = new Audience('urn:x-simplesamlphp:audience');

        $this->assertEquals(
            self::$xmlRepresentation->saveXML(self::$xmlRepresentation->documentElement),
            strval($audience),
        );
    }
}
