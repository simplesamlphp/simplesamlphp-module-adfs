<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\Test\SAML11\XML\saml;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\adfs\SAML11\Constants as C;
use SimpleSAML\Module\adfs\SAML11\XML\saml\Assertion;
use SimpleSAML\Module\adfs\SAML11\XML\saml\ConfirmationMethod;
use SimpleSAML\Module\adfs\SAML11\XML\saml\NameIdentifier;
use SimpleSAML\Module\adfs\SAML11\XML\saml\Subject;
use SimpleSAML\Module\adfs\SAML11\XML\saml\SubjectConfirmation;
use SimpleSAML\Module\adfs\SAML11\XML\saml\SubjectConfirmationData;
use SimpleSAML\XML\Chunk;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XML\TestUtils\SchemaValidationTestTrait;
use SimpleSAML\XML\TestUtils\SerializableElementTestTrait;
use SimpleSAML\XMLSecurity\TestUtils\PEMCertificatesMock;
use SimpleSAML\XMLSecurity\XML\ds\KeyInfo;
use SimpleSAML\XMLSecurity\XML\ds\KeyName;
use SimpleSAML\XMLSecurity\XML\ds\X509Certificate;
use SimpleSAML\XMLSecurity\XML\ds\X509Data;
use SimpleSAML\XMLSecurity\XML\ds\X509SubjectName;

use function dirname;
use function strval;

/**
 * Tests for Subject elements.
 *
 * @covers \SimpleSAML\Module\adfs\SAML11\XML\saml\Subject
 * @covers \SimpleSAML\Module\adfs\SAML11\XML\saml\AbstractSubjectType
 * @covers \SimpleSAML\Module\adfs\SAML11\XML\saml\AbstractSamlElement
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */
final class SubjectTest extends TestCase
{
    use SchemaValidationTestTrait;
    use SerializableElementTestTrait;

    /** @var string */
    private static string $certificate;

    /** @var string[] */
    private static array $certData;


    /**
     */
    public static function setUpBeforeClass(): void
    {
        self::$schemaFile = dirname(__FILE__, 6) . '/resources/schemas/oasis-sstc-saml-schema-assertion-1.1.xsd';

        self::$testedClass = Subject::class;

        self::$xmlRepresentation = DOMDocumentFactory::fromFile(
            dirname(__FILE__, 5) . '/resources/xml/saml_Subject.xml',
        );

        self::$certificate = str_replace(
            [
                '-----BEGIN CERTIFICATE-----',
                '-----END CERTIFICATE-----',
                '-----BEGIN RSA PUBLIC KEY-----',
                '-----END RSA PUBLIC KEY-----',
                "\r\n",
                "\n",
            ],
            [
                '',
                '',
                '',
                '',
                "\n",
                ''
            ],
            PEMCertificatesMock::getPlainCertificate(PEMCertificatesMock::SELFSIGNED_CERTIFICATE),
        );

        self::$certData = openssl_x509_parse(
            PEMCertificatesMock::getPlainCertificate(PEMCertificatesMock::SELFSIGNED_CERTIFICATE),
        );
    }


    // marshalling


    /**
     * Test creating an Subject from scratch.
     */
    public function testMarshalling(): void
    {
        $scd = new SubjectConfirmationData(2);

        $keyInfo = new KeyInfo(
            [
                new KeyName('testkey'),
                new X509Data(
                    [
                        new X509Certificate(self::$certificate),
                        new X509SubjectName(self::$certData['name']),
                    ],
                ),
                new Chunk(DOMDocumentFactory::fromString(
                    '<ssp:Chunk xmlns:ssp="urn:x-simplesamlphp:namespace">some</ssp:Chunk>'
                )->documentElement),
            ],
            'fed654',
        );

        $sc = new SubjectConfirmation(
            [new ConfirmationMethod('_Test1'), new ConfirmationMethod('_Test2')],
            $scd,
            $keyInfo,
        );

        $nameIdentifier = new NameIdentifier(
            'TheNameIDValue',
            'TheNameQualifier',
            'urn:the:format',
        );

        $subject = new Subject($sc, $nameIdentifier);

        $this->assertEquals(
            self::$xmlRepresentation->saveXML(self::$xmlRepresentation->documentElement),
            strval($subject),
        );
    }
}
