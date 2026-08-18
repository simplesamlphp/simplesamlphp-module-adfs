<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\adfs\IdP;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\adfs\IdP\MetadataBuilder;
use SimpleSAML\WebServices\Federation\Constants as C_FED;
use SimpleSAML\WebServices\Federation\XML\fed\AbstractSecurityTokenServiceType;

use function dirname;
use function strval;

/**
 */
#[CoversClass(MetadataBuilder::class)]
final class MetadataBuilderTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;


    /**
     * The setup method that is run before any tests in this class.
     */
    protected function setup(): void
    {
        parent::setUp();

        $this->config = Configuration::loadFromArray(
            [
                'enable.adfs-idp' => true,
                'module.enable' => ['adfs' => true],
                'metadata.sources' => [
                    ['type' => 'flatfile', 'directory' => dirname(__DIR__, 2) . '/metadata'],
                ],
            ],
            '[ARRAY]',
            'simplesaml',
        );

        Configuration::setPreLoadedConfig($this->config, 'config.php');
    }


    /**
     * Test that the SecurityTokenService is typed as fed:SecurityTokenServiceType.
     *
     * The first constructor argument is the element's xsi:type, not its own name. Building it from
     * getLocalName()/NS/NS_PREFIX describes the element this serialises to — md:RoleDescriptor —
     * and so publishes a role descriptor that claims to be typed as itself.
     */
    public function testSecurityTokenServiceCarriesItsXsiType(): void
    {
        $metadata = Configuration::loadFromArray(
            ['entityid' => 'urn:example:adfs'],
            'adfs-idp-hosted',
        );

        $xsiType = (new MetadataBuilder($this->config, $metadata))
            ->getSecurityTokenService()
            ->getXsiType();

        $this->assertEquals('fed:SecurityTokenServiceType', strval($xsiType));
        $this->assertEquals(
            AbstractSecurityTokenServiceType::XSI_TYPE_NAME,
            $xsiType->getLocalName()->getValue(),
        );

        // The prefix is lexical; what identifies the type is the namespace it resolves to.
        $namespaceURI = $xsiType->getNamespaceURI();
        $this->assertNotNull($namespaceURI);
        $this->assertEquals(C_FED::NS_FED, $namespaceURI->getValue());
    }
}
