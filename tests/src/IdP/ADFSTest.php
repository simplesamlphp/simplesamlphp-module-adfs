<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\adfs\IdP;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ReflectionFunction;
use SimpleSAML\Configuration;
use SimpleSAML\IdP;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\adfs\IdP\ADFS;
use SimpleSAML\SAML2\Constants as C_SAML2;
use SimpleSAML\Session;
use SimpleSAML\XMLSecurity\TestUtils\PEMCertificatesMock;
use Symfony\Component\HttpFoundation\Request;

use function dirname;

/**
 */
#[CoversClass(ADFS::class)]
final class ADFSTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Session */
    protected Session $session;


    /**
     * The setup method that is run before any tests in this class.
     */
    protected function setup(): void
    {
        parent::setUp();

        $this->config = Configuration::loadFromArray(
            [
                'enable.saml20-idp' => true,
                'enable.adfs-idp' => true,
                'module.enable' => ['adfs' => true, 'exampleauth' => true],
                'metadata.sources' => [
                    ['type' => 'flatfile', 'directory' =>  dirname(__DIR__, 2) . '/metadata'],
                ],
            ],
            '[ARRAY]',
            'simplesaml',
        );
        $this->session = Session::getSessionFromRequest();

        Configuration::setPreLoadedConfig($this->config, 'config.php');
    }


    /**
     * Test that the responder registered for passive sign-in can actually be called.
     *
     * \SimpleSAML\IdP::postAuthProc() asserts that $state['Responder'] is callable and then invokes
     * it with a single argument, but that only happens once the returned StreamedResponse is sent,
     * long after this method has returned. A registration naming a method that does not exist is
     * therefore invisible until a user completes a sign-in.
     */
    public function testPassiveAuthnRequestRegistersCallableResponder(): void
    {
        $request = Request::create(
            '/prp',
            'GET',
            ['wa' => 'wsignin1.0', 'wtrealm' => 'urn:federation:localhost'],
        );

        $metadata = MetaDataStorageHandler::getMetadataHandler();
        $idp = IdP::getById('adfs:' . $metadata->getMetaDataCurrentEntityID('adfs-idp-hosted'));

        $response = ADFS::receivePassiveAuthnRequest($request, $idp);

        $callback = $response->getCallback();
        $this->assertNotNull($callback);

        // The state array is only reachable as a variable bound to the streamed callback.
        $state = (new ReflectionFunction($callback))->getClosureUsedVariables()['state'] ?? null;
        $this->assertIsArray($state);
        $this->assertArrayHasKey('Responder', $state);
        $this->assertIsCallable($state['Responder']);
    }


    /**
     * Test that hosted metadata falls back to the module's own endpoint.
     */
    public function testHostedMetadataDefaultsToModuleEndpoint(): void
    {
        $handler = MetaDataStorageHandler::getMetadataHandler();
        $entityId = $handler->getMetaDataCurrentEntityID('adfs-idp-hosted');

        $metadata = ADFS::getHostedMetadata($entityId, $handler);

        $endpoint = Module::getModuleURL('adfs/idp/prp.php');
        $this->assertStringEndsWith('/module.php/adfs/idp/prp.php', $endpoint);

        $expected = [['Binding' => C_SAML2::BINDING_HTTP_REDIRECT, 'Location' => $endpoint]];
        $this->assertSame($expected, $metadata['SingleSignOnService']);
        $this->assertSame($expected, $metadata['SingleLogoutService']);
    }


    /**
     * Test that endpoints configured on the metadata entry take precedence over the defaults.
     */
    public function testHostedMetadataHonoursConfiguredEndpoints(): void
    {
        $resourceDir = dirname(__DIR__, 3) . '/vendor/simplesamlphp/xml-security/';

        $handler = $this->createStub(MetaDataStorageHandler::class);
        $handler->method('getMetaDataConfig')
            ->willReturn(Configuration::loadFromArray(
                [
                    'privatekey_pass' => PEMCertificatesMock::PASSPHRASE,
                    'privatekey' => $resourceDir . PEMCertificatesMock::KEYS_DIR
                        . '/' . PEMCertificatesMock::PRIVATE_KEY,
                    'certificate' => $resourceDir . PEMCertificatesMock::CERTS_DIR
                        . '/' . PEMCertificatesMock::CERTIFICATE,
                    'SingleSignOnService' => 'https://idp.example.org/wsfed/sso',
                    // A list of bindings yields one endpoint per binding.
                    'SingleSignOnServiceBinding' => [
                        C_SAML2::BINDING_HTTP_REDIRECT,
                        C_SAML2::BINDING_HTTP_POST,
                    ],
                    'SingleLogoutService' => 'https://idp.example.org/wsfed/slo',
                    // A single binding does not have to be wrapped in an array.
                    'SingleLogoutServiceBinding' => C_SAML2::BINDING_HTTP_POST,
                ],
                'adfs-idp-hosted',
            ));

        $metadata = ADFS::getHostedMetadata('urn:example:adfs', $handler);

        $this->assertSame(
            [
                ['Binding' => C_SAML2::BINDING_HTTP_REDIRECT, 'Location' => 'https://idp.example.org/wsfed/sso'],
                ['Binding' => C_SAML2::BINDING_HTTP_POST, 'Location' => 'https://idp.example.org/wsfed/sso'],
            ],
            $metadata['SingleSignOnService'],
        );
        $this->assertSame(
            [['Binding' => C_SAML2::BINDING_HTTP_POST, 'Location' => 'https://idp.example.org/wsfed/slo']],
            $metadata['SingleLogoutService'],
        );
    }
}
