<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\adfs\IdP;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ReflectionFunction;
use SimpleSAML\Configuration;
use SimpleSAML\IdP;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module\adfs\IdP\ADFS;
use SimpleSAML\Session;
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
}
