<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\adfs\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module\adfs\Controller;
use SimpleSAML\Session;
use Symfony\Component\HttpFoundation\{Request, StreamedResponse};

use function dirname;

/**
 */
#[CoversClass(Controller\Adfs::class)]
final class AdfsControllerTest extends TestCase
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
     * Test missing require query parameters is an error
     */
    public function testNoQueryParameters(): void
    {
        $request = Request::create(
            '/prp',
            'GET',
        );

        $c = new Controller\Adfs($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage(
            "BADREQUEST('%REASON%' => 'Missing parameter \'wa\' or \'assocId\' in request.')",
        );

        $c->prp($request);
    }


    /**
     * Test that the service request authentication is not found in the metadata
     */
    public function testMissingMetadataForRP(): void
    {
        $request = Request::create(
            '/prp',
            'GET',
            ['wa' => 'wsignin1.0', 'wtrealm' => 'urn:example-sp'],
        );

        $c = new Controller\Adfs($this->config, $this->session);

        $this->expectException(Error\MetadataNotFound::class);
        $this->expectExceptionMessage("METADATANOTFOUND('%ENTITYID%' => 'urn:example-sp')");

        $c->prp($request);
    }


    /**
     * Test a valid request
     */
    public function testValidRequest(): void
    {
        $request = Request::create(
            '/prp',
            'GET',
            ['wa' => 'wsignin1.0', 'wtrealm' => 'urn:federation:localhost'],
        );

        $c = new Controller\Adfs($this->config, $this->session);
        $response = $c->prp($request);

        $this->assertTrue($response->isSuccessful());
        $this->assertInstanceOf(StreamedResponse::class, $response);
    }
}
