<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\adfs\Controller;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Module\adfs\Controller;
use SimpleSAML\Session;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

use function dirname;

/**
 * @covers \SimpleSAML\Module\adfs\Controller\Adfs
 */
class AdfsControllerTest extends TestCase
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
                'enable.adfs-idp' => true,
                'module.enable' => ['adfs' => true, 'exampleauth' => true],
                'metadata.sources' => [
                    ['type' => 'flatfile', 'directory' =>  dirname(dirname(__DIR__)) . '/metadata'],
                ],
            ],
            '[ARRAY]',
            'simplesaml'
        );
        $this->session = Session::getSessionFromRequest();

        Configuration::setPreLoadedConfig($this->config, 'config.php');
    }


    /**
     * Test missing require query parameters is an error
     */
    public function testNoQueryParameters()
    {
        $request = Request::create(
            '/prp',
            'GET',
        );

        $c = new Controller\Adfs($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage("BADREQUEST('%REASON%' => 'Missing parameter \'wa\' or \'assocId\' in request.')");

        $c->prp($request);
    }


    /**
     * Test that the service request authentication is not found in the metadata
     */
    public function testMissingMetadataForRP()
    {
        $request = Request::create(
            '/prp',
            'GET',
            ['wa' => 'wsignin1.0', 'wtrealm' => 'urn:example-sp'],
        );

        $c = new Controller\Adfs($this->config, $this->session);

        $this->expectException(Error\MetadataNotFound::class);
        $this->expectExceptionMessage("METADATANOTFOUND('%ENTITYID%' => '\'urn:example-sp\'')");

        $c->prp($request);
    }


    /**
     * Test a valid request
     */
    public function testValidRequest()
    {
        $request = Request::create(
            '/prp',
            'GET',
            ['wa' => 'wsignin1.0', 'wtrealm' => 'urn:federation:localhost'],
        );

        $c = new Controller\Adfs($this->config, $this->session);
        $response = $c->prp($request);

        $this->assertTrue($response->isSuccessful());
        $this->assertInstanceOf(RunnableResponse::class, $response);
    }
}
