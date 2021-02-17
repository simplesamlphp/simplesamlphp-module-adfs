<?php

declare(strict_types=1);

namespace Simplesamlphp\adfs;

use PHPUnit\Framework\TestCase;
use SimpleSAML\TestUtils\BuiltInServer;

class PrpIntegrationTest extends TestCase
{

    /**
     * @var \SimpleSAML\TestUtils\BuiltInServer
     */
    protected BuiltInServer $server;

    /**
     * @var string
     */
    protected string $server_addr;

    /**
     * @var int
     */
    protected int $server_pid;

    /**
     * @var string
     */
    protected string $shared_file;

    /**
     * @var string
     */
    protected string $cookies_file;

    /** @var string $PRP_URL */
    private static string $PRP_URL = '/module.php/adfs/idp/prp.php';

    /**
     * @param array $config
     */
    protected function updateConfig(array $config): void
    {
        @unlink($this->shared_file);
        $config = "<?php\n\$config = " . var_export($config, true) . ";\n";
        file_put_contents($this->shared_file, $config);
    }

    /**
     * The setup method that is run before any tests in this class.
     */
    protected function setup(): void
    {
        $this->server = new BuiltInServer(
            'configLoader',
            dirname(__FILE__, 3) . '/vendor/simplesamlphp/simplesamlphp/www'
        );
        $this->server_addr = $this->server->start();
        $this->server_pid = $this->server->getPid();
        $this->shared_file = sys_get_temp_dir() . '/' . $this->server_pid . '.lock';
        $this->cookies_file = sys_get_temp_dir() . '/' . $this->server_pid . '.cookies';
        @unlink($this->shared_file); // remove it if it exists
    }

    /**
     * The tear down method that is executed after all tests in this class.
     * Removes the lock file and cookies file
     */
    protected function tearDown(): void
    {
        @unlink($this->shared_file);
        @unlink($this->cookies_file); // remove it if it exists
        $this->server->stop();
    }

    /**
     * Make a request with the provided query parameters to the prp endpoint
     * @param array|null $queryParams
     * @return array The response
     */
    private function makeWsFedRequest(array $queryParams = []): array
    {
        return $this->server->get(
            self::$PRP_URL,
            $queryParams,
            [
                CURLOPT_COOKIEJAR => $this->cookies_file,
                CURLOPT_COOKIEFILE => $this->cookies_file,
                CURLOPT_FOLLOWLOCATION => true
            ]
        );
    }


    /**
     * Test missing require query parameters is an error
     */
    public function testNoQueryParameters()
    {
        $resp = $this->makeWsFedRequest();
        $this->assertEquals(400, $resp['code']);

        $this->assertStringContainsString(
            ' Missing parameter &#039;wa&#039; or &#039;assocId&#039; in request',
            $resp['body'],
            'Missing required parameters should be useful error message'
        );
    }

    /**
     * Test that the service request authentication is not found in the metadata
     */
    public function testMissingMetadataForRP()
    {
        $params = [
            'wa' => 'wsignin1.0',
            'wtrealm' => 'urn:example-sp'
        ];
        $resp = $this->makeWsFedRequest($params);
        $this->assertEquals(500, $resp['code']);

        $this->assertStringContainsString(
            'MetadataNotFound',
            $resp['body']
        );
    }

    /**
     * Test a valid request
     */
    public function testValidRequest()
    {
        $params = [
            'wa' => 'wsignin1.0',
            'wtrealm' => 'urn:federation:localhost'
        ];
        $resp = $this->makeWsFedRequest($params);
        $this->assertEquals(200, $resp['code']);

        $this->assertStringContainsString(
            'saml:AttributeValue&gt;testuser&lt;/saml:AttributeValue',
            $resp['body']
        );
        //TODO: parse out the post body and confirm it is an acceptable format.
    }
}
