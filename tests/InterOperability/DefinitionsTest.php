<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\adfs\InterOperability;

use DOMElement;
use Exception;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\WSDL\XML\wsdl\Definitions;
use SimpleSAML\XML\DOMDocumentFactory;

/**
 * Class \SimpleSAML\Test\Module\adfs\InterOperability\DefinitionsTest
 *
 * @package simplesamlphp\ws-security
 */
final class DefinitionsTest extends TestCase
{
    /**
     * @param boolean $shouldPass
     * @param \DOMElement $mex
     */
    #[DataProvider('provideMex')]
    public function testUnmarshalling(bool $shouldPass, DOMElement $mex): void
    {
        try {
            Definitions::fromXML($mex);
            $this->assertTrue($shouldPass);
        } catch (Exception $e) {
            fwrite(STDERR, $e->getFile() . '(' . strval($e->getLine()) . '):' . $e->getMessage());
            fwrite(STDERR, $e->getTraceAsString());
            $this->assertFalse($shouldPass);
        }
    }


    /**
     * @return array
     */
    public static function provideMex(): array
    {
        return [
            'MicrosoftAdfs' => [
                true,
                DOMDocumentFactory::fromFile(
                    dirname(__FILE__, 2) . '/resources/interoperability/adfs_mex.xml',
                )->documentElement,
            ],
        ];
    }
}
