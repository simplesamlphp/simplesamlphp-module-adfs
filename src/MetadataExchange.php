<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs;

use SimpleSAML\Module;
use SimpleSAML\Module\adfs\Trust;
use SimpleSAML\WSSecurity\XML\wsdl\{
    Definitions,
    Input,
    Message,
    Output,
    Part,
    PortType,
    PortTypeOperation,
    Types,
};
use SimpleSAML\WSSecurity\Constants as C;
use SimpleSAML\WSSecurity\XML\wst_200502\{
    RequestSecurityToken as RequestSecurityToken2005,
    RequestSecurityTokenResponse as RequestSecurityTokenResponse2005,
};
use SimpleSAML\WSSecurity\XML\wst_200512\{
    RequestSecurityToken as RequestSecurityToken13,
    RequestSecurityTokenResponseCollection as RequestSecurityTokenResponseCollection13,
};
use SimpleSAML\XML\Attribute as XMLAttribute;
use SimpleSAML\XML\Chunk;
use SimpleSAML\XML\DOMDocumentFactory;

use function array_merge;
use function sprintf;

/**
 * Common code for building MetaExchange (mex) documents based on the available configuration.
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */
class MetadataExchange
{
    /**
     * Constructor.
     *
     * @param \SimpleSAML\Configuration $config The general configuration
     * @param \SimpleSAML\Configuration $metadata The metadata configuration
     */
    public function __construct()
    {
    }


    /**
     * Build a mex document
     *
     * @return \SimpleSAML\WSSecurity\XML\wsdl\Definitions
     */
    public function buildDocument(): Definitions
    {
        return new Definitions(
            targetNamespace: 'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
            name: 'SecurityTokenService',
            import: [],
            types: $this->getTypes(),
            message: $this->getMessages(),
            portType: $this->getPortTypes(),
            binding: [],
            service: [],
            elements: $this->getPolicies(),
        );
    }


    /**
     * This method builds the wsp:Policy elements
     *
     * @param \SimpleSAML\WSSecurity\XML\wsp\Policy[]
     */
    private function getPolicies(): array
    {
        $policy2005 = new Trust\Policy2005();
        $policy13 = new Trust\Policy13();

        return array_merge(
            $policy2005->getPolicies(),
            $policy13->getPolicies(),
        );
    }


    /**
     * This method builds the wsdl:types elements
     *
     * @param \SimpleSAML\WSSecurity\XML\wsdl\Types[]
     */
    private function getTypes(): array
    {
        $defaultEndpoint = Module::getModuleURL('adfs/services/trust/mex');
        $xml = <<<IMPORT
<xsd:schema
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  targetNamespace="http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice/Imports">
<xsd:import schemaLocation="$defaultEndpoint?xsd=xsd0" namespace="http://schemas.microsoft.com/Message"/>
<xsd:import schemaLocation="$defaultEndpoint?xsd=xsd1" namespace="http://schemas.xmlsoap.org/ws/2005/02/trust"/>
<xsd:import schemaLocation="$defaultEndpoint?xsd=xsd2" namespace="http://docs.oasis-open.org/ws-sx/ws-trust/200512"/>
</xsd:schema>
IMPORT;

        return [
            new Types([
                new Chunk(DOMDocumentFactory::fromString($xml)->documentElement),
            ]),
        ];
    }


    /**
     * This method builds the wsdl:message elements
     *
     * @param \SimpleSAML\WSSecurity\XML\wsdl\Message[]
     */
    private function getMessages(): array
    {
        return [
            new Message(
                'IWSTrustFeb2005Async_TrustFeb2005IssueAsync_InputMessage',
                [new Part(
                    'request',
                    sprintf(
                        "%s:%s",
                        RequestSecurityToken2005::getNamespacePrefix(),
                        RequestSecurityToken2005::getLocalName(),
                    ),
                )],
            ),
            new Message(
                'IWSTrustFeb2005Async_TrustFeb2005IssueAsync_OutputMessage',
                [new Part(
                    'TrustFeb2005IssueAsyncResult',
                    sprintf(
                        "%s:%s",
                        RequestSecurityTokenResponse2005::getNamespacePrefix(),
                        RequestSecurityTokenResponse2005::getLocalName(),
                    ),
                )],
            ),
            new Message(
                'IWSTrust13Async_Trust13IssueAsync_InputMessage',
                [new Part(
                    'request',
                    sprintf(
                        "%s:%s",
                        RequestSecurityToken13::getNamespacePrefix(),
                        RequestSecurityToken13::getLocalName(),
                    ),
                )],
            ),
            new Message(
                'IWSTrust13Async_Trust13IssueAsync_OutputMessage',
                [new Part(
                    'Trust13IssueAsyncResult',
                    sprintf(
                        "%s:%s",
                        RequestSecurityTokenResponseCollection13::getNamespacePrefix(),
                        RequestSecurityTokenResponseCollection13::getLocalName(),
                    ),
                )],
            ),
        ];
    }


    /**
     * This method builds the wsdl:portType elements
     *
     * @param \SimpleSAML\WSSecurity\XML\wsdl\PortType[]
     */
    private function getPortTypes(): array
    {
        return [
            new PortType('IWSTrustFeb2005Async', [
                new PortTypeOperation(
                    name: 'TrustFeb2005IssueAsync',
                    input: new Input(
                        message: 'tns:IWSTrustFeb2005Async_TrustFeb2005IssueAsync_InputMessage',
                        attributes: [
                            new XMLAttribute(
                                C::NS_WSDL_ADDR,
                                'wsaw',
                                'Action',
                                'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                            ),
                        ],
                    ),
                    output: new Output(
                        message: 'tns:IWSTrustFeb2005Async_TrustFeb2005IssueAsync_OutputMessage',
                        attributes: [
                            new XMLAttribute(
                                C::NS_WSDL_ADDR,
                                'wsaw',
                                'Action',
                                'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                            ),
                        ],
                    ),
                ),
            ]),
            new PortType('IWSTrust13Async', [
                new PortTypeOperation(
                    name: 'Trust13IssueAsync',
                    input: new Input(
                        message: 'tns:IWSTrust13Async_Trust13IssueAsync_InputMessage',
                        attributes: [
                            new XMLAttribute(
                                C::NS_WSDL_ADDR,
                                'wsaw',
                                'Action',
                                'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue',
                            ),
                        ],
                    ),
                    output: new Output(
                        message: 'tns:IWSTrust13Async_Trust13IssueAsync_OutputMessage',
                        attributes: [
                            new XMLAttribute(
                                C::NS_WSDL_ADDR,
                                'wsaw',
                                'Action',
                                'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal',
                            ),
                        ],
                    ),
                ),
            ]),
        ];
    }
}
