<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs;

use SimpleSAML\Module;
use SimpleSAML\Module\adfs\Trust;
use SimpleSAML\WSDL\XML\soap12\{
    Address as Soap12Address,
    Binding as Soap12Binding,
    Body as Soap12Body,
    Operation as Soap12Operation,
};
use SimpleSAML\WSDL\XML\wsdl\{
    Binding,
    BindingOperation,
    BindingOperationInput,
    BindingOperationOutput,
    Definitions,
    Input,
    Message,
    Output,
    Part,
    Port,
    PortType,
    PortTypeOperation,
    Service,
    Types,
};
use SimpleSAML\WSSecurity\Constants as C;
use SimpleSAML\WSSecurity\XML\wsa_200508\{Address, EndpointReference};
use SimpleSAML\WSSecurity\XML\wsp\PolicyReference;
use SimpleSAML\WSSecurity\XML\wst_200502\{
    RequestSecurityToken as RequestSecurityToken2005,
    RequestSecurityTokenResponse as RequestSecurityTokenResponse2005,
};
use SimpleSAML\WSSecurity\XML\wst_200512\{
    RequestSecurityToken as RequestSecurityToken13,
    RequestSecurityTokenResponseCollection as RequestSecurityTokenResponseCollection13,
};
use SimpleSAML\XML\Attribute as XMLAttribute;

//use SimpleSAML\XML\Chunk;
//use SimpleSAML\XML\DOMDocumentFactory;

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
            //import: [],
            //types: $this->getTypes(),
            message: $this->getMessages(),
            portType: $this->getPortTypes(),
            binding: $this->getBindings(),
            service: $this->getServices(),
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
            //$policy13->getPolicies(),
        );
    }


    /**
     * This method builds the wsdl:types elements
     *
     * @param \SimpleSAML\WSSecurity\XML\wsdl\Types[]
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
     */


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
/*
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
*/
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
                                'http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue',
                            ),
                        ],
                    ),
                ),
            ]),
/*
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
*/
        ];
    }


    /**
     * This method builds the wsdl:binding elements
     *
     * @param \SimpleSAML\WSSecurity\XML\wsdl\Binding[]
     */
    private function getBindings(): array
    {
        return [
            new Binding(
                name: 'CertificateWSTrustBinding_IWSTrustFeb2005Async',
                type: 'tns:IWSTrustFeb2005Async',
                operation: [
                    new BindingOperation(
                        name: 'TrustFeb2005IssueAsync',
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                null,
                                'document',
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: '#CertificateWSTrustBinding_IWSTrustFeb2005Async_policy',
                        DigestAlgorithm: null,
                    ),
                    new Soap12Binding('http://schemas.xmlsoap.org/soap/http'),
                ],
            ),
            new Binding(
                name: 'CertificateWSTrustBinding_IWSTrustFeb2005Async1',
                type: 'tns:IWSTrustFeb2005Async',
                operation: [
                    new BindingOperation(
                        name: 'TrustFeb2005IssueAsync',
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                null,
                                'document',
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: '#CertificateWSTrustBinding_IWSTrustFeb2005Async1_policy',
                        DigestAlgorithm: null,
                    ),
                    new Soap12Binding('http://schemas.xmlsoap.org/soap/http'),
                ],
            ),
            new Binding(
                name: 'UserNameWSTrustBinding_IWSTrustFeb2005Async',
                type: 'tns:IWSTrustFeb2005Async',
                operation: [
                    new BindingOperation(
                        name: 'TrustFeb2005IssueAsync',
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                null,
                                'document',
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: '#UserNameWSTrustBinding_IWSTrustFeb2005Async_policy',
                        DigestAlgorithm: null,
                    ),
                    new Soap12Binding('http://schemas.xmlsoap.org/soap/http'),
                ],
            ),
            new Binding(
                name: 'IssuedTokenWSTrustBinding_IWSTrustFeb2005Async',
                type: 'tns:IWSTrustFeb2005Async',
                operation: [
                    new BindingOperation(
                        name: 'TrustFeb2005IssueAsync',
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                null,
                                'document',
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: '#IssuedTokenWSTrustBinding_IWSTrustFeb2005Async_policy',
                        DigestAlgorithm: null,
                    ),
                    new Soap12Binding('http://schemas.xmlsoap.org/soap/http'),
                ],
            ),
            new Binding(
                name: 'IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1',
                type: 'tns:IWSTrustFeb2005Async',
                operation: [
                    new BindingOperation(
                        name: 'TrustFeb2005IssueAsync',
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                null,
                                'document',
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: '#IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1_policy',
                        DigestAlgorithm: null,
                    ),
                    new Soap12Binding('http://schemas.xmlsoap.org/soap/http'),
                ],
            ),
/*
            new Binding(
                name: 'CertificateWSTrustBinding_IWSTrust13Async',
                type: 'tns:IWSTrust13Async',
                operation: [
                    new BindingOperation(
                        name: 'Trust13IssueAsync',
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue',
                                null,
                                'document',
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: '#CertificateWSTrustBinding_IWSTrust13Async_policy',
                        DigestAlgorithm: null,
                    ),
                    new Soap12Binding('http://schemas.xmlsoap.org/soap/http'),
                ],
            ),
            new Binding(
                name: 'UserNameWSTrustBinding_IWSTrust13Async',
                type: 'tns:IWSTrust13Async',
                operation: [
                    new BindingOperation(
                        name: 'Trust13IssueAsync',
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue',
                                null,
                                'document',
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: '#UserNameWSTrustBinding_IWSTrust13Async_policy',
                        DigestAlgorithm: null,
                    ),
                    new Soap12Binding('http://schemas.xmlsoap.org/soap/http'),
                ],
            ),
            new Binding(
                name: 'IssuedTokenWSTrustBinding_IWSTrust13Async',
                type: 'tns:IWSTrust13Async',
                operation: [
                    new BindingOperation(
                        name: 'Trust13IssueAsync',
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue',
                                null,
                                'document',
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: '#IssuedTokenWSTrustBinding_IWSTrust13Async_policy',
                        DigestAlgorithm: null,
                    ),
                    new Soap12Binding('http://schemas.xmlsoap.org/soap/http'),
                ],
            ),
            new Binding(
                name: 'IssuedTokenWSTrustBinding_IWSTrust13Async1',
                type: 'tns:IWSTrust13Async',
                operation: [
                    new BindingOperation(
                        name: 'Trust13IssueAsync',
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(null, null, 'literal'),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue',
                                null,
                                'document',
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: '#IssuedTokenWSTrustBinding_IWSTrust13Async1_policy',
                        DigestAlgorithm: null,
                    ),
                    new Soap12Binding('http://schemas.xmlsoap.org/soap/http'),
                ],
            ),
*/
        ];
    }


    /**
     * This method builds the wsdl:service elements
     *
     * @param \SimpleSAML\WSSecurity\XML\wsdl\Service[]
     */
    private function getServices(): array
    {
        $defaultEndpoint = Module::getModuleURL('adfs/ws-trust/2005/services/');

        return [
            new Service(
                name: 'SecurityTokenService',
                ports: [
                    new Port(
                        name: 'CertificateWSTrustBinding_IWSTrustFeb2005Async',
                        binding: 'tns:CertificateWSTrustBinding_IWSTrustFeb2005Async',
                        elements: [
                            new Soap12Address($defaultEndpoint . 'certificatemixed'),
                            new EndpointReference(
                                new Address($defaultEndpoint . 'certificatemixed'),
                            ),
                        ],
                    ),
                    new Port(
                        name: 'CertificateWSTrustBinding_IWSTrustFeb2005Async1',
                        binding: 'tns:CertificateWSTrustBinding_IWSTrustFeb2005Async1',
                        elements: [
                            new Soap12Address($defaultEndpoint . 'certificatetransport'),
                            new EndpointReference(
                                new Address($defaultEndpoint . 'certificatetransport'),
                            ),
                        ],
                    ),
                    new Port(
                        name: 'UserNameWSTrustBinding_IWSTrustFeb2005Async',
                        binding: 'tns:UserNameWSTrustBinding_IWSTrustFeb2005Async',
                        elements: [
                            new Soap12Address($defaultEndpoint . 'usernamemixed'),
                            new EndpointReference(
                                new Address($defaultEndpoint . 'usernamemixed'),
                            ),
                        ],
                    ),
                    new Port(
                        name: 'IssuedTokenWSTrustBinding_IWSTrustFeb2005Async',
                        binding: 'tns:IssuedTokenWSTrustBinding_IWSTrustFeb2005Async',
                        elements: [
                            new Soap12Address($defaultEndpoint . 'issuedtokenmixedasymmetricbasic256'),
                            new EndpointReference(
                                new Address($defaultEndpoint . 'issuedtokenmixedasymmetricbasic256'),
                            ),
                        ],
                    ),
                    new Port(
                        name: 'IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1',
                        binding: 'tns:IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1',
                        elements: [
                            new Soap12Address($defaultEndpoint . 'issuedtokenmixedsymmetricbasic256'),
                            new EndpointReference(
                                new Address($defaultEndpoint . 'issuedtokenmixedsymmetricbasic256'),
                            ),
                        ],
                    ),
                /*
                    new Port(
                        name: 'CertificateWSTrustBinding_IWSTrust13Async',
                        binding: 'tns:CertificateWSTrustBinding_IWSTrust13Async',
                        elements: [
                            new Soap12Address($defaultEndpoint . '13/certificatemixed'),
                            new EndpointReference(
                                new Address($defaultEndpoint . '13/certificatemixed'),
                            ),
                        ],
                    ),
                    new Port(
                        name: 'UserNameWSTrustBinding_IWSTrust13Async',
                        binding: 'tns:UserNameWSTrustBinding_IWSTrust13Async',
                        elements: [
                            new Soap12Address($defaultEndpoint . '13/usernamemixed'),
                            new EndpointReference(
                                new Address($defaultEndpoint . '13/usernamemixed'),
                            ),
                        ],
                    ),
                    new Port(
                        name: 'IssuedTokenWSTrustBinding_IWSTrust13Async',
                        binding: 'tns:IssuedTokenWSTrustBinding_IWSTrust13Async',
                        elements: [
                            new Soap12Address($defaultEndpoint . '13/issuedtokenmixedasymmetricbasic256'),
                            new EndpointReference(
                                new Address($defaultEndpoint . '13/issuedtokenmixedasymmetricbasic256'),
                            ),
                        ],
                    ),
                    new Port(
                        name: 'IssuedTokenWSTrustBinding_IWSTrust13Async1',
                        binding: 'tns:IssuedTokenWSTrustBinding_IWSTrust13Async1',
                        elements: [
                            new Soap12Address($defaultEndpoint . '13/issuedtokenmixedsymmetricbasic256'),
                            new EndpointReference(
                                new Address($defaultEndpoint . '13/issuedtokenmixedsymmetricbasic256'),
                            ),
                        ],
                    ),
                */
                ],
            ),
        ];
    }
}
