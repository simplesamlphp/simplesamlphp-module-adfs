<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs;

use SimpleSAML\Module;
use SimpleSAML\Module\adfs\Trust;
use SimpleSAML\WebServices\Addressing\Constants as C;
use SimpleSAML\WebServices\Addressing\XML\wsa_200508\Address;
use SimpleSAML\WebServices\Addressing\XML\wsa_200508\EndpointReference;
use SimpleSAML\WebServices\Policy\XML\wsp_200409\PolicyReference;
use SimpleSAML\WebServices\Trust\XML\wst_200502\RequestSecurityToken as RequestSecurityToken2005;
use SimpleSAML\WebServices\Trust\XML\wst_200502\RequestSecurityTokenResponse as RequestSecurityTokenResponse2005;
//use SimpleSAML\WebServices\Trust\XML\wst_200512\RequestSecurityToken as RequestSecurityToken13;
//use SimpleSAML\WebServices\Trust\XML\wst_200512\RequestSecurityTokenResponseCollection as \
//RequestSecurityTokenResponseCollection13;
use SimpleSAML\WSDL\Enumeration\StyleChoiceEnum;
use SimpleSAML\WSDL\Enumeration\UseChoiceEnum;
use SimpleSAML\WSDL\Type\StyleChoiceValue;
use SimpleSAML\WSDL\Type\UseChoiceValue;
use SimpleSAML\WSDL\XML\soap12\Address as Soap12Address;
use SimpleSAML\WSDL\XML\soap12\Binding as Soap12Binding;
use SimpleSAML\WSDL\XML\soap12\Body as Soap12Body;
use SimpleSAML\WSDL\XML\soap12\Operation as Soap12Operation;
use SimpleSAML\WSDL\XML\wsdl\Binding;
use SimpleSAML\WSDL\XML\wsdl\BindingOperation;
use SimpleSAML\WSDL\XML\wsdl\BindingOperationInput;
use SimpleSAML\WSDL\XML\wsdl\BindingOperationOutput;
use SimpleSAML\WSDL\XML\wsdl\Definitions;
use SimpleSAML\WSDL\XML\wsdl\Input;
use SimpleSAML\WSDL\XML\wsdl\Message;
use SimpleSAML\WSDL\XML\wsdl\Output;
use SimpleSAML\WSDL\XML\wsdl\Part;
use SimpleSAML\WSDL\XML\wsdl\Port;
use SimpleSAML\WSDL\XML\wsdl\PortType;
use SimpleSAML\WSDL\XML\wsdl\PortTypeOperation;
use SimpleSAML\WSDL\XML\wsdl\Service;
use SimpleSAML\XML\Attribute as XMLAttribute;
use SimpleSAML\XMLSchema\Type\AnyURIValue;
use SimpleSAML\XMLSchema\Type\NCNameValue;
use SimpleSAML\XMLSchema\Type\QNameValue;

//use SimpleSAML\XML\Chunk;
//use SimpleSAML\XML\DOMDocumentFactory;
use function array_merge;

/**
 * Common code for building MetaExchange (mex) documents based on the available configuration.
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */
class MetadataExchange
{
    /**
     * Constructor.
     */
    public function __construct()
    {
    }


    /**
     * Build a mex document
     *
     * @return \SimpleSAML\WSDL\XML\wsdl\Definitions
     */
    public function buildDocument(): Definitions
    {
        return new Definitions(
            targetNamespace: AnyURIValue::fromString(
                'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
            ),
            name: NCNameValue::fromString('SecurityTokenService'),
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
     * @return \SimpleSAML\WebServices\Policy\XML\wsp_200409\Policy[]
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
     * @return \SimpleSAML\WSSL\XML\wsdl\Types[]
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
     * @return \SimpleSAML\WSDL\XML\wsdl\Message[]
     */
    private function getMessages(): array
    {
        return [
            new Message(
                NCNameValue::fromString('IWSTrustFeb2005Async_TrustFeb2005IssueAsync_InputMessage'),
                [new Part(
                    NCNameValue::fromString('request'),
                    QNameValue::fromParts(
                        NCNameValue::fromString(RequestSecurityToken2005::getLocalName()),
                        AnyURIValue::fromString(RequestSecurityToken2005::getNamespaceUri()),
                        NCNameValue::fromString(RequestSecurityToken2005::getNamespacePrefix()),
                    ),
                )],
            ),
            new Message(
                NCNameValue::fromString('IWSTrustFeb2005Async_TrustFeb2005IssueAsync_OutputMessage'),
                [new Part(
                    NCNameValue::fromString('TrustFeb2005IssueAsyncResult'),
                    QNameValue::fromParts(
                        NCNameValue::fromString(RequestSecurityTokenResponse2005::getLocalName()),
                        AnyURIValue::fromString(RequestSecurityTokenResponse2005::getNamespaceUri()),
                        NCNameValue::fromString(RequestSecurityTokenResponse2005::getNamespacePrefix()),
                    ),
                )],
            ),
/*
            new Message(
                NCNameValue::fromString('IWSTrust13Async_Trust13IssueAsync_InputMessage'),
                [new Part(
                    NCNameValue::fromString('request'),
                    QNameValue::fromParts(
                        NCNameValue::fromString(RequestSecurityToken13::getLocalName()),
                        AnyURIValue::fromString(RequestSecurityToken13::getNamespaceUri()),
                        NCNameValue::fromString(RequestSecurityToken13::getNamespacePrefix()),
                    ),
                )],
            ),
            new Message(
                NCNameValue::fromString('IWSTrust13Async_Trust13IssueAsync_OutputMessage'),
                [new Part(
                    NCNameValue::fromString('Trust13IssueAsyncResult'),
                    QNameValue::fromParts(
                        NCNameValue::fromString(RequestSecurityTokenResponseCollection13::getLocalName()),
                        AnyURIValue::fromString(RequestSecurityTokenResponseCollection13::getNamespaceUri()),
                        NCNameValue::fromString(RequestSecurityTokenResponseCollection13::getNamespacePrefix()),
                    ),
                )],
            ),
*/
        ];
    }


    /**
     * This method builds the wsdl:portType elements
     *
     * @return \SimpleSAML\WSDL\XML\wsdl\PortType[]
     */
    private function getPortTypes(): array
    {
        return [
            new PortType(
                NCNameValue::fromString('IWSTrustFeb2005Async'),
                [
                    new PortTypeOperation(
                        name: NCNameValue::fromString('TrustFeb2005IssueAsync'),
                        input: new Input(
                            message: QNameValue::fromParts(
                                NCNameValue::fromString('IWSTrustFeb2005Async_TrustFeb2005IssueAsync_InputMessage'),
                                AnyURIValue::fromString(
                                    'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
                                ),
                                NCNameValue::fromString('tns'),
                            ),
                            attributes: [
                                new XMLAttribute(
                                    C::NS_ADDR_WSDL,
                                    'wsaw',
                                    'Action',
                                    AnyURIValue::fromString('http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue'),
                                ),
                            ],
                        ),
                        output: new Output(
                            message: QNameValue::fromParts(
                                NCNameValue::fromString('IWSTrustFeb2005Async_TrustFeb2005IssueAsync_OutputMessage'),
                                AnyURIValue::fromString(
                                    'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
                                ),
                                NCNameValue::fromString('tns'),
                            ),
                            attributes: [
                                new XMLAttribute(
                                    C::NS_ADDR_WSDL,
                                    'wsaw',
                                    'Action',
                                    AnyURIValue::fromString('http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue'),
                                ),
                            ],
                        ),
                    ),
                ],
            ),
/*
            new PortType(
                NCNameValue::fromString('IWSTrust13Async'),
                [
                    new PortTypeOperation(
                        name: NCNameValue::fromString('Trust13IssueAsync'),
                        input: new Input(
                            message: QNameValue::fromParts(
                                NCNameValue::fromString('IWSTrust13Async_Trust13IssueAsync_InputMessage'),
                                AnyURIValue::fromString(
                                    'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
                                ),
                                NCNameValue::fromString('tns'),
                            ),
                            attributes: [
                                new XMLAttribute(
                                    C::NS_ADDR_WSDL,
                                    'wsaw',
                                    'Action',
                                    'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue',
                                ),
                            ],
                        ),
                        output: new Output(
                            message: QNameValue::fromParts(
                                NCNameValue::fromString('IWSTrust13Async_Trust13IssueAsync_OutputMessage'),
                                AnyURIValue::fromString(
                                    'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
                                ),
                                NCNameValue::fromString('tns'),
                            ),
                            attributes: [
                                new XMLAttribute(
                                    C::NS_ADDR_WSDL,
                                    'wsaw',
                                    'Action',
                                    'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal',
                                ),
                            ],
                        ),
                    ),
                ],
            ),
*/
        ];
    }


    /**
     * This method builds the wsdl:binding elements
     *
     * @return \SimpleSAML\WSDL\XML\wsdl\Binding[]
     */
    private function getBindings(): array
    {
        return [
            new Binding(
                name: NCNameValue::fromString('CertificateWSTrustBinding_IWSTrustFeb2005Async'),
                type: QNameValue::fromParts(
                    NCNameValue::fromString('IWSTrustFeb2005Async'),
                    AnyURIValue::fromString('http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice'),
                    NCNameValue::fromString('tns'),
                ),
                operation: [
                    new BindingOperation(
                        name: NCNameValue::fromString('TrustFeb2005IssueAsync'),
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                soapAction: AnyURIValue::fromString(
                                    'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                ),
                                style: StyleChoiceValue::fromEnum(StyleChoiceEnum::Document),
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        AnyURIValue::fromString('#CertificateWSTrustBinding_IWSTrustFeb2005Async_policy'),
                    ),
                    new Soap12Binding(
                        AnyURIValue::fromString('http://schemas.xmlsoap.org/soap/http'),
                    ),
                ],
            ),
            new Binding(
                name: NCNameValue::fromString('CertificateWSTrustBinding_IWSTrustFeb2005Async1'),
                type: QNameValue::fromParts(
                    NCNameValue::fromString('IWSTrustFeb2005Async'),
                    AnyURIValue::fromString('http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice'),
                    NCNameValue::fromString('tns'),
                ),
                operation: [
                    new BindingOperation(
                        name: NCNameValue::fromString('TrustFeb2005IssueAsync'),
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                soapAction: AnyURIValue::fromString(
                                    'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                ),
                                style: StyleChoiceValue::fromEnum(StyleChoiceEnum::Document),
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: AnyURIValue::fromString('#CertificateWSTrustBinding_IWSTrustFeb2005Async1_policy'),
                    ),
                    new Soap12Binding(
                        AnyURIValue::fromString('http://schemas.xmlsoap.org/soap/http'),
                    ),
                ],
            ),
            new Binding(
                name: NCNameValue::fromString('UserNameWSTrustBinding_IWSTrustFeb2005Async'),
                type: QNameValue::fromParts(
                    NCNameValue::fromString('IWSTrustFeb2005Async'),
                    AnyURIValue::fromString('http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice'),
                    NCNameValue::fromString('tns'),
                ),
                operation: [
                    new BindingOperation(
                        name: NCNameValue::fromString('TrustFeb2005IssueAsync'),
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                soapAction: AnyURIValue::fromString(
                                    'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                ),
                                style: StyleChoiceValue::fromEnum(StyleChoiceEnum::Document),
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: AnyURIValue::fromString('#UserNameWSTrustBinding_IWSTrustFeb2005Async_policy'),
                    ),
                    new Soap12Binding(AnyURIValue::fromString('http://schemas.xmlsoap.org/soap/http')),
                ],
            ),
            new Binding(
                name: NCNameValue::fromString('IssuedTokenWSTrustBinding_IWSTrustFeb2005Async'),
                type: QNameValue::fromParts(
                    NCNameValue::fromString('IWSTrustFeb2005Async'),
                    AnyURIValue::fromString('http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice'),
                    NCNameValue::fromString('tns'),
                ),
                operation: [
                    new BindingOperation(
                        name: NCNameValue::fromString('TrustFeb2005IssueAsync'),
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                soapAction: AnyURIValue::fromString(
                                    'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                ),
                                style: StyleChoiceValue::fromEnum(StyleChoiceEnum::Document),
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: AnyURIValue::fromString('#IssuedTokenWSTrustBinding_IWSTrustFeb2005Async_policy'),
                    ),
                    new Soap12Binding(AnyURIValue::fromString('http://schemas.xmlsoap.org/soap/http')),
                ],
            ),
            new Binding(
                name: NCNameValue::fromString('IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1'),
                type: QNameValue::fromParts(
                    NCNameValue::fromString('IWSTrustFeb2005Async'),
                    AnyURIValue::fromString('http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice'),
                    NCNameValue::fromString('tns'),
                ),
                operation: [
                    new BindingOperation(
                        name: NCNameValue::fromString('TrustFeb2005IssueAsync'),
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                soapAction: AnyURIValue::fromString(
                                    'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                ),
                                style: StyleChoiceValue::fromEnum(StyleChoiceEnum::Document),
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: AnyURIValue::fromString('#IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1_policy'),
                    ),
                    new Soap12Binding(AnyURIValue::fromString('http://schemas.xmlsoap.org/soap/http')),
                ],
            ),
/*
            new Binding(
                name: NCNameValue::fromString('CertificateWSTrustBinding_IWSTrust13Async'),
                type: QNameValue::fromParts(
                    NCNameValue::fromString('IWSTrust13Async'),
                    AnyURIValue::fromString('http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice'),
                    NCNameValue::fromString('tns'),
                ),
                operation: [
                    new BindingOperation(
                        name: NCNameValue::fromString('Trust13IssueAsync'),
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                soapAction: AnyURIValue::fromString(
                                    'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                ),
                                style: StyleChoiceValue::fromEnum(StyleChoiceEnum::Document),
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: AnyURIValue::fromString('#CertificateWSTrustBinding_IWSTrust13Async_policy'),
                    ),
                    new Soap12Binding(AnyURIValue::fromString('http://schemas.xmlsoap.org/soap/http')),
                ],
            ),
            new Binding(
                name: NCNameValue::fromString('UserNameWSTrustBinding_IWSTrust13Async'),
                type: QNameValue::fromParts(
                    NCNameValue::fromString('IWSTrust13Async'),
                    AnyURIValue::fromString('http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice'),
                    NCNameValue::fromString('tns'),
                ),
                operation: [
                    new BindingOperation(
                        name: NCNameValue::fromString('Trust13IssueAsync'),
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                soapAction: AnyURIValue::fromString(
                                    'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                ),
                                style: StyleChoiceValue::fromEnum(StyleChoiceEnum::Document),
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: AnyURIValue::fromString('#UserNameWSTrustBinding_IWSTrust13Async_policy'),
                    ),
                    new Soap12Binding(AnyURIValue::fromString('http://schemas.xmlsoap.org/soap/http')),
                ],
            ),
            new Binding(
                name: NCNameValue::fromString('IssuedTokenWSTrustBinding_IWSTrust13Async'),
                type: QNameValue::fromParts(
                    NCNameValue::fromString('IWSTrust13Async'),
                    AnyURIValue::fromString('http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice'),
                    NCNameValue::fromString('tns'),
                ),
                operation: [
                    new BindingOperation(
                        name: 'Trust13IssueAsync',
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                soapAction: AnyURIValue::fromString(
                                    'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                ),
                                style: StyleChoiceValue::fromEnum(StyleChoiceEnum::Document),
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: AnyURIValue::fromString('#IssuedTokenWSTrustBinding_IWSTrust13Async_policy'),
                    ),
                    new Soap12Binding(AnyURIValue::fromString('http://schemas.xmlsoap.org/soap/http')),
                ],
            ),
            new Binding(
                name: NCNameValue::fromString('IssuedTokenWSTrustBinding_IWSTrust13Async1'),
                type: QNameValue::fromParts(
                    NCNameValue::fromString('IWSTrust13Async'),
                    AnyURIValue::fromString('http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice'),
                    NCNameValue::fromString('tns'),
                ),
                operation: [
                    new BindingOperation(
                        name: 'Trust13IssueAsync',
                        input: new BindingOperationInput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        output: new BindingOperationOutput(
                            elements: [
                                new Soap12Body(
                                    use: UseChoiceValue::fromEnum(UseChoiceEnum::Literal),
                                ),
                            ],
                        ),
                        elements: [
                            new Soap12Operation(
                                soapAction: AnyURIValue::fromString(
                                    'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                                ),
                                style: StyleChoiceValue::fromEnum(StyleChoiceEnum::Document),
                            ),
                        ],
                    ),
                ],
                elements: [
                    new PolicyReference(
                        URI: AnyURIValue::fromString('#IssuedTokenWSTrustBinding_IWSTrust13Async1_policy'),
                    ),
                    new Soap12Binding(AnyURIValue::fromString('http://schemas.xmlsoap.org/soap/http')),
                ],
            ),
*/
        ];
    }


    /**
     * This method builds the wsdl:service elements
     *
     * @return \SimpleSAML\WSDL\XML\wsdl\Service[]
     */
    private function getServices(): array
    {
        $defaultEndpoint = Module::getModuleURL('adfs/ws-trust/2005/services/');

        return [
            new Service(
                name: NCNameValue::fromString('SecurityTokenService'),
                ports: [
                    new Port(
                        name: NCNameValue::fromString('CertificateWSTrustBinding_IWSTrustFeb2005Async'),
                        binding: QNameValue::fromParts(
                            NCNameValue::fromString('CertificateWSTrustBinding_IWSTrustFeb2005Async'),
                            AnyURIValue::fromString(
                                'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
                            ),
                            NCNameValue::fromString('tns'),
                        ),
                        elements: [
                            new Soap12Address(AnyURIValue::fromString($defaultEndpoint . 'certificatemixed')),
                            new EndpointReference(
                                new Address(AnyURIValue::fromString($defaultEndpoint . 'certificatemixed')),
                            ),
                        ],
                    ),
                    new Port(
                        name: NCNameValue::fromString('CertificateWSTrustBinding_IWSTrustFeb2005Async1'),
                        binding: QNameValue::fromParts(
                            NCNameValue::fromString('CertificateWSTrustBinding_IWSTrustFeb2005Async1'),
                            AnyURIValue::fromString(
                                'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
                            ),
                            NCNameValue::fromString('tns'),
                        ),
                        elements: [
                            new Soap12Address(AnyURIValue::fromString($defaultEndpoint . 'certificatetransport')),
                            new EndpointReference(
                                new Address(AnyURIValue::fromString($defaultEndpoint . 'certificatetransport')),
                            ),
                        ],
                    ),
                    new Port(
                        name: NCNameValue::fromString('UserNameWSTrustBinding_IWSTrustFeb2005Async'),
                        binding: QNameValue::fromParts(
                            NCNameValue::fromString('UserNameWSTrustBinding_IWSTrustFeb2005Async'),
                            AnyURIValue::fromString(
                                'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
                            ),
                            NCNameValue::fromString('tns'),
                        ),
                        elements: [
                            new Soap12Address(AnyURIValue::fromString($defaultEndpoint . 'usernamemixed')),
                            new EndpointReference(
                                new Address(AnyURIValue::fromString($defaultEndpoint . 'usernamemixed')),
                            ),
                        ],
                    ),
                    new Port(
                        name: NCNameValue::fromString('IssuedTokenWSTrustBinding_IWSTrustFeb2005Async'),
                        binding: QNameValue::fromParts(
                            NCNameValue::fromString('IssuedTokenWSTrustBinding_IWSTrustFeb2005Async'),
                            AnyURIValue::fromString(
                                'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
                            ),
                            NCNameValue::fromString('tns'),
                        ),
                        elements: [
                            new Soap12Address(
                                AnyURIValue::fromString($defaultEndpoint . 'issuedtokenmixedasymmetricbasic256'),
                            ),
                            new EndpointReference(
                                new Address(
                                    AnyURIValue::fromString($defaultEndpoint . 'issuedtokenmixedasymmetricbasic256'),
                                ),
                            ),
                        ],
                    ),
                    new Port(
                        name: NCNameValue::fromString('IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1'),
                        binding: QNameValue::fromParts(
                            NCNameValue::fromString('IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1'),
                            AnyURIValue::fromString(
                                'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
                            ),
                            NCNameValue::fromString('tns'),
                        ),
                        elements: [
                            new Soap12Address(
                                AnyURIValue::fromString($defaultEndpoint . 'issuedtokenmixedsymmetricbasic256'),
                            ),
                            new EndpointReference(
                                new Address(
                                    AnyURIValue::fromString($defaultEndpoint . 'issuedtokenmixedsymmetricbasic256'),
                                ),
                            ),
                        ],
                    ),
                /*
                    new Port(
                        name: NCNameValue::fromString('CertificateWSTrustBinding_IWSTrust13Async'),
                        binding: QNameValue::fromParts(
                            NCNameValue::fromString('CertificateWSTrustBinding_IWSTrust13Async'),
                            AnyURIValue::fromString(
                                'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
                            ),
                            NCNameValue::fromString('tns'),
                        ),
                        elements: [
                            new Soap12Address(AnyURIValue::fromString($defaultEndpoint . '13/certificatemixed')),
                            new EndpointReference(
                                new Address(AnyURIValue::fromString($defaultEndpoint . '13/certificatemixed')),
                            ),
                        ],
                    ),
                    new Port(
                        name: NCNameValue::fromString('UserNameWSTrustBinding_IWSTrust13Async'),
                        binding: QNameValue::fromParts(
                            NCNameValue::fromString('UserNameWSTrustBinding_IWSTrust13Async'),
                            AnyURIValue::fromString(
                                'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
                            ),
                            NCNameValue::fromString('tns'),
                        ),
                        elements: [
                            new Soap12Address(AnyURIValue::fromString($defaultEndpoint . '13/usernamemixed')),
                            new EndpointReference(
                                new Address(AnyURIValue::fromString($defaultEndpoint . '13/usernamemixed')),
                            ),
                        ],
                    ),
                    new Port(
                        name: NCNameValue::fromString('IssuedTokenWSTrustBinding_IWSTrust13Async'),
                        binding: QNameValue::fromParts(
                            NCNameValue::fromString('IssuedTokenWSTrustBinding_IWSTrust13Async'),
                            AnyURIValue::fromString(
                                'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
                            ),
                            NCNameValue::fromString('tns'),
                        ),
                        elements: [
                            new Soap12Address(
                                AnyURIValue::fromString($defaultEndpoint . '13/issuedtokenmixedasymmetricbasic256'),
                            ),
                            new EndpointReference(
                                new Address(
                                    AnyURIValue::fromString($defaultEndpoint . '13/issuedtokenmixedasymmetricbasic256'),
                                ),
                            ),
                        ],
                    ),
                    new Port(
                        name: NCNameValue::fromString('IssuedTokenWSTrustBinding_IWSTrust13Async1'),
                        binding: QNameValue::fromParts(
                            NCNameValue::fromString('IssuedTokenWSTrustBinding_IWSTrust13Async1'),
                            AnyURIValue::fromString(
                                'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
                            ),
                            NCNameValue::fromString('tns'),
                        ),
                        elements: [
                            new Soap12Address(
                                AnyURIValue::fromString($defaultEndpoint . '13/issuedtokenmixedsymmetricbasic256'),
                            ),
                            new EndpointReference(
                                new Address(
                                    AnyURIValue::fromString($defaultEndpoint . '13/issuedtokenmixedsymmetricbasic256'),
                                ),
                            ),
                        ],
                    ),
                */
                ],
            ),
        ];
    }
}
