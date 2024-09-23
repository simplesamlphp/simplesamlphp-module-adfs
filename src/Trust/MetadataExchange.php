<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\Trust;

use SimpleSAML\WSSecurity\Constants as C;
use SimpleSAML\WSSecurity\XML\mssp\RsaToken;
use SimpleSAML\WSSecurity\XML\sp_200507\AlgorithmSuite;
use SimpleSAML\WSSecurity\XML\sp_200507\Basic256;
use SimpleSAML\WSSecurity\XML\sp_200507\EndorsingSupportingTokens;
use SimpleSAML\WSSecurity\XML\sp_200507\Header;
use SimpleSAML\WSSecurity\XML\sp_200507\HttpsToken;
use SimpleSAML\WSSecurity\XML\sp_200507\IncludeTimestamp;
use SimpleSAML\WSSecurity\XML\sp_200507\IncludeToken;
use SimpleSAML\WSSecurity\XML\sp_200507\Layout;
use SimpleSAML\WSSecurity\XML\sp_200507\MustSupportIssuedTokens;
use SimpleSAML\WSSecurity\XML\sp_200507\MustSupportRefThumbprint;
use SimpleSAML\WSSecurity\XML\sp_200507\RequireClientEntropy;
use SimpleSAML\WSSecurity\XML\sp_200507\RequireServerEntropy;
use SimpleSAML\WSSecurity\XML\sp_200507\RequireThumbprintReference;
use SimpleSAML\WSSecurity\XML\sp_200507\SignedParts;
use SimpleSAML\WSSecurity\XML\sp_200507\SignedSupportingTokens;
use SimpleSAML\WSSecurity\XML\sp_200507\Strict;
use SimpleSAML\WSSecurity\XML\sp_200507\TransportBinding;
use SimpleSAML\WSSecurity\XML\sp_200507\TransportToken;
use SimpleSAML\WSSecurity\XML\sp_200507\Trust10;
use SimpleSAML\WSSecurity\XML\sp_200507\UsernameToken;
use SimpleSAML\WSSecurity\XML\sp_200507\Wss11;
use SimpleSAML\WSSecurity\XML\sp_200507\WssUsernameToken10;
use SimpleSAML\WSSecurity\XML\sp_200507\WssX509V3Token10;
use SimpleSAML\WSSecurity\XML\sp_200507\X509Token;
use SimpleSAML\WSSecurity\XML\wsdl\Definitions;
use SimpleSAML\WSSecurity\XML\wsp\All;
use SimpleSAML\WSSecurity\XML\wsp\ExactlyOne;
use SimpleSAML\WSSecurity\XML\wsp\Policy;
use SimpleSAML\WSSecurity\XML\wsaw\UsingAddressing;
use SimpleSAML\XML\Attribute as XMLAttribute;

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
    public function __construct(
    ) {
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
        return [
            $this->getCertificateWSTrustBinding(),
            $this->getCertificateWSTrustBinding1(),
            $this->getUserNameWSTrustBindingPolicy(),
        ];
    }


    /**
     * This method builds the CertificateWSTrustBinding policy.
     *
     * @param \SimpleSAML\WSSecurity\XML\wsp\Policy
     */
    private function getCertificateWSTrustBinding(): Policy
    {
        $transportBinding = new TransportBinding(
            elements: [new Policy(
                children: [
                    new TransportToken(
                        elements: [new Policy(
                            children: [new HttpsToken(false)],
                        )],
                    ),
                    new AlgorithmSuite(
                        elements: [new Policy(
                            children: [new Basic256()],
                        )],
                    ),
                    new Layout(
                        elements: [new Policy(
                            children: [new Strict()],
                        )],
                    ),
                    new IncludeTimestamp(),
                ],
            )],
        );

        $endorsingSupportingTokens = new EndorsingSupportingTokens(
            elements: [new Policy(
                children: [
                    new X509Token(
                        elts: [new Policy(
                            children: [
                                new RequireThumbprintReference(),
                                new WssX509V3Token10(),
                            ],
                        )],
                        namespacedAttributes: [
                            new XMLAttribute(
                                C::NS_SEC_POLICY_11,
                                'sp',
                                'IncludeToken',
                                IncludeToken::AlwaysToRecipient->value,
                            ),
                        ],
                    ),
                    new RsaToken(
                        namespacedAttributes: [
                            new XMLAttribute(C::NS_SEC_POLICY_11, 'sp', 'IncludeToken', IncludeToken::Never->value),
                            new XMLAttribute(C::NS_POLICY, 'wsp', 'Optional', 'true'),
                        ],
                    ),
                    new SignedParts(
                        header: [
                            new Header(
                                namespace: C::NS_ADDR_200508,
                                name: 'To',
                            ),
                        ],
                    ),
                ],
            )],
        );

        $wss11 = new Wss11(
            elements: [new Policy(
                children: [
                    new MustSupportRefThumbprint(),
                ],
            )],
        );

        $trust10 = new Trust10(
            elements: [new Policy(
                children: [
                    new MustSupportIssuedTokens(),
                    new RequireClientEntropy(),
                    new RequireServerEntropy(),
                ],
            )],
        );

        $usingAddressing = new UsingAddressing();

        return new Policy(
            Id: new XMLAttribute(C::NS_SEC_UTIL, 'wsu', 'Id', 'CertificateWSTrustBinding_IWSTrustFeb2005Async_policy'),
            operatorContent: [new ExactlyOne(
                operatorContent: [new All(
                   children: [
                       $transportBinding,
                       $endorsingSupportingTokens,
                       $wss11,
                       $trust10,
                       $usingAddressing,
                   ],
                )],
            )],
        );
    }


    /**
     * This method builds the CertificateWSTrustBinding1 policy.
     *
     * @param \SimpleSAML\WSSecurity\XML\wsp\Policy
     */
    private function getCertificateWSTrustBinding1(): Policy
    {
        $transportBinding = new TransportBinding(
            elements: [new Policy(
                children: [
                    new TransportToken(
                        elements: [new Policy(
                            children: [new HttpsToken(true)],
                        )],
                    ),
                    new AlgorithmSuite(
                        elements: [new Policy(
                            children: [new Basic256()],
                        )],
                    ),
                    new Layout(
                        elements: [new Policy(
                            children: [new Strict()],
                        )],
                    ),
                ],
            )],
        );

        $usingAddressing = new UsingAddressing();

        return new Policy(
            Id: new XMLAttribute(C::NS_SEC_UTIL, 'wsu', 'Id', 'CertificateWSTrustBinding_IWSTrustFeb2005Async1_policy'),
            operatorContent: [new ExactlyOne(
                operatorContent: [new All(
                   children: [
                       $transportBinding,
                       $usingAddressing,
                   ],
                )],
            )],
        );
    }


    /**
     * This method builds the UserNameWSTrustBinding policy.
     *
     * @param \SimpleSAML\WSSecurity\XML\wsp\Policy
     */
    private function getUserNameWSTrustBindingPolicy(): Policy
    {
        $transportBinding = new TransportBinding(
            elements: [new Policy(
                children: [
                    new TransportToken(
                        elements: [new Policy(
                            children: [new HttpsToken(false)],
                        )],
                    ),
                    new AlgorithmSuite(
                        elements: [new Policy(
                            children: [new Basic256()],
                        )],
                    ),
                    new Layout(
                        elements: [new Policy(
                            children: [new Strict()],
                        )],
                    ),
                    new IncludeTimestamp(),
                ],
            )],
        );

        $signedSupportingTokens = new SignedSupportingTokens(
            elements: [new Policy(
                children: [new UsernameToken(
                    elts: [new Policy(
                        children: [new WssUsernameToken10()],
                    )],
                    namespacedAttributes: [
                        new XMLAttribute(
                            C::NS_SEC_POLICY_11,
                            'sp',
                            'IncludeToken',
                            IncludeToken::AlwaysToRecipient->value,
                        ),
                    ],
                )],
            )],
        );

        $endorsingSupportingTokens = new EndorsingSupportingTokens(
            elements: [new Policy(
                children: [
                    new RsaToken(
                        namespacedAttributes: [
                            new XMLAttribute(C::NS_SEC_POLICY_11, 'sp', 'IncludeToken', IncludeToken::Never->value),
                            new XMLAttribute(C::NS_POLICY, 'wsp', 'Optional', 'true'),
                        ],
                    ),
                    new SignedParts(
                        header: [
                            new Header(
                                namespace: C::NS_ADDR_200508,
                                name: 'To',
                            ),
                        ],
                    ),
                ],
            )],
        );

        $wss11 = new Wss11(
            elements: [new Policy()],
        );

        $trust10 = new Trust10(
            elements: [new Policy(
                children: [
                    new MustSupportIssuedTokens(),
                    new RequireClientEntropy(),
                    new RequireServerEntropy(),
                ],
            )],
        );

        $usingAddressing = new UsingAddressing();

        return new Policy(
            Id: new XMLAttribute(C::NS_SEC_UTIL, 'wsu', 'Id', 'UserNameWSTrustBinding_IWSTrustFeb2005Async_policy'),
            operatorContent: [new ExactlyOne(
                operatorContent: [new All(
                   children: [
                       $transportBinding,
                       $signedSupportingTokens,
                       $endorsingSupportingTokens,
                       $wss11,
                       $trust10,
                       $usingAddressing,
                   ],
                )],
            )],
        );
    }
}
