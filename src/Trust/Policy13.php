<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\Trust;

use SimpleSAML\WSSecurity\Constants as C;
/*
use SimpleSAML\WSSecurity\XML\mssp\RsaToken;
use SimpleSAML\WSSecurity\XML\sp_200507\AlgorithmSuite;
use SimpleSAML\WSSecurity\XML\sp_200507\Basic256;
use SimpleSAML\WSSecurity\XML\sp_200507\EndorsingSupportingTokens;
use SimpleSAML\WSSecurity\XML\sp_200507\Header;
use SimpleSAML\WSSecurity\XML\sp_200507\HttpsToken;
use SimpleSAML\WSSecurity\XML\sp_200507\IncludeTimestamp;
use SimpleSAML\WSSecurity\XML\sp_200507\IncludeToken;
use SimpleSAML\WSSecurity\XML\sp_200507\IssuedToken;
use SimpleSAML\WSSecurity\XML\sp_200507\Layout;
use SimpleSAML\WSSecurity\XML\sp_200507\MustSupportIssuedTokens;
use SimpleSAML\WSSecurity\XML\sp_200507\MustSupportRefThumbprint;
use SimpleSAML\WSSecurity\XML\sp_200507\RequestSecurityTokenTemplate;
use SimpleSAML\WSSecurity\XML\sp_200507\RequireClientEntropy;
use SimpleSAML\WSSecurity\XML\sp_200507\RequireInternalReference;
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
use SimpleSAML\WSSecurity\XML\wsaw\UsingAddressing;
use SimpleSAML\WSSecurity\XML\wsdl\Definitions;
use SimpleSAML\WSSecurity\XML\wsp\All;
use SimpleSAML\WSSecurity\XML\wsp\ExactlyOne;
use SimpleSAML\WSSecurity\XML\wsp\Policy;
use SimpleSAML\WSSecurity\XML\wst\CanonicalizationAlgorithm;
use SimpleSAML\WSSecurity\XML\wst\EncryptionAlgorithm;
use SimpleSAML\WSSecurity\XML\wst\EncryptWith;
use SimpleSAML\WSSecurity\XML\wst\KeyType;
use SimpleSAML\WSSecurity\XML\wst\KeyTypeEnum;
use SimpleSAML\WSSecurity\XML\wst\SignatureAlgorithm;
*/
use SimpleSAML\XML\Attribute as XMLAttribute;

/**
 * @package simplesamlphp/simplesamlphp-module-adfs
 */
class Policy13
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
     * This method builds the wsp:Policy elements
     *
     * @param \SimpleSAML\WSSecurity\XML\wsp\Policy[]
     */
    public function getPolicies(): array
    {
        return [
//            $this->getCertificateWSTrustBinding(),
//            $this->getUserNameWSTrustBindingPolicy(),
//            $this->getIssuedTokenWSTrustBinding(),
//            $this->getIssuedTokenWSTrustBinding1(),
        ];
    }


    /**
     * This method builds the CertificateWSTrustBinding policy.
     *
     * @param \SimpleSAML\WSSecurity\XML\wsp\Policy
     */
    private function getCertificateWSTrustBinding(): Policy
    {
/*
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
*/
    }


    /**
     * This method builds the UserNameWSTrustBinding policy.
     *
     * @param \SimpleSAML\WSSecurity\XML\wsp\Policy
     */
    private function getUserNameWSTrustBindingPolicy(): Policy
    {
/*
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
*/
    }


    /**
     * This method builds the IssuedTokenWSTrustBinding policy.
     *
     * @param \SimpleSAML\WSSecurity\XML\wsp\Policy
     */
    private function getIssuedTokenWSTrustBinding(): Policy
    {
/*
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
                    new IssuedToken(
                        elts: [
                            new RequestSecurityTokenTemplate(
                                elts: [
                                    new KeyType([KeyTypeEnum::PublicKey]),
                                    new EncryptWith(C::KEY_TRANSPORT_OAEP_MGF1P),
                                    new SignatureAlgorithm(C::SIG_RSA_SHA1),
                                    new CanonicalizationAlgorithm(C::C14N_EXCLUSIVE_WITHOUT_COMMENTS),
                                    new EncryptionAlgorithm(C::BLOCK_ENC_AES256),
                                ],
                            ),
                            new Policy(
                                children: [
                                    new RequireInternalReference(),
                                ],
                            ),
                        ],
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
            Id: new XMLAttribute(C::NS_SEC_UTIL, 'wsu', 'Id', 'IssuedTokenWSTrustBinding_IWSTrustFeb2005Async_policy'),
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
*/
    }


    /**
     * This method builds the IssuedTokenWSTrustBinding1 policy.
     *
     * @param \SimpleSAML\WSSecurity\XML\wsp\Policy
     */
    private function getIssuedTokenWSTrustBinding1(): Policy
    {
/*
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
                    new IssuedToken(
                        elts: [
                            new RequestSecurityTokenTemplate(
                                elts: [
                                    new KeyType([KeyTypeEnum::SymmetricKey]),
                                    new KeySize('256'),
                                    new EncryptWith(C::KEY_TRANSPORT_OAEP_MGF1P),
                                    new SignatureAlgorithm(C::SIG_HMAC_SHA1),
                                    new CanonicalizationAlgorithm(C::C14N_EXCLUSIVE_WITHOUT_COMMENTS),
                                    new EncryptionAlgorithm(C::BLOCK_ENC_AES256),
                                ],
                            ),
                            new Policy(
                                children: [
                                    new RequireInternalReference(),
                                ],
                            ),
                        ],
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

        return new Policy(
            Id: new XMLAttribute(C::NS_SEC_UTIL, 'wsu', 'Id', 'IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1_policy'),
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
*/
    }
}
