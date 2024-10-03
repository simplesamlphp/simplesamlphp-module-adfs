<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\Trust;

use SimpleSAML\WSSecurity\Constants as C;
use SimpleSAML\WSSecurity\XML\sp_200702\AlgorithmSuite;
use SimpleSAML\WSSecurity\XML\sp_200702\Basic256;
use SimpleSAML\WSSecurity\XML\sp_200702\EndorsingSupportingTokens;
use SimpleSAML\WSSecurity\XML\sp_200702\Header;
use SimpleSAML\WSSecurity\XML\sp_200702\HttpsToken;
use SimpleSAML\WSSecurity\XML\sp_200702\IncludeTimestamp;
use SimpleSAML\WSSecurity\XML\sp_200702\IncludeToken;
use SimpleSAML\WSSecurity\XML\sp_200702\IssuedToken;
use SimpleSAML\WSSecurity\XML\sp_200702\KeyValueToken;
use SimpleSAML\WSSecurity\XML\sp_200702\Layout;
use SimpleSAML\WSSecurity\XML\sp_200702\MustSupportIssuedTokens;
use SimpleSAML\WSSecurity\XML\sp_200702\MustSupportRefThumbprint;
use SimpleSAML\WSSecurity\XML\sp_200702\RequestSecurityTokenTemplate;
use SimpleSAML\WSSecurity\XML\sp_200702\RequireClientEntropy;
use SimpleSAML\WSSecurity\XML\sp_200702\RequireInternalReference;
use SimpleSAML\WSSecurity\XML\sp_200702\RequireServerEntropy;
use SimpleSAML\WSSecurity\XML\sp_200702\RequireThumbprintReference;
use SimpleSAML\WSSecurity\XML\sp_200702\SignedParts;
use SimpleSAML\WSSecurity\XML\sp_200702\SignedEncryptedSupportingTokens;
use SimpleSAML\WSSecurity\XML\sp_200702\Strict;
use SimpleSAML\WSSecurity\XML\sp_200702\TransportBinding;
use SimpleSAML\WSSecurity\XML\sp_200702\TransportToken;
use SimpleSAML\WSSecurity\XML\sp_200702\Trust13;
use SimpleSAML\WSSecurity\XML\sp_200702\UsernameToken;
use SimpleSAML\WSSecurity\XML\sp_200702\Wss11;
use SimpleSAML\WSSecurity\XML\sp_200702\WssUsernameToken10;
use SimpleSAML\WSSecurity\XML\sp_200702\WssX509V3Token10;
use SimpleSAML\WSSecurity\XML\sp_200702\X509Token;
use SimpleSAML\WSSecurity\XML\wsaw\UsingAddressing;
use SimpleSAML\WSSecurity\XML\wsp\All;
use SimpleSAML\WSSecurity\XML\wsp\ExactlyOne;
use SimpleSAML\WSSecurity\XML\wsp\Policy;
use SimpleSAML\WSSecurity\XML\wst_200512\CanonicalizationAlgorithm;
use SimpleSAML\WSSecurity\XML\wst_200512\EncryptionAlgorithm;
use SimpleSAML\WSSecurity\XML\wst_200512\EncryptWith;
use SimpleSAML\WSSecurity\XML\wst_200512\KeySize;
use SimpleSAML\WSSecurity\XML\wst_200512\KeyType;
use SimpleSAML\WSSecurity\XML\wst_200512\KeyTypeEnum;
use SimpleSAML\WSSecurity\XML\wst_200512\KeyWrapAlgorithm;
use SimpleSAML\WSSecurity\XML\wst_200512\SignatureAlgorithm;
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
            $this->getCertificateWSTrustBinding(),
            $this->getUserNameWSTrustBindingPolicy(),
            $this->getIssuedTokenWSTrustBinding(),
            $this->getIssuedTokenWSTrustBinding1(),
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
                            children: [new HttpsToken()],
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
                                C::NS_SEC_POLICY_12,
                                'sp',
                                'IncludeToken',
                                IncludeToken::AlwaysToRecipient->value,
                            ),
                        ],
                    ),
                    new KeyValueToken(
                        namespacedAttributes: [
                            new XMLAttribute(C::NS_SEC_POLICY_12, 'sp', 'IncludeToken', IncludeToken::Never->value),
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

        $trust10 = new Trust13(
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
            Id: new XMLAttribute(C::NS_SEC_UTIL, 'wsu', 'Id', 'CertificateWSTrustBinding_IWSTrust13Async_policy'),
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
                            children: [new HttpsToken()],
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

        $signedEncryptedSupportingTokens = new SignedEncryptedSupportingTokens(
            elements: [new Policy(
                children: [new UsernameToken(
                    elts: [new Policy(
                        children: [new WssUsernameToken10()],
                    )],
                    namespacedAttributes: [
                        new XMLAttribute(
                            C::NS_SEC_POLICY_12,
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
                    new KeyValueToken(
                        namespacedAttributes: [
                            new XMLAttribute(C::NS_SEC_POLICY_12, 'sp', 'IncludeToken', IncludeToken::Never->value),
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

        $trust13 = new Trust13(
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
                       $signedEncryptedSupportingTokens,
                       $endorsingSupportingTokens,
                       $wss11,
                       $trust13,
                       $usingAddressing,
                   ],
                )],
            )],
        );
    }


    /**
     * This method builds the IssuedTokenWSTrustBinding policy.
     *
     * @param \SimpleSAML\WSSecurity\XML\wsp\Policy
     */
    private function getIssuedTokenWSTrustBinding(): Policy
    {
        $transportBinding = new TransportBinding(
            elements: [new Policy(
                children: [
                    new TransportToken(
                        elements: [new Policy(
                            children: [new HttpsToken()],
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
                        requestSecurityTokenTemplate: new RequestSecurityTokenTemplate(
                            elts: [
                                new KeyType([KeyTypeEnum::PublicKey]),
                                new KeyWrapAlgorithm(C::KEY_TRANSPORT_OAEP_MGF1P),
                                new EncryptWith(C::KEY_TRANSPORT_OAEP_MGF1P),
                                new SignatureAlgorithm(C::SIG_RSA_SHA1),
                                new CanonicalizationAlgorithm(C::C14N_EXCLUSIVE_WITHOUT_COMMENTS),
                                new EncryptionAlgorithm(C::BLOCK_ENC_AES256),
                            ],
                        ),
                        elts: [
                            new Policy(
                                children: [
                                    new RequireInternalReference(),
                                ],
                            ),
                        ],
                        namespacedAttributes: [
                            new XMLAttribute(
                                C::NS_SEC_POLICY_12,
                                'sp',
                                'IncludeToken',
                                IncludeToken::AlwaysToRecipient->value,
                            ),
                        ],
                    ),
                    new KeyValueToken(
                        namespacedAttributes: [
                            new XMLAttribute(C::NS_SEC_POLICY_12, 'sp', 'IncludeToken', IncludeToken::Never->value),
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

        $trust13 = new Trust13(
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
            Id: new XMLAttribute(C::NS_SEC_UTIL, 'wsu', 'Id', 'IssuedTokenWSTrustBinding_IWSTrust13Async_policy'),
            operatorContent: [new ExactlyOne(
                operatorContent: [new All(
                   children: [
                       $transportBinding,
                       $endorsingSupportingTokens,
                       $wss11,
                       $trust13,
                       $usingAddressing,
                   ],
                )],
            )],
        );
    }


    /**
     * This method builds the IssuedTokenWSTrustBinding1 policy.
     *
     * @param \SimpleSAML\WSSecurity\XML\wsp\Policy
     */
    private function getIssuedTokenWSTrustBinding1(): Policy
    {
        $transportBinding = new TransportBinding(
            elements: [new Policy(
                children: [
                    new TransportToken(
                        elements: [new Policy(
                            children: [new HttpsToken()],
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
                        requestSecurityTokenTemplate: new RequestSecurityTokenTemplate(
                            elts: [
                                new KeyType([KeyTypeEnum::SymmetricKey]),
                                new KeySize('256'),
                                new EncryptWith(C::KEY_TRANSPORT_OAEP_MGF1P),
                                new SignatureAlgorithm(C::SIG_HMAC_SHA1),
                                new CanonicalizationAlgorithm(C::C14N_EXCLUSIVE_WITHOUT_COMMENTS),
                                new EncryptionAlgorithm(C::BLOCK_ENC_AES256),
                            ],
                        ),
                        elts: [
                            new Policy(
                                children: [
                                    new RequireInternalReference(),
                                ],
                            ),
                        ],
                        namespacedAttributes: [
                            new XMLAttribute(
                                C::NS_SEC_POLICY_12,
                                'sp',
                                'IncludeToken',
                                IncludeToken::AlwaysToRecipient->value,
                            ),
                        ],
                    ),
                    new KeyValueToken(
                        namespacedAttributes: [
                            new XMLAttribute(C::NS_SEC_POLICY_12, 'sp', 'IncludeToken', IncludeToken::Never->value),
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

        $trust13 = new Trust13(
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
            Id: new XMLAttribute(C::NS_SEC_UTIL, 'wsu', 'Id', 'IssuedTokenWSTrustBinding_IWSTrust13Async1_policy'),
            operatorContent: [new ExactlyOne(
                operatorContent: [new All(
                   children: [
                       $transportBinding,
                       $endorsingSupportingTokens,
                       $wss11,
                       $trust13,
                       $usingAddressing,
                   ],
                )],
            )],
        );
    }
}
