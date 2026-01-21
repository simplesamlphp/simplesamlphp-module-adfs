<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\Trust;

use SimpleSAML\WebServices\Addressing\Constants as C_ADDR;
use SimpleSAML\WebServices\Addressing\XML\wsaw\UsingAddressing;
use SimpleSAML\WebServices\Policy\Constants as C_POL;
use SimpleSAML\WebServices\Policy\XML\wsp_200409\All;
use SimpleSAML\WebServices\Policy\XML\wsp_200409\ExactlyOne;
use SimpleSAML\WebServices\Policy\XML\wsp_200409\Policy;
use SimpleSAML\WebServices\Security\Type\IDValue;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\AlgorithmSuite;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\Basic256;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\EndorsingSupportingTokens;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\Header;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\HttpsToken;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\IncludeTimestamp;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\IncludeToken;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\IssuedToken;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\KeyValueToken;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\Layout;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\MustSupportIssuedTokens;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\MustSupportRefThumbprint;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\RequestSecurityTokenTemplate;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\RequireClientEntropy;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\RequireInternalReference;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\RequireServerEntropy;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\RequireThumbprintReference;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\SignedEncryptedSupportingTokens;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\SignedParts;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\Strict;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\TransportBinding;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\TransportToken;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\Trust13;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\Type\IncludeTokenValue;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\UsernameToken;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\Wss11;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\WssUsernameToken10;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\WssX509V3Token10;
use SimpleSAML\WebServices\SecurityPolicy\XML\sp_200702\X509Token;
use SimpleSAML\WebServices\Trust\XML\wst_200512\CanonicalizationAlgorithm;
use SimpleSAML\WebServices\Trust\XML\wst_200512\EncryptionAlgorithm;
use SimpleSAML\WebServices\Trust\XML\wst_200512\EncryptWith;
use SimpleSAML\WebServices\Trust\XML\wst_200512\KeySize;
use SimpleSAML\WebServices\Trust\XML\wst_200512\KeyType;
use SimpleSAML\WebServices\Trust\XML\wst_200512\KeyTypeEnum;
use SimpleSAML\WebServices\Trust\XML\wst_200512\KeyWrapAlgorithm;
use SimpleSAML\WebServices\Trust\XML\wst_200512\SignatureAlgorithm;
use SimpleSAML\XML\Attribute as XMLAttribute;
use SimpleSAML\XMLSchema\Type\AnyURIValue;
use SimpleSAML\XMLSchema\Type\BooleanValue;
use SimpleSAML\XMLSchema\Type\QNameValue;
use SimpleSAML\XMLSecurity\Constants as C_XMLSEC;

/**
 * @package simplesamlphp/simplesamlphp-module-adfs
 */
class Policy13
{
    /**
     * Constructor.
     */
    public function __construct()
    {
    }


    /**
     * This method builds the wsp:Policy elements
     *
     * @return \SimpleSAML\WebServices\Policy\XML\wsp_200409\Policy[]
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
     * @return \SimpleSAML\WebServices\Policy\XML\wsp_200409\Policy
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
                            IncludeTokenValue::fromEnum(IncludeToken::AlwaysToRecipient)->toAttribute(),
                        ],
                    ),
                    new KeyValueToken(
                        namespacedAttributes: [
                            IncludeTokenValue::fromEnum(IncludeToken::Never)->toAttribute(),
                            new XMLAttribute(
                                C_POL::NS_POLICY_200409,
                                'wsp',
                                'Optional',
                                BooleanValue::fromBoolean(true),
                            ),
                        ],
                    ),
                    new SignedParts(
                        header: [
                            new Header(
                                namespace: AnyURIValue::fromString(C_ADDR::NS_ADDR_200508),
                                name: QNameValue::fromString('To'),
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
            Id: IDValue::fromString('CertificateWSTrustBinding_IWSTrust13Async_policy'),
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
     * @return \SimpleSAML\WebServices\Policy\XML\wsp_200409\Policy
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
                        IncludeTokenValue::fromEnum(IncludeToken::AlwaysToRecipient)->toAttribute(),
                    ],
                )],
            )],
        );

        $endorsingSupportingTokens = new EndorsingSupportingTokens(
            elements: [new Policy(
                children: [
                    new KeyValueToken(
                        namespacedAttributes: [
                            IncludeTokenValue::fromEnum(IncludeToken::Never)->toAttribute(),
                            new XMLAttribute(
                                C_POL::NS_POLICY_200409,
                                'wsp',
                                'Optional',
                                BooleanValue::fromBoolean(true),
                            ),
                        ],
                    ),
                    new SignedParts(
                        header: [
                            new Header(
                                namespace: AnyURIValue::fromString(C_ADDR::NS_ADDR_200508),
                                name: QNameValue::fromString('To'),
                            ),
                        ],
                    ),
                ],
            )],
        );

        $wss11 = new Wss11(
            elements: [
                new Policy(),
            ],
        );

        $trust13 = new Trust13(
            elements: [
                new Policy(
                    children: [
                        new MustSupportIssuedTokens(),
                        new RequireClientEntropy(),
                        new RequireServerEntropy(),
                    ],
                ),
            ],
        );

        $usingAddressing = new UsingAddressing();

        return new Policy(
            Id: IDValue::fromString('UserNameWSTrustBinding_IWSTrustFeb2005Async_policy'),
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
     * @return \SimpleSAML\WebServices\Policy\XML\wsp_200409\Policy
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
                                KeyType::fromString(KeyTypeEnum::PublicKey->value),
                                KeyWrapAlgorithm::fromString(C_XMLSEC::KEY_TRANSPORT_OAEP_MGF1P),
                                EncryptWith::fromString(C_XMLSEC::KEY_TRANSPORT_OAEP_MGF1P),
                                SignatureAlgorithm::fromString(C_XMLSEC::SIG_RSA_SHA1),
                                CanonicalizationAlgorithm::fromString(C_XMLSEC::C14N_EXCLUSIVE_WITHOUT_COMMENTS),
                                EncryptionAlgorithm::fromString(C_XMLSEC::BLOCK_ENC_AES256),
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
                            IncludeTokenValue::fromEnum(IncludeToken::AlwaysToRecipient)->toAttribute(),
                        ],
                    ),
                    new KeyValueToken(
                        namespacedAttributes: [
                            IncludeTokenValue::fromEnum(IncludeToken::Never)->toAttribute(),
                            new XMLAttribute(
                                C_POL::NS_POLICY_200409,
                                'wsp',
                                'Optional',
                                BooleanValue::fromBoolean(true),
                            ),
                        ],
                    ),
                    new SignedParts(
                        header: [
                            new Header(
                                namespace: AnyURIValue::fromString(C_ADDR::NS_ADDR_200508),
                                name: QNameValue::fromString('To'),
                            ),
                        ],
                    ),
                ],
            )],
        );

        $wss11 = new Wss11(
            elements: [
                new Policy(),
            ],
        );

        $trust13 = new Trust13(
            elements: [
                new Policy(
                    children: [
                        new MustSupportIssuedTokens(),
                        new RequireClientEntropy(),
                        new RequireServerEntropy(),
                    ],
                ),
            ],
        );

        $usingAddressing = new UsingAddressing();

        return new Policy(
            Id: IDValue::fromString('IssuedTokenWSTrustBinding_IWSTrust13Async_policy'),
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
     * @return \SimpleSAML\WebServices\Policy\XML\wsp_200409\Policy
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
                                KeyType::fromString(KeyTypeEnum::SymmetricKey->value),
                                KeySize::fromString('256'),
                                KeyWrapAlgorithm::fromString(C_XMLSEC::KEY_TRANSPORT_OAEP_MGF1P),
                                EncryptWith::fromString(C_XMLSEC::BLOCK_ENC_AES256),
                                SignatureAlgorithm::fromString(C_XMLSEC::SIG_HMAC_SHA1),
                                CanonicalizationAlgorithm::fromString(C_XMLSEC::C14N_EXCLUSIVE_WITHOUT_COMMENTS),
                                EncryptionAlgorithm::fromString(C_XMLSEC::BLOCK_ENC_AES256),
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
                            IncludeTokenValue::fromEnum(IncludeToken::AlwaysToRecipient)->toAttribute(),
                        ],
                    ),
                    new KeyValueToken(
                        namespacedAttributes: [
                            IncludeTokenValue::fromEnum(IncludeToken::Never)->toAttribute(),
                            new XMLAttribute(
                                C_POL::NS_POLICY_200409,
                                'wsp',
                                'Optional',
                                BooleanValue::fromBoolean(true),
                            ),
                        ],
                    ),
                    new SignedParts(
                        header: [
                            new Header(
                                namespace: AnyURIValue::fromString(C_ADDR::NS_ADDR_200508),
                                name: QNameValue::fromString('To'),
                            ),
                        ],
                    ),
                ],
            )],
        );

        $wss11 = new Wss11(
            elements: [
                new Policy(),
            ],
        );

        $trust13 = new Trust13(
            elements: [
                new Policy(
                    children: [
                        new MustSupportIssuedTokens(),
                        new RequireClientEntropy(),
                        new RequireServerEntropy(),
                    ],
                ),
            ],
        );

        $usingAddressing = new UsingAddressing();

        return new Policy(
            Id: IDValue::fromString('IssuedTokenWSTrustBinding_IWSTrust13Async1_policy'),
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
