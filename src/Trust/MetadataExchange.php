<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\Trust;

use SimpleSAML\WSSecurity\Constants as C;
use SimpleSAML\WSSecurity\XML\mssp\RsaToken;
use SimpleSAML\WSSecurity\XML\sp\AlgorithmSuite;
use SimpleSAML\WSSecurity\XML\sp\Basic256;
use SimpleSAML\WSSecurity\XML\sp\EndorsingSupportingTokens;
use SimpleSAML\WSSecurity\XML\sp\Header;
use SimpleSAML\WSSecurity\XML\sp\HttpsToken;
use SimpleSAML\WSSecurity\XML\sp\IncludeTimestamp;
use SimpleSAML\WSSecurity\XML\sp\IncludeToken;
use SimpleSAML\WSSecurity\XML\sp\Layout;
use SimpleSAML\WSSecurity\XML\sp\MustSupportIssuedTokens;
use SimpleSAML\WSSecurity\XML\sp\RequireClientEntropy;
use SimpleSAML\WSSecurity\XML\sp\RequireServerEntropy;
use SimpleSAML\WSSecurity\XML\sp\SignedParts;
use SimpleSAML\WSSecurity\XML\sp\SignedSupportingTokens;
use SimpleSAML\WSSecurity\XML\sp\Strict;
use SimpleSAML\WSSecurity\XML\sp\TransportBinding;
use SimpleSAML\WSSecurity\XML\sp\TransportToken;
use SimpleSAML\WSSecurity\XML\sp\Trust10;
use SimpleSAML\WSSecurity\XML\sp\UsernameToken;
use SimpleSAML\WSSecurity\XML\sp\Wss11;
use SimpleSAML\WSSecurity\XML\sp\WssUsernameToken10;
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
        return [$this->getUserNameWSTrustBindingPolicy()];
    }


    /**
     * This method builds the UserNameWSTrustBinding policy.
     *
     * @param \SimpleSAML\WSSecurity\XML\wsp\Policy
     */
    private function getUserNameWSTrustBindingPolicy(): Policy
    {
        return new Policy(
            Id: 'UserNameWSTrustBinding_IWSTrustFeb2005Async_policy',
            operatorContent: [new ExactlyOne(
                operatorContent: [new All(
                   children: [
                       new TransportBinding(
                           elements: [new Policy(
                               children: [
                                   new TransportToken(
                                       elements: [new Policy(
                                           children: [new HttpsToken(
                                               namespacedAttributes: [
                                                   new XMLAttribute(null, null, 'RequireClientCertificate', 'false'),
                                               ],
                                           )],
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
                       ),
                       new SignedSupportingTokens(
                           elements: [new Policy(
                               children: [new UsernameToken(
                                   includeToken: IncludeToken::AlwaysToRecipient,
                                   elts: [new Policy(
                                       children: [new WssUsernameToken10()],
                                   )],
                               )],
                           )],
                       ),
                       new EndorsingSupportingTokens(
                           elements: [new Policy(
                               children: [new RsaToken(
                                   includeToken: IncludeToken::Never,
                                   elts: [new SignedParts(
                                       header: [
                                           new Header(
                                               namespace: C::NS_ADDR,
                                               name: 'To',
                                           ),
                                       ],
                                   )],
                                   namespacedAttributes: [
                                       new XMLAttribute(C::NS_POLICY, 'wsp', 'Optional', 'true'),
                                   ],
                               )],
                           )],
                       ),
                       new Wss11(
                           elements: [new Policy()],
                       ),
                       new Trust10(
                           elements: [new Policy(
                               children: [
                                   new MustSupportIssuedTokens(),
                                   new RequireClientEntropy(),
                                    new RequireServerEntropy(),
                               ],
                           )],
                       ),
                       new UsingAddressing(),
                   ],
                )],
            )],
        );
    }
}
