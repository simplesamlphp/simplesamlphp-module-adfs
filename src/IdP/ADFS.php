<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\IdP;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use Exception;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\IdP;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\SAML11\Type\SAMLAnyURIValue;
use SimpleSAML\SAML11\Type\SAMLDateTimeValue;
use SimpleSAML\SAML11\Type\SAMLStringValue;
use SimpleSAML\SAML11\XML\saml\Assertion;
use SimpleSAML\SAML11\XML\saml\Attribute;
use SimpleSAML\SAML11\XML\saml\AttributeStatement;
use SimpleSAML\SAML11\XML\saml\AttributeValue;
use SimpleSAML\SAML11\XML\saml\Audience;
use SimpleSAML\SAML11\XML\saml\AudienceRestrictionCondition;
use SimpleSAML\SAML11\XML\saml\AuthenticationStatement;
use SimpleSAML\SAML11\XML\saml\Conditions;
use SimpleSAML\SAML11\XML\saml\ConfirmationMethod;
use SimpleSAML\SAML11\XML\saml\NameIdentifier;
use SimpleSAML\SAML11\XML\saml\Subject;
use SimpleSAML\SAML11\XML\saml\SubjectConfirmation;
use SimpleSAML\SAML2\Constants as C_SAML2;
use SimpleSAML\SOAP12\Type\MustUnderstandValue;
use SimpleSAML\SOAP12\XML\Body;
use SimpleSAML\SOAP12\XML\Envelope;
use SimpleSAML\SOAP12\XML\Header;
use SimpleSAML\Utils;
use SimpleSAML\WebServices\Addressing\XML\wsa_200508\Action;
use SimpleSAML\WebServices\Addressing\XML\wsa_200508\Address;
use SimpleSAML\WebServices\Addressing\XML\wsa_200508\EndpointReference;
use SimpleSAML\WebServices\Addressing\XML\wsa_200508\MessageID;
use SimpleSAML\WebServices\Addressing\XML\wsa_200508\RelatesTo;
use SimpleSAML\WebServices\Addressing\XML\wsa_200508\To;
use SimpleSAML\WebServices\Policy\XML\wsp_200409\AppliesTo;
use SimpleSAML\WebServices\Security\Type\DateTimeValue;
use SimpleSAML\WebServices\Security\Type\IDValue as WSSE_IDValue;
use SimpleSAML\WebServices\Security\XML\wsse\KeyIdentifier;
use SimpleSAML\WebServices\Security\XML\wsse\Password;
use SimpleSAML\WebServices\Security\XML\wsse\Security;
use SimpleSAML\WebServices\Security\XML\wsse\SecurityTokenReference;
use SimpleSAML\WebServices\Security\XML\wsse\UsernameToken;
use SimpleSAML\WebServices\Security\XML\wsu\Created;
use SimpleSAML\WebServices\Security\XML\wsu\Expires;
use SimpleSAML\WebServices\Security\XML\wsu\Timestamp;
use SimpleSAML\WebServices\Trust\XML\wst_200502\KeyType;
use SimpleSAML\WebServices\Trust\XML\wst_200502\Lifetime;
use SimpleSAML\WebServices\Trust\XML\wst_200502\RequestedAttachedReference;
use SimpleSAML\WebServices\Trust\XML\wst_200502\RequestedSecurityToken;
use SimpleSAML\WebServices\Trust\XML\wst_200502\RequestedUnattachedReference;
use SimpleSAML\WebServices\Trust\XML\wst_200502\RequestSecurityToken;
use SimpleSAML\WebServices\Trust\XML\wst_200502\RequestSecurityTokenResponse;
use SimpleSAML\WebServices\Trust\XML\wst_200502\RequestType;
use SimpleSAML\WebServices\Trust\XML\wst_200502\RequestTypeEnum;
use SimpleSAML\WebServices\Trust\XML\wst_200502\TokenType;
use SimpleSAML\XHTML\Template;
use SimpleSAML\XMLSchema\Type\AnyURIValue;
use SimpleSAML\XMLSchema\Type\Base64BinaryValue;
use SimpleSAML\XMLSchema\Type\IDValue;
use SimpleSAML\XMLSchema\Type\NonNegativeIntegerValue;
use SimpleSAML\XMLSchema\Type\StringValue;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Constants as C_XMLSEC;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate as PublicKey;
use SimpleSAML\XMLSecurity\XML\ds\KeyInfo;
use SimpleSAML\XMLSecurity\XML\ds\X509Certificate;
use SimpleSAML\XMLSecurity\XML\ds\X509Data;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\StreamedResponse;

use function array_pop;
use function base64_encode;
use function chunk_split;
use function str_replace;
use function trim;

class ADFS
{
    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \SimpleSAML\SOAP12\XML\Envelope $soapEnvelope
     * @param \SimpleSAML\Module\adfs\IdP\PassiveIdP $idp
     * @throws \SimpleSAML\Error\MetadataNotFound
     */
    public static function receivePassiveAuthnRequest(
        Request $request,
        Envelope $soapEnvelope,
        PassiveIdP $idp,
    ): StreamedResponse {
        // Parse the SOAP-header
        $header = $soapEnvelope->getHeader();

        $to = To::getChildrenOfClass($header->toXML());
        Assert::count($to, 1, 'Missing To in SOAP Header.');
        $to = array_pop($to);

        $action = Action::getChildrenOfClass($header->toXML());
        Assert::count($action, 1, 'Missing Action in SOAP Header.');
        $action = array_pop($action);

        $messageid = MessageID::getChildrenOfClass($header->toXML());
        Assert::count($messageid, 1, 'Missing MessageID in SOAP Header.');
        $messageid = array_pop($messageid);

        $security = Security::getChildrenOfClass($header->toXML());
        Assert::count($security, 1, 'Missing Security in SOAP Header.');
        $security = array_pop($security);

        // Parse the SOAP-body
        $body = $soapEnvelope->getBody();

        $requestSecurityToken = RequestSecurityToken::getChildrenOfClass($body->toXML());
        Assert::count($requestSecurityToken, 1, 'Missing RequestSecurityToken in SOAP Body.');
        $requestSecurityToken = array_pop($requestSecurityToken);

        $appliesTo = AppliesTo::getChildrenOfClass($requestSecurityToken->toXML());
        Assert::count($appliesTo, 1, 'Missing AppliesTo in RequestSecurityToken.');
        $appliesTo = array_pop($appliesTo);

        $endpointReference = EndpointReference::getChildrenOfClass($appliesTo->toXML());
        Assert::count($endpointReference, 1, 'Missing EndpointReference in AppliesTo.');
        $endpointReference = array_pop($endpointReference);

        // Make sure the message was addressed to us.
        if ($to === null || $request->server->get('SCRIPT_URI') !== $to->getContent()) {
            throw new Error\BadRequest('This server is not the audience for the message received.');
        }

        // Ensure we know the issuer
        $issuer = $endpointReference->getAddress()->getContent();

        $metadata = MetaDataStorageHandler::getMetadataHandler();
        $spMetadata = $metadata->getMetaDataConfig($issuer->getValue(), 'adfs-sp-remote');

        $usernameToken = UsernameToken::getChildrenOfClass($security->toXML());
        Assert::count($usernameToken, 1, 'Missing UsernameToken in Security.');
        $usernameToken = array_pop($usernameToken);

        $username = $usernameToken->getUsername();
        $password = Password::getChildrenOfClass($usernameToken->toXML());
        $password = array_pop($password);

        if ($password === null) {
            throw new Error\BadRequest('Missing username or password in SOAP header.');
        } else {
            $_SERVER['PHP_AUTH_USER'] = $username->getContent();
            $_SERVER['PHP_AUTH_PW'] = $password->getContent();
        }

        $requestSecurityTokenStr = $requestSecurityToken->toXML()->ownerDocument->saveXML();
        $requestSecurityTokenStr = str_replace($password->getContent()->getValue(), '*****', $requestSecurityTokenStr);
        Logger::debug($requestSecurityTokenStr);

        $state = [
            'Responder' => [ADFS::class, 'sendPassiveResponse'],
            'SPMetadata' => $spMetadata->toArray(),
            'MessageID' => $messageid->getContent()->getValue(),
            // Dirty hack to leverage the SAML ECP logics
            'saml:Binding' => C_SAML2::BINDING_PAOS,
        ];

        return new StreamedResponse(
            function () use ($idp, &$state) {
                $idp->handleAuthenticationRequest($state);
            },
        );
    }


    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \SimpleSAML\IdP $idp
     * @throws \SimpleSAML\Error\MetadataNotFound
     */
    public static function receiveAuthnRequest(Request $request, IdP $idp): StreamedResponse
    {
        parse_str($request->server->get('QUERY_STRING'), $query);

        $requestid = $query['wctx'] ?? null;
        $issuer = $query['wtrealm'];

        $metadata = MetaDataStorageHandler::getMetadataHandler();
        $spMetadata = $metadata->getMetaDataConfig($issuer, 'adfs-sp-remote');

        Logger::info('ADFS - IdP.prp: Incoming Authentication request: ' . $issuer . ' id ' . $requestid);

        $username = null;
        if ($request->query->has('username')) {
            $username = (string) $request->query->get('username');
        }

        $wauth = null;
        if ($request->query->has('wauth')) {
            $wauth = (string) $request->query->get('wauth');
        }

        $state = [
            'Responder' => [ADFS::class, 'sendResponse'],
            'SPMetadata' => $spMetadata->toArray(),
            'ForceAuthn' => false,
            'isPassive' => false,
            'adfs:wctx' => $requestid,
            'adfs:wreply' => false,
        ];

        if ($username !== null) {
            $state['core:username'] = $username;
        }

        if ($wauth !== null) {
            $state['saml:RequestedAuthnContext'] = ['AuthnContextClassRef' => [$wauth]];
        }

        if (isset($query['wreply']) && !empty($query['wreply'])) {
            $httpUtils = new Utils\HTTP();
            $state['adfs:wreply'] = $httpUtils->checkURLAllowed($query['wreply']);
        }

        return new StreamedResponse(
            function () use ($idp, &$state) {
                $idp->handleAuthenticationRequest($state);
            },
        );
    }


    /**
     * @param string $issuer
     * @param string $target
     * @param string $nameid
     * @param array<mixed> $attributes
     * @param int $assertionLifetime
     * @param string $method
     * @return \SimpleSAML\SAML11\XML\saml\Assertion
     */
    private static function generateActiveAssertion(
        string $issuer,
        string $target,
        string $nameid,
        array $attributes,
        int $assertionLifetime,
        string $method,
    ): Assertion {
        $httpUtils = new Utils\HTTP();
        $randomUtils = new Utils\Random();
        $timeUtils = new Utils\Time();

        $issueInstant = $timeUtils->generateTimestamp();
        $notBefore = DateInterval::createFromDateString('30 seconds');
        $notOnOrAfter = DateInterval::createFromDateString(sprintf('%d seconds', $assertionLifetime));
        $assertionID = $randomUtils->generateID();
        $nameidFormat = SAMLAnyURIValue::fromString('http://schemas.xmlsoap.org/claims/UPN');
        $nameid = SAMLStringValue::fromString(htmlspecialchars($nameid));
        $now = new DateTimeImmutable('now', new DateTimeZone('Z'));

        $audience = new Audience(SAMLAnyURIValue::fromString($target));
        $audienceRestrictionCondition = new AudienceRestrictionCondition([$audience]);
        $conditions = new Conditions(
            [$audienceRestrictionCondition],
            [],
            [],
            SAMLDateTimeValue::fromDateTime($now->sub($notBefore)),
            SAMLDateTimeValue::fromDateTime($now->add($notOnOrAfter)),
        );

        $nameIdentifier = new NameIdentifier($nameid, null, $nameidFormat);
        $subject = new Subject(null, $nameIdentifier);

        $authenticationStatement = new AuthenticationStatement(
            $subject,
            SAMLAnyURIValue::fromSTring($method),
            SAMLDateTimeValue::fromDateTime($now),
        );

        $attrs = [];
        $attrUtils = new Utils\Attributes();
        foreach ($attributes as $name => $values) {
            if ((!is_array($values)) || (count($values) == 0)) {
                continue;
            }

            list($namespace, $name) = $attrUtils->getAttributeNamespace(
                $name,
                'http://schemas.xmlsoap.org/claims',
            );

            $namespace = SAMLAnyURIValue::fromString(htmlspecialchars($namespace));
            $name = SAMLStringValue::fromString(htmlspecialchars($name));
            $attrValue = [];
            foreach ($values as $value) {
                if ((!isset($value)) || ($value === '')) {
                    continue;
                }
                $attrValue[] = new AttributeValue(SAMLStringValue::fromString($value));
            }
            $attrs[] = new Attribute($name, $namespace, $attrValue);
        }
        $attributeStatement = new AttributeStatement($subject, $attrs);

        return new Assertion(
            NonNegativeIntegerValue::fromInteger(1),
            NonNegativeIntegerValue::fromInteger(1),
            IDValue::fromString($assertionID),
            SAMLStringValue::fromString($issuer),
            SAMLDateTimeValue::fromDateTime($now),
            $conditions,
            null, // Advice
            [$authenticationStatement, $attributeStatement],
        );
    }


    /**
     * @param string $issuer
     * @param string $target
     * @param string $nameid
     * @param array<mixed> $attributes
     * @param int $assertionLifetime
     * @return \SimpleSAML\SAML11\XML\saml\Assertion
     */
    private static function generatePassiveAssertion(
        string $issuer,
        string $target,
        string $nameid,
        array $attributes,
        int $assertionLifetime,
    ): Assertion {
        $httpUtils = new Utils\HTTP();
        $randomUtils = new Utils\Random();
        $timeUtils = new Utils\Time();

        $issueInstant = $timeUtils->generateTimestamp();
        $notBefore = DateInterval::createFromDateString('30 seconds');
        $notOnOrAfter = DateInterval::createFromDateString(sprintf('%d seconds', $assertionLifetime));
        $assertionID = $randomUtils->generateID();
        $now = new DateTimeImmutable('now', new DateTimeZone('Z'));

        if ($httpUtils->isHTTPS()) {
            $method = C_SAML2::AC_PASSWORD_PROTECTED_TRANSPORT;
        } else {
            $method = C_SAML2::AC_PASSWORD;
        }

        $audience = new Audience(SAMLAnyURIValue::fromString($target));
        $audienceRestrictionCondition = new AudienceRestrictionCondition([$audience]);
        $conditions = new Conditions(
            [$audienceRestrictionCondition],
            [],
            [],
            SAMLDateTimeValue::fromDateTime($now->sub($notBefore)),
            SAMLDateTimeValue::fromDateTime($now->add($notOnOrAfter)),
        );

        $nameIdentifier = new NameIdentifier(
            SAMLStringValue::fromString($nameid),
            null,
            SAMLAnyURIValue::fromString(C_SAML2::NAMEID_UNSPECIFIED),
        );
        $subject = new Subject(
            new SubjectConfirmation(
                [
                    ConfirmationMethod::fromString(C_SAML2::CM_BEARER),
                ],
            ),
            $nameIdentifier,
        );

        $authenticationStatement = new AuthenticationStatement(
            $subject,
            SAMLAnyURIValue::fromString($method),
            SAMLDateTimeValue::fromDateTime($now),
        );

        $attrs = [];
        $attrs[] = new Attribute(
            SAMLStringValue::fromString('UPN'),
            SAMLAnyURIValue::fromString('http://schemas.xmlsoap.org/claims'),
            [
                new AttributeValue(
                    SAMLStringValue::fromString($attributes['http://schemas.xmlsoap.org/claims/UPN'][0]),
                ),
            ],
        );
        $attrs[] = new Attribute(
            SAMLStringValue::fromString('ImmutableID'),
            SAMLAnyURIValue::fromString('http://schemas.microsoft.com/LiveID/Federation/2008/05'),
            [
                new AttributeValue(
                    SAMLStringValue::fromString(
                        $attributes['http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID'][0],
                    ),
                ),
            ],
        );

        $attributeStatement = new AttributeStatement($subject, $attrs);

        return new Assertion(
            NonNegativeIntegerValue::fromInteger(1),
            NonNegativeIntegerValue::fromInteger(1),
            IDValue::fromString($assertionID),
            SAMLStringValue::fromString($issuer),
            SAMLDateTimeValue::fromDateTime($now),
            $conditions,
            null, // Advice
            [$attributeStatement, $authenticationStatement],
        );
    }


    /**
     * @param \SimpleSAML\SAML11\XML\saml\Assertion $assertion
     * @param string $key
     * @param string $cert
     * @param string $algo
     * @param string|null $passphrase
     * @return \SimpleSAML\SAML11\XML\saml\Assertion
     */
    private static function signAssertion(
        Assertion $assertion,
        string $key,
        string $cert,
        string $algo,
        #[\SensitiveParameter]
        ?string $passphrase = null,
    ): Assertion {
        $key = PrivateKey::fromFile($key, $passphrase);
        $pubkey = PublicKey::fromFile($cert);
        $keyInfo = new KeyInfo([
            new X509Data(
                [new X509Certificate(
                    Base64BinaryValue::fromString(trim(chunk_split(base64_encode($pubkey->getPEM()->data())))),
                )],
            ),
        ]);

        $signer = (new SignatureAlgorithmFactory())->getAlgorithm(
            $algo,
            $key,
        );

        $assertion->sign($signer, C_XMLSEC::C14N_EXCLUSIVE_WITHOUT_COMMENTS, $keyInfo);
        return $assertion;
    }


    /**
     * @param string $wreply
     * @param string $wresult
     * @param ?string $wctx
     */
    private static function postResponse(string $wreply, string $wresult, ?string $wctx): void
    {
        $config = Configuration::getInstance();
        $t = new Template($config, 'adfs:postResponse.twig');
        $t->data['wreply'] = $wreply;
        $t->data['wresult'] = $wresult;
        $t->data['wctx'] = $wctx;
        $t->send();
        // Idp->postAuthProc expects this function to exit
        exit();
    }


    /**
     * Get the metadata of a given hosted ADFS IdP.
     *
     * @param string $entityid The entity ID of the hosted ADFS IdP whose metadata we want to fetch.
     * @param \SimpleSAML\Metadata\MetaDataStorageHandler $handler Optionally the metadata storage to use,
     *        if omitted the configured handler will be used.
     * @return array<mixed>
     *
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Error\MetadataNotFound
     */
    public static function getHostedMetadata(string $entityid, ?MetaDataStorageHandler $handler = null): array
    {
        $cryptoUtils = new Utils\Crypto();

        $handler = $handler ?? MetaDataStorageHandler::getMetadataHandler();
        $config = $handler->getMetaDataConfig($entityid, 'adfs-idp-hosted');

        $host = Module::getModuleURL('adfs/idp/prp.php');

        // configure endpoints
        $ssob = $handler->getGenerated('SingleSignOnServiceBinding', 'adfs-idp-hosted', $host);
        $slob = $handler->getGenerated('SingleLogoutServiceBinding', 'adfs-idp-hosted', $host);
        $ssol = $handler->getGenerated('SingleSignOnService', 'adfs-idp-hosted', $host);
        $slol = $handler->getGenerated('SingleLogoutService', 'adfs-idp-hosted', $host);

        $sso = [];
        if (is_array($ssob)) {
            foreach ($ssob as $binding) {
                $sso[] = [
                    'Binding'  => $binding,
                    'Location' => $ssol,
                ];
            }
        } else {
            $sso[] = [
                'Binding'  => $ssob,
                'Location' => $ssol,
            ];
        }

        $slo = [];
        if (is_array($slob)) {
            foreach ($slob as $binding) {
                $slo[] = [
                    'Binding'  => $binding,
                    'Location' => $slol,
                ];
            }
        } else {
            $slo[] = [
                'Binding'  => $slob,
                'Location' => $slol,
            ];
        }


        $metadata = [
            'metadata-set' => 'adfs-idp-hosted',
            'entityid' => $entityid,
            'SingleSignOnService' => $sso,
            'SingleLogoutService' => $slo,
            'NameIDFormat' => $config->getOptionalArrayizeString('NameIDFormat', [C_SAML2::NAMEID_TRANSIENT]),
            'contacts' => [],
        ];

        // add certificates
        $keys = [];
        $certInfo = $cryptoUtils->loadPublicKey($config, false, 'new_');
        $hasNewCert = false;
        if ($certInfo !== null) {
            $keys[] = [
                'type' => 'X509Certificate',
                'signing' => true,
                'encryption' => true,
                'X509Certificate' => $certInfo['certData'],
                'prefix' => 'new_',
            ];
            $hasNewCert = true;
        }

        /** @var array<mixed> $certInfo */
        $certInfo = $cryptoUtils->loadPublicKey($config, true);
        $keys[] = [
            'type' => 'X509Certificate',
            'signing' => true,
            'encryption' => $hasNewCert === false,
            'X509Certificate' => $certInfo['certData'],
            'prefix' => '',
        ];

        if ($config->hasValue('https.certificate')) {
            /** @var array<mixed> $httpsCert */
            $httpsCert = $cryptoUtils->loadPublicKey($config, true, 'https.');
            $keys[] = [
                'type' => 'X509Certificate',
                'signing' => true,
                'encryption' => false,
                'X509Certificate' => $httpsCert['certData'],
                'prefix' => 'https.',
            ];
        }
        $metadata['keys'] = $keys;

        // add organization information
        if ($config->hasValue('OrganizationName')) {
            $metadata['OrganizationName'] = $config->getLocalizedString('OrganizationName');
            $metadata['OrganizationDisplayName'] = $config->getOptionalLocalizedString(
                'OrganizationDisplayName',
                $metadata['OrganizationName'],
            );

            if (!$config->hasValue('OrganizationURL')) {
                throw new Error\Exception('If OrganizationName is set, OrganizationURL must also be set.');
            }
            $metadata['OrganizationURL'] = $config->getLocalizedString('OrganizationURL');
        }

        // add scope
        if ($config->hasValue('scope')) {
            $metadata['scope'] = $config->getArray('scope');
        }

        // add extensions
        if ($config->hasValue('EntityAttributes')) {
            $metadata['EntityAttributes'] = $config->getArray('EntityAttributes');

            // check for entity categories
            if (Utils\Config\Metadata::isHiddenFromDiscovery($metadata)) {
                $metadata['hide.from.discovery'] = true;
            }
        }

        if ($config->hasValue('UIInfo')) {
            $metadata['UIInfo'] = $config->getArray('UIInfo');
        }

        if ($config->hasValue('DiscoHints')) {
            $metadata['DiscoHints'] = $config->getArray('DiscoHints');
        }

        if ($config->hasValue('RegistrationInfo')) {
            $metadata['RegistrationInfo'] = $config->getArray('RegistrationInfo');
        }

        // add contact information
        $globalConfig = Configuration::getInstance();
        $email = $globalConfig->getOptionalString('technicalcontact_email', null);
        if ($email !== null && $email !== 'na@example.org') {
            $contact = [
                'emailAddress' => $email,
                'givenName' => $globalConfig->getOptionalString('technicalcontact_name', null),
                'contactType' => 'technical',
            ];
            $metadata['contacts'][] = Utils\Config\Metadata::getContact($contact);
        }

        return $metadata;
    }


    /**
     * @param array<mixed> $state
     * @throws \Exception
     */
    public static function sendPassiveResponse(array $state): void
    {
        $idp = IdP::getByState($state);
        $idpMetadata = $idp->getConfig();
        $idpEntityId = $state['IdPMetadata']['entityid'];

        $spMetadata = $state['SPMetadata'];
        $spEntityId = $spMetadata['entityid'];
        $spMetadata = Configuration::loadFromArray(
            $spMetadata,
            '$metadata[' . var_export($spEntityId, true) . ']',
        );

        $assertionLifetime = $spMetadata->getOptionalInteger('assertion.lifetime', null);
        if ($assertionLifetime === null) {
            $assertionLifetime = $idpMetadata->getOptionalInteger('assertion.lifetime', 300);
        }

        $now = new DateTimeImmutable('now', new DateTimeZone('Z'));
        $created = $now->sub(DateInterval::createFromDateString(sprintf('30 seconds')));
        $expires = $now->add(DateInterval::createFromDateString(sprintf('%d seconds', $assertionLifetime)));

        $attributes = $state['Attributes'];
        $nameid = $state['saml:NameID'][C_SAML2::NAMEID_UNSPECIFIED];

        $assertion = ADFS::generatePassiveAssertion(
            $idpEntityId,
            $spEntityId,
            $nameid->getValue(),
            $attributes,
            $assertionLifetime,
        );

        $privateKeyCfg = $idpMetadata->getOptionalString('privatekey', null);
        $certificateCfg = $idpMetadata->getOptionalString('certificate', null);

        if ($privateKeyCfg !== null && $certificateCfg !== null) {
            $configUtils = new Utils\Config();
            $privateKeyFile = $configUtils->getCertPath($privateKeyCfg);
            $certificateFile = $configUtils->getCertPath($certificateCfg);
            $passphrase = $idpMetadata->getOptionalString('privatekey_pass', null);

            $algo = $spMetadata->getOptionalString('signature.algorithm', null);
            if ($algo === null) {
                $algo = $idpMetadata->getOptionalString('signature.algorithm', C_XMLSEC::SIG_RSA_SHA256);
            }

            $assertion = ADFS::signAssertion($assertion, $privateKeyFile, $certificateFile, $algo, $passphrase);
            $assertion = Assertion::fromXML($assertion->toXML());
        }

        $requestedSecurityToken = new RequestedSecurityToken($assertion);
        $lifetime = new LifeTime(
            new Created(DateTimeValue::fromDateTime($created)),
            new Expires(DateTimeValue::fromDateTime($expires)),
        );
        $appliesTo = new AppliesTo([new EndpointReference(Address::fromString($spEntityId))]);

        $requestedAttachedReference = new RequestedAttachedReference(
            new SecurityTokenReference(null, null, [
                new KeyIdentifier(
                    StringValue::fromString(
                        'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID',
                    ),
                    WSSE_IDValue::fromString($assertion->getId()->getValue()),
                ),
            ]),
        );
        $requestedUnattachedReference = new RequestedUnattachedReference(
            new SecurityTokenReference(null, null, [
                new KeyIdentifier(
                    StringValue::fromString(
                        'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID',
                    ),
                    WSSE_IDValue::fromString($assertion->getId()->getValue()),
                ),
            ]),
        );
        $tokenType = TokenType::fromString(C_SAML2::NS_SAML);
        $requestType = RequestType::fromString(RequestTypeEnum::Issue->value);
        $keyType = new KeyType(AnyURIValue::fromString('http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey'));

        $requestSecurityTokenResponse = new RequestSecurityTokenResponse(null, [
            $lifetime,
            $appliesTo,
            $requestedSecurityToken,
            $requestedAttachedReference,
            $requestedUnattachedReference,
            $tokenType,
            $requestType,
            $keyType,
        ]);

        // Build envelope
        $mustUnderstand = MustUnderstandValue::fromBoolean(true);
        $header = new Header([
            new Action(
                AnyURIValue::fromString('http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue'),
                [$mustUnderstand->toAttribute()],
            ),
            new RelatesTo(AnyURIValue::fromString($state['MessageID'])),
            new Security(
                [
                    new Timestamp(
                        new Created(DateTimeValue::fromDateTime($created)),
                        new Expires(DateTimeValue::fromDateTime($expires)),
                    ),
                ],
                [$mustUnderstand->toAttribute()],
            ),
        ]);
        $body = new Body(null, [$requestSecurityTokenResponse]);
        $envelope = new Envelope($body, $header);

        $xmlResponse = $envelope->toXML();
        Logger::debug($xmlResponse->ownerDocument->saveXML($xmlResponse));

        echo $xmlResponse->ownerDocument->saveXML($xmlResponse);
        exit();
    }


    /**
     * @param array<mixed> $state
     * @throws \Exception
     */
    public static function sendResponse(array $state): void
    {
        $spMetadata = $state['SPMetadata'];
        $spEntityId = $spMetadata['entityid'];
        $spMetadata = Configuration::loadFromArray(
            $spMetadata,
            '$metadata[' . var_export($spEntityId, true) . ']',
        );

        $attributes = $state['Attributes'];

        $nameidattribute = $spMetadata->getValue('simplesaml.nameidattribute');
        if (!empty($nameidattribute)) {
            if (!array_key_exists($nameidattribute, $attributes)) {
                throw new Exception('simplesaml.nameidattribute does not exist in resulting attribute set');
            }
            $nameid = $attributes[$nameidattribute][0];
        } else {
            $randomUtils = new Utils\Random();
            $nameid = $randomUtils->generateID();
        }

        $idp = IdP::getByState($state);
        $idpMetadata = $idp->getConfig();
        $idpEntityId = $state['IdPMetadata']['entityid'];

        $idp->addAssociation([
            'id' => 'adfs:' . $spEntityId,
            'Handler' => ADFS::class,
            'adfs:entityID' => $spEntityId,
        ]);

        $assertionLifetime = $spMetadata->getOptionalInteger('assertion.lifetime', null);
        if ($assertionLifetime === null) {
            $assertionLifetime = $idpMetadata->getOptionalInteger('assertion.lifetime', 300);
        }

        if (isset($state['saml:AuthnContextClassRef'])) {
            $method = $state['saml:AuthnContextClassRef'];
        } elseif ((new Utils\HTTP())->isHTTPS()) {
            $method = C_SAML2::AC_PASSWORD_PROTECTED_TRANSPORT;
        } else {
            $method = C_SAML2::AC_PASSWORD;
        }

        $assertion = ADFS::generateActiveAssertion(
            $idpEntityId,
            $spEntityId,
            $nameid,
            $attributes,
            $assertionLifetime,
            $method,
        );

        $privateKeyCfg = $idpMetadata->getOptionalString('privatekey', null);
        $certificateCfg = $idpMetadata->getOptionalString('certificate', null);

        if ($privateKeyCfg !== null && $certificateCfg !== null) {
            $configUtils = new Utils\Config();
            $privateKeyFile = $configUtils->getCertPath($privateKeyCfg);
            $certificateFile = $configUtils->getCertPath($certificateCfg);
            $passphrase = $idpMetadata->getOptionalString('privatekey_pass', null);

            $algo = $spMetadata->getOptionalString('signature.algorithm', null);
            if ($algo === null) {
                $algo = $idpMetadata->getOptionalString('signature.algorithm', C_XMLSEC::SIG_RSA_SHA256);
            }

            $assertion = ADFS::signAssertion($assertion, $privateKeyFile, $certificateFile, $algo, $passphrase);
            $assertion = Assertion::fromXML($assertion->toXML());
        }

        $requestedSecurityToken = new RequestedSecurityToken($assertion);
        $appliesTo = new AppliesTo([new EndpointReference(new Address($spEntityId))]);
        $requestSecurityTokenResponse = new RequestSecurityTokenResponse(null, [$requestedSecurityToken, $appliesTo]);

        $xmlResponse = $requestSecurityTokenResponse->toXML();
        $wresult = $xmlResponse->ownerDocument->saveXML($xmlResponse);
        Logger::debug($wresult);

        $wctx = $state['adfs:wctx'];
        $wreply = $state['adfs:wreply'] ? : $spMetadata->getValue('prp');
        ADFS::postResponse($wreply, $wresult, $wctx);
    }


    /**
     * @param \SimpleSAML\IdP $idp
     * @param array<mixed> $state
     */
    public static function sendLogoutResponse(IdP $idp, array $state): void
    {
        // NB:: we don't know from which SP the logout request came from
        $idpMetadata = $idp->getConfig();
        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL(
            $idpMetadata->getOptionalString('redirect-after-logout', $httpUtils->getBaseURL()),
        );
    }


    /**
     * @param \SimpleSAML\IdP $idp
     * @throws \Exception
     */
    public static function receiveLogoutMessage(IdP $idp): void
    {
        // if a redirect is to occur based on wreply, we will redirect to url as
        // this implies an override to normal sp notification
        if (isset($_GET['wreply']) && !empty($_GET['wreply'])) {
            $httpUtils = new Utils\HTTP();
            $idp->doLogoutRedirect($httpUtils->checkURLAllowed($_GET['wreply']));
            throw new Exception("Code should never be reached");
        }

        $state = [
            'Responder' => [ADFS::class, 'sendLogoutResponse'],
        ];
        $assocId = null;
        // TODO: verify that this is really no problem for:
        //       a) SSP, because there's no caller SP.
        //       b) ADFS SP because caller will be called back..
        $idp->handleLogoutRequest($state, $assocId);
    }


    /**
     * accepts an association array, and returns a URL that can be accessed to terminate the association
     *
     * @param \SimpleSAML\IdP $idp
     * @param array<mixed> $association
     * @param string|null $relayState
     * @return string
     */
    public static function getLogoutURL(IdP $idp, array $association, ?string $relayState = null): string
    {
        $metadata = MetaDataStorageHandler::getMetadataHandler();
        $spMetadata = $metadata->getMetaDataConfig($association['adfs:entityID'], 'adfs-sp-remote');
        $params = ['assocId' => urlencode($association['id'])];
        if ($relayState !== null) {
            $params['relayState'] = urlencode($relayState);
        }
        $returnTo = Module::getModuleURL(
            'adfs/idp/prp.php',
            $params,
        );
        return $spMetadata->getValue('prp') . '?wa=wsignoutcleanup1.0&wreply=' . urlencode($returnTo);
    }
}
