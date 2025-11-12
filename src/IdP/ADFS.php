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
use SimpleSAML\SAML11\Constants as C;
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
use SimpleSAML\SAML2\Constants as SAML2_C;
use SimpleSAML\SOAP\Constants as SOAP_C;
use SimpleSAML\SOAP\XML\env_200305\Body;
use SimpleSAML\SOAP\XML\env_200305\Envelope;
use SimpleSAML\SOAP\XML\env_200305\Header;
use SimpleSAML\Utils;
use SimpleSAML\WSSecurity\XML\wsa_200508\Action;
use SimpleSAML\WSSecurity\XML\wsa_200508\Address;
use SimpleSAML\WSSecurity\XML\wsa_200508\EndpointReference;
use SimpleSAML\WSSecurity\XML\wsa_200508\MessageID;
use SimpleSAML\WSSecurity\XML\wsa_200508\RelatesTo;
use SimpleSAML\WSSecurity\XML\wsa_200508\To;
use SimpleSAML\WSSecurity\XML\wsp\AppliesTo;
use SimpleSAML\WSSecurity\XML\wsse\KeyIdentifier;
use SimpleSAML\WSSecurity\XML\wsse\Password;
use SimpleSAML\WSSecurity\XML\wsse\Security;
use SimpleSAML\WSSecurity\XML\wsse\SecurityTokenReference;
use SimpleSAML\WSSecurity\XML\wsse\UsernameToken;
use SimpleSAML\WSSecurity\XML\wst_200502\KeyType;
use SimpleSAML\WSSecurity\XML\wst_200502\Lifetime;
use SimpleSAML\WSSecurity\XML\wst_200502\RequestedAttachedReference;
use SimpleSAML\WSSecurity\XML\wst_200502\RequestedSecurityToken;
use SimpleSAML\WSSecurity\XML\wst_200502\RequestedUnattachedReference;
use SimpleSAML\WSSecurity\XML\wst_200502\RequestSecurityToken;
use SimpleSAML\WSSecurity\XML\wst_200502\RequestSecurityTokenResponse;
use SimpleSAML\WSSecurity\XML\wst_200502\RequestType;
use SimpleSAML\WSSecurity\XML\wst_200502\RequestTypeEnum;
use SimpleSAML\WSSecurity\XML\wst_200502\TokenType;
use SimpleSAML\WSSecurity\XML\wsu\Created;
use SimpleSAML\WSSecurity\XML\wsu\Expires;
use SimpleSAML\WSSecurity\XML\wsu\Timestamp;
use SimpleSAML\XHTML\Template;
use SimpleSAML\XML\Attribute as XMLAttribute;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
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
     * @param \SimpleSAML\SOAP\XML\env_200305\Envelope $soapEnvelope
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

        $metadata = MetaDataStorageHandler::getMetadataHandler(Configuration::getInstance());
        $spMetadata = $metadata->getMetaDataConfig($issuer, 'adfs-sp-remote');

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
        $requestSecurityTokenStr = str_replace($password->getContent(), '*****', $requestSecurityTokenStr);
        Logger::debug($requestSecurityTokenStr);

        $state = [
            'Responder' => [ADFS::class, 'sendPassiveResponse'],
            'SPMetadata' => $spMetadata->toArray(),
            'MessageID' => $messageid->getContent(),
            // Dirty hack to leverage the SAML ECP logics
            'saml:Binding' => SAML2_C::BINDING_PAOS,
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

        $metadata = MetaDataStorageHandler::getMetadataHandler(Configuration::getInstance());
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
        $nameidFormat = 'http://schemas.xmlsoap.org/claims/UPN';
        $nameid = htmlspecialchars($nameid);
        $now = new DateTimeImmutable('now', new DateTimeZone('Z'));

        $audience = new Audience($target);
        $audienceRestrictionCondition = new AudienceRestrictionCondition([$audience]);
        $conditions = new Conditions(
            [$audienceRestrictionCondition],
            [],
            [],
            $now->sub($notBefore),
            $now->add($notOnOrAfter),
        );

        $nameIdentifier = new NameIdentifier($nameid, null, $nameidFormat);
        $subject = new Subject(null, $nameIdentifier);

        $authenticationStatement = new AuthenticationStatement($subject, $method, $now);

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

            $namespace = htmlspecialchars($namespace);
            $name = htmlspecialchars($name);
            $attrValue = [];
            foreach ($values as $value) {
                if ((!isset($value)) || ($value === '')) {
                    continue;
                }
                $attrValue[] = new AttributeValue($value);
            }
            $attrs[] = new Attribute($name, $namespace, $attrValue);
        }
        $attributeStatement = new AttributeStatement($subject, $attrs);

        return new Assertion(
            $assertionID,
            $issuer,
            $now,
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
            $method = SAML2_C::AC_PASSWORD_PROTECTED_TRANSPORT;
        } else {
            $method = C::AC_PASSWORD;
        }

        $audience = new Audience($target);
        $audienceRestrictionCondition = new AudienceRestrictionCondition([$audience]);
        $conditions = new Conditions(
            [$audienceRestrictionCondition],
            [],
            [],
            $now->sub($notBefore),
            $now->add($notOnOrAfter),
        );

        $nameIdentifier = new NameIdentifier($nameid, null, C::NAMEID_UNSPECIFIED);
        $subject = new Subject(new SubjectConfirmation([new ConfirmationMethod(C::CM_BEARER)]), $nameIdentifier);

        $authenticationStatement = new AuthenticationStatement($subject, $method, $now);

        $attrs = [];
        $attrs[] = new Attribute(
            'UPN',
            'http://schemas.xmlsoap.org/claims',
            [new AttributeValue($attributes['http://schemas.xmlsoap.org/claims/UPN'][0])],
        );
        $attrs[] = new Attribute(
            'ImmutableID',
            'http://schemas.microsoft.com/LiveID/Federation/2008/05',
            [new AttributeValue($attributes['http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID'][0])],
        );

        $attributeStatement = new AttributeStatement($subject, $attrs);

        return new Assertion(
            $assertionID,
            $issuer,
            $now,
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
                    trim(chunk_split(base64_encode($pubkey->getPEM()->data()))),
                )],
            ),
        ]);

        $signer = (new SignatureAlgorithmFactory())->getAlgorithm(
            $algo,
            $key,
        );

        $assertion->sign($signer, C::C14N_EXCLUSIVE_WITHOUT_COMMENTS, $keyInfo);
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
        $nameid = $state['saml:NameID'][SAML2_C::NAMEID_UNSPECIFIED];

        $assertion = ADFS::generatePassiveAssertion($idpEntityId, $spEntityId, $nameid->getValue(), $attributes, $assertionLifetime);

        $privateKeyCfg = $idpMetadata->getOptionalString('privatekey', null);
        $certificateCfg = $idpMetadata->getOptionalString('certificate', null);

        if ($privateKeyCfg !== null && $certificateCfg !== null) {
            $configUtils = new Utils\Config();
            $privateKeyFile = $configUtils->getCertPath($privateKeyCfg);
            $certificateFile = $configUtils->getCertPath($certificateCfg);
            $passphrase = $idpMetadata->getOptionalString('privatekey_pass', null);

            $algo = $spMetadata->getOptionalString('signature.algorithm', null);
            if ($algo === null) {
                $algo = $idpMetadata->getOptionalString('signature.algorithm', C::SIG_RSA_SHA256);
            }

            $assertion = ADFS::signAssertion($assertion, $privateKeyFile, $certificateFile, $algo, $passphrase);
            $assertion = Assertion::fromXML($assertion->toXML());
        }

        $requestedSecurityToken = new RequestedSecurityToken($assertion);
        $lifetime = new LifeTime(new Created($created), new Expires($expires));
        $appliesTo = new AppliesTo([new EndpointReference(new Address($spEntityId))]);

        $requestedAttachedReference = new RequestedAttachedReference(
            new SecurityTokenReference(null, null, [
                new KeyIdentifier(
                    $assertion->getId(),
                    'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID',
                ),
            ]),
        );
        $requestedUnattachedReference = new RequestedUnattachedReference(
            new SecurityTokenReference(null, null, [
                new KeyIdentifier(
                    $assertion->getId(),
                    'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID',
                ),
            ]),
        );
        $tokenType = new TokenType(C::NS_SAML);
        $requestType = new RequestType([RequestTypeEnum::Issue]);
        $keyType = new KeyType(['http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey']);

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
        $mustUnderstand = new XMLAttribute(SOAP_C::NS_SOAP_ENV_12, 'env', 'mustUnderstand', '1');
        $header = new Header([
            new Action('http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue', [$mustUnderstand]),
            new RelatesTo($state['MessageID'], null),
            new Security(
                [
                    new Timestamp(
                        new Created($created),
                        new Expires($expires),
                    ),
                ],
                [$mustUnderstand],
            ),
        ]);
        $body = new Body(null, [$requestSecurityTokenResponse]);
        $envelope = new Envelope($body, $header);

        $xmlResponse = $envelope->toXML();
        \SimpleSAML\Logger::debug($xmlResponse->ownerDocument->saveXML($xmlResponse));

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
            $method = SAML2_C::AC_PASSWORD_PROTECTED_TRANSPORT;
        } else {
            $method = C::AC_PASSWORD;
        }

        $assertion = ADFS::generateActiveAssertion($idpEntityId, $spEntityId, $nameid, $attributes, $assertionLifetime, $method);

        $privateKeyCfg = $idpMetadata->getOptionalString('privatekey', null);
        $certificateCfg = $idpMetadata->getOptionalString('certificate', null);

        if ($privateKeyCfg !== null && $certificateCfg !== null) {
            $configUtils = new Utils\Config();
            $privateKeyFile = $configUtils->getCertPath($privateKeyCfg);
            $certificateFile = $configUtils->getCertPath($certificateCfg);
            $passphrase = $idpMetadata->getOptionalString('privatekey_pass', null);

            $algo = $spMetadata->getOptionalString('signature.algorithm', null);
            if ($algo === null) {
                $algo = $idpMetadata->getOptionalString('signature.algorithm', C::SIG_RSA_SHA256);
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
            'adfs/idp/prp.php', $params
        );
        return $spMetadata->getValue('prp') . '?wa=wsignoutcleanup1.0&wreply=' . urlencode($returnTo);
    }
}
