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
use SimpleSAML\SAML11\Attribute;
use SimpleSAML\SAML11\AttributeStatement;
use SimpleSAML\SAML11\AttributeValue;
use SimpleSAML\SAML11\Audience;
use SimpleSAML\SAML11\AudienceRestrictionCondition;
use SimpleSAML\SAML11\AuthenticationStatement;
use SimpleSAML\SAML11\Conditions;
use SimpleSAML\SAML11\NameIdentifier;
use SimpleSAML\SAML11\Subject;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\Utils;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate as PublicKey;
use SimpleSAML\XMLSecurity\XML\ds\KeyInfo;
use SimpleSAML\XMLSecurity\XML\ds\X509Certificate;
use SimpleSAML\XMLSecurity\XML\ds\X509Data;
use SimpleSAML\WSSecurity\XML\wsa\Address;
use SimpleSAML\WSSecurity\XML\wsa\EndpointReference;
use SimpleSAML\WSSecurity\XML\wsp\AppliesTo;
use SimpleSAML\WSSecurity\XML\wst\RequestSecurityTokenResponse;
use SimpleSAML\WSSecurity\XML\wst\RequestSecurityToken;
use SimpleSAML\XHTML\Template;
use SimpleSAML\XML\DOMDocumentFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\StreamedResponse;

class ADFS
{
    /**
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

        $state = [
            'Responder' => [ADFS::class, 'sendResponse'],
            'SPMetadata' => $spMetadata->toArray(),
            'ForceAuthn' => false,
            'isPassive' => false,
            'adfs:wctx' => $requestid,
            'adfs:wreply' => false,
        ];

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
     * @param array $attributes
     * @param int $assertionLifetime
     * @return \SimpleSAML\SAML11\XML\saml\Assertion
     */
    private static function generateAssertion(
        string $issuer,
        string $target,
        string $nameid,
        array $attributes,
        int $assertionLifetime,
    ): string {
        $httpUtils = new Utils\HTTP();
        $randomUtils = new Utils\Random();
        $timeUtils = new Utils\Time();

        $issueInstant = $timeUtils->generateTimestamp();
        $notBefore = new DateInterval('PT30S');
        $notOnOrAfter = new DateInterval($assertionLifetime);
        $assertionID = $randomUtils->generateID();
        $nameidFormat = 'http://schemas.xmlsoap.org/claims/UPN';
        $nameid = htmlspecialchars($nameid);
        $now = new DateTimeImmutable('now', new DateTimeZone('Z'));

        if ($httpUtils->isHTTPS()) {
            $method = Constants::AC_PASSWORD_PROTECTED_TRANSPORT;
        } else {
            $method = Constants::AC_PASSWORD;
        }

        $audience = new Audience($target);
        $audienceRestrictionCondition = new AudienceRestrictionCondition([$audience]);
        $conditions = new Conditions(
            $audience,
            [],
            [],
            $now->sub($notBefore),
            $now->add($assertionLifetime),
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
        $attributeStatement = new AttributeStatement($subject, $attributes);

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
        string $passphrase = null,
    ): string {
        $key = PrivateKey::fromFile($key, $passphrase);
        $pubkey = PublicKey::fromFile($cert);
        $keyInfo = new KeyInfo([
            new X509Data(
                [new X509Certificate($pubkey->getPEM()->getData())],
            ),
        ]);

        $signer = (new SignatureAlgorithmFactory())->getAlgorithm(
            $algo,
            $key,
        );

        return $assertion->sign($signer, C::C14N_EXCLUSIVE_WITHOUT_COMMENTS, $keyInfo);
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
     *
     * @return array
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Error\MetadataNotFound
     */
    public static function getHostedMetadata(string $entityid): array
    {
        $handler = MetaDataStorageHandler::getMetadataHandler();
        $cryptoUtils = new Utils\Crypto();
        $config = $handler->getMetaDataConfig($entityid, 'adfs-idp-hosted');

        $endpoint = Module::getModuleURL('adfs/idp/prp.php');
        $metadata = [
            'metadata-set' => 'adfs-idp-hosted',
            'entityid' => $entityid,
            'SingleSignOnService' => [
                [
                    'Binding' => Constants::BINDING_HTTP_REDIRECT,
                    'Location' => $endpoint,
                ],
            ],
            'SingleLogoutService' => [
                'Binding' => Constants::BINDING_HTTP_REDIRECT,
                'Location' => $endpoint,
            ],
            'NameIDFormat' => $config->getOptionalString('NameIDFormat', Constants::NAMEID_TRANSIENT),
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

        /** @var array $certInfo */
        $certInfo = $cryptoUtils->loadPublicKey($config, true);
        $keys[] = [
            'type' => 'X509Certificate',
            'signing' => true,
            'encryption' => $hasNewCert === false,
            'X509Certificate' => $certInfo['certData'],
            'prefix' => '',
        ];

        if ($config->hasValue('https.certificate')) {
            /** @var array $httpsCert */
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
     * @param array $state
     * @throws \Exception
     */
    public static function sendResponse(array $state): void
    {
        $spMetadata = $state["SPMetadata"];
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
        $idpEntityId = $idpMetadata->getString('entityid');

        $idp->addAssociation([
            'id' => 'adfs:' . $spEntityId,
            'Handler' => ADFS::class,
            'adfs:entityID' => $spEntityId,
        ]);

        $assertionLifetime = $spMetadata->getOptionalString('assertion.lifetime', null);
        if ($assertionLifetime === null) {
            $assertionLifetime = $idpMetadata->getOptionalString('assertion.lifetime', 'PT300S');
        }
        Assert::nullOrValidDuration($assertionLifetime);

        $assertion = ADFS::generateAssertion($idpEntityId, $spEntityId, $nameid, $attributes, $assertionLifetime);

        $configUtils = new Utils\Config();
        $privateKeyFile = $configUtils->getCertPath($idpMetadata->getString('privatekey'));
        $certificateFile = $configUtils->getCertPath($idpMetadata->getString('certificate'));
        $passphrase = $idpMetadata->getOptionalString('privatekey_pass', null);

        $algo = $spMetadata->getOptionalString('signature.algorithm', null);
        if ($algo === null) {
            $algo = $idpMetadata->getOptionalString('signature.algorithm', C::SIG_RSA_SHA256);
        }
        $assertion = ADFS::signAssertion($assertion, $privateKeyFile, $certificateFile, $algo, $passphrase);

        $requestSecurityToken = new RequestSecurityToken(null, [$assertion]);
        $appliesTo = new AppliesTo([new EndpointReference(new Address($target))]);
        $requestSecurityTokenResponse = RequestSecurityTokenResponse(null, [$requestSecurityToken, $appliesTo]);

        $wresult = $requestSecurityTokenResponse->saveXML();;
        $wctx = $state['adfs:wctx'];
        $wreply = $state['adfs:wreply'] ? : $spMetadata->getValue('prp');
        ADFS::postResponse($wreply, $wresult, $wctx);
    }


    /**
     * @param \SimpleSAML\IdP $idp
     * @param array $state
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
     * @param array $association
     * @param string $relayState
     * @return string
     */
    public static function getLogoutURL(IdP $idp, array $association, string $relayState): string
    {
        $metadata = MetaDataStorageHandler::getMetadataHandler();
        $spMetadata = $metadata->getMetaDataConfig($association['adfs:entityID'], 'adfs-sp-remote');
        $returnTo = Module::getModuleURL(
            'adfs/idp/prp.php?assocId=' . urlencode($association["id"]) . '&relayState=' . urlencode($relayState),
        );
        return $spMetadata->getValue('prp') . '?wa=wsignoutcleanup1.0&wreply=' . urlencode($returnTo);
    }
}
