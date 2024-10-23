<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\IdP;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use Exception;
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
use SimpleSAML\SAML11\XML\saml\NameIdentifier;
use SimpleSAML\SAML11\XML\saml\Subject;
use SimpleSAML\Utils;
use SimpleSAML\WSSecurity\XML\wsa_200508\Address;
use SimpleSAML\WSSecurity\XML\wsa_200508\EndpointReference;
use SimpleSAML\WSSecurity\XML\wsp\AppliesTo;
use SimpleSAML\WSSecurity\XML\wst_200502\RequestSecurityToken;
use SimpleSAML\WSSecurity\XML\wst_200502\RequestSecurityTokenResponse;
use SimpleSAML\XHTML\Template;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate as PublicKey;
use SimpleSAML\XMLSecurity\XML\ds\KeyInfo;
use SimpleSAML\XMLSecurity\XML\ds\X509Certificate;
use SimpleSAML\XMLSecurity\XML\ds\X509Data;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\StreamedResponse;

use function base64_encode;
use function chunk_split;
use function trim;

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

        $username = null;
        if ($request->query->has('username')) {
            $username = (string) $request->query->get('username');
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

        if ($httpUtils->isHTTPS()) {
            $method = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
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

        $assertionLifetime = $spMetadata->getOptionalInteger('assertion.lifetime', null);
        if ($assertionLifetime === null) {
            $assertionLifetime = $idpMetadata->getOptionalInteger('assertion.lifetime', 300);
        }

        $assertion = ADFS::generateAssertion($idpEntityId, $spEntityId, $nameid, $attributes, $assertionLifetime);

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

        $requestSecurityToken = new RequestSecurityToken(null, [$assertion]);
        $appliesTo = new AppliesTo([new EndpointReference(new Address($spEntityId))]);
        $requestSecurityTokenResponse = new RequestSecurityTokenResponse(null, [$requestSecurityToken, $appliesTo]);

        $xmlResponse = $requestSecurityTokenResponse->toXML();
        $wresult = $xmlResponse->ownerDocument->saveXML($xmlResponse);
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
