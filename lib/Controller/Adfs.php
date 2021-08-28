<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\Controller;

use SAML2\Constants;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Configuration;
use SimpleSAML\Error as SspError;
use SimpleSAML\IdP;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\adfs\IdP\ADFS as ADFS_IDP;
use SimpleSAML\Metadata;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Controller class for the adfs module.
 *
 * This class serves the adfs views available in the module.
 *
 * @package SimpleSAML\Module\adfs
 */
class Adfs
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Metadata\MetaDataStorageHandler */
    protected Metadata\MetaDataStorageHandler $metadata;

    /** @var \SimpleSAML\Session */
    protected Session $session;

    /** @var \SimpleSAML\Utils\Crypto */
    protected Utils\Crypto $cryptoUtils;

    /**
     * AdfsController constructor.
     *
     * @param \SimpleSAML\Configuration $config The configuration to use.
     * @param \SimpleSAML\Session $session The current user session.
     */
    public function __construct(Configuration $config, Session $session)
    {
        $this->config = $config;
        $this->metadata = Metadata\MetaDataStorageHandler::getMetadataHandler();
        $this->session = $session;
        $this->cryptoUtils = new Utils\Crypto();
    }


    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\Response|\SimpleSAML\XHTML\Template
     */
    public function metadata(Request $request): Response
    {
        if (!$this->config->getBoolean('enable.adfs-idp', false)) {
            throw new SspError\Error('NOACCESS');
        }

        // check if valid local session exists
        if ($this->config->getBoolean('admin.protectmetadata', false)) {
            $authUtils = new Utils\Auth();
            $authUtils->requireAdmin();
        }

        try {
            $idpentityid = $request->get('idpentityid') ?: $this->metadata->getMetaDataCurrentEntityID('adfs-idp-hosted');
            $idpmeta = $this->metadata->getMetaDataConfig($idpentityid, 'adfs-idp-hosted');

            $availableCerts = [];
            $keys = [];
            $certInfo = $this->cryptoUtils->loadPublicKey($idpmeta, false, 'new_');

            if ($certInfo !== null) {
                $availableCerts['new_idp.crt'] = $certInfo;
                $keys[] = [
                    'type'            => 'X509Certificate',
                    'signing'         => true,
                    'encryption'      => true,
                    'X509Certificate' => $certInfo['certData'],
                ];
                $hasNewCert = true;
            } else {
                $hasNewCert = false;
            }

            /** @var array $certInfo */
            $certInfo = $this->cryptoUtils->loadPublicKey($idpmeta, true);
            $availableCerts['idp.crt'] = $certInfo;
            $keys[] = [
                'type'            => 'X509Certificate',
                'signing'         => true,
                'encryption'      => ($hasNewCert ? false : true),
                'X509Certificate' => $certInfo['certData'],
            ];

            if ($idpmeta->hasValue('https.certificate')) {
                /** @var array $httpsCert */
                $httpsCert = $this->cryptoUtils->loadPublicKey($idpmeta, true, 'https.');
                Assert::keyExists($httpsCert, 'certData');
                $availableCerts['https.crt'] = $httpsCert;
                $keys[] = [
                    'type'            => 'X509Certificate',
                    'signing'         => true,
                    'encryption'      => false,
                    'X509Certificate' => $httpsCert['certData'],
                ];
            }

            $adfs_service_location = Module::getModuleURL('adfs') . '/idp/prp.php';
            $metaArray = [
                'metadata-set'        => 'adfs-idp-remote',
                'entityid'            => $idpentityid,
                'SingleSignOnService' => [
                    0 => [
                        'Binding'  => Constants::BINDING_HTTP_REDIRECT,
                        'Location' => $adfs_service_location
                    ]
                ],
                'SingleLogoutService' => [
                    0 => [
                        'Binding'  => Constants::BINDING_HTTP_REDIRECT,
                        'Location' => $adfs_service_location
                    ]
                ],
            ];

            if (count($keys) === 1) {
                $metaArray['certData'] = $keys[0]['X509Certificate'];
            } else {
                $metaArray['keys'] = $keys;
            }

            $metaArray['NameIDFormat'] = $idpmeta->getString(
                'NameIDFormat',
                Constants::NAMEID_TRANSIENT
            );

            if ($idpmeta->hasValue('OrganizationName')) {
                $metaArray['OrganizationName'] = $idpmeta->getLocalizedString('OrganizationName');
                $metaArray['OrganizationDisplayName'] = $idpmeta->getLocalizedString(
                    'OrganizationDisplayName',
                    $metaArray['OrganizationName']
                );

                if (!$idpmeta->hasValue('OrganizationURL')) {
                    throw new SspError\Exception('If OrganizationName is set, OrganizationURL must also be set.');
                }
                $metaArray['OrganizationURL'] = $idpmeta->getLocalizedString('OrganizationURL');
            }

            if ($idpmeta->hasValue('scope')) {
                $metaArray['scope'] = $idpmeta->getArray('scope');
            }

            if ($idpmeta->hasValue('EntityAttributes')) {
                $metaArray['EntityAttributes'] = $idpmeta->getArray('EntityAttributes');
            }

            if ($idpmeta->hasValue('UIInfo')) {
                $metaArray['UIInfo'] = $idpmeta->getArray('UIInfo');
            }

            if ($idpmeta->hasValue('DiscoHints')) {
                $metaArray['DiscoHints'] = $idpmeta->getArray('DiscoHints');
            }

            if ($idpmeta->hasValue('RegistrationInfo')) {
                $metaArray['RegistrationInfo'] = $idpmeta->getArray('RegistrationInfo');
            }

            $metaflat = '$metadata[' . var_export($idpentityid, true) . '] = ' . var_export($metaArray, true) . ';';

            $metaBuilder = new Metadata\SAMLBuilder($idpentityid);
            $metaBuilder->addSecurityTokenServiceType($metaArray);
            $metaBuilder->addOrganizationInfo($metaArray);
            $technicalContactEmail = $this->config->getString('technicalcontact_email', null);
            if ($technicalContactEmail && $technicalContactEmail !== 'na@example.org') {
                $metaBuilder->addContact('technical', Utils\Config\Metadata::getContact([
                    'emailAddress' => $technicalContactEmail,
                    'name'         => $this->config->getString('technicalcontact_name', null),
                    'contactType'  => 'technical',
                ]));
            }
            $output_xhtml = array_key_exists('output', $_GET) && $_GET['output'] == 'xhtml';
            $metaxml = $metaBuilder->getEntityDescriptorText($output_xhtml);
            if (!$output_xhtml) {
                $metaxml = str_replace("\n", '', $metaxml);
            }

            // sign the metadata if enabled
            $metaxml = Metadata\Signer::sign($metaxml, $idpmeta->toArray(), 'ADFS IdP');

            if ($output_xhtml) {
                $t = new Template($this->config, 'metadata.twig', 'admin');

                $t->data['clipboard.js'] = true;
                $t->data['available_certs'] = $availableCerts;
                $certdata = [];
                foreach (array_keys($availableCerts) as $availableCert) {
                    $certdata[$availableCert]['name'] = $availableCert;
                    $certdata[$availableCert]['url'] = Module::getModuleURL('saml/idp/certs.php') .
                        '/' . $availableCert;

                    $certdata[$availableCert]['comment'] = '';
                }
                $t->data['certdata'] = $certdata;
                $t->data['headerString'] = Translate::noop('metadata_adfs-idp');
                $httpUtils = new Utils\HTTP();
                $t->data['metaurl'] = $httpUtils->getSelfURLNoQuery();
                $t->data['metadata'] = htmlspecialchars($metaxml);
                $t->data['metadataflat'] = htmlspecialchars($metaflat);

                return $t;
            } else {
                // make sure to export only the md:EntityDescriptor
                $i = strpos($metaxml, '<md:EntityDescriptor');
                $metaxml = substr($metaxml, $i ? $i : 0);

                // 22 = strlen('</md:EntityDescriptor>')
                $i = strrpos($metaxml, '</md:EntityDescriptor>');
                $metaxml = substr($metaxml, 0, $i ? $i + 22 : 0);

                $response = new Response();
                $response->headers->set('Content-Type', 'application/xml');
                $response->setContent($metaxml);

                return $response;
            }
        } catch (\Exception $exception) {
            throw new SspError\Error('METADATA', $exception);
        }
    }


    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function prp(Request $request): Response
    {
        Logger::info('ADFS - IdP.prp: Accessing ADFS IdP endpoint prp');

        $idpEntityId = $this->metadata->getMetaDataCurrentEntityID('adfs-idp-hosted');
        $idp = IdP::getById('adfs:' . $idpEntityId);

        if ($request->query->has('wa')) {
            $wa = $request->get('wa');
            if ($wa === 'wsignout1.0') {
                return new StreamedResponse(
                    function () use ($idp) {
                        ADFS_IDP::receiveLogoutMessage($idp);
                    }
                );
            } elseif ($wa === 'wsignin1.0') {
                return ADFS_IDP::receiveAuthnRequest($request, $idp);
            }
            throw new SspError\BadRequest("Unsupported value for 'wa' specified in request.");
        } elseif ($request->query->has('assocId')) {
            // logout response from ADFS SP
            $assocId = $request->get('assocId'); // Association ID of the SP that sent the logout response
            $relayState = $request->get('relayState'); // Data that was sent in the logout request to the SP. Can be null
            $logoutError = null; // null on success, or an instance of a \SimpleSAML\Error\Exception on failure.

            return new StreamedResponse(
                function () use ($idp, /** @scrutinizer ignore-type */ $assocId, $relayState, $logoutError) {
                    $idp->handleLogoutResponse($assocId, $relayState, $logoutError);
                }
            );
        }
        throw new SspError\BadRequest("Missing parameter 'wa' or 'assocId' in request.");
    }
}
