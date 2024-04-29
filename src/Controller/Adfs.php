<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\Controller;

use Exception;
use SimpleSAML\Configuration;
use SimpleSAML\Error as SspError;
use SimpleSAML\IdP;
use SimpleSAML\Logger;
use SimpleSAML\Metadata;
use SimpleSAML\Module\adfs\IdP\ADFS as ADFS_IDP;
use SimpleSAML\Session;
use SimpleSAML\Utils;
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
        $this->metadata = Metadata\MetaDataStorageHandler::getMetadataHandler($config);
        $this->session = $session;
        $this->cryptoUtils = new Utils\Crypto();
    }


    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\Response|\SimpleSAML\XHTML\Template
     */
    public function metadata(Request $request): Response
    {
        if (!$this->config->getOptionalBoolean('enable.adfs-idp', false)) {
            throw new SspError\Error('NOACCESS');
        }

        // check if valid local session exists
        $authUtils = new Utils\Auth();
        if ($this->config->getOptionalBoolean('admin.protectmetadata', false) && !$authUtils->isAdmin()) {
            return new RunnableResponse([$authUtils, 'requireAdmin']);
        }

        try {
            if ($request->query->has('idpentityid')) {
                $idpentityid = $request->query->get('idpentityid');
            } else {
                $idpentityid = $this->metadata->getMetaDataCurrentEntityID('adfs-idp-hosted');
            }
            $idpmeta = $this->metadata->getMetaDataConfig($idpentityid, 'adfs-idp-hosted');

            $document = $builder->buildDocument()->toXML();
            $document->ownerDocument->formatOutput = true;
            $document->ownerDocument->encoding = 'UTF-8';
            $metaxml = $document->ownerDocument->saveXML();

            $response = new Response();
            $response->setEtag(hash('sha256', $metaxml));
            $response->setPublic();
            if ($response->isNotModified($request)) {
                return $response;
            }
            $response->headers->set('Content-Type', 'application/samlmetadata+xml');
            $response->headers->set('Content-Disposition', 'attachment; filename="idp-metadata.xml"');
            $response->setContent($metaxml);

            return $response;
        } catch (Exception $exception) {
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
        $idp = IdP::getById($this->config, 'adfs:' . $idpEntityId);

        if ($request->query->has('wa')) {
            $wa = $request->query->get('wa');
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
            // Association ID of the SP that sent the logout response
            $assocId = $request->query->get('assocId');
            // Data that was sent in the logout request to the SP. Can be null
            $relayState = $request->query->get('relayState');
            // null on success, or an instance of a \SimpleSAML\Error\Exception on failure.
            $logoutError = null;

            return new StreamedResponse(
                function () use ($idp, /** @scrutinizer ignore-type */ $assocId, $relayState, $logoutError) {
                    $idp->handleLogoutResponse($assocId, $relayState, $logoutError);
                }
            );
        }
        throw new SspError\BadRequest("Missing parameter 'wa' or 'assocId' in request.");
    }
}
