<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\Controller;

use Exception;
use SimpleSAML\{Configuration, IdP, Logger, Metadata, Module, Session, Utils};
use SimpleSAML\Error as SspError;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module\adfs\IdP\ADFS as ADFS_IDP;
use SimpleSAML\Module\adfs\IdP\MetadataBuilder;
use SimpleSAML\Module\adfs\MetadataExchange;
use SimpleSAML\SOAP\XML\env_200305\Envelope;
use SimpleSAML\XML\DOMDocumentFactory;
use Symfony\Component\HttpFoundation\{Request, Response, StreamedResponse};

use function array_pop;

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
            return new StreamedResponse([$authUtils, 'requireAdmin']);
        }

        try {
            if ($request->query->has('idpentityid')) {
                $idpentityid = $request->query->get('idpentityid');
            } else {
                $idpentityid = $this->metadata->getMetaDataCurrentEntityID('adfs-idp-hosted');
            }
            $idpmeta = $this->metadata->getMetaDataConfig($idpentityid, 'adfs-idp-hosted');

            $builder = new MetadataBuilder($this->config, $idpmeta);

            $document = $builder->buildDocument()->toXML();
            // Some products like DirX are known to break on pretty-printed XML
            $document->ownerDocument->formatOutput = false;
            $document->ownerDocument->encoding = 'UTF-8';
            $metaxml = $document->ownerDocument->saveXML();

            $response = new Response();
            $response->setEtag(hash('sha256', $metaxml));
            $response->setPublic();
            if ($response->isNotModified($request)) {
                return $response;
            }
            $response->headers->set('Content-Type', 'application/samlmetadata+xml');
            $response->headers->set('Content-Disposition', 'attachment; filename="FederationMetadata.xml"');
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
        $idp = IdP::getById('adfs:' . $idpEntityId);

        if ($request->get('wa', null) !== null) {
            $wa = $request->get('wa');
            if ($wa === 'wsignout1.0') {
                return new StreamedResponse(
                    function () use ($idp) {
                        ADFS_IDP::receiveLogoutMessage($idp);
                    },
                );
            } elseif ($wa === 'wsignin1.0') {
                return ADFS_IDP::receiveAuthnRequest($request, $idp);
            }
            throw new SspError\BadRequest("Unsupported value for 'wa' specified in request.");
        } elseif ($request->get('assocId', null) !== null) {
            // logout response from ADFS SP
            // Association ID of the SP that sent the logout response
            $assocId = $request->get('assocId');
            // Data that was sent in the logout request to the SP. Can be null
            $relayState = $request->get('relayState');
            // null on success, or an instance of a \SimpleSAML\Error\Exception on failure.
            $logoutError = null;

            return new StreamedResponse(
                function () use ($idp, /** @scrutinizer ignore-type */ $assocId, $relayState, $logoutError) {
                    $idp->handleLogoutResponse($assocId, $relayState, $logoutError);
                },
            );
        }
        throw new SspError\BadRequest("Missing parameter 'wa' or 'assocId' in request.");
    }


    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function mex(Request $request): Response
    {
        if (!$this->config->getOptionalBoolean('enable.adfs-idp', false)) {
            throw new SspError\Error('NOACCESS');
        }

        // check if valid local session exists
        $authUtils = new Utils\Auth();
        if ($this->config->getOptionalBoolean('admin.protectmetadata', false) && !$authUtils->isAdmin()) {
            return new StreamedResponse([$authUtils, 'requireAdmin']);
        }

        $mexBuilder = new MetadataExchange();
        $document = $mexBuilder->buildDocument()->toXML();
        // Some products like DirX are known to break on pretty-printed XML
        $document->ownerDocument->formatOutput = false;
        $document->ownerDocument->encoding = 'UTF-8';

        $document->setAttributeNS(
            'http://www.w3.org/2000/xmlns/',
            'xmlns:tns',
            'http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice',
        );

        $document->setAttributeNS(
            'http://www.w3.org/2000/xmlns/',
            'xmlns:soapenc',
            'http://schemas.xmlsoap.org/soap/encoding/'
        );

        $document->setAttributeNS(
            'http://www.w3.org/2000/xmlns/',
            'xmlns:msc',
            'http://schemas.microsoft.com/ws/2005/12/wsdl/contract'
        );

        $document->setAttributeNS(
            'http://www.w3.org/2000/xmlns/',
            'xmlns:wsam',
            'http://www.w3.org/2007/05/addressing/metadata'
        );

        $document->setAttributeNS(
            'http://www.w3.org/2000/xmlns/',
            'xmlns:wsap',
            'http://schemas.xmlsoap.org/ws/2004/08/addressing/policy'
        );

        $metaxml = $document->ownerDocument->saveXML();

        $response = new Response();
        $response->setEtag(hash('sha256', $metaxml));
        $response->setPublic();
        if ($response->isNotModified($request)) {
            return $response;
        }
        $response->headers->set('Content-Type', 'text/xml');
        $response->setContent($metaxml);

        return $response;
    }


    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function usernamemixed(Request $request): Response
    {
        if (!$this->config->getOptionalBoolean('enable.adfs-idp', false)) {
            throw new SspError\Error('NOACCESS');
        }

        $soapMessage = $request->getContent();
        if ($soapMessage === false) {
            throw new SspError\BadRequest('Missing SOAP-content.');
        }

        $domDocument = DOMDocumentFactory::fromString($soapMessage);
        $soapEnvelope = Envelope::fromXML($domDocument->documentElement);

        $idpEntityId = $this->metadata->getMetaDataCurrentEntityID('adfs-idp-hosted');
        $idp = IdP::getById('adfs:' . $idpEntityId);

        return ADFS_IDP::receivePassiveAuthnRequest($request, $soapEnvelope, $idp);
    }
}
