<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\IdP;

use Beste\Clock\LocalizedClock;
use Exception;
use Psr\Clock\ClockInterface;
use SimpleSAML\{Configuration, Logger, Utils};
use SimpleSAML\Assert\Assert;
use SimpleSAML\SAML2\Exception\ArrayValidationException;
use SimpleSAML\SAML2\XML\md\AbstractMetadataDocument;
use SimpleSAML\SAML2\XML\md\ContactPerson;
use SimpleSAML\SAML2\XML\md\EntityDescriptor;
use SimpleSAML\SAML2\XML\md\NameIDFormat;
use SimpleSAML\SAML2\XML\md\KeyDescriptor;
use SimpleSAML\SAML2\XML\md\Organization;
use SimpleSAML\SAML2\XML\md\RequestedAttribute;
use SimpleSAML\SAML2\XML\md\ServiceDescription;
use SimpleSAML\SAML2\XML\md\ServiceName;
use SimpleSAML\XML\Chunk;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\XML\ds\{KeyInfo, KeyName, X509Certificate, X509Data};
use SimpleSAML\WSSecurity\Constants as C;
use SimpleSAML\WSSecurity\XML\fed\{
    PassiveRequestorEndpoint,
    SecurityTokenServiceEndpoint,
    SecurityTokenServiceType,
    TokenTypesOffered,
    TokenType,
};
use SimpleSAML\WSSecurity\XML\wsa\{Address, EndpointReference};

use function array_key_exists;
use function preg_match;

/**
 * Common code for building SAML 2 metadata based on the available configuration.
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */
class MetadataBuilder
{
    /** @var \Psr\Clock\ClockInterface */
    protected ClockInterface $clock;

    /**
     * Constructor.
     *
     * @param \SimpleSAML\Configuration $config The general configuration
     * @param \SimpleSAML\Configuration $metadata The metadata configuration
     */
    public function __construct(
        protected Configuration $config,
        protected Configuration $metadata
    ) {
        $this->clock = LocalizedClock::in('Z');
    }


    /**
     * Build a metadata document
     *
     * @return \SimpleSAML\SAML2\XML\md\EntityDescriptor
     */
    public function buildDocument(): EntityDescriptor
    {
        $entityId = $this->metadata->getString('entityid');
        $contactPerson = $this->getContactPerson();
        $organization = $this->getOrganization();
        $roleDescriptor = $this->getRoleDescriptor();

        $entityDescriptor = new EntityDescriptor(
            entityId: $entityId,
            contactPerson: $contactPerson,
            organization: $organization,
            roleDescriptor: $roleDescriptor,
        );

        if ($this->config->getOptionalBoolean('metadata.sign.enable', false) === true) {
            $this->signDocument($entityDescriptor);
        }

        return $entityDescriptor;
    }


    /**
     * @param \SimpleSAML\SAML2\XML\md\AbstractMetadataDocument $document
     * @return \SimpleSAML\SAML2\XML\md\AbstractMetadataDocument
     */
    protected function signDocument(AbstractMetadataDocument $document): AbstractMetadataDocument
    {
        $cryptoUtils = new Utils\Crypto();

        /** @var array $keyArray */
        $keyArray = $cryptoUtils->loadPrivateKey($this->config, true, 'metadata.sign.');
        $certArray = $cryptoUtils->loadPublicKey($this->config, false, 'metadata.sign.');
        $algo = $this->config->getOptionalString('metadata.sign.algorithm', C::SIG_RSA_SHA256);

        $key = PrivateKey::fromFile($keyArray['PEM'], $keyArray['password'] ?? '');
        $signer = (new SignatureAlgorithmFactory())->getAlgorithm($algo, $key);

        $keyInfo = null;
        if ($certArray !== null) {
            $keyInfo = new KeyInfo([
                new X509Data([
                    new X509Certificate($certArray['certData']),
                ]),
            ]);
        }

        $document->sign($signer, C::C14N_EXCLUSIVE_WITHOUT_COMMENTS, $keyInfo);
        return $document;
    }


    /**
     * This method builds the md:Organization element, if any
     */
    private function getOrganization(): ?Organization
    {
        if (
            !$this->metadata->hasValue('OrganizationName') ||
            !$this->metadata->hasValue('OrganizationDisplayName') ||
            !$this->metadata->hasValue('OrganizationURL')
        ) {
            // empty or incomplete organization information
            return null;
        }

        $arrayUtils = new Utils\Arrays();
        $org = null;

        try {
            $org = Organization::fromArray([
                'OrganizationName' => $arrayUtils->arrayize($this->metadata->getArray('OrganizationName'), 'en'),
                'OrganizationDisplayName' => $arrayUtils->arrayize($this->metadata->getArray('OrganizationDisplayName'), 'en'),
                'OrganizationURL' => $arrayUtils->arrayize($this->metadata->getArray('OrganizationURL'), 'en'),
            ]);
        } catch (ArrayValidationException $e) {
            Logger::error('Federation: invalid content found in contact: ' . $e->getMessage());
        }

        return $org;
    }


    /**
     * This method builds the role descriptor elements
     */
    private function getRoleDescriptor(): array
    {
        $descriptors = [];

        $set = $this->metadata->getString('metadata-set');
        switch ($set) {
            case 'adfs-idp-hosted':
                $descriptors[] = $this->getSecurityTokenService();
                break;
            default:
                throw new Exception('Not implemented');
        }

        return $descriptors;
    }


    /**
     * This method builds the SecurityTokenService element
     */
    private function getSecurityTokenService(): SecurityTokenService
    {
        $defaultEndpoint = $this->metadata->getDefaultEndpoint('SingleSignOnService');

        return new SecurityTokenServiceType(
            protocolSupportEnumeration: [C::NS_TRUST, C::NS_FED],
            keyDescriptors: $this->getKeyDescriptor(),
            tokenTypesOffered: new TokenTypesOffered([new TokenType('urn:oasis:names:tc:SAML:1.0:assertion')]),
            securityTokenServiceEndpoint: [
                new SecurityTokenServiceEndpoint([
                    new EndpointReference(new Address($defaultEndpoint['Location'])),
                ]),
            ],
            passiveRequestorEndpoint: [
                new PassiveRequestorEndpoint([
                    new EndpointReference(new Address($defaultEndpoint['Location'])),
                ]),
            ],
        );
    }


    /**
     * This method builds the md:KeyDescriptor elements, if any
     */
    private function getKeyDescriptor(): array
    {
        $keyDescriptor = [];

        $keys = $this->metadata->getPublicKeys();
        foreach ($keys as $key) {
            if ($key['type'] !== 'X509Certificate') {
                continue;
            }
            if (!isset($key['signing']) || $key['signing'] === true) {
                $keyDescriptor[] = self::buildKeyDescriptor('signing', $key['X509Certificate'], $key['name'] ?? null);
            }
            if (!isset($key['encryption']) || $key['encryption'] === true) {
                $keyDescriptor[] = self::buildKeyDescriptor('encryption', $key['X509Certificate'], $key['name'] ?? null);
            }
        }

        if ($this->metadata->hasValue('https.certData')) {
            $keyDescriptor[] = self::buildKeyDescriptor('signing', $this->metadata->getString('https.certData'), null);
        }

        return $keyDescriptor;
    }


    /**
     * This method builds the md:ContactPerson elements, if any
     */
    private function getContactPerson(): array
    {
        $contacts = [];

        foreach ($this->metadata->getOptionalArray('contacts', []) as $contact) {
            if (array_key_exists('ContactType', $contact) && array_key_exists('EmailAddress', $contact)) {
                $contacts[] = ContactPerson::fromArray($contact);
            }
        }

        return $contacts;
    }


    /**
     * This method builds the md:Extensions, if any
     */
    private function getExtensions(): ?Extensions
    {
        $extensions = [];

        if ($this->metadata->hasValue('scope')) {
            foreach ($this->metadata->getArray('scope') as $scopetext) {
                $isRegexpScope = (1 === preg_match('/[\$\^\)\(\*\|\\\\]/', $scopetext));
                $extensions[] = new Scope($scopetext, $isRegexpScope);
            }
        }

        if ($this->metadata->hasValue('EntityAttributes')) {
            $attr = [];
            foreach ($this->metadata->getArray('EntityAttributes') as $attributeName => $attributeValues) {
                $attrValues = [];
                foreach ($attributeValues as $attributeValue) {
                    $attrValues[] = new AttributeValue($attributeValue);
                }

                // Attribute names that is not URI is prefixed as this: '{nameformat}name'
                if (preg_match('/^\{(.*?)\}(.*)$/', $attributeName, $matches)) {
                    $attr[] = new Attribute(
                        name: $matches[2],
                        nameFormat: $matches[1] === C::NAMEFORMAT_UNSPECIFIED ? null : $matches[1],
                        attributeValue: $attrValues,
                    );
                } else {
                    $attr[] = new Attribute(
                        name: $attributeName,
                        nameFormat: C::NAMEFORMAT_UNSPECIFIED,
                        attributeValue: $attrValues,
                    );
                }
            }

            $extensions[] = new EntityAttributes($attr);
        }

        if ($this->metadata->hasValue('saml:Extensions')) {
            $chunks = $this->metadata->getArray('saml:Extensions');
            Assert::allIsInstanceOf($chunks, Chunk::class);
            $extensions = array_merge($extensions, $chunks);
        }

        if ($this->metadata->hasValue('RegistrationInfo')) {
            try {
                $extensions[] = RegistrationInfo::fromArray($this->metadata->getArray('RegistrationInfo'));
            } catch (ArrayValidationException $err) {
                Logger::error('Metadata: invalid content found in RegistrationInfo: ' . $err->getMessage());
            }
        }

        if ($this->metadata->hasValue('UIInfo')) {
            try {
                $extensions[] = UIInfo::fromArray($this->metadata->getArray('UIInfo'));
            } catch (ArrayValidationException $err) {
                Logger::error('Metadata: invalid content found in UIInfo: ' . $err->getMessage());
            }
        }

        if ($this->metadata->hasValue('DiscoHints')) {
            try {
                $extensions[] = DiscoHints::fromArray($this->metadata->getArray('DiscoHints'));
            } catch (ArrayValidationException $err) {
                Logger::error('Metadata: invalid content found in DiscoHints: ' . $err->getMessage());
            }
        }

        if ($extensions !== []) {
            return new Extensions($extensions);
        }

        return null;
    }


    private static function buildKeyDescriptor(string $use, string $x509Cert, ?string $keyName): KeyDescriptor
    {
        Assert::oneOf($use, ['encryption', 'signing']);
        $info = [
            new X509Data([
                new X509Certificate($x509Cert),
            ]),
        ];

        if ($keyName !== null) {
            $info[] = new KeyName($keyName);
        }

        return new KeyDescriptor(
            new KeyInfo($info),
            $use,
        );
    }
}
