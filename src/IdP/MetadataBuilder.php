<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\IdP;

use Beste\Clock\LocalizedClock;
use Exception;
use Psr\Clock\ClockInterface;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\SAML2\Constants as C_SAML2;
use SimpleSAML\SAML2\Exception\ArrayValidationException;
use SimpleSAML\SAML2\Type\EntityIDValue;
use SimpleSAML\SAML2\Type\KeyTypesValue;
use SimpleSAML\SAML2\Type\SAMLAnyURIListValue;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\Type\SAMLStringValue;
use SimpleSAML\SAML2\XML\md\AbstractMetadataDocument;
use SimpleSAML\SAML2\XML\md\ContactPerson;
use SimpleSAML\SAML2\XML\md\EntityDescriptor;
use SimpleSAML\SAML2\XML\md\Extensions;
use SimpleSAML\SAML2\XML\md\KeyDescriptor;
use SimpleSAML\SAML2\XML\md\Organization;
use SimpleSAML\SAML2\XML\mdattr\EntityAttributes;
use SimpleSAML\SAML2\XML\mdrpi\RegistrationInfo;
use SimpleSAML\SAML2\XML\mdui\DiscoHints;
use SimpleSAML\SAML2\XML\mdui\UIInfo;
use SimpleSAML\SAML2\XML\saml\Attribute;
use SimpleSAML\SAML2\XML\saml\AttributeValue;
use SimpleSAML\SAML2\XML\shibmd\Scope;
use SimpleSAML\Utils;
use SimpleSAML\WebServices\Addressing\XML\wsa_200508\Address;
use SimpleSAML\WebServices\Addressing\XML\wsa_200508\EndpointReference;
use SimpleSAML\WebServices\Federation\Constants as C_FED;
use SimpleSAML\WebServices\Federation\XML\fed\PassiveRequestorEndpoint;
use SimpleSAML\WebServices\Federation\XML\fed\SecurityTokenServiceEndpoint;
use SimpleSAML\WebServices\Federation\XML\fed\SecurityTokenServiceType;
use SimpleSAML\WebServices\Federation\XML\fed\TokenType;
use SimpleSAML\WebServices\Federation\XML\fed\TokenTypesOffered;
use SimpleSAML\WebServices\Trust\Constants as C_TRUST;
use SimpleSAML\XML\Chunk;
use SimpleSAML\XMLSchema\Type\AnyURIValue;
use SimpleSAML\XMLSchema\Type\BooleanValue;
use SimpleSAML\XMLSchema\Type\IDValue;
use SimpleSAML\XMLSchema\Type\NCNameValue;
use SimpleSAML\XMLSchema\Type\QNameValue;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Constants as C_XMLSEC;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\XML\ds\KeyInfo;
use SimpleSAML\XMLSecurity\XML\ds\KeyName;
use SimpleSAML\XMLSecurity\XML\ds\X509Certificate;
use SimpleSAML\XMLSecurity\XML\ds\X509Data;

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
        protected Configuration $metadata,
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
        $extensions = $this->getExtensions();

        $randomUtils = new Utils\Random();
        $entityDescriptor = new EntityDescriptor(
            id: IDValue::fromString($randomUtils->generateID()),
            extensions: $extensions,
            entityId: EntityIDValue::fromString($entityId),
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

        /** @var array<mixed> $keyArray */
        $keyArray = $cryptoUtils->loadPrivateKey($this->config, true, 'metadata.sign.');
        $certArray = $cryptoUtils->loadPublicKey($this->config, false, 'metadata.sign.');
        $algo = $this->config->getOptionalString('metadata.sign.algorithm', C_XMLSEC::SIG_RSA_SHA256);

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

        $document->sign($signer, C_XMLSEC::C14N_EXCLUSIVE_WITHOUT_COMMENTS, $keyInfo);
        return $document;
    }


    /**
     * This method builds the md:Organization element, if any
     *
     * @return \SimpleSAML\SAML2\XML\md\Organization
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
                'OrganizationDisplayName' => $arrayUtils->arrayize(
                    $this->metadata->getArray('OrganizationDisplayName'),
                    'en',
                ),
                'OrganizationURL' => $arrayUtils->arrayize($this->metadata->getArray('OrganizationURL'), 'en'),
            ]);
        } catch (ArrayValidationException $e) {
            Logger::error('Federation: invalid content found in contact: ' . $e->getMessage());
        }

        return $org;
    }


    /**
     * This method builds the role descriptor elements
     *
     * @return \SimpleSAML\SAML2\XML\md\AbstractRoleDescriptor[]
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
     *
     * @return \SimpleSAML\WebServices\Federation\XML\fed\SecurityTokenServiceType
     */
    public function getSecurityTokenService(): SecurityTokenServiceType
    {
        $defaultEndpoint = Module::getModuleURL('adfs') . '/idp/prp.php';

        return new SecurityTokenServiceType(
            QNameValue::fromParts(
                NCNameValue::fromString(SecurityTokenServiceType::getLocalName()),
                AnyURIValue::fromString(SecurityTokenServiceType::NS),
                NCNameValue::fromString(SecurityTokenServiceType::NS_PREFIX),
            ),
            protocolSupportEnumeration: SAMLAnyURIListValue::fromArray(
                [C_TRUST::NS_TRUST_200512, C_TRUST::NS_TRUST_200502, C_FED::NS_FED],
            ),
            keyDescriptors: $this->getKeyDescriptor(),
            tokenTypesOffered: new TokenTypesOffered(
                [
                    new TokenType(AnyURIValue::fromString('urn:oasis:names:tc:SAML:1.0:assertion')),
                ],
            ),
            securityTokenServiceEndpoint: [
                new SecurityTokenServiceEndpoint([
                    new EndpointReference(new Address(AnyURIValue::fromString($defaultEndpoint))),
                ]),
            ],
            passiveRequestorEndpoint: [
                new PassiveRequestorEndpoint([
                    new EndpointReference(new Address(AnyURIValue::fromString($defaultEndpoint))),
                ]),
            ],
        );
    }


    /**
     * This method builds the md:KeyDescriptor elements, if any
     *
     * @return \SimpleSAML\SAML2\XML\md\KeyDescriptor[]
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
                $keyDescriptor[] = self::buildKeyDescriptor(
                    'signing',
                    $key['X509Certificate'],
                    $key['name'] ?? null,
                );
            }
            if (!isset($key['encryption']) || $key['encryption'] === true) {
                $keyDescriptor[] = self::buildKeyDescriptor(
                    'encryption',
                    $key['X509Certificate'],
                    $key['name'] ?? null,
                );
            }
        }

        if ($this->metadata->hasValue('https.certData')) {
            $keyDescriptor[] = self::buildKeyDescriptor('signing', $this->metadata->getString('https.certData'), null);
        }

        return $keyDescriptor;
    }


    /**
     * This method builds the md:ContactPerson elements, if any
     *
     * @return \SimpleSAML\SAML2\XML\md\ContactPerson[]
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
     *
     * @return \SimpleSAML\SAML2\XML\md\Extensions|null
     */
    private function getExtensions(): ?Extensions
    {
        $extensions = [];

        if ($this->metadata->hasValue('scope')) {
            foreach ($this->metadata->getArray('scope') as $scopetext) {
                $isRegexpScope = 1 === preg_match('/[\$\^\)\(\*\|\\\\]/', $scopetext);
                $extensions[] = new Scope(
                    SAMLStringValue::fromString($scopetext),
                    BooleanValue::fromBoolean($isRegexpScope),
                );
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
                        name: SAMLStringValue::fromString($matches[2]),
                        nameFormat: SAMLAnyURIValue::fromString(
                            $matches[1] === C_SAML2::NAMEFORMAT_UNSPECIFIED ? null : $matches[1],
                        ),
                        attributeValue: $attrValues,
                    );
                } else {
                    $attr[] = new Attribute(
                        name: SAMLStringValue::fromString($attributeName),
                        nameFormat: SAMLAnyURIValue::fromString(C_SAML2::NAMEFORMAT_UNSPECIFIED),
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


    /**
     * @param string $use
     * @param string $x509Cert
     * @param string|null $keyName
     *
     * @return \SimpleSAML\SAML2\XML\md\KeyDescriptor
     */
    private static function buildKeyDescriptor(string $use, string $x509Cert, ?string $keyName): KeyDescriptor
    {
        Assert::oneOf($use, ['encryption', 'signing']);
        $info = [
            new X509Data([
                X509Certificate::fromString($x509Cert),
            ]),
        ];

        if ($keyName !== null) {
            $info[] = KeyName::fromString($keyName);
        }

        return new KeyDescriptor(
            new KeyInfo($info),
            KeyTypesValue::fromString($use),
        );
    }
}
