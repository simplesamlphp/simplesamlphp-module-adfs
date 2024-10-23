<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\IdP;

use Exception;
use SimpleSAML\{Auth, Configuration, Error, Utils};
use SimpleSAML\Assert\Assert;
use SimpleSAML\IdP\{IFrameLogoutHandler, LogoutHandlerInterface, TraditionalLogoutHandler};
use SimpleSAML\Metadata\MetaDataStorageHandler;
use Symfony\Component\HttpFoundation\{RedirectResponse, Response};

use function call_user_func;
use function substr;
use function time;
use function var_export;

/**
 * IdP class.
 *
 * This class implements the various functions used by IdP.
 *
 * @package simplesamlphp/simplesamlphp-module-adfs
 */

class PassiveIdP
{
    /**
     * A cache for resolving IdP id's.
     *
     * @var array
     */
    private static array $idpCache = [];

    /**
     * The identifier for this IdP.
     *
     * @var string
     */
    private string $id;

    /**
     * The configuration for this IdP.
     *
     * @var \SimpleSAML\Configuration
     */
    private Configuration $config;

    /**
     * The global configuration.
     *
     * @var \SimpleSAML\Configuration
     */
    private Configuration $globalConfig;

    /**
     * Our authsource.
     *
     * @var \SimpleSAML\Auth\Simple
     */
    private Auth\Simple $authSource;


    /**
     * Initialize an IdP.
     *
     * @param \SimpleSAML\Configuration $config The configuration
     * @param string $id The identifier of this IdP.
     *
     * @throws \SimpleSAML\Error\Exception If the IdP is disabled or no such auth source was found.
     */
    private function __construct(Configuration $config, string $id)
    {
        $this->id = $id;

        $this->globalConfig = $config;
        $metadata = MetaDataStorageHandler::getMetadataHandler($this->globalConfig);

        if (substr($id, 0, 5) === 'adfs:') {
            if (!$this->globalConfig->getOptionalBoolean('enable.adfs-idp', false)) {
                throw new Error\Exception('enable.adfs-idp disabled in config.php.');
            }
            $this->config = $metadata->getMetaDataConfig(substr($id, 5), 'adfs-idp-hosted');
        } else {
            throw new Exception("Protocol not implemented.");
        }

        $auth = $this->config->getString('passiveAuth');
        if (Auth\Source::getById($auth) !== null) {
            $this->authSource = new Auth\Simple($auth);
        } else {
            throw new Error\Exception('No such "' . $auth . '" auth source found.');
        }
    }


    /**
     * Retrieve the ID of this IdP.
     *
     * @return string The ID of this IdP.
     */
    public function getId(): string
    {
        return $this->id;
    }


    /**
     * Retrieve an IdP by ID.
     *
     * @param \SimpleSAML\Configuration $config The Configuration
     * @param string $id The identifier of the IdP.
     *
     * @return \SimpleSAML\Module\adfs\IdP\PassiveIdP The IdP.
     */
    public static function getById(Configuration $config, string $id): PassiveIdP
    {
        if (isset(self::$idpCache[$id])) {
            return self::$idpCache[$id];
        }

        $idp = new self($config, $id);
        self::$idpCache[$id] = $idp;
        return $idp;
    }


    /**
     * Retrieve the IdP "owning" the state.
     *
     * @param \SimpleSAML\Configuration $config The Configuration.
     * @param array &$state The state array.
     *
     * @return \SimpleSAML\Module\adfs\IdP\PassiveIdP The IdP.
     */
    public static function getByState(Configuration $config, array &$state): PassiveIdP
    {
        Assert::notNull($state['core:IdP']);

        return self::getById($config, $state['core:IdP']);
    }


    /**
     * Retrieve the configuration for this IdP.
     *
     * @return Configuration The configuration object.
     */
    public function getConfig(): Configuration
    {
        return $this->config;
    }


    /**
     * Is the current user authenticated?
     *
     * @return boolean True if the user is authenticated, false otherwise.
     */
    public function isAuthenticated(): bool
    {
        return $this->authSource->isAuthenticated();
    }


    /**
     * Called after authproc has run.
     *
     * @param array $state The authentication request state array.
     */
    public static function postAuthProc(array $state): Response
    {
        Assert::isCallable($state['Responder']);

        if (isset($state['core:SP'])) {
            $session = Session::getSessionFromRequest();
            $session->setData(
                'core:idp-ssotime',
                $state['core:IdP'] . ';' . $state['core:SP'],
                time(),
                Session::DATA_TIMEOUT_SESSION_END,
            );
        }

        $response = call_user_func($state['Responder'], $state);
        Assert::isInstanceOf($response, Response::class);
        return $response;
    }


    /**
     * The user is authenticated.
     *
     * @param array $state The authentication request state array.
     *
     * @throws \SimpleSAML\Error\Exception If we are not authenticated.
     */
    public static function postAuth(array $state): Response
    {
        $idp = IdP::getByState(Configuration::getInstance(), $state);

        if (!$idp->isAuthenticated()) {
            throw new Error\Exception('Not authenticated.');
        }

        $state['Attributes'] = $idp->authSource->getAttributes();

        if (isset($state['SPMetadata'])) {
            $spMetadata = $state['SPMetadata'];
        } else {
            $spMetadata = [];
        }

        if (isset($state['core:SP'])) {
            $session = Session::getSessionFromRequest();
            $previousSSOTime = $session->getData('core:idp-ssotime', $state['core:IdP'] . ';' . $state['core:SP']);
            if ($previousSSOTime !== null) {
                $state['PreviousSSOTimestamp'] = $previousSSOTime;
            }
        }

        $idpMetadata = $idp->getConfig()->toArray();

        $pc = new Auth\ProcessingChain($idpMetadata, $spMetadata, 'idp');

        $state['ReturnCall'] = ['\SimpleSAML\Module\adfs\IdP\PassiveIdP', 'postAuthProc'];
        $state['Destination'] = $spMetadata;
        $state['Source'] = $idpMetadata;

        $pc->processState($state);

        return self::postAuthProc($state);
    }


    /**
     * Authenticate the user.
     *
     * This function authenticates the user.
     *
     * @param array &$state The authentication request state.
     */
    private function authenticate(array &$state): Response
    {
        return $this->authSource->login($state);
    }


    /**
     * Process authentication requests.
     *
     * @param array &$state The authentication request state.
     */
    public function handleAuthenticationRequest(array &$state): Response
    {
        Assert::notNull($state['Responder']);

        $state['core:IdP'] = $this->id;

        if (isset($state['SPMetadata']['entityid'])) {
            $spEntityId = $state['SPMetadata']['entityid'];
        } elseif (isset($state['SPMetadata']['entityID'])) {
            $spEntityId = $state['SPMetadata']['entityID'];
        } else {
            $spEntityId = null;
        }

        $state['core:SP'] = $spEntityId;
        $state['IdPMetadata'] = $this->getConfig()->toArray();
        $state['ReturnCallback'] = ['\SimpleSAML\Module\saml\IdP\PassiveIdP', 'postAuth'];

        try {
            return $this->authenticate($state);
        } catch (Error\Exception $e) {
            Auth\State::throwException($state, $e);
        } catch (Exception $e) {
            $e = new Error\UnserializableException($e);
            Auth\State::throwException($state, $e);
        }

        throw new Exception('Should never happen.');
    }


    /**
     * Find the logout handler of this IdP.
     *
     * @return \SimpleSAML\IdP\LogoutHandlerInterface The logout handler class.
     *
     * @throws \Exception If we cannot find a logout handler.
     */
    public function getLogoutHandler(): LogoutHandlerInterface
    {
        // find the logout handler
        $logouttype = $this->getConfig()->getOptionalString('logouttype', 'traditional');
        switch ($logouttype) {
            case 'traditional':
                $handler = TraditionalLogoutHandler::class;
                break;
            case 'iframe':
                $handler = IFrameLogoutHandler::class;
                break;
            default:
                throw new Error\Exception('Unknown logout handler: ' . var_export($logouttype, true));
        }

        /** @var \SimpleSAML\IdP\LogoutHandlerInterface */
        return new $handler($this);
    }


    /**
     * Finish the logout operation.
     *
     * This function will never return.
     *
     * @param array &$state The logout request state.
     */
    public function finishLogout(array &$state): Response
    {
        Assert::notNull($state['Responder']);
        return call_user_func($state['Responder'], $state);
    }
}
