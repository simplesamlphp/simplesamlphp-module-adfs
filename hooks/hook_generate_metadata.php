<?php

declare(strict_types=1);

use SimpleSAML\Assert\Assert;
use SimpleSAML\SAML2\Constants as C;
use SimpleSAML\Configuration;
use SimpleSAML\Utils;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Metadata\MetaDataStorageHandler;

/**
 * @param array<mixed> $hookinfo
 */
function adfs_hook_generate_metadata(array &$hookinfo): void
{
    if ($hookinfo['set'] === 'adfs-idp-hosted') {
        $property = $hookinfo['property'];
        $endpoint = Module::getModuleURL('adfs/idp/prp.php');

        switch ($property) {
            case 'SingleSignOnService':
                $hookinfo['result'] = $endpoint;
                break;
            case 'SingleSignOnServiceBinding':
                $hookinfo['result'] = C::BINDING_HTTP_REDIRECT;
                break;
            case 'SingleLogoutService':
                $hookinfo['result'] = $endpoint;
                break;
            case 'SingleLogoutServiceBinding':
                $hookinfo['result'] = C::BINDING_HTTP_REDIRECT;
                break;
        }
    }
}

