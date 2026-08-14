<?php

use SimpleSAML\XMLSecurity\TestUtils\PEMCertificatesMock;

$resourceDir = dirname(__DIR__, 2) . '/vendor/simplesamlphp/xml-security/';
$certDir = $resourceDir . PEMCertificatesMock::CERTS_DIR;
$keyDir = $resourceDir . PEMCertificatesMock::KEYS_DIR;
// A static entityID: the '__DYNAMIC:n__' placeholder is no longer implemented anywhere in
// SimpleSAMLphp core, so it is taken literally and rejected as a non-URI by consumers such as
// the admin Federation page.
$metadata['https://localhost/adfs/services/trust'] = [
    'host' => '__DEFAULT__',
    'privatekey_pass' => PEMCertificatesMock::PASSPHRASE,
    'privatekey' =>  $keyDir . '/' . PEMCertificatesMock::PRIVATE_KEY,
    'certificate' => $certDir . '/' . PEMCertificatesMock::CERTIFICATE,
    // Some WS-Fed relying parties applications set the session lifetime to the assertion lifetime
    // 'assertion.lifetime' => 3600,

    'auth' => 'example',
    'authproc' => [
        // Convert LDAP names to WS-Fed Claims.
        100 => ['class' => 'core:AttributeMap', 'name2claim'],
    ],
];
