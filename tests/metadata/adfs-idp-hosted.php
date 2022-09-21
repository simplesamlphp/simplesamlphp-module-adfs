<?php

use SimpleSAML\XMLSecurity\TestUtils\PEMCertificatesMock;

$certDir = dirname(__DIR__, 2) . '/vendor/simplesamlphp/xml-security' . PEMCertificatesMock::CERTIFICATE_DIR;
$metadata['__DYNAMIC:1__'] = [
    'host' => '__DEFAULT__',
    'privatekey_pass' => '1234',
    'privatekey' =>  $certDir . '/' . PEMCertificatesMock::PRIVATE_KEY,
    'certificate' => $certDir . '/' . PEMCertificatesMock::PUBLIC_KEY,
    // Some WS-Fed relying parties applications set the session lifetime to the assertion lifetime
    // 'assertion.lifetime' => 3600,

    'auth' => 'example',
    'authproc' => [
        // Convert LDAP names to WS-Fed Claims.
        100 => ['class' => 'core:AttributeMap', 'name2claim'],
    ],
];
