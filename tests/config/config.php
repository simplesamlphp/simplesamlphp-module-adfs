<?php

/**
 * Config file to use during integration testing
 */

use SimpleSAML\Logger;

$config = [
    'baseurlpath' => '/',
    'tempdir' => '/tmp/simplesaml',
    'loggingdir' => '/tmp/simplesaml',
    'secretsalt' => 'salty',

    'metadata.sources' => [
        ['type' => 'flatfile', 'directory' =>  dirname(__DIR__) . '/metadata'],
    ],

    'module.enable' => [
        'adfs' => true,
        'exampleauth' => true
    ],

    'enable.adfs-idp' => true,
    'debug' => [
        'saml' => false,
        'backtraces' => true,
        'validatexml' => false,
    ],
    'logging.level' => Logger::DEBUG,
    'logging.handler' => 'errorlog',
];
