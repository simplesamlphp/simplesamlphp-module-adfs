<?php

declare(strict_types=1);

$projectRoot = dirname(__DIR__);
/** @psalm-suppress UnresolvableInclude */
require_once($projectRoot . '/vendor/autoload.php');

// Symlink module into ssp vendor lib so that templates and urls can resolve correctly
// Symlink in our config

$adfsModulePath = $projectRoot . '/vendor/simplesamlphp/simplesamlphp/modules/adfs';
$simplesamlphpConfig = $projectRoot . '/vendor/simplesamlphp/simplesamlphp/config';

function symlinkModulePathInVendorDirectory($target, $link)
{
    if (file_exists($link) === false) {
        // If the link is invalid, remove it.
        if (is_link($link)) {
            unlink($link);
        }
        print "Linking '$link' to '$target'\n";
        symlink($target, $link);
    } else {
        if (is_link($link) === false) {
            // Looks like there is a directory here. Lets remove it and symlink in this one
            print "Renaming pre-installed path and linking '$link' to '$target'\n";
            rename($link, $link . '-preinstalled');
            symlink($target, $link);
        }
    }
}

symlinkModulePathInVendorDirectory($projectRoot, $adfsModulePath);
symlinkModulePathInVendorDirectory($projectRoot . '/tests/config/', $simplesamlphpConfig);
