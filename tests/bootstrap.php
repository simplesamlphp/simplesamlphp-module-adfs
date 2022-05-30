<?php

declare(strict_types=1);

$projectRoot = dirname(__DIR__);
/** @psalm-suppress UnresolvableInclude */
require_once($projectRoot . '/vendor/autoload.php');

// Symlink in our config
function symlinkModulePathInVendorDirectory(string $target, string $link): void
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

$simplesamlphpConfig = $projectRoot . '/vendor/simplesamlphp/simplesamlphp/config';
symlinkModulePathInVendorDirectory($projectRoot . '/tests/config/', $simplesamlphpConfig);
