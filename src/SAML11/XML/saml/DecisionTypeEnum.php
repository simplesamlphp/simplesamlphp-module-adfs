<?php

declare(strict_types=1);

namespace SimpleSAML\Module\adfs\XML\SAML11;

enum DecisionTypeEnum
{
    case Deny;
    case Indeterminate;
    case Permit;
}
