<?php

use Rector\Config\RectorConfig;
use Rector\Set\ValueObject\SetList;
use Rector\Core\ValueObject\PhpVersion;
use Rector\TypeDeclaration\Rector\Property\TypedPropertyFromStrictConstructorRector;
use Rector\Set\ValueObject\DowngradeLevelSetList;


return static function (RectorConfig $rectorConfig): void {
    $rectorConfig->phpVersion(PhpVersion::PHP_71);
    $rectorConfig->rule(TypedPropertyFromStrictConstructorRector::class);
    $rectorConfig->paths([
        __DIR__ . DIRECTORY_SEPARATOR . "src71",
    ]);
    $rectorConfig->sets([
        SetList::CODE_QUALITY,
        DowngradeLevelSetList::DOWN_TO_PHP_71,
    ]);
};
