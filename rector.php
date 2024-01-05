<?php

use Rector\Config\RectorConfig;
use Rector\Set\ValueObject\SetList;
use Rector\TypeDeclaration\Rector\Property\TypedPropertyFromStrictConstructorRector;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\DowngradeLevelSetList;

function recursiveCopy(string $source, string $destination)
{
    if (!is_dir($source)) {
        return false;
    }
    if (!is_dir($destination)) {
        mkdir($destination, 0777, true);
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $item) {
        $target = $destination . DIRECTORY_SEPARATOR . $iterator->getSubPathName();
        if ($item->isDir()) {
            if (!is_dir($target)) {
                mkdir($target);
            }
        } else {
            copy($item, $target);
        }
    }

    return true;
}
function getPhpVersionNormalized()
{
    $builderPhpVersion = getenv("BUILDER_PHP_VERSION");
    if (!$builderPhpVersion)
        $builderPhpVersion = phpversion();

    $builderPhpVersionArray = explode(".", $builderPhpVersion);
    $builderPhpVersionNormalized = $builderPhpVersionArray[0] . $builderPhpVersionArray[1];
    $targetPhpVersion = getenv("TARGET_PHP_VERSION");
    if (!$targetPhpVersion) {
        return [
            [
                $builderPhpVersion,
                null,
            ],
            [
                $builderPhpVersionNormalized,
                null
            ]
        ];
    }
    $targetPhpVersionArray = explode(".", $targetPhpVersion);
    $targetPhpVersionNormalized = $targetPhpVersionArray[0] . $targetPhpVersionArray[1];
    return [
        [
            $builderPhpVersion,
            $targetPhpVersion
        ],
        [
            $builderPhpVersionNormalized,
            $targetPhpVersionNormalized
        ]
    ];
}
function getTargetPhpLevelSetList()
{
    [
        [$builderPhpVersion, $targetPhpVersion],
        [$builderPhpVersionNormalized, $targetPhpVersionNormalized]
    ] = getPhpVersionNormalized();
    $defaultRectorPhpLevelSet = constant(LevelSetList::class . "::UP_TO_PHP_{$builderPhpVersionNormalized}");
    if (!$targetPhpVersion) {
        return $defaultRectorPhpLevelSet;
    }
    $versionCompare = version_compare($builderPhpVersion, $targetPhpVersion);
    $rectorPhpLevelSet = match ($versionCompare) {
        1  => constant(DowngradeLevelSetList::class . "::DOWN_TO_PHP_{$targetPhpVersionNormalized}"),
        -1 => constant(LevelSetList::class . "::UP_TO_PHP_{$targetPhpVersionNormalized}"),
        default => $defaultRectorPhpLevelSet,
    };
    return $rectorPhpLevelSet;
}

recursiveCopy("src", "src_build");

return static function (RectorConfig $rectorConfig): void {
    $rectorConfig->rule(TypedPropertyFromStrictConstructorRector::class);
    $rectorConfig->paths([
        __DIR__ . DIRECTORY_SEPARATOR . "src_build",
    ]);
    $rectorConfig->sets([
        SetList::CODE_QUALITY,
        getTargetPhpLevelSetList()
    ]);
};
