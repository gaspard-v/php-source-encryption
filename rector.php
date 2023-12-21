<?php

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
recursiveCopy("src", "src71");
exec("vendor/bin/rector --config=rector8.3.php");
exec("vendor/bin/rector --config=rector7.1.php");
