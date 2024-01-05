<?php

namespace utils;

function formatPhpString(string &$phpString): void
{
    $removeSubStrings = ["<?php", "?>", "<?"];
    foreach ($removeSubStrings as $subString) {
        $phpString = str_replace($subString, "", $phpString);
    }
}
