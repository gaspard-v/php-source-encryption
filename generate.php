<?php
require_once(__DIR__ . DIRECTORY_SEPARATOR . "utils" . DIRECTORY_SEPARATOR . "format_php_string.php");
function deleteComents(string $phpFilePath)
{
    $phpString = file_get_contents($phpFilePath);
    $phpString = preg_replace('/\/\/[^\n]*|#[^\n]*/', '', $phpString);
    $phpString = preg_replace('/\/\*.*?\*\//s', '', $phpString);
    return file_put_contents($phpFilePath, $phpString);
}

function formatPhpFile(string $phpFilePath)
{
    $phpString = file_get_contents($phpFilePath);
    utils\formatPhpString($phpString);
    return file_put_contents($phpFilePath, $phpString);
}

$targetPhpVersion = getenv("TARGET_PHP_VERSION");
$phpSourceFile = getenv("PHP_SOURCE_FILE");

if (!$targetPhpVersion) {
    echo "Environment variable \"TARGET_PHP_VERSION\" must be set";
    exit(1);
}

if (!$phpSourceFile) {
    echo "Environment variable \"PHP_SOURCE_FILE\" must be set";
    exit(1);
}

echo "Target Php Version: $targetPhpVersion\nPhp Source File: $phpSourceFile\n";

$finalBuildFile = __DIR__ . DIRECTORY_SEPARATOR . "build.php";
$intermediateBuildFile = __DIR__ . DIRECTORY_SEPARATOR . "intermediate.php";
$sourceBuildFile = __DIR__ . DIRECTORY_SEPARATOR . "source_build.php";

if (file_get_contents($finalBuildFile)) {
    echo "file $finalBuildFile exists and has content, exiting ...\n";
    exit(0);
}
unlink($intermediateBuildFile);
unlink($sourceBuildFile);

passthru(__DIR__ . DIRECTORY_SEPARATOR . "vendor/bin/rector");
$decryptorFile = __DIR__ . DIRECTORY_SEPARATOR .
    "src_build" .
    DIRECTORY_SEPARATOR .
    "decryptor.php";

passthru("yakpro-po {$phpSourceFile} -o {$sourceBuildFile}");
deleteComents($sourceBuildFile);
formatPhpFile($sourceBuildFile);
require_once(__DIR__ . DIRECTORY_SEPARATOR . "utils" . DIRECTORY_SEPARATOR . "generate_keys_and_encrypt.php");
$plainText = file_get_contents($sourceBuildFile);
unlink($sourceBuildFile);
$encryptor = new utils\OpenSSL();
$encryptor->encrypt($plainText)->display();

$expression = "\n" . '$encryptedPhpString=' . "\"{$encryptor->cipherText}\";\n";
$expression .= <<<'EOD'
$executor = Executor::getInstance();
$executor->exec($encryptedPhpString);
EOD;
$expression .= "\n";
copy($decryptorFile, $intermediateBuildFile);
file_put_contents($intermediateBuildFile, $expression, FILE_APPEND);
passthru("yakpro-po {$intermediateBuildFile} -o {$finalBuildFile}");
deleteComents($finalBuildFile);
unlink($intermediateBuildFile);
