<?php

$targetPhpVersion = getenv("TARGET_PHP_VERSION");
$phpSourceFile = getenv("PHP_SOURCE_FILE");
$availiblePhpVersion = [
    "7" => "src71",
    "8" => "src"
];
if (!$targetPhpVersion) {
    echo "Environment variable \"TARGET_PHP_VERSION\" must be set";
    exit(1);
}

if (!array_key_exists($targetPhpVersion, $availiblePhpVersion)) {
    echo "Environment variable \"TARGET_PHP_VERSION\" value must be \"7\" or \"8\"";
    exit(1);
}
if (!$phpSourceFile) {
    echo "Environment variable \"PHP_SOURCE_FILE\" must be set";
    exit(1);
}

$finalBuildFile = __DIR__ . DIRECTORY_SEPARATOR . "build.php";
$intermediateBuildFile = __DIR__ . DIRECTORY_SEPARATOR . "intermediate.php";
$sourceBuildFile = __DIR__ . DIRECTORY_SEPARATOR . "source_build.php";
unlink($finalBuildFile);
unlink($intermediateBuildFile);
unlink($sourceBuildFile);

require_once "rector.php";
$decryptorFile = __DIR__ . DIRECTORY_SEPARATOR .
    $availiblePhpVersion[$targetPhpVersion] .
    DIRECTORY_SEPARATOR .
    "decryptor.php";

passthru("yakpro-po {$phpSourceFile} -o {$sourceBuildFile}");
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
unlink($intermediateBuildFile);
