<?php
require_once(dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . "utils" . DIRECTORY_SEPARATOR . "generate_keys_and_encrypt.php");

$plainText = file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . "test_script.php");
$encryptor = new utils\OpenSSL();
$encryptor->encrypt($plainText);
$encryptor->display();
