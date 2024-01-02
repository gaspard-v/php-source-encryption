<?php

// Encryption Cipher: aes-256-gcm
// Encryption Key: bfcb5659f04e2a7608dec03adef3a1b8673877c56e9d5c74fd120ad9e5f8d817
// IV: ff174fa21ef864d4e6ebc4d8
// Authentication Tag: 0d7ada861994cc26963c79251e7abf0a
// Cipher Text: 40Qg0UMNyL3HHyo/MER3ArlifmNQQD5sTvDtDr+cAwraLxvPZy94XIgbm5mdjUNB
// Plain Text: <?php
//
// function hello()
// {
//     echo "Hello !";
// }

require_once(dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . "src" . DIRECTORY_SEPARATOR . "decryptor.php");
$executor = Executor::getInstance();
$ciphertext = "40Qg0UMNyL3HHyo/MER3ArlifmNQQD5sTvDtDr+cAwraLxvPZy94XIgbm5mdjUNB";
$executor->exec($ciphertext);
