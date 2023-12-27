<?php

$plaintext = "Hello, World!";
$cipher = "aes-256-gcm";

function display($ciphertext, $encryptionKey, $iv, $tag)
{
    global $cipher, $plaintext;
    echo "Encryption Cipher: " . $cipher . "\n";
    echo "Encryption Key: " . bin2hex($encryptionKey) . "\n";
    echo "IV: " . bin2hex($iv) . "\n";
    echo "Authentication Tag: " . bin2hex($tag) . "\n";
    echo "Encrypted Text: $ciphertext\n";
}

$encryptionKey = openssl_random_pseudo_bytes(32);
$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($cipher));
$ciphertext = openssl_encrypt($plaintext, $cipher, $encryptionKey, 0, $iv, $tag);
display($ciphertext, $encryptionKey, $iv, $tag);


// $decryptedText = openssl_decrypt($ciphertext, $cipher, $encryptionKey, 0, $iv, $tag);
