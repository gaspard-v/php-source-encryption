<?php

namespace utils;

$plaintext = "Hello, World!";
$cipher = "aes-256-gcm";

class OpenSSL
{
    public string $cipher = "aes-256-gcm";
    public string $encryptionKey;
    public string $iv;
    public ?string $tag;
    public ?string $plainText;
    public ?string $cipherText;
    public function __construct()
    {
        $this->encryptionKey = openssl_random_pseudo_bytes(32);
        $this->iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cipher));
    }
    public function encrypt(string $plainText): static
    {
        $this->plainText = $plainText;
        $this->cipherText = openssl_encrypt($this->plainText, $this->cipher, $this->encryptionKey, 0, $this->iv, $this->tag);
        return $this;
    }
    function display()
    {
        if (!$this->cipherText || !$this->plainText || !$this->tag)
            throw new \Exception("execute \"encrypt\" function first");
        echo "Encryption Cipher: " . $this->cipher . "\n";
        echo "Encryption Key: " . bin2hex($this->encryptionKey) . "\n";
        echo "IV: " . bin2hex($this->iv) . "\n";
        echo "Authentication Tag: " . bin2hex($this->tag) . "\n";
        echo "Cipher Text: " . $this->cipherText . "\n";
        echo "Plain Text: " . $this->plainText . "\n";
    }
}

// $decryptedText = openssl_decrypt($ciphertext, $cipher, $encryptionKey, 0, $iv, $tag);
