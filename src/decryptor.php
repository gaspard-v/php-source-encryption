<?php

class TestPhpServer {
    private static $instances = array();
    private array $opensslFunctions = [
        "openssl_decrypt",
        "openssl_get_cipher_methods"
    ];
    private array $wantedOpenSslCipher = [
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "chacha20-poly1305",
        "aes-128-ocb",
        "aes-192-ocb",
        "aes-256-ocb",
        "aes-128-ccm",
        "aes-192-ccm",
        "aes-256-ccm",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-128-cbc-hmac-sha256",
        "aes-256-cbc-hmac-sha256",
        "aes-128-cbc",
        "aes-192-cbc",
        "aes-256-cbc",
        "des-ede3-cfb",
        "des-ede3-cbc",
        "des-cbc",
        "rc4-hmac-md5",
        "rc4"
    ];
    private string $opensslCipher;
    private array $uncallableFunctions = [];
    private function __construct() {}

    final public function opensslFunctions(): array {
        foreach ($this->opensslFunctions as $funcName) {
            if(!is_callable($funcName))
                array_push($this->uncallableFunctions, $funcName);
        }
        return $this->uncallableFunctions;
    }
    final public function opensslCipher(): string {
        $ciphers = openssl_get_cipher_methods();
        foreach ($ciphers as $cipherName) {
            if(in_array($cipherName, $this->wantedOpenSslCipher))
                $this->opensslCipher = $cipherName;
        }
        return $this->opensslCipher;
    }
    final public function getOpensslCipher(): string {
        return $this->opensslCipher;
    }

    public function launch(): void {

        // TODO: throw error if failure
        if (!$this->opensslFunctions)
            return;
        if (!$this->opensslCipher())
            return;
    }
    final public static function getInstance() {
        $c = get_called_class();
        if(!isset(self::$instances[$c]))
            self::$instances[$c] = new $c;
        return self::$instances[$c];
    }
}