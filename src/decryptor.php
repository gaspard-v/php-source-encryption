<?php
interface Decryptor {
    public function decrypt(string $data): string;
}

class OpensslDecryptor implements Decryptor {
    public function __construct(
        private string $cipher_algo, 
        private string $passphrase) {
            
        }
    final public function decrypt(string $data): string{
        return "TODO";
    }
}

class TestPhpOpenssl {
    private static $instances = array();
    private array $opensslFunctions = [
        "openssl_decrypt",
        "openssl_get_cipher_methods"
    ];
    private string $wantedOpenSslCipher = "aes-256-gcm";
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
        if (!in_array($this->wantedOpenSslCipher, $ciphers))
            return "";
        return "TODO";
    }

    public function launch(): void {

        // TODO: throw error if failure
        if (!$this->opensslFunctions)
            return;
    }
    final public static function getInstance() {
        $c = get_called_class();
        if(!isset(self::$instances[$c]))
            self::$instances[$c] = new $c;
        return self::$instances[$c];
    }
}