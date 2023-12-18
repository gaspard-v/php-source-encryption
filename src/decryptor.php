<?php
class MultipleExceptions extends Exception
{
    public function __construct(
        private array $exceptions, 
        int $code = 0, 
        Throwable $previous = null) {
        $message = $this->createMessage();
        parent::__construct($message, $code, $previous);
    }

    private function createMessage(string $message = "Multiple Exceptions"): string {
        $message = "{$message}: ";
        foreach ($this->exceptions as $exception) {
            if (!method_exists($exception, 'getMessage'))
            {
                $message .= "Exception does not have a message...";
                continue;
            }
            $message .=  "\"{$exception->getMessage()}\" ";
        }
        return $message;
    }

    public function getExceptions() {
       return $this->exceptions;
    }
}
class UncallableFunctionException extends Exception
{
    public function __construct(
        private string $uncallableFunction, 
        int $code = 0, 
        Throwable $previous = null) {
        $message = "Function \"{$this->uncallableFunction}\" is not callable";
        parent::__construct($message, $code, $previous);
    }

    public function getUncallableFunction(): string {
       return $this->uncallableFunction;
    }
}

class UnavailableCipherException extends Exception {
    public function __construct(
        private string $unavailableCipher, 
        int $code = 0, 
        Throwable $previous = null) {
        $message = "Cipher \"{$this->unavailableCipher}\" is not available";
        parent::__construct($message, $code, $previous);
    }
    public function getUnavailableCipher(): string {
        return $this->unavailableCipher;
    }
}

interface Decryptor {
    public function decrypt(string $data): string|false;
}

class OpensslDecryptor implements Decryptor {
    private int $options = 0;
    private string $iv = "";

    private ?string $tag = null;
    private string $aad = "";
    public function __construct(
        private string $cipher_algo, 
        private string $passphrase) {
            
        }
    final public function decrypt(string $data): string|false {
        return openssl_decrypt(
            $data, 
            $this->cipher_algo, 
            $this->passphrase, 
            $this->options, 
            $this->iv,
            $this->tag,
            $this->aad 
        );
    }
    final public function setOptions(int $options): OpensslDecryptor {
        $this->options = $options;
        return $this;
    }

    final public function setIv(string $iv): OpensslDecryptor {
        $this->iv = $iv;
        return $this;
    }

    final public function setTag(string $tag): OpensslDecryptor {
        $this->tag = $tag;
        return $this;
    }

    final public function setAad(string $aad): OpensslDecryptor {
        $this->aad = $aad;
        return $this;
    }
}

class McryptDecryptor implements Decryptor {
    public function __construct(
        private string $cipher,
        private string $key,
        private string $data,
        private $mode,
        private ?string $iv = null
    ) {}
    public function decrypt(string $data): string|false {
        return mcrypt_decrypt(
            $this->cipher,
            $this->key,
            $this->data,
            $this->mode,
            $this->iv
        );
    }
}

class TestPhpOpenssl {
    private static $instances = array();
    private array $opensslFunctions = [
        "openssl_decrypt",
        "openssl_get_cipher_methods"
    ];
    private string $wantedOpenSslCipher = "aes-256-gcm";
    private function __construct() {}

    final public function testOpensslFunctions(): array {
        $uncallableFunctions = [];
        $callableFunctions = [];
        foreach ($this->opensslFunctions as $funcName) {
            if(!is_callable($funcName))
                $uncallableFunctions[] = new UncallableFunctionException($funcName);
            $callableFunctions[] = $funcName;
        }
        if($uncallableFunctions)
            throw new MultipleExceptions($uncallableFunctions);
        return $callableFunctions;
    }
    final public function testOpensslCipher(): ?string {
        $ciphers = openssl_get_cipher_methods();
        if (in_array($this->wantedOpenSslCipher, $ciphers))
            return $this->wantedOpenSslCipher;
        throw new UnavailableCipherException($this->wantedOpenSslCipher);
    }

    public function launch(): void {
        $exceptionArray = [];
        $functions = [
            [$this, "testOpensslFunctions"],
            [$this, "testOpensslCipher"]
        ];
        foreach ($functions as $func) {
            try {
            call_user_func($func);
            } catch(Exception $e) {
                $exceptionArray[] = $e;
            }
        }
        if ($exceptionArray)
            throw new MultipleExceptions($exceptionArray);

    }
    final public static function getInstance() {
        $c = get_called_class();
        if(!isset(self::$instances[$c]))
            self::$instances[$c] = new $c;
        return self::$instances[$c];
    }
}