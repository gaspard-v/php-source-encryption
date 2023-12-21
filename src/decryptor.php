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
    function __construct(string $lol);
    public function decrypt(string $data): string|false;
}

interface Tester {

    /**
     * Launch all tests
     * 
     * @return void
     * @throws Exception
     */
    public function launch(): void;
}

interface DecryptorTester {
    public function getDecryptor(): string;
}

trait Singleton {
    private static array $instances = [];
    private function __construct() {}
    final protected function  __clone() {}
    final public static function getInstance(...$args): self
    {
        $className = static::class;
        if(!isset(self::$instances[$className]))
            self::$instances[$className] = new $className(...$args);
        return self::$instances[$className];
    }
}

class OpensslDecryptor implements Decryptor {
    use Singleton;
    private int $options = 0;
    private string $iv = "";

    private ?string $tag = null;
    private string $aad = "";
    private function __construct(
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
    use Singleton;
    private function __construct(
        private string $cipher,
        private string $key,
        private $mode,
        private ?string $iv = null
    ) {}
    public function decrypt(string $data): string|false {
        return mcrypt_decrypt(
            $this->cipher,
            $this->key,
            $data,
            $this->mode,
            $this->iv
        );
    }
}

class TestPhpOpenssl implements Tester, DecryptorTester {
    use Singleton;
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
    public function getDecryptor(): string {
        return OpensslDecryptor::class;
    }
}


class GetPHP {
    use Singleton;
    private array $decryptorTesters = [];
    private function __construct() {
        $this->decryptorTesters[] = TestPhpOpenssl::getInstance();
    }
    public function getDecryptor(): string {
        foreach($this->decryptorTesters as $tester) {
            try {
                $tester->launch();
                return $tester->getDecryptor();
            } catch (Exception $e) {
                continue;
            }
        }
        throw new Exception("non");
    }
}

// $phpInstance = GetPHP::getInstance();
// $dec = $phpInstance->getDecryptor();
// $dec::getInstance();
// var_dump($dec);