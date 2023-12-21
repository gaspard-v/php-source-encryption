<?php

declare(strict_types=1);
class MultipleExceptions extends Exception
{
    /**
     * @readonly
     * @var mixed[]
     */
    private $exceptions;
    public function __construct(
        array $exceptions,
        int $code = 0,
        Throwable $previous = null
    ) {
        $this->exceptions = $exceptions;
        $message = $this->createMessage();
        parent::__construct($message, $code, $previous);
    }

    private function createMessage(string $message = "Multiple Exceptions"): string
    {
        $message = "{$message}: ";
        foreach ($this->exceptions as $exception) {
            if (!method_exists($exception, 'getMessage')) {
                $message .= "Exception does not have a message...";
                continue;
            }
            $message .=  "\"{$exception->getMessage()}\" ";
        }
        return $message;
    }

    public function getExceptions()
    {
        return $this->exceptions;
    }
}
class UncallableFunctionException extends Exception
{
    /**
     * @readonly
     * @var string
     */
    private $uncallableFunction;
    public function __construct(
        string $uncallableFunction,
        int $code = 0,
        Throwable $previous = null
    ) {
        $this->uncallableFunction = $uncallableFunction;
        $message = "Function \"{$this->uncallableFunction}\" is not callable";
        parent::__construct($message, $code, $previous);
    }

    public function getUncallableFunction(): string
    {
        return $this->uncallableFunction;
    }
}

class UnavailableCipherException extends Exception
{
    /**
     * @readonly
     * @var string
     */
    private $unavailableCipher;
    public function __construct(
        string $unavailableCipher,
        int $code = 0,
        Throwable $previous = null
    ) {
        $this->unavailableCipher = $unavailableCipher;
        $message = "Cipher \"{$this->unavailableCipher}\" is not available";
        parent::__construct($message, $code, $previous);
    }
    public function getUnavailableCipher(): string
    {
        return $this->unavailableCipher;
    }
}

class MissingRequirementException extends Exception
{
    /**
     * @readonly
     * @var string
     */
    private $missingRequirement;
    public function __construct(
        string $missingRequirement,
        int $code = 0,
        Throwable $previous = null
    ) {
        $this->missingRequirement = $missingRequirement;
        $message = "Requirement \"{$this->missingRequirement}\" is missing";
        parent::__construct($message, $code, $previous);
    }
    public function getUnavailableRequirement(): string
    {
        return $this->missingRequirement;
    }
}

interface Decryptor
{
    function __construct(string $lol);
    /**
     * @param string $data
     * @return string|false
     */
    public function decrypt($data);
}

interface Tester
{
    /**
     * Launch all tests
     * 
     * @return void
     * @throws Exception
     */
    public function launch(): void;
}

interface DecryptorTester extends Tester
{
    public function getDecryptor(): string;
}

trait Singleton
{
    /**
     * @var mixed[]
     */
    private static $instances = [];
    private function __construct()
    {
    }
    final protected function  __clone()
    {
    }
    final public static function getInstance(...$args): self
    {
        $className = static::class;
        if (!isset(self::$instances[$className])) {
            self::$instances[$className] = new $className(...$args);
        }
        return self::$instances[$className];
    }
}

class OpensslDecryptor implements Decryptor
{
    /**
     * @readonly
     * @var string
     */
    private $cipher_algo;
    /**
     * @readonly
     * @var string
     */
    private $passphrase;
    /**
     * @readonly
     * @var string|null
     */
    private $tag;
    /**
     * @readonly
     * @var int
     */
    private $options = 0;
    /**
     * @readonly
     * @var string
     */
    private $iv = "";
    /**
     * @readonly
     * @var string
     */
    private $aad = "";
    use Singleton;
    private function __construct(string $cipher_algo, string $passphrase, ?string $tag, int $options = 0, string $iv = "", string $aad = "")
    {
        $this->cipher_algo = $cipher_algo;
        $this->passphrase = $passphrase;
        $this->tag = $tag;
        $this->options = $options;
        $this->iv = $iv;
        $this->aad = $aad;
    }
    /**
     * @param string $data
     * @return string|false
     */
    final public function decrypt($data)
    {
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
}

class McryptDecryptor implements Decryptor
{
    /**
     * @readonly
     * @var string
     */
    private $cipher;
    /**
     * @readonly
     * @var string
     */
    private $key;
    private $mode;
    /**
     * @readonly
     * @var string|null
     */
    private $iv;
    use Singleton;
    private function __construct(string $cipher, string $key, $mode, ?string $iv = null)
    {
        $this->cipher = $cipher;
        $this->key = $key;
        $this->mode = $mode;
        $this->iv = $iv;
    }
    /**
     * @param string $data
     * @return string|false
     */
    public function decrypt($data)
    {
        return mcrypt_decrypt(
            $this->cipher,
            $this->key,
            $data,
            $this->mode,
            $this->iv
        );
    }
}

class TestPhpOpenssl implements DecryptorTester
{
    use Singleton;
    /**
     * @var mixed[]
     */
    private $opensslFunctions = [
        "openssl_decrypt",
        "openssl_get_cipher_methods"
    ];
    /**
     * @var string
     */
    private $wantedOpenSslCipher = "aes-256-gcm";
    private function __construct()
    {
    }

    final public function testOpensslFunctions(): ?array
    {
        $uncallableFunctions = [];
        $callableFunctions = [];
        foreach ($this->opensslFunctions as $funcName) {
            if (!is_callable($funcName)) {
                $uncallableFunctions[] = new UncallableFunctionException($funcName);
            }
            $callableFunctions[] = $funcName;
        }
        if ($uncallableFunctions !== []) {
            throw new MultipleExceptions($uncallableFunctions);
        }
        return $callableFunctions;
    }
    final public function testOpensslCipher(): ?string
    {
        $ciphers = openssl_get_cipher_methods();
        if (in_array($this->wantedOpenSslCipher, $ciphers)) {
            return $this->wantedOpenSslCipher;
        }
        throw new UnavailableCipherException($this->wantedOpenSslCipher);
    }

    public function launch(): void
    {
        $exceptionArray = [];
        $functions = [
            function () : ?array {
                return $this->testOpensslFunctions();
            },
            function () : ?string {
                return $this->testOpensslCipher();
            }
        ];
        foreach ($functions as $func) {
            try {
                $func();
            } catch (Exception $e) {
                $exceptionArray[] = $e;
            }
        }
        if ($exceptionArray !== []) {
            throw new MultipleExceptions($exceptionArray);
        }
    }
    public function getDecryptor(): string
    {
        return OpensslDecryptor::class;
    }
}


class GetPHP
{
    use Singleton;

    /**
     * @var array<DecryptorTester> $decryptorTesters
     */
    private $decryptorTesters = [
        TestPhpOpenssl::getInstance(),
    ];
    private function __construct()
    {
    }
    public function getDecryptor(): string
    {
        $exceptions = [];
        foreach ($this->decryptorTesters as $tester) {
            try {
                $tester->launch();
                return $tester->getDecryptor();
            } catch (Exception $e) {
                $exceptions[] = $e;
            }
        }
        if ($exceptions !== []) {
            throw new MultipleExceptions($exceptions);
        }
        throw new MissingRequirementException("There's no decryptor!");
    }
}

class Executor
{
    /**
     * @var \Decryptor
     */
    private $decryptor;
    /**
     * @var mixed[]
     */
    private $clientData = [];
    use Singleton;

    private function __construct(
        Decryptor $decryptor,
        array $clientData = []
    ) {
        $this->decryptor = $decryptor;
        $this->clientData = $clientData;
        $rawClientData = file_get_contents('php://input');
        $this->clientData = json_decode(
            $rawClientData,
            true,
            512,
            0
        );
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \Exception(json_last_error_msg());
        }
        $decryptorPtr = GetPHP::getInstance()->getDecryptor();
        $this->decryptor = $decryptorPtr::getInstance(...$this->clientData);
    }
    private function exec($encryptedPhpString)
    {
    }
}
