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
    use Singleton;
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
     * @var int
     */
    private $options = 0;
    /**
     * @var string
     */
    private $iv = "";
    /**
     * @var string
     */
    private $aad = "";
    private function __construct(array $args)
    {
        $this->cipher_algo = $args["cipher_algo"];
        $this->passphrase = $args["passphrase"];
        $optArgs = ["tag", "options", "iv", "aad"];
        foreach ($optArgs as $optArg) {
            $this->$optArg = $args[$optArg];
        }
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
    use Singleton;
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
    private function __construct(array $args)
    {
        $this->cipher = $args["cipher"];
        $this->key = $args["key"];
        $this->mode = $args["mode"];
        $optArgs = ["iv"];
        foreach ($optArgs as $optArg) {
            $this->$optArg = $args[$optArg];
        }
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
    private $decryptorTesters = [];
    private function __construct()
    {
        $this->decryptorTesters[] = TestPhpOpenssl::getInstance();
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
    use Singleton;
    /**
     * @readonly
     * @var \Decryptor
     */
    private $decryptor;
    /**
     * @var mixed[]
     */
    private $clientData = [];
    private function __construct()
    {
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
        $this->decryptor = $decryptorPtr::getInstance($this->clientData);
    }
    private function exec($encryptedPhpString)
    {
    }
}

