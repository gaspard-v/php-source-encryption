<?php

declare(strict_types=1);
class MultipleExceptions extends Exception
{
    public function __construct(
        private readonly array $exceptions,
        int $code = 0,
        Throwable $previous = null
    ) {
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
    public function __construct(
        private readonly string $uncallableFunction,
        int $code = 0,
        Throwable $previous = null
    ) {
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
    public function __construct(
        private readonly string $unavailableCipher,
        int $code = 0,
        Throwable $previous = null
    ) {
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
    public function __construct(
        private readonly string $missingRequirement,
        int $code = 0,
        Throwable $previous = null
    ) {
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
    public function decrypt(string $data): string|false;
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
    private static array $instances = [];
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
    private function __construct(
        private readonly string $cipher_algo,
        private readonly string $passphrase,
        private readonly ?string $tag,
        private readonly int $options = 0,
        private readonly string $iv = "",
        private readonly string $aad = ""
    ) {
    }
    final public function decrypt(string $data): string|false
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
    private function __construct(
        private readonly string $cipher,
        private readonly string $key,
        private $mode,
        private readonly ?string $iv = null
    ) {
    }
    public function decrypt(string $data): string|false
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
    private array $opensslFunctions = [
        "openssl_decrypt",
        "openssl_get_cipher_methods"
    ];
    private string $wantedOpenSslCipher = "aes-256-gcm";
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
            fn(): ?array => $this->testOpensslFunctions(),
            fn(): ?string => $this->testOpensslCipher()
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
    private array $decryptorTesters = [
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
    use Singleton;

    private function __construct(
        private Decryptor $decryptor,
        private array $clientData = []
    ) {
        $rawClientData = file_get_contents('php://input');
        $this->clientData = json_decode(
            json: $rawClientData,
            associative: true,
            flags: JSON_THROW_ON_ERROR
        );
        $decryptorPtr = GetPHP::getInstance()->getDecryptor();
        $this->decryptor = $decryptorPtr::getInstance(...$this->clientData);
    }
    private function exec($encryptedPhpString)
    {
    }
}
