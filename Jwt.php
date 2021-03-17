<?php

namespace sizeg\jwt;

use Codeception\Specify\Config;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Yii;
use yii\base\Component;
use yii\base\InvalidArgumentException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;

/**
 * JSON Web Token implementation, based on this library:
 * https://github.com/lcobucci/jwt
 *
 * @author Dmitriy Demin <sizemail@gmail.com>
 * @since 1.0.0-a
 */
class Jwt extends Component
{

    /**
     * @var array Supported algorithms
     */
    public $supportedAlgs = [
        'HS256' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
        'HS384' => \Lcobucci\JWT\Signer\Hmac\Sha384::class,
        'HS512' => \Lcobucci\JWT\Signer\Hmac\Sha512::class,
        'ES256' => \Lcobucci\JWT\Signer\Ecdsa\Sha256::class,
        'ES384' => \Lcobucci\JWT\Signer\Ecdsa\Sha384::class,
        'ES512' => \Lcobucci\JWT\Signer\Ecdsa\Sha512::class,
        'RS256' => \Lcobucci\JWT\Signer\Rsa\Sha256::class,
        'RS384' => \Lcobucci\JWT\Signer\Rsa\Sha384::class,
        'RS512' => \Lcobucci\JWT\Signer\Rsa\Sha512::class,
    ];

    public string $key;

    protected Configuration $_config;

    public function __construct($config = [])
    {
        parent::__construct($config);
        $this->_config = Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText($this->key));
        $this->_config->setValidationConstraints(new IdentifiedBy('4f1g23a12aa'));
    }

    /**
     * @var string|array|callable \sizeg\jwtJwtValidationData
     * @see [[Yii::createObject()]]
     */
    public $jwtValidationData = JwtValidationData::class;

    public function getBuilder() : Builder
    {
        return $this->_config->builder();
    }

    public function getConfig() : Configuration
    {
        return $this->_config;
    }

    /**
     * @see [[Lcobucci\JWT\Parser::__construct()]]
     * @param Decoder|null $decoder
     * @param ClaimFactory|null $claimFactory
     * @return Parser
     */
    public function getParser(Decoder $decoder = null, ClaimFactory $claimFactory = null)
    {
        return $this->getConfig()->parser();
    }

    /**
     * @see [[Lcobucci\JWT\ValidationData::__construct()]]
     * @return ValidationData
     */
    public function getValidationData()
    {
        return Yii::createObject($this->jwtValidationData)->getValidationData();
    }

    /**
     * @param string $alg
     * @return Signer
     */
    public function getSigner($alg)
    {
        $class = $this->supportedAlgs[$alg];

        return new $class();
    }

    public function getKey($content = null, $passphrase = null) : InMemory
    {
        $content = $content ?: $this->key;

        if ($content instanceof InMemory) {
            return $content;
        }

        return InMemory::plainText($content);
    }

    /**
     * Parses the JWT and returns a token class
     * @param string $token JWT
     * @param bool $validate
     * @param bool $verify
     * @return Token|null
     * @throws \Throwable
     */
    public function loadToken(string $token, $validate = true, $verify = true)
    {
        try {
            $token = $this->getParser()->parse($token);
        } catch (\RuntimeException $e) {
            Yii::warning('Invalid JWT provided: ' . $e->getMessage(), 'jwt');
            return null;
        } catch (\InvalidArgumentException $e) {
            Yii::warning('Invalid JWT provided: ' . $e->getMessage(), 'jwt');
        }
        if(!$this->getConfig()->validator()->validate($token, ...$this->getConfig()->validationConstraints())){
            throw new InvalidArgumentException('Invalid token provided');
        }

        return $token;
    }

    /**
     * Validate token
     * @param Token $token token object
     * @param int|null $currentTime
     * @return bool
     */
    public function validateToken(Token $token, $currentTime = null)
    {
        $validationData = $this->getValidationData();
        if ($currentTime !== null) {
            $validationData->setCurrentTime($currentTime);
        }
        return $token->validate($validationData);
    }

    /**
     * Validate token
     * @param Token $token token object
     * @return bool
     * @throws \Throwable
     */
    public function verifyToken(Token $token)
    {
        $alg = $token->getHeader('alg');

        if (empty($this->supportedAlgs[$alg])) {
            throw new InvalidArgumentException('Algorithm not supported');
        }

        /** @var Signer $signer */
        $signer = Yii::createObject($this->supportedAlgs[$alg]);

        return $token->verify($signer, $this->key);
    }
}
