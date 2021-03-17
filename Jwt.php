<?php

namespace sizeg\jwt;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Yii;
use yii\base\Component;
use yii\base\InvalidArgumentException;

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
    public array $supportedAlgs = [
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

    public function getBuilder() : Builder
    {
        return $this->_config->builder();
    }

    public function getConfig() : Configuration
    {
        return $this->_config;
    }

    public function getParser() : Parser
    {
        return $this->getConfig()->parser();
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
}
