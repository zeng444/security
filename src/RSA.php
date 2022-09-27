<?php

namespace Janfish\Security;

use Janfish\Security\Exception\EncryptionException;

/**
 * Class RSA
 * @package Janfish\Security
 */
class RSA
{

    const OPENSSL_ALGO_SHA1 = 1; //default

    const OPENSSL_ALGO_MD5 = 2;

    const OPENSSL_ALGO_MD4 = 3;

    const OPENSSL_ALGO_MD2 = 4;

    const OPENSSL_ALGO_DSS1 = 5;

    const OPENSSL_ALGO_SHA224 = 6;

    const OPENSSL_ALGO_SHA256 = 7;

    const OPENSSL_ALGO_SHA384 = 8;

    const OPENSSL_ALGO_SHA512 = 9;

    const OPENSSL_ALGO_RMD160 = 10;

    const OPENSSL_PKCS1_PADDING = 1; //default

    const OPENSSL_SSLV23_PADDING = 2;

    const OPENSSL_NO_PADDING = 3;

    const OPENSSL_PKCS1_OAEP_PADDING = 4;

    /**
     * @var
     */
    private $_priKey;
    /**
     * @var
     */
    private $_pubKey;

    /**
     * RSA constructor.
     * @throws \Exception
     */
    public function __construct()
    {
        if (!extension_loaded('openssl')) {
            throw new EncryptionException('openssl extension is not exist');
        }
    }

    /**
     * @param string $string
     * @throws \Exception
     */
    public function setPubKey(string $string)
    {
        if (strpos($string, 'BEGIN') === false) {
            $string = "-----BEGIN PUBLIC KEY-----\n" .
                $this->formatKey($string) .
                "\n-----END PUBLIC KEY-----";
        }
        $this->_pubKey = openssl_pkey_get_public($string);
        if (!$this->_pubKey) {
            throw new EncryptionException('请检查公钥文件格式');
        }
    }

    /**
     * @param string $key
     * @return string
     */
    private function formatKey(string $key): string
    {
        return trim(wordwrap($key, 64, "\n", true));
    }

    /**
     * @param string $string
     * @throws \Exception
     */
    public function setPriKey(string $string)
    {
        if (strpos($string, 'BEGIN') === false) {
            $string = "-----BEGIN RSA PRIVATE KEY-----\n" .
                $this->formatKey($string) .
                "\n-----END RSA PRIVATE KEY-----";
        }
        $this->_priKey = openssl_pkey_get_private($string);
        if (!$this->_priKey) {
            throw new EncryptionException('请检查私钥文件格式');
        }
    }

    /**
     * @param string $source
     * @param string $padding
     * @return string
     */
    public function encrypt(string $source, string $padding = self::OPENSSL_PKCS1_PADDING): string
    {
        openssl_public_encrypt($source, $encryptData, $this->_pubKey, $padding);
        return base64_encode($encryptData);
    }

    /**
     * @param string $encryptData
     * @param string $padding
     * @return mixed
     */
    public function decrypt(string $encryptData, string $padding = self::OPENSSL_PKCS1_PADDING)
    {
        openssl_private_decrypt(base64_decode($encryptData), $decryptData, $this->_priKey, $padding);
        return $decryptData;
    }

    /**
     * @param string $source
     * @param int $signType
     * @return string
     */
    public function sign(string $source, int $signType = self::OPENSSL_ALGO_SHA1): string
    {
        openssl_sign($source, $sign, $this->_priKey, $signType);
        return base64_encode($sign);
    }

    /**
     * @param string $source
     * @param string $sign
     * @param int $signType
     * @return bool
     */
    public function verify(string $source, string $sign, int $signType = self::OPENSSL_ALGO_SHA1): bool
    {
        return (bool)openssl_verify($source, base64_decode($sign), $this->_pubKey, $signType);
    }

    /**
     *
     */
    public function __destruct()
    {
        if ($this->_priKey) {
            openssl_free_key($this->_priKey);
        }
        if ($this->_pubKey) {
            openssl_free_key($this->_pubKey);
        }
    }

}