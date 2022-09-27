<?php

namespace Janfish\Security;

use Janfish\Security\Exception\EncryptionException;

/**
 * Class Crypt
 * @package Janfish\Security
 */
class Crypt
{

    /**
     * 默认加密方式
     */
//    const  DEFAULT_CIPHER = 'AES-256-CFB';
    const  DEFAULT_CIPHER = 'des-ede3';

    const OPENSSL_DEFAULT_DATA = 0;

    const OPENSSL_RAW_DATA = 1;

    const OPENSSL_ZERO_PADDING = 2;

    const OPENSSL_NO_PADDING = 3;

    /**
     * @var
     */
    public $cipher;
    /**
     * 向量
     * @var
     */
    public $iv;
    /**
     * 向量长
     * @var
     */
    public $ivSize;

    /**
     * @param array $options
     * @throws EncryptionException
     */
    public function __construct(array $options = [])
    {
        if (!extension_loaded('openssl')) {
            throw new EncryptionException('openssl extension is not exist');
        }
        if (isset($options['cipher'])) {
            $this->cipher = $options['cipher'];
        }
        $this->cipher = $this->cipher ?: self::DEFAULT_CIPHER;
        if (!in_array($this->cipher, self::getSupportCipher())) {
            throw new EncryptionException('不支持的加密算法');
        }
        $this->ivSize = openssl_cipher_iv_length($this->cipher);
    }

    /**
     * @return array
     */
    public static function getSupportCipher(): array
    {
        return openssl_get_cipher_methods(false);
    }

    /**
     * 计算向量
     * @return string
     */
    public function makeIv(): string
    {
        $this->iv = openssl_random_pseudo_bytes($this->ivSize); //随机生成向量
        return $this->iv;
    }

    /**
     * @return mixed
     */
    public function getIv()
    {
        return $this->iv;
    }

    /**
     * 将加密后的字符串以及向量一并返回
     * @param string $data
     * @param string $encryptKey
     * @param string $iv
     * @param int $option
     * @return false|string
     */
    public function encrypt(string $data, string $encryptKey, string $iv = null, int $option = self::OPENSSL_DEFAULT_DATA)
    {
        if ($iv) {
            return openssl_encrypt($data, $this->cipher, $encryptKey, $option, $iv);
        }
        $iv = $this->makeIv();
        return $iv . openssl_encrypt($data, $this->cipher, $encryptKey, $option, $iv);
    }

    /**
     * @param string $encryptedData
     * @param string $encryptKey
     * @param string $iv
     * @param int $option
     * @return false|string
     */
    public function decrypt(string $encryptedData, string $encryptKey, string $iv = null, int $option = self::OPENSSL_DEFAULT_DATA)
    {
        if (!$iv) {
            $iv = $this->parseIv($encryptedData);
            $encryptedData = substr($encryptedData, $this->ivSize);
        }
        return openssl_decrypt($encryptedData, $this->cipher, $encryptKey, $option, $iv);
    }

    /**
     * 从加密串中分离向量
     * @param $encryptedData
     * @return string
     * @author Robert
     *
     */
    public function parseIv($encryptedData): string
    {
        $this->iv = substr($encryptedData, 0, $this->ivSize);
        return $this->iv;
    }
}