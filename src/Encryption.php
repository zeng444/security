<?php

namespace Janfish\Security;

/**
 * Class Encryption
 * @package Janfish\Security
 */
class Encryption
{

    /**
     * 默认加密方式
     */
//    const  DEFAULT_CIPHER = 'AES-256-CFB';
    const  DEFAULT_CIPHER = 'des-ede3';

    const OPENSSL_RAW_DATA = 1;

    const OPENSSL_ZERO_PADDING = 2;
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
     * @throws \Exception
     */
    public function __construct(array $options = [])
    {
        if (isset($options['cipher'])) {
            $this->cipher = $options['cipher'];
        }
        $this->cipher = $this->cipher ? $this->cipher : self::DEFAULT_CIPHER;
        if (!in_array($this->cipher, self::getSupportCipher())) {
            throw new \Exception('不支持的加密算法');
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
     * 将加密后的字符串以及向量一并返回
     * @param $data
     * @param string $encryptKey
     * @param int $option
     * @return string
     * @throws \Exception
     */
    public function encrypt($data, $encryptKey = '', $option = self::OPENSSL_RAW_DATA)
    {
        $iv = $this->makeIv();
        $encryptedData = openssl_encrypt($data, $this->cipher, $encryptKey, $option, $iv);
        return $iv . $encryptedData;
    }

    /**
     * 计算向量
     * @return string
     * @throws \Exception
     * @author Robert
     *
     */
    private function makeIv()
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
     * @param $encryptedData
     * @param string $encryptKey
     * @param int $option
     * @return false|string
     */
    public function decrypt($encryptedData, $encryptKey = '', $option = self::OPENSSL_RAW_DATA)
    {
        return openssl_decrypt(substr($encryptedData, $this->ivSize), $this->cipher, $encryptKey, $option, $this->parseIv($encryptedData));
    }

    /**
     * 从加密串中分离向量
     * @param $encryptedData
     * @return string
     * @author Robert
     *
     */
    public function parseIv($encryptedData)
    {
        $this->iv = substr($encryptedData, 0, $this->ivSize);
        return $this->iv;
    }
}