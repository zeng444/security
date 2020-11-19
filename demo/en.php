<?php

require '../vendor/autoload.php';

use \Janfish\Security\Encryption;
//print_r(Encryption::getSupportCipher());
$en = new Encryption(['cipher' => 'AES-256-CFB']); //AES-256-CFB
$encode = $en->encrypt("hello", 'keyToMyHeart', Encryption::OPENSSL_RAW_DATA);
$decode = $en->decrypt($encode, 'keyToMyHeart', Encryption::OPENSSL_RAW_DATA);
//$encode = $en->encrypt("hello", 'keyToMyHeart',Encryption::OPENSSL_ZERO_PADDING);
//$decode = $en->decrypt($encode, 'keyToMyHeart',Encryption::OPENSSL_ZERO_PADDING);
var_dump([
    $en->getIv(),
    $encode,
    $decode
]);