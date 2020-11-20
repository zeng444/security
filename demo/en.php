<?php

require '../vendor/autoload.php';

use \Janfish\Security\Crypt;
//print_r(Crypt::getSupportCipher());
$en = new Crypt(['cipher' => 'AES-256-CFB']); //AES-256-CFB
$encode = $en->encrypt("hello", 'keyToMyHeart', Crypt::OPENSSL_RAW_DATA);
$decode = $en->decrypt($encode, 'keyToMyHeart', Crypt::OPENSSL_RAW_DATA);
//$encode = $en->encrypt("hello", 'keyToMyHeart',Crypt::OPENSSL_ZERO_PADDING);
//$decode = $en->decrypt($encode, 'keyToMyHeart',Crypt::OPENSSL_ZERO_PADDING);
var_dump([
    $en->getIv(),
    $encode,
    $decode
]);