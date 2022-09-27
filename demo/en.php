<?php


require (dirname(__DIR__)) . '/vendor/autoload.php';

use \Janfish\Security\Crypt;

//print_r(Crypt::getSupportCipher());
$en = new Crypt(['cipher' => 'aes-256-cbc']); //AES-256-CFB
$encode = $en->encrypt("hello", 'keyToMyHeart');
$decode = $en->decrypt($encode, 'keyToMyHeart');
//var_dump([
//    $en->ivSize,
//    $encode,
//    $decode
//]);


$en = new Crypt(['cipher' => 'aes-256-cbc']); //AES-256-CFB
$iv = '0123456789abcdef';
//$iv = $en->makeIv();
$clientSecret = 'nuasndu89382j3d3d9238';
$encode = $en->encrypt("hello", $clientSecret, $iv);
$decode = $en->decrypt($encode, $clientSecret, $iv);

//var_dump([
//    $en->ivSize,
//    $encode,
//    $decode
//]);


// ZERO Padding ISO/IEC 9797-1, ISO/IEC 10118-1
function pad_zero($data)
{
    $len = @mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
    if (strlen($data) % $len) {
        $padLength = $len - strlen($data) % $len;
        $data .= str_repeat("\0", $padLength);
    }
    return $data;
}

$en = new Crypt(['cipher' => 'aes-256-cbc']); //AES-256-CFB
$iv = '0123456789abcdef';
//$iv = $en->makeIv();
$clientSecret = 'nuasndu89382j3d3d9238';
$encode = $en->encrypt(pad_zero("hello"), $clientSecret, $iv, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
$decode = $en->decrypt($encode, $clientSecret, $iv, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

var_dump([
    $en->ivSize,
    $encode,
    $decode
]);