<?php

require '../vendor/autoload.php';

use \Janfish\Security\RSA;

$pri = file_get_contents('keys/rsa_private_key.pem');
$pub = file_get_contents('keys/rsa_public_key.pem');


//encode
$rsa = new RSA();
$rsa->setPubKey($pub);
$encodedData = $rsa->encrypt("hello", RSA::OPENSSL_PKCS1_PADDING);
var_dump($encodedData);

//decode
$rsa = new RSA();
$rsa->setPriKey($pri);
$sourceData = $rsa->decrypt($encodedData, RSA::OPENSSL_PKCS1_PADDING);
var_dump($sourceData);

//sign
$rsa = new RSA();
$rsa->setPriKey($pri);
$signedData = $rsa->sign('hello', Rsa::OPENSSL_ALGO_SHA256);
var_dump($signedData);

//verify
$rsa = new RSA();
$rsa->setPubKey($pub);
$result = $rsa->verify('hello', $signedData, Rsa::OPENSSL_ALGO_SHA256);
var_dump($result);