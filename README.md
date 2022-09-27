# Usage

## RSA

#### Generate Rsa keys

> the available key lengths are 1024 and 2048

```
$ openssl genrsa -out rsa_private_key.pem 1024
$ openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
```


#### Encrypt & Sign

- prepare keys

```php
$pri = file_get_contents('keys/rsa_private_key.pem');
$pub = file_get_contents('keys/rsa_public_key.pem');
```
- encrypt

``` 
$rsa = new RSA();
$rsa->setPubKey($pub);
$encodedData = $rsa->encrypt("hello", RSA::OPENSSL_PKCS1_PADDING);
```

- decrypt

```
$rsa = new RSA();
$rsa->setPriKey($pri);
$sourceData = $rsa->decrypt($encodedData, RSA::OPENSSL_PKCS1_PADDING);
```

- sign

```
$rsa = new RSA();
$rsa->setPriKey($pri);
$signedData = $rsa->sign('hello',Rsa::OPENSSL_ALGO_SHA256);
```


- verify

```
$rsa = new RSA();
$rsa->setPubKey($pri);
$result = $rsa->verify('hello',$signedData,Rsa::OPENSSL_ALGO_SHA256);
```

#### Support Params

- Signature Algorithm Type

| name | default |value |
|------|-------|-------|
|OPENSSL_ALGO_SSHA1 | yes | 1 |
|OPENSSL_ALGO_SMD5 | | 2 |
|OPENSSL_ALGO_SMD4 | | 3 |
|OPENSSL_ALGO_SMD2 | | 4 |
|OPENSSL_ALGO_SDSS1 | | 5|
|OPENSSL_ALGO_SSHA224 | | 6 |
|OPENSSL_ALGO_SSHA256 | | 7 |
|OPENSSL_ALGO_SSHA384 | | 8  |
|OPENSSL_ALGO_SSHA512 | | 9 |
|OPENSSL_ALGO_SRMD160 | | 10 |

- Encryption Padding Type

| name | default | value |
|------|-------|-------|
| PKCS1_PKCS1_PADDING | yes | 1 |
| PKCS1_SSLV23_PADDING | | 2 |
| PKCS1_NO_PADDING |  | 3 |
| PKCS1_OAEP_PADDING | | 4 |

#### Tips

- When OpenSSL is used "OPENSSL_NO_PADDING" to padding parameter, you need to manually fill in the original data

``` 
$str = str_pad("hello", 256); //128 or 256 
$rsa = new RSA();
$rsa->setPubKey($pub);
$encodedData = $rsa->encrypt($str, RSA::OPENSSL_NO_PADDING);
```

## Other Encryption

```
$encryption= new Crypt(['cipher' => 'aes-256-cbc']);
$encode = $encryption->encrypt("hello", 'keyToMyHeart');
$decode = $encryption->decrypt($encode, 'keyToMyHeart');
var_dump([
    $encryption->getIv(),
    $encode,
    $decode
]);
```


```

$en = new Crypt(['cipher' => 'aes-256-cbc']); //des-ede3;
$iv = '0123456789abcdef';
//$iv = $en->makeIv();
$clientSecret = 'nuasndu89382j3d3d9238';

$encode = $en->encrypt("hello", $clientSecret, $iv);
$decode = $en->decrypt($encode, $clientSecret, $iv);

var_dump([
    $en->getIv(),
    $en->ivSize,
    $encode,
    $decode
]);

```