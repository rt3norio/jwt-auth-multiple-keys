# JWT Auth with Multiple Keys

This is an extension of [tymon/jwt-auth](https://github.com/tymondesigns/jwt-auth),
adding support to:

* Replace deprecated `namshi/jose` with `lcobucci/jwt`
* JWT with key pairs instead of a secret
* Validate a JWT against multiple public keys
* Use JWT secret as a fallback

## Installing

Firstly, you must install [tymon/jwt-auth](https://github.com/tymondesigns/jwt-auth).

Add this package through Composer: `composer require "fidelize/jwt-auth-multiple-keys"`

Edit your `config/jwt.php` file adding/editing these lines:

```php
<?php
return [
    // ...

    'jwt' => 'Fidelize\JWTAuth\JwtAdapter',
    'auth' => 'Fidelize\JWTAuth\AuthAdapter',
    'keys_directory' => '/path/yo/your/keys/directory/'

    // ...
];
?>
```

```bash
# Don't add a passphrase!
ssh-keygen -t rsa -b 4096 -f keys/jwt.app.key
openssl rsa -in keys/jwt.wholesaler.key -pubout -outform PEM -out keys/jwt.app.key.pub
```

## Warning

Keys must follow the pattern name `key.*.key` and `key.*.key.pub`

## TODO List

* [ ] Support different name patterns
* [ ] Add command to generate keys
