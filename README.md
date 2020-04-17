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
    'providers' => [
        // ...
        'jwt' => 'Fidelize\JWTAuth\JwtAdapter',
        'auth' => 'Fidelize\JWTAuth\AuthAdapter',
        // ...
    ],
    'keys_directory' => '/path/yo/your/keys/directory/'
];
?>
```

if you plan to use the vault adapter, insert these into jwt.php
```php
<?php
return [
    // ...
    'providers' => [
        // ...
        'vault' => [
            'expiration' => env('JWT_KEY_VAULT_KEY_EXPIRATION', 1440),
            'url' => env('JWT_KEY_VAULT_URL', 'http://0.0.0.0:1234'),
            'secret' => env('JWT_KEY_VAULT_SECRET_ENGINE_PATH', 'secret'),
            'secret_engine' => env('JWT_KEY_VAULT_SECRET_ENGINE', 'secret_engine'),
            'token' => env('JWT_KEY_VAULT_TOKEN', 'myroot'),
            'private' => [
                'secret' => env('JWT_KEY_VAULT_PRIVATE_SECRET_ENGINE_PATH', 'secret'),
                'secret_engine' => env('JWT_KEY_VAULT_PRIVATE_SECRET_ENGINE', 'secret_engine'),
            ]
        ],
        // ...
    ],
];
?>
```

and set these in your .env
```bash

JWT_KEY_VAULT_URL=http://172.17.0.1:1234/
JWT_KEY_VAULT_SECRET_ENGINE_PATH=myApplication
JWT_KEY_VAULT_SECRET_ENGINE=myAppKeychain
JWT_KEY_VAULT_TOKEN='myroot'
JWT_KEY_VAULT_PRIVATE_SECRET_ENGINE_PATH=myApplication
JWT_KEY_VAULT_PRIVATE_SECRET_ENGINE=myAppKeychainPrivate
JWT_KEY_VAULT_KEY_EXPIRATION=120


```
and run 
```bash
docker run --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:1234' -p 1234:1234 
vault
```


to create the keys:
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
