<?php

namespace Fidelize\JWTAuth;

use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redis;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Claim;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Keychain;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Providers\JWT\JWTInterface;

class JwtVaultAdapter extends JwtAdapter implements JWTInterface
{
    /**
     * Create a JSON Web Token.
     *
     * @return string
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function encode(array $payload)
    {
        try {
            $builder = new Builder;
            foreach ($payload as $key => $value) {
                $builder->set($key, $value);
            }
            $key = $this->getPrivateKey();
            $signer = is_object($key) ? new RS256() : new HS256();
            $builder->sign($signer, $key);
            $token = $builder->getToken();
            return $token->__toString();
        } catch (Exception $e) {
            throw new JWTException('Could not create token: ' . $e->getMessage());
        }
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param  string  $token
     * @return array
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function decode($token)
    {
        try {
            $parser = new Parser;
            $token = $parser->parse((string) $token);
        } catch (Exception $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage());
        }

        // Test token signature against all available public keys + JWT secret
        $atLeastOnePublicKeyWorked = false;

        foreach ($this->getPublicKeys() as $publicKey) {
            $signer = is_object($publicKey) ? new RS256() : new HS256();
            if ($token->verify($signer, $publicKey)) {
                $atLeastOnePublicKeyWorked = true;
                break;
            }
        }

        if (!$atLeastOnePublicKeyWorked) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        // Convert to plain scalar values instead of an array of Claim objects
        return array_map(
            function (Claim $claim) {
                return $claim->getValue();
            },
            $token->getClaims()
        );
    }

    /**
     * PRIVATE key is used to generate new tokens. In order to be trusted,
     * the system receiving the token must validate it against the PUBLIC key.
     */
    private function getPrivateKey()
    {
        $secretObj = Redis::get('vault.privateKey');
        if ($secretObj) {
            $secretArr =  json_decode($secretObj);
            if (now()->timestamp - $secretArr->timestamp < Config::get('jwt.providers.vault.expiration')) {
                $keychain = new Keychain();
                $chave = $keychain->getPrivateKey($secretArr->key);
                return $chave;
            }
        }

        $secrets = $this->getVaultPrivateSecret();

        if (!$secrets) {
            if (isset($secretArr)) {
                $keychain = new Keychain();
                $chave = $keychain->getPrivateKey($secretArr->key);
                return $chave;
            }
        }

        if (count($secrets) > 1) {
            throw new TokenInvalidException('Multiple private keys found.');
        }

        // If there is no private key, fallback to JWT_SECRET
        if (count($secrets) == 0) {
            return $this->secret;
        }

        $secret = trim(array_pop($secrets));

        $keychain = new Keychain();
        $chave = $keychain->getPrivateKey($secret);

        $obj = [
            'key' => $secret,
            'timestamp' => time()
        ];

        Redis::set('vault.privateKey', json_encode($obj));
        return $chave;
    }

    /**
     * PUBLIC keys against which it will try to validate and trust the token.
     * Note that though you can trust and use the token, you are not able
     * to generate tokens using PUBLIC keys, only PRIVATE ones.
     */
    private function getPublicKeys()
    {
        $secretsObj = Redis::hgetall('vault.publicKeys');
        if ($secretsObj) {
            $secretsArr =  json_decode($secretsObj);
            if (time() - $secretsArr->timestamp < Config::get('jwt.providers.vault.expiration')) {
                unset($secretsArr->timestamp);
                return $this->checkPublicKeys($secretsArr->keys);
            }
        }

        $secrets = $this->getVaultPublicSecret();

        if (!$secrets) {
            if (isset($secretsArr)) {
                unset($secretsArr->timestamp);
                return $this->checkPublicKeys($secretsArr->keys);
            }
        }

        $obj = [
            'keys' => $secrets,
            'timestamp' => time()
        ];
        Redis::hmset('vault.publicKeys', json_encode($obj));

        return $this->checkPublicKeys($secrets);
    }

    /**
     * Get the secret value for the provided key
     *
     * @param string $secretKey Key to locate in the vault
     * * @param string $accessToken Key to locate in the vault
     * * @param string $baseUrl Key to locate in the vault
     * @throws \Exception If secret is not found
     * @throws \Exception If error on GET request
     * @return mixed Returns value if found or false
     */
    public function getVaultPublicSecret()
    {
        try {
            $response = $this->buildClient(
                Config::get('jwt.providers.vault.token'),
                Config::get('jwt.providers.vault.url')
            )
            ->request(
                'GET',
                '/v1/' .
                    Config::get('jwt.providers.vault.secret_engine') .
                    '/data/' .
                    Config::get('jwt.providers.vault.secret')
            );
            return $this->getFullBody($response->getBody())['data']['data'];
        } catch (\Exception $e) {
            Log::emergency($e);
            return false;
        }
        return false;
    }

    private function checkPublicKeys($publickeys)
    {
        $keychain = new Keychain();
        $keys = [];
        foreach ($publickeys as $key) {
            $keys[] = $keychain->getPublicKey($key);
        }
        return $keys;
    }

    public function getVaultPrivateSecret()
    {
        try {
            $response = $this->buildClient(
                Config::get('jwt.providers.vault.token'),
                Config::get('jwt.providers.vault.url') . ':8200'
            )
            ->request(
                'GET',
                '/v1/' .
                    Config::get('jwt.providers.vault.private.secret_engine') .
                    '/data/' .
                    Config::get('jwt.providers.vault.private.secret'),
                ['stream' => true]
            );

            $body = $response->getBody();
            $buffer = '';
            while (!$body->eof()) {
                $buffer.= trim($body->read(1024));
            }
            $data = json_decode($buffer, true)['data']['data'];
            return $data;

        } catch (\Exception $e) {
            Log::emergency($e);
            return false;
        }
        return false;
    }

    /**
     * Build the HTTP client with the provided token and URL
     *
     * @param string $accessToken Vault access token
     * @param string $baseUrl Base URL of the remote Vault system (include port)
     * @return \GuzzleHttp\Client instance
     */
    public function buildClient($accessToken, $baseUrl)
    {
        $client = new \GuzzleHttp\Client([
            'base_uri' => $baseUrl,
            'timeout'  => 2.0,
            'headers' => [
                'X-Vault-Token' => $accessToken,
                'Accept' => 'application/json',
            ]
        ]);
        return $client;
    }


    /**
     * Get the full body contents of the provided response instance
     *
     * @param \GuzzleHttp\Psr7\Stream $responseBody Stream instance
     * @throws \Exception If there was an error parsin the JSON response
     * @return string Body contents
     */
    public function getFullBody(\GuzzleHttp\Psr7\Stream $responseBody)
    {
        $buffer = '';
        while (!$responseBody->eof()) {
            $buffer .= trim($responseBody->read(1024));
        }
        $responseBody->close();
        $output = json_decode($buffer);
        if ($output === null) {
            throw new \Exception('Error parsing response JSON (' . json_last_error() . ')');
        }

        return $output;
    }
}
