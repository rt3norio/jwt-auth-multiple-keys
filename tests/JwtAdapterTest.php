<?php

namespace Fidelize\JWTAuth\Test;

use Fidelize\JWTAuth\JwtAdapter;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\JWTException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Builder;

class JwtAdapterTest extends AbstractTestCase
{
    protected function setUp()
    {
        parent::setUp();
        Config::shouldReceive('get')->with('jwt.keys_directory')->andReturn(__DIR__ . '/keys');
    }

    public function testEncodeWhenThereIsNoPrivateKey()
    {
        File::shouldReceive('glob')->andReturn([])->byDefault();
        $adapter = $this->getJwtAdapter();
        $this->assertEquals(
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.4cLrK125FhNhtEsOfzEvLb9iNobv-_1oBLJsx2J9xtw',
            $adapter->encode($this->getPayload())
        );
    }

    public function testEncodeWhenThereIsAPrivateKey()
    {
        File::shouldReceive('glob')->andReturn([
            __DIR__ . '/keys/jwt.app.key'
        ])->byDefault();
        $adapter = $this->getJwtAdapter();
        $this->assertEquals(
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.Jel4wfqCdyviybf5whcyAKLJS_8hPe2_ejJtHE-2Eph_s2IZh_OSrjhaesTq1EyKO4CrHz5HwjLi_QcdYqRW9CV8HRPCAwtm2wbBKtxLgTnwjjQWvD8qEhIao-8DcaRGLvS9nnQsbWx33uGihalhs4g-CWkmizLQFz52_mO_8iwhHFalqA-hNlmmkHhY0SSTjqVgPO_lo5ZlvZeQXI12aHQnDj64e6pGjOyZcc6iAkmN8tBBqDBv1nhQ0N7OUrhHG8t-TUJK7Nc0o1E3TWfgE-m1lCcG2uhx_1fLqq558iDmZN73uDNzL_1B-pg6pgG4M-vosU9FXZvVlOXwemRY-8eMVjZY-_bnR2GxddAK5_AtfZiXy_nR4kYN8pwu8B3QAo7RR3dbCCWCrSVGm46Y09oCzBUgkAuyOCsF5DUg1mvw9U02KhzWZ5cMGrIA3_yrXWuzw4rXgLbvX5XRk0izQjIdazqoqWw8Hpa_uA_Ae-vijK14kNiNCW4g2Ehr-TXmvSGQGSmgkxaliIhounq-3XmEDAOlLPeBuf-OAheGg6BaA2rruowaekVC17mTNQ-NhyYZoJWxRt4W56gqyq9EdhNGERqDEA-6_rxwAZmJ6gWiC4zeGANXMEzK_UazS17PuPRNw_wPelFXsulMA0MHKWIObZ08i30mGbu4-L3e7yk',
            $adapter->encode($this->getPayload())
        );
    }

    public function testEncodeWhenThereAreMultiplePrivateKey()
    {
        File::shouldReceive('glob')->andReturn([
            __DIR__ . '/keys/jwt.app.key',
            __DIR__ . '/keys/jwt.another.key',
        ])->byDefault();
        $adapter = $this->getJwtAdapter();
        $this->expectException(JWTException::class);
        $adapter->encode($this->getPayload());
    }

    public function testDecodeWithInvalidToken()
    {
        File::shouldReceive('glob')->andReturn([])->byDefault();
        $adapter = $this->getJwtAdapter();
        $this->expectException(TokenInvalidException::class);
        $adapter->decode('invalid_token');
    }

    public function testDecodeWithInvalidSignature()
    {
        File::shouldReceive('glob')->andReturn([])->byDefault();
        $adapter = $this->getJwtAdapter('INVALID_secret');
        $this->expectException(TokenInvalidException::class);
        $adapter->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.4cLrK125FhNhtEsOfzEvLb9iNobv-_1oBLJsx2J9xtw');
    }

    public function testDecodeWithValidTokenUsingSecret()
    {
        File::shouldReceive('glob')->andReturn([])->byDefault();
        $adapter = $this->getJwtAdapter();
        $result = $adapter->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.4cLrK125FhNhtEsOfzEvLb9iNobv-_1oBLJsx2J9xtw');
        $this->assertEquals($this->getPayload(), $result);
    }

    public function testDecodeWithValidTokenUsingPublicKey()
    {
        File::shouldReceive('glob')->andReturn([
            __DIR__ . '/keys/jwt.app.key.pub',
        ])->byDefault();
        $adapter = $this->getJwtAdapter();
        $result = $adapter->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.Jel4wfqCdyviybf5whcyAKLJS_8hPe2_ejJtHE-2Eph_s2IZh_OSrjhaesTq1EyKO4CrHz5HwjLi_QcdYqRW9CV8HRPCAwtm2wbBKtxLgTnwjjQWvD8qEhIao-8DcaRGLvS9nnQsbWx33uGihalhs4g-CWkmizLQFz52_mO_8iwhHFalqA-hNlmmkHhY0SSTjqVgPO_lo5ZlvZeQXI12aHQnDj64e6pGjOyZcc6iAkmN8tBBqDBv1nhQ0N7OUrhHG8t-TUJK7Nc0o1E3TWfgE-m1lCcG2uhx_1fLqq558iDmZN73uDNzL_1B-pg6pgG4M-vosU9FXZvVlOXwemRY-8eMVjZY-_bnR2GxddAK5_AtfZiXy_nR4kYN8pwu8B3QAo7RR3dbCCWCrSVGm46Y09oCzBUgkAuyOCsF5DUg1mvw9U02KhzWZ5cMGrIA3_yrXWuzw4rXgLbvX5XRk0izQjIdazqoqWw8Hpa_uA_Ae-vijK14kNiNCW4g2Ehr-TXmvSGQGSmgkxaliIhounq-3XmEDAOlLPeBuf-OAheGg6BaA2rruowaekVC17mTNQ-NhyYZoJWxRt4W56gqyq9EdhNGERqDEA-6_rxwAZmJ6gWiC4zeGANXMEzK_UazS17PuPRNw_wPelFXsulMA0MHKWIObZ08i30mGbu4-L3e7yk');
        $this->assertEquals($this->getPayload(), $result);
    }

    private function getPayload()
    {
        return [
            'sub' => 'fidmaster',
            'iat' => 123456,
            'exp' => 123456 + 3600,
            'jat' => 'foobarbaz',
        ];
    }

    private function getJwtAdapter($secret = 'secret')
    {
        return new JwtAdapter(
            new Builder(),
            new Parser(),
            $secret,
            'RS256',
            []
        );
    }
}
