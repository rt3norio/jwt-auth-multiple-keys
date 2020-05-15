<?php

namespace Fidelize\JWTAuth\Test;

use Fidelize\JWTAuth\JwtVaultAdapter;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Redis;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\JWTException;
use Mockery;

class JwtVaultAdapterTest extends AbstractTestCase
{
    protected $privateKey = null;
    protected $privateKeyObj = [];
    protected $publicKeys = null;
    protected $publicKeysObj = [];
    protected $jwtVaultAdapterMock = null;

    protected function setUp()
    {
        parent::setUp();
        Config::shouldReceive('get')->with('jwt.providers.vault.expiration')->andReturn(1440);
        Config::shouldReceive('get')->with('jwt.providers.vault.token')->andReturn('s.72I7nMPcmrLMaFJkePwDWCmc');
        Config::shouldReceive('get')->with('jwt.providers.vault.url')->andReturn('http://10.8.8.99');
        Config::shouldReceive('get')->with('jwt.providers.vault.secret_engine')->andReturn('jwt');
        Config::shouldReceive('get')->with('jwt.providers.vault.secret')->andReturn('publicKeys');
        Config::shouldReceive('get')->with('jwt.providers.vault.private.secret_engine')->andReturn('jwt');
        Config::shouldReceive('get')->with('jwt.providers.vault.private.secret')->andReturn('jwt.app.key');

        $this->privateKey = trim(file_get_contents( __DIR__ . '/keys/jwt.app.key'));
        $this->publicKeys = [
            0 =>  trim(file_get_contents( __DIR__ . '/keys/jwt.app.key.pub'))
        ];

        $this->privateKeyObj = json_encode([
            'key' => $this->privateKey,
            'timestamp' => time()
        ]);

        $obj = [
            'keys' => $this->publicKeys,
            'timestamp' => time()
        ];
        $this->publicKeysObj = json_encode($obj);

        Redis::shouldReceive('get')
            ->with('vault.privateKey')
            ->andReturn(
                false,
                $this->privateKeyObj,
                false
            );

        Redis::shouldReceive('set')
        ->with('vault.privateKey', $this->privateKeyObj);

        Redis::shouldReceive('hgetall')
            ->with('vault.publicKeys')
            ->andReturn(
                false,
                $this->publicKeysObj
            );

        Redis::shouldReceive('hmset')
            ->with('vault.publicKeys', $this->publicKeysObj)
        ->andReturn(true);

        $this->jwtVaultAdapterMock = $this->getMockBuilder(JwtVaultAdapter::class)
        ->setMethods(['getVaultPrivateSecret', 'getVaultPublicSecret'])
        ->getMock();
    }

    public function testEncodeWhenThereIsAPrivateKeyWithoutRedis()
    {
        $this->jwtVaultAdapterMock->expects($this->any())
            ->method('getVaultPrivateSecret')
            ->will($this->returnValue( ['1' => $this->privateKey] ));

        $this->assertEquals(
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.Jel4wfqCdyviybf5whcyAKLJS_8hPe2_ejJtHE-2Eph_s2IZh_OSrjhaesTq1EyKO4CrHz5HwjLi_QcdYqRW9CV8HRPCAwtm2wbBKtxLgTnwjjQWvD8qEhIao-8DcaRGLvS9nnQsbWx33uGihalhs4g-CWkmizLQFz52_mO_8iwhHFalqA-hNlmmkHhY0SSTjqVgPO_lo5ZlvZeQXI12aHQnDj64e6pGjOyZcc6iAkmN8tBBqDBv1nhQ0N7OUrhHG8t-TUJK7Nc0o1E3TWfgE-m1lCcG2uhx_1fLqq558iDmZN73uDNzL_1B-pg6pgG4M-vosU9FXZvVlOXwemRY-8eMVjZY-_bnR2GxddAK5_AtfZiXy_nR4kYN8pwu8B3QAo7RR3dbCCWCrSVGm46Y09oCzBUgkAuyOCsF5DUg1mvw9U02KhzWZ5cMGrIA3_yrXWuzw4rXgLbvX5XRk0izQjIdazqoqWw8Hpa_uA_Ae-vijK14kNiNCW4g2Ehr-TXmvSGQGSmgkxaliIhounq-3XmEDAOlLPeBuf-OAheGg6BaA2rruowaekVC17mTNQ-NhyYZoJWxRt4W56gqyq9EdhNGERqDEA-6_rxwAZmJ6gWiC4zeGANXMEzK_UazS17PuPRNw_wPelFXsulMA0MHKWIObZ08i30mGbu4-L3e7yk',
            $this->jwtVaultAdapterMock->encode($this->getPayload())
        );
    }

    public function testEncodeWhenThereIsAPrivateKeyWithRedis()
    {
        $adapter = new JwtVaultAdapter();
        $this->assertEquals(
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.Jel4wfqCdyviybf5whcyAKLJS_8hPe2_ejJtHE-2Eph_s2IZh_OSrjhaesTq1EyKO4CrHz5HwjLi_QcdYqRW9CV8HRPCAwtm2wbBKtxLgTnwjjQWvD8qEhIao-8DcaRGLvS9nnQsbWx33uGihalhs4g-CWkmizLQFz52_mO_8iwhHFalqA-hNlmmkHhY0SSTjqVgPO_lo5ZlvZeQXI12aHQnDj64e6pGjOyZcc6iAkmN8tBBqDBv1nhQ0N7OUrhHG8t-TUJK7Nc0o1E3TWfgE-m1lCcG2uhx_1fLqq558iDmZN73uDNzL_1B-pg6pgG4M-vosU9FXZvVlOXwemRY-8eMVjZY-_bnR2GxddAK5_AtfZiXy_nR4kYN8pwu8B3QAo7RR3dbCCWCrSVGm46Y09oCzBUgkAuyOCsF5DUg1mvw9U02KhzWZ5cMGrIA3_yrXWuzw4rXgLbvX5XRk0izQjIdazqoqWw8Hpa_uA_Ae-vijK14kNiNCW4g2Ehr-TXmvSGQGSmgkxaliIhounq-3XmEDAOlLPeBuf-OAheGg6BaA2rruowaekVC17mTNQ-NhyYZoJWxRt4W56gqyq9EdhNGERqDEA-6_rxwAZmJ6gWiC4zeGANXMEzK_UazS17PuPRNw_wPelFXsulMA0MHKWIObZ08i30mGbu4-L3e7yk',
            $adapter->encode($this->getPayload())
        );
    }

    public function testEncodeWhenThereIsNoPrivateKey()
    {
        $this->jwtVaultAdapterMock->expects($this->any())
            ->method('getVaultPrivateSecret')
            ->will($this->returnValue([]));
        $this->jwtVaultAdapterMock->setSecret('secret');

        $this->assertEquals(
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.4cLrK125FhNhtEsOfzEvLb9iNobv-_1oBLJsx2J9xtw',
            $this->jwtVaultAdapterMock->encode($this->getPayload())
        );
    }

    public function testDecodeWithValidTokenUsingPublicKeyWithoutRedis()
    {
        $this->jwtVaultAdapterMock->expects($this->any())
            ->method('getVaultPublicSecret')
            ->will($this->returnValue($this->publicKeys));

        $this->jwtVaultAdapterMock->setSecret('secret');
        $result = $this->jwtVaultAdapterMock->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.Jel4wfqCdyviybf5whcyAKLJS_8hPe2_ejJtHE-2Eph_s2IZh_OSrjhaesTq1EyKO4CrHz5HwjLi_QcdYqRW9CV8HRPCAwtm2wbBKtxLgTnwjjQWvD8qEhIao-8DcaRGLvS9nnQsbWx33uGihalhs4g-CWkmizLQFz52_mO_8iwhHFalqA-hNlmmkHhY0SSTjqVgPO_lo5ZlvZeQXI12aHQnDj64e6pGjOyZcc6iAkmN8tBBqDBv1nhQ0N7OUrhHG8t-TUJK7Nc0o1E3TWfgE-m1lCcG2uhx_1fLqq558iDmZN73uDNzL_1B-pg6pgG4M-vosU9FXZvVlOXwemRY-8eMVjZY-_bnR2GxddAK5_AtfZiXy_nR4kYN8pwu8B3QAo7RR3dbCCWCrSVGm46Y09oCzBUgkAuyOCsF5DUg1mvw9U02KhzWZ5cMGrIA3_yrXWuzw4rXgLbvX5XRk0izQjIdazqoqWw8Hpa_uA_Ae-vijK14kNiNCW4g2Ehr-TXmvSGQGSmgkxaliIhounq-3XmEDAOlLPeBuf-OAheGg6BaA2rruowaekVC17mTNQ-NhyYZoJWxRt4W56gqyq9EdhNGERqDEA-6_rxwAZmJ6gWiC4zeGANXMEzK_UazS17PuPRNw_wPelFXsulMA0MHKWIObZ08i30mGbu4-L3e7yk');
        $this->assertEquals($this->getPayload(), $result);
    }

    public function testDecodeWithValidTokenUsingPublicKeyWithRedis()
    {
        $this->jwtVaultAdapterMock->expects($this->any())
            ->method('getVaultPublicSecret')
            ->will($this->returnValue($this->publicKeysObj));

        $result = $this->jwtVaultAdapterMock->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaWRtYXN0ZXIiLCJpYXQiOjEyMzQ1NiwiZXhwIjoxMjcwNTYsImphdCI6ImZvb2JhcmJheiJ9.Jel4wfqCdyviybf5whcyAKLJS_8hPe2_ejJtHE-2Eph_s2IZh_OSrjhaesTq1EyKO4CrHz5HwjLi_QcdYqRW9CV8HRPCAwtm2wbBKtxLgTnwjjQWvD8qEhIao-8DcaRGLvS9nnQsbWx33uGihalhs4g-CWkmizLQFz52_mO_8iwhHFalqA-hNlmmkHhY0SSTjqVgPO_lo5ZlvZeQXI12aHQnDj64e6pGjOyZcc6iAkmN8tBBqDBv1nhQ0N7OUrhHG8t-TUJK7Nc0o1E3TWfgE-m1lCcG2uhx_1fLqq558iDmZN73uDNzL_1B-pg6pgG4M-vosU9FXZvVlOXwemRY-8eMVjZY-_bnR2GxddAK5_AtfZiXy_nR4kYN8pwu8B3QAo7RR3dbCCWCrSVGm46Y09oCzBUgkAuyOCsF5DUg1mvw9U02KhzWZ5cMGrIA3_yrXWuzw4rXgLbvX5XRk0izQjIdazqoqWw8Hpa_uA_Ae-vijK14kNiNCW4g2Ehr-TXmvSGQGSmgkxaliIhounq-3XmEDAOlLPeBuf-OAheGg6BaA2rruowaekVC17mTNQ-NhyYZoJWxRt4W56gqyq9EdhNGERqDEA-6_rxwAZmJ6gWiC4zeGANXMEzK_UazS17PuPRNw_wPelFXsulMA0MHKWIObZ08i30mGbu4-L3e7yk');
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

    function time()
    {
        return ReferenceTest::$now ?: \time();
    }

}




