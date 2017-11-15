<?php

namespace Fidelize\JWTAuth\Test;

use Fidelize\JWTAuth\AuthAdapter;
use App\Models\User;
use Illuminate\Auth\AuthManager;
use Illuminate\Support\Facades\Config;
use Mockery;

class AuthAdapterTest extends AbstractTestCase
{
    protected function setUp()
    {
        parent::setUp();

        Config::shouldReceive('get')->with('jwt.user')->andReturn(UserStub::class);
        Config::shouldReceive('get')->with('jwt.identifier')->andReturn('id');
    }

    public function testByIdSetUserIfFound()
    {
        UserStub::$shouldBeFound = true;
        $manager = Mockery::mock(AuthManager::class);
        $manager->shouldReceive('setUser')->andReturn(true);
        $adapter = new AuthAdapter($manager);

        $this->assertTrue($adapter->byId('johndoe'));
    }

    public function testByIdReceivesAStringAndDoesNotFindUserByLogin()
    {
        UserStub::$shouldBeFound = false;
        $manager = Mockery::mock(AuthManager::class);
        $manager->shouldNotReceive('setUser');
        $adapter = new AuthAdapter($manager);

        $this->assertFalse($adapter->byId('johndoe'));
    }
}
