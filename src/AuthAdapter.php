<?php
namespace Fidelize\JWTAuth;

use Illuminate\Contracts\Auth\Factory;
use Illuminate\Support\Facades\Config;
use Tymon\JWTAuth\Providers\Auth\Illuminate;
use Tymon\JWTAuth\Contracts\Providers\Auth;

class AuthAdapter implements Auth
{
    /**
     * The authentication guard.
     *
     * @var \Illuminate\Contracts\Auth\Guard
     */
    protected $auth;

    public function __construct(Factory $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Authenticate a user via the id.
     *
     * @param  mixed  $id
     *
     * @return bool
     */
    public function byId($id)
    {
        $userClass = Config::get('jwt.user');
        $userAttribute = Config::get('jwt.identifier');
        $user = $userClass::where($userAttribute, $id)->first();
        if (!$user) {
            return false;
        }
        return $this->auth->setUser($user);
    }

    /**
     * Check a user's credentials.
     *
     * @param  array  $credentials
     *
     * @return bool
     */
    public function byCredentials(array $credentials)
    {
        return $this->auth->once($credentials);
    }

    /**
     * Get the currently authenticated user.
     *
     * @return mixed
     */
    public function user()
    {
        return $this->auth->user();
    }
}
