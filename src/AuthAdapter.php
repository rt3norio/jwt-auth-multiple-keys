<?php
namespace Fidelize\JWTAuth;

use Illuminate\Support\Facades\Config;
use Tymon\JWTAuth\Providers\Auth\IlluminateAuthAdapter;

class AuthAdapter extends IlluminateAuthAdapter
{
    /**
     * @inheritdoc
     * @SuppressWarnings("shortVariable")
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
}
