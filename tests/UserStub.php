<?php
namespace Fidelize\JWTAuth\Test;

class UserStub
{
    public static $shouldBeFound = true;

    public static function where($attribute, $value)
    {
        return new self;
    }

    public function first()
    {
        if (!self::$shouldBeFound) {
            return;
        }
        return $this;
    }
}
