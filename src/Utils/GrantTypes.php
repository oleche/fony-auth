<?php

namespace Geekcow\FonyAuth\Utils;

abstract class GrantTypes
{
    public const PASSWORD = "password";
    public const CLIENT_CREDENTIAL = "client_credentials";
    public const REFRESH_TOKEN = "refresh_token";
}
