<?php

namespace Geekcow\FonyAuth\Model;

use Geekcow\Dbcore\Entity;
use Geekcow\FonyAuth\Utils\ConfigurationUtils;

class ApiToken extends Entity
{
    private $api_token;

    public function __construct($config_file = __DIR__ . "/src/config/config.ini")
    {
        $config = ConfigurationUtils::getInstance($config_file);
        $this->api_token = [
            'id' => ['type' => 'int', 'pk' => true, 'incremental' => true],
            'username' => ['type' => 'string', 'length' => 70, 'foreign' => array('username', new ApiUser())],
            'token' => ['type' => 'string', 'length' => 128],
            'created_at' => ['type' => 'datetime'],
            'expires' => ['type' => 'int'],
            'enabled' => ['type' => 'boolean'],
            'refresh_token' => ['type' => 'string', 'length' => 128],
            'blacklisted' => ['type' => 'boolean'],
            'client_id' => [
                'type' => 'string',
                'length' => 64,
                'pk' => true,
                'foreign' => array('client_id', new ApiClient())
            ],
            'updated_at' => ['type' => 'datetime'],
            'scopes' => ['type' => 'string', 'length' => 250],
            'timestamp' => ['type' => 'string', 'length' => 128],
        ];
        parent::__construct($this->api_token, get_class($this), $config->getFilename());
    }
}
