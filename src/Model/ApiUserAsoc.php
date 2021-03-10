<?php

namespace Geekcow\FonyAuth\Model;

use Geekcow\Dbcore\Entity;
use Geekcow\FonyAuth\Utils\ConfigurationUtils;

class ApiUserAsoc extends Entity
{
    private $api_user_asoc;

    public function __construct($config_file = MY_DOC_ROOT . "/src/config/config.ini")
    {
        $config = ConfigurationUtils::getInstance($config_file);
        $this->api_user_asoc = [
            'username' => [
                'type' => 'string',
                'length' => 70,
                'pk' => true,
                'foreign' => array('username', new ApiUser())
            ],
            'client_id' => [
                'type' => 'string',
                'length' => 64,
                'pk' => true,
                'foreign' => array('client_id', new ApiClient())
            ]
        ];
        parent::__construct($this->api_user_asoc, get_class($this), $config->getFilename());
    }
}
