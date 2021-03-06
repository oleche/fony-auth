<?php

namespace Geekcow\FonyAuth\Model;

use Geekcow\Dbcore\Entity;
use Geekcow\FonyAuth\Utils\ConfigurationUtils;

class ApiUserType extends Entity
{
    private $api_user_type = [
        'id' => ['type' => 'int', 'unique' => true, 'pk' => true, 'incremental' => true],
        'name' => ['type' => 'string', 'length' => 32, 'unique' => true],
        'priority' => ['type' => 'int', 'unique' => true],
        'scope' => ['type' => 'string', 'length' => 45, 'unique' => true]
    ];

    public function __construct($config_file = MY_DOC_ROOT . "/src/config/config.ini")
    {
        $config = ConfigurationUtils::getInstance($config_file);
        parent::__construct($this->api_user_type, get_class($this), $config->getFilename());
    }
}
