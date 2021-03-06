<?php

namespace Geekcow\FonyAuth\Model;

use Geekcow\Dbcore\Entity;
use Geekcow\FonyAuth\Utils\ConfigurationUtils;

class ApiScope extends Entity
{
    private $api_scope = [
        'name' => ['type' => 'string', 'length' => 45, 'unique' => true, 'pk' => true],
        'level' => ['type' => 'int'],
        'priority' => ['type' => 'int']
    ];

    public function __construct($config_file = MY_DOC_ROOT . "/src/config/config.ini")
    {
        $config = ConfigurationUtils::getInstance($config_file);
        parent::__construct($this->api_scope, get_class($this), $config->getFilename());
    }
}
