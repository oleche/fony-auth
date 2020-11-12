<?php
namespace Geekcow\FonyAuth\Model;

use \Geekcow\Dbcore\Entity;
use Geekcow\FonyAuth\Utils\ConfigurationUtils;
use Geekcow\FonyAuth\Model\ApiClient;
use Geekcow\FonyAuth\Model\ApiScope;

class ApiClientScope extends Entity{
  private $api_client_scope;

  public function __construct($config_file = MY_DOC_ROOT . "/src/config/config.ini"){
    $config = ConfigurationUtils::getInstance($config_file);
    $this->api_client_scope = [
        'id_scope' => [ 'type' => 'string', 'length' => 32, 'pk' => true, 'foreign' => array('name', new ApiScope()) ],
        'id_client' => [ 'type' => 'string', 'length' => 64, 'pk' => true, 'foreign' => array('client_id', new ApiClient()) ]
    ];
    parent::__construct($this->api_client_scope, get_class($this), $config->getFilename());
  }
}

?>
