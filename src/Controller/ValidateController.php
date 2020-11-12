<?php
/* API authentication controller
 * Developed by OSCAR LECHE
 * V.1.0
 * DESCRIPTION: Class for validating a bearer token
 */
namespace Geekcow\FonyAuth\Controller;

use Geekcow\FonyCore\Controller\CoreController;
use Geekcow\FonyCore\Controller\ApiMethods;
use Geekcow\FonyCore\Utils\TokenUtils;
use Geekcow\FonyAuth\Utils\AuthUtils;

class ValidateController extends CoreController implements ApiMethods
{
  const BASIC = 'Basic ';
  const BEARER = 'Bearer ';

  private $auth_handler;

  public function __construct() {
    $configfile = ConfigurationUtils::getInstance(MY_DOC_ROOT . "/src/config/config.ini");
		parent::__construct($configfile);
		$this->response = array();
    $this->auth_handler = new AuthUtils($configfile);
	}

  public function doPOST($token = null, $params = array()){
		try{
      if (is_array($params) && empty($params)){
        if ($verb == 'refresh'){
          //TODO Refresh token
          $this->response['code'] = 501;
          $this->response['msg'] = "Not Implemented yet";
        }else{
          $this->response['code'] = 501;
          $this->response['msg'] = "Not Implemented";
        }
      }else{
        $token = TokenUtils::sanitizeToken($token, self::BASIC);
        if (TokenUtils::validateTokenSanity($token, self::BASIC)){
          if ($this->auth_handler->validateBasicToken($token)){
            if ($this->validate_fields($params, 'validate', 'POST')){
              if (!$this->auth_handler->validateBearerToken($params['token'])){
                $this->err = $this->auth_handler->getErr();
                $this->buildErrorSet();
                return false;
              }
            }else{
              return false;
            }

    				$this->response['code'] = 200;
            $this->response['active'] = true;
    				$this->response['client_id'] = $this->auth_handler->getClientId();
            $this->response['scope'] = $this->auth_handler->getScopes();
            $this->response['username'] = $this->auth_handler->getUsername();
    				$this->response['exp'] = ((time($this->auth_handler->getApiToken()->columns['updated_at'])*1000)+$this->auth_handler->getApiToken()->columns['expires']) - (time()*1000);
    				return true;
    			}else{
            $this->buildErrorSet();
    				return false;
    			}
  			}else{
  				$this->response['type'] = 'error';
  		    $this->response['code'] = 401;
          $this->response['message'] = 'Malformed token';
  				return false;
  			}
      }

		}catch(Exception $e){
			$this->response['type'] = 'error';
			$this->response['code'] = 500;
			$this->response['message'] = $this->err;
			return false;
		}
  }

  public function doGET() {
    $this->response['code'] = 501;
    $this->response['msg'] = "Not Implemented";
  }
  public function doPUT() {
    $this->response['code'] = 501;
    $this->response['msg'] = "Not Implemented";
  }
  public function doDELETE() {
    $this->response['code'] = 501;
    $this->response['msg'] = "Not Implemented";
  }

  private function buildErrorSet(){
    $this->response['type'] = 'error';
    if (isset($this->response['http_code']) && trim($this->response['http_code']) != "")
      $this->response['code'] = 422;
    else if ($this->err == 'User disabled')
      $this->response['code'] = 423;
    else if (strpos($this->err, 'token') !== false) {
      $this->response['code'] = 200;
      $this->response['active'] = false;
    }
    else
      $this->response['code'] = 401;
    $this->response['message'] = $this->auth_handler-getErr();
  }
}

?>
