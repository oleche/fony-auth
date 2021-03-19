<?php

/* API authentication controller
 * Developed by OSCAR LECHE
 * V.1.0
 * DESCRIPTION: Class for validating a bearer token
 */

namespace Geekcow\FonyAuth\Controller;

use Geekcow\FonyAuth\Utils\AuthUtils;
use Geekcow\FonyAuth\Utils\ConfigurationUtils;
use Geekcow\FonyAuth\Utils\TokenType;
use Geekcow\FonyCore\Controller\ApiMethods;
use Geekcow\FonyCore\Controller\CoreController;
use Geekcow\FonyCore\Utils\TokenUtils;

class ValidateController extends CoreController implements ApiMethods
{
    private $auth_handler;

    public function __construct()
    {
        $configfile = ConfigurationUtils::getInstance(MY_DOC_ROOT . "/src/config/config.ini");
        parent::__construct($configfile);
        $this->response = array();
        $this->auth_handler = new AuthUtils($configfile);
    }

    public function doPOST($token = null)
    {
        try {
            if (TokenUtils::validateTokenSanity($token, TokenType::BASIC)) {
                $token = TokenUtils::sanitizeToken($token, TokenType::BASIC);
                if ($this->auth_handler->validateBasicToken($token)) {
                    if ($this->validateFields($this->request, 'v1/validate', 'POST')) {
                        if (!$this->auth_handler->validateBearerToken($this->request['token'])) {
                            $this->err = $this->auth_handler->getErr();
                            $this->buildErrorSet();
                            return false;
                        }
                    } else {
                        return false;
                    }

                    $this->response['code'] = 200;
                    $this->response['active'] = true;
                    $this->response['client_id'] = $this->auth_handler->getClientId();
                    $this->response['scope'] = $this->auth_handler->getScopes();
                    $this->response['scope_level'] = $this->auth_handler->getScopeLevel();
                    $this->response['username'] = $this->auth_handler->getUsername();
                    $this->response['exp'] = $this->auth_handler->getExpiration();
                    return true;
                } else {
                    $this->buildErrorSet();
                    return false;
                }
            } else {
                $this->response['type'] = 'error';
                $this->response['code'] = 401;
                $this->response['message'] = 'Malformed token';
                return false;
            }
        } catch (\Exception $e) {
            $this->response['type'] = 'error';
            $this->response['code'] = 500;
            $this->response['message'] = $e->getMessage();
            return false;
        }
    }

    public function doGET()
    {
        $this->response['code'] = 501;
        $this->response['msg'] = "Not Implemented";
    }

    public function doPUT()
    {
        $this->response['code'] = 501;
        $this->response['msg'] = "Not Implemented";
    }

    public function doDELETE()
    {
        $this->response['code'] = 501;
        $this->response['msg'] = "Not Implemented";
    }

    private function buildErrorSet()
    {
        $this->response['type'] = 'error';
        if (isset($this->response['http_code']) && trim($this->response['http_code']) != "") {
            $this->response['code'] = 422;
        } else {
            if ($this->err == 'User disabled') {
                $this->response['code'] = 423;
            } else {
                if (strpos($this->err, 'token') !== false) {
                    $this->response['code'] = 200;
                    $this->response['active'] = false;
                } else {
                    $this->response['code'] = 401;
                }
            }
        }
        $this->response['message'] = $this->auth_handler->getErr();
    }
}
