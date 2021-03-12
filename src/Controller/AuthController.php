<?php

/* API authentication controller
 * Developed by OSCAR LECHE
 * V.1.0
 * DESCRIPTION: Class for authentication handling
 */

namespace Geekcow\FonyAuth\Controller;

use Geekcow\FonyAuth\Utils\AuthUtils;
use Geekcow\FonyAuth\Utils\ConfigurationUtils;
use Geekcow\FonyAuth\Utils\GrantTypes;
use Geekcow\FonyAuth\Utils\TokenType;
use Geekcow\FonyCore\Controller\ApiMethods;
use Geekcow\FonyCore\Controller\CoreController;
use Geekcow\FonyCore\Utils\TokenUtils;

class AuthController extends CoreController implements ApiMethods
{
    private $auth_handler;

    public function __construct()
    {
        $configfile = ConfigurationUtils::getInstance(MY_DOC_ROOT . "/src/config/config.ini");
        parent::__construct($configfile);
        $this->response = array();
        $this->auth_handler = new AuthUtils($configfile);
    }

    public function doPOST($token = null, $params = array(), $verb = null)
    {
        try {
            if (TokenUtils::validateTokenSanity($token, TokenType::BASIC)) {
                $token = TokenUtils::sanitizeToken($token, TokenType::BASIC);
                if (is_array($params) && empty($params)) {
                    $this->response['code'] = 501;
                    $this->response['msg'] = "Not Implemented";
                } else {
                    if ($verb == 'refresh') {
                        if ($this->auth_handler->validateBasicToken($token)) {
                            if ($this->validateFields($params, 'v1/authenticate/refresh', 'POST')) {
                                if (!$this->auth_handler->validateRefreshToken($params['refresh_token'])) {
                                    $this->err = $this->auth_handler->getErr();
                                    $this->buildErrorSet();
                                    return false;
                                }

                                $this->response['code'] = 200;
                                $this->response['access_token'] = $this->auth_handler->generateToken();
                                $this->response['token_type'] = 'bearer';
                                $this->response['username'] = $this->auth_handler->getUsername();
                                $this->response['refresh_token'] = $this->auth_handler->getApiToken(
                                )->columns['refresh_token'];
                                $this->response['expires'] = (
                                    (strtotime($this->auth_handler->getApiToken()->columns['updated_at']) * 1000)
                                    + $this->auth_handler->getApiToken()->columns['expires']
                                    ) - (time() * 1000);
                                return true;
                            } else {
                                return false;
                            }
                        } else {
                            $this->buildErrorSet();
                            return false;
                        }
                    } else {
                        if ($this->validateFields($params, 'v1/authenticate', 'POST')) {
                            $this->auth_handler->setScopes(
                                (isset($params['scope']) && $params['scope'] != '') ? $params['scope'] : ''
                            );
                            if (
                                $this->auth_handler->validateBasicToken($token) &&
                                $this->auth_handler->validateScopes()
                            ) {
                                switch ($params['grant_type']) {
                                    case GrantTypes::PASSWORD:
                                        if ($this->auth_handler->getAsoc() == 1) {
                                            if (!$this->auth_handler->validateLogin($params)) {
                                                $this->err = $this->auth_handler->getErr();
                                                $this->buildErrorSet();
                                                return false;
                                            }
                                        }
                                        break;
                                    case GrantTypes::CLIENT_CREDENTIAL:
                                        if ($this->auth_handler->getAsoc() != 0) {
                                            $this->response['type'] = 'error';
                                            $this->response['code'] = 401;
                                            $this->response['message'] = 'invalid_client';
                                            return false;
                                        }
                                        break;
                                    default:
                                        $this->response['type'] = 'error';
                                        $this->response['code'] = 400;
                                        $this->response['message'] = 'unsupported_grant_type';
                                        return false;
                                }

                                $this->response['code'] = 200;
                                $this->response['access_token'] = $this->auth_handler->generateToken();
                                $this->response['token_type'] = 'bearer';
                                $this->response['username'] = $this->auth_handler->getUsername();
                                $this->response['refresh_token'] = $this->auth_handler->getApiToken(
                                )->columns['refresh_token'];
                                $this->response['expires'] = (
                                    (strtotime($this->auth_handler->getApiToken()->columns['updated_at']) * 1000) +
                                    $this->auth_handler->getApiToken()->columns['expires']
                                    ) - (time() * 1000);
                                return true;
                            } else {
                                $this->buildErrorSet();
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                }
            } else {
                $this->response['type'] = 'error';
                $this->response['code'] = 401;
                $this->response['message'] = 'Malformed basic token';
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
                $this->response['code'] = 401;
            }
        }
        $this->response['message'] = $this->auth_handler->getErr();
    }
}
