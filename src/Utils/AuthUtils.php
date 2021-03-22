<?php

/* Auth Utils
 * Developed by OSCAR LECHE
 * V.1.0
 * DESCRIPTION: Authentication support for token generation and general authentication
 */

namespace Geekcow\FonyAuth\Utils;

use Geekcow\FonyAuth\Model\ApiClient;
use Geekcow\FonyAuth\Model\ApiClientScope;
use Geekcow\FonyAuth\Model\ApiScope;
use Geekcow\FonyAuth\Model\ApiToken;
use Geekcow\FonyAuth\Model\ApiUser;
use Geekcow\FonyAuth\Model\ApiUserAsoc;
use Geekcow\FonyCore\Utils\AuthenticatorInterface;
use Geekcow\FonyCore\Utils\TokenUtils;

class AuthUtils implements AuthenticatorInterface
{
    private $err;
    private $api_client;
    private $api_client_scope;
    private $api_token;
    private $api_user_asoc;
    private $user;

    protected $scope;

    private $client_id;
    private $email;
    private $username;
    private $expiration;
    private $asoc;
    private $scopes;
    private $scope_level;
    private $config;

    public function __construct()
    {
        $this->config = ConfigurationUtils::getInstance();
        $this->api_client = new ApiClient();
        $this->api_client_scope = new ApiClientScope();
        $this->api_token = new ApiToken();
        $this->scope = new ApiScope();
        $this->api_user_asoc = new ApiUserAsoc();
        $this->user = new ApiUser();
    }

    public function getErr()
    {
        return $this->err;
    }

    public function getClientId()
    {
        return $this->client_id;
    }

    public function getExpiration()
    {
        return $this->expiration;
    }

    public function getEmail()
    {
        return $this->email;
    }

    public function getUsername()
    {
        return $this->username;
    }

    public function getAsoc()
    {
        return $this->asoc;
    }

    public function getApiToken()
    {
        return $this->api_token;
    }

    public function getScopes()
    {
        return $this->scopes;
    }

    public function setScopes($scopes)
    {
        $this->scopes = $scopes;
    }

    /**
     * @return mixed
     */
    public function getScopeLevel()
    {
        return $this->scope_level;
    }

    /**
     * Validates a basic token to identify if its related to a valid and active
     * client
     *
     * @return BOOLEAN if found and assigns the client_id, email, username and asociation status
     *
     */
    public function validateBasicToken($token)
    {
        $token64 = base64_decode($token);
        $tokens = explode(":", $token64);
        $result = (array)$this->api_client->fetch(
            "client_id = '$tokens[0]' AND client_secret = '$tokens[1]' AND enabled = 1"
        );
        if (count($result) == 1) {
            if (isset($result[0]->columns)) {
                $this->client_id = $result[0]->columns['client_id'];
                $this->email = $result[0]->columns['email'];
                $this->username = $result[0]->columns['user_id']['username'];
                $this->asoc = $result[0]->columns['asoc'];
                return true;
            } else {
                $this->err = 'Client fetch error';
                return false;
            }
        } else {
            $this->err = 'Client not found';
            return false;
        }
    }

    /**
     * Validates if the refresh token is active and valid and then it invalidates it
     *
     * @return BOOLEAN
     *
     */
    private function isRefreshToken($token)
    {
        $result = $this->api_token->fetch(
            "refresh_token = '$token' AND blacklisted = 0",
            false,
            array('updated_at'),
            false
        );
        if (count($result) == 1) {
            if ($result[0]->columns['client_id']['client_id'] == $this->client_id) {
                $this->scopes = $result[0]->columns['scopes'];
                $this->scope_level = $result[0]->columns['scope_level'];
                $this->username = $result[0]->columns['username']['username'];
                $result[0]->columns['enabled'] = 0;
                $result[0]->columns['blacklisted'] = 1;
                $result[0]->columns['client_id'] = $result[0]->columns['client_id']['client_id'];
                $result[0]->columns['username'] = $result[0]->columns['username']['username'];
                $result[0]->update();
                return true;
            } else {
                $this->err = 'Invalid client';
                return false;
            }
        } else {
            $this->err = 'Invalid token';
            return false;
        }
    }

    /**
     * Validates if the token is active and valid then retrieves the scopes and username
     * Structure of a token:
     *   client_id
     *   timestamp - created at
     *   scopes
     *   scope_level
     *   username
     * @param $token
     * @return BOOLEAN the user and password matches
     */
    private function validateToken($token)
    {
        $result = $this->api_token->fetch(
            "token = '$token' AND enabled = 1 AND blacklisted = 0",
            false,
            array('updated_at'),
            false
        );
        if (count($result) == 1) {
            $token = utf8_decode(
                TokenUtils::decrypt(TokenUtils::base64UrlDecode($token), $this->config->getAppSecret())
            );
            $token = explode('|', $token);
            if (count($token) == 5) {
                if (
                    ((strtotime($result[0]->columns['updated_at']) * 1000) + $result[0]->columns['expires']) >
                    (time() * 1000)
                ) {
                    $this->scopes = $token[2];
                    $this->scope_level = $token[3];
                    $this->username = trim($token[4]);
                    $this->client_id = $result[0]->columns['client_id']['client_id'];
                    $this->expiration = (
                            (strtotime($result[0]->columns['updated_at']) * 1000) + $result[0]->columns['expires']) -
                        (time() * 1000);
                    return true;
                } else {
                    $result[0]->columns['enabled'] = 0;
                    $result[0]->columns['client_id'] = $result[0]->columns['client_id']['client_id'];
                    $result[0]->columns['username'] = $result[0]->columns['username']['username'];
                    $result[0]->update();
                    $this->err = 'Expired token';
                    return false;
                }
            } else {
                $this->err = 'Malformed token';
                return false;
            }
        } else {
            $this->err = 'Invalid token';
            return false;
        }
    }

    /**
     * Validates a BEARER token to identify if its related to a valid and active
     * client and with a valid session
     *
     * @param $token
     * @return BOOLEAN if found and assigns the client_id, email, username and asociation status
     */
    public function validateRefreshToken($token)
    {
        try {
            return $this->isRefreshToken($token);
        } catch (Exception $e) {
            $this->err = $e->getMessage();
            return false;
        }
    }

    /**
     * Validates a refresh token and disables the existing one if found
     *
     * @param $token
     * @return BOOLEAN if found and assigns the client_id, email, username and asociation status
     */
    public function validateBearerToken($token)
    {
        try {
            if (TokenUtils::validateTokenSanity($token, TokenType::BEARER)) {
                $token = TokenUtils::sanitizeToken($token, TokenType::BEARER);
                return $this->validateToken($token);
            } else {
                $this->err = 'Malformed token';
                return false;
            }
        } catch (Exception $e) {
            $this->err = $e->getMessage();
            return false;
        }
    }

    /**
     * Identifies if the scopes provided do exists in the database and are assigned
     * to the required username or client
     *
     * @param $grant_type
     * @return BOOLEAN if found
     */
    public function validateScopes($grant_type)
    {
        $retval = true;

        $scopes_arr = explode(',', $this->scopes);
        if (count($scopes_arr) <= 0) {
            $retval = ($retval && false);
            $this->err = "no scopes selected";
        }

        $this->scope_level = 10;
        foreach ($scopes_arr as $value) {
            if ($this->scope->fetch_id(array("name" => $value))) {
                if ($this->scope->columns['level'] < $this->scope_level) {
                    $this->scope_level = $this->scope->columns['level'];
                }
                switch ($grant_type) {
                    case GrantTypes::PASSWORD:
                        $retval = ($retval && true);
                        break;
                    case GrantTypes::CLIENT_CREDENTIAL:
                        $result = $this->api_client_scope->fetch(
                            "id_client = '$this->client_id' AND id_scope = '" . $this->scope->columns['name'] . "'"
                        );
                        if (count($result) > 0) {
                            $retval = ($retval && true);
                        } else {
                            $retval = ($retval && false);
                            $this->err = "invalid scope for client";
                        }
                        break;
                    default:
                        $this->err = 'Bad grant type to evaluate';
                        $retval = ($retval && false);
                        break;
                }
            } else {
                $this->err = "scope '$value' not found";
                $retval = ($retval && false);
            }
        }
        return $retval;
    }

    /**
     * Identifies if the scopes provided do exists in the database and are assigned
     * to the required username or client
     *
     * @param $user_scopes
     * @return BOOLEAN if found
     */
    public function validatePasswordGrantScopes($user_scopes)
    {
        $retval = true;

        $request_scopes = explode(',', $this->scopes);
        if (count($request_scopes) <= 0) {
            $retval = ($retval && false);
            $this->err = "no scopes selected";
        }

        $user_scopes = explode(',', $user_scopes);
        if (count($user_scopes) <= 0) {
            $this->err = "no scopes available for user";
            return false;
        }

        foreach ($request_scopes as $value) {
            if (in_array($value, $user_scopes)){
                $retval = ($retval && true);
            }else{
                $retval = ($retval && false);
                $this->err = "invalid scope '$value' for client";
            }
        }
        return $retval;
    }

    /**
     * Generates a new token or fetch the latest active token
     * Structure of a token:
     *   client_id
     *   timestamp - created at
     *   scopes
     *   username
     *
     * @return TOKEN if found or created, or FALSE if error
     *
     */
    public function generateToken()
    {
        if ($this->locateValidToken()) {
            return $this->api_token->columns['token'];
        } else {
            $timestamp = time();
            $token = TokenUtils::encrypt(
                $this->client_id . '|' . $timestamp . '|' . $this->scopes . '|' . $this->scope_level . '|' . $this->username,
                $this->config->getAppSecret()
            );
            $token = TokenUtils::base64UrlEncode($token);
            $refresh_token = TokenUtils::encrypt(date("Y-m-d H:i:s"), $this->config->getAppSecret());
            $refresh_token = TokenUtils::base64UrlEncode($refresh_token);
            $this->api_token->columns['token'] = $token;
            $this->api_token->columns['username'] = $this->username;
            $this->api_token->columns['created_at'] = date("Y-m-d H:i:s");
            $this->api_token->columns['updated_at'] = date("Y-m-d H:i:s");
            $this->api_token->columns['expires'] = 3600000;
            $this->api_token->columns['enabled'] = 1;
            $this->api_token->columns['blacklisted'] = 0;
            $this->api_token->columns['refresh_token'] = $refresh_token;
            $this->api_token->columns['client_id'] = $this->client_id;
            $this->api_token->columns['scopes'] = $this->scopes;
            $this->api_token->columns['scope_level'] = $this->scope_level;
            $this->api_token->columns['timestamp'] = $timestamp;
            $insertResult = $this->api_token->insert();
            if (is_numeric($insertResult)) {
                return $token;
            } else {
                $this->err = 'Error saving token: ' . $this->api_token->err_data;
                throw new \Exception($this->err, 1);
            }
        }
    }

    /**
     * Finds a valid token based on the client and username and determines if can be
     * provided or it gets expired
     *
     * Structure of a token:
     *   client_id
     *   timestamp - created at
     *   scopes
     *   username
     *
     * @return BOOLEAN if found or created
     *
     */
    private function locateValidToken()
    {
        $result = $this->api_token->fetch(
            "client_id = '$this->client_id' AND username = '$this->username' AND enabled = 1",
            false,
            array('updated_at'),
            false
        );
        $last = false;
        foreach ($result as $r) {
            if (count($result) > 0) {
                $token = utf8_decode(
                    TokenUtils::decrypt(
                        TokenUtils::base64UrlDecode($r->columns['token']),
                        $this->config->getAppSecret()
                    )
                );
                $token = explode('|', $token);
                if (count($token) == 5) {
                    $token[2] = (string)$token[2];
                    $token[4] = (string)$token[4];

                    if (trim($this->username) == "" || trim($this->username) == trim($token[4])) {
                        if (
                            (trim($this->scopes) == trim($token[2])) &&
                            (
                                (
                                    (strtotime($result[0]->columns['updated_at']) * 1000) +
                                    $result[0]->columns['expires']
                                ) > (time() * 1000)
                            )
                        ) {
                            $this->api_token = $result[0];
                            $this->api_token->columns['updated_at'] = date("Y-m-d H:i:s");
                            $this->api_token->columns['client_id'] = $result[0]->columns['client_id']['client_id'];
                            $this->api_token->columns['username'] = $result[0]->columns['username']['username'];
                            $this->api_token->update();
                            return true;
                        } else {
                            $result[0]->columns['enabled'] = 0;
                            $result[0]->columns['client_id'] = $result[0]->columns['client_id']['client_id'];
                            $result[0]->columns['username'] = $result[0]->columns['username']['username'];
                            if (!$result[0]->update()) {
                                $this->err = 'Error invalidating token';
                            }
                            return false;
                        }
                    } else {
                        $last = false;
                    }
                } else {
                    $this->err = 'Malformed token';
                    return false;
                }
            } else {
                $last = false;
            }
        }
        return $last;
    }

    private function validateScopeLevel(){
        $scopes_arr = explode(',', $this->scopes);

        $this->scope_level = 10;
        foreach ($scopes_arr as $value) {
            if ($this->scope->fetch_id(array("name" => $value))) {
                if ($this->scope->columns['level'] < $this->scope_level) {
                    $this->scope_level = $this->scope->columns['level'];
                }
            }
        }
    }

    /**
     * Performs the login validation of the user and password
     *
     * @param array $params
     * @return BOOLEAN the user and password matches
     */
    public function validateLogin($params = array())
    {
        $params['username'] = md5($params['username']);
        $result = array();
        $pass = sha1($params['password']);
        if (
            $this->user->fetch_id(
                array('username' => $params['username']),
                null,
                true,
                " password = '$pass' AND enabled = 1 "
            )
        ) {
            if ($this->validatePasswordGrantScopes($this->user->columns['type']['scope'])) {
                if (
                    $this->api_user_asoc->fetch_id(
                        array('client_id' => $this->client_id, 'username' => $this->user->columns['username'])
                    )
                ) {
                    $this->validateScopeLevel();
                    $this->username = trim($this->user->columns['username']);
                    return true;
                } else {
                    $this->err = 'User not associated';
                    return false;
                }
            } else {
                return false;
            }
        } else {
            if (
                $this->user
                    ->fetch_id(array('username' => $params['username']), null, true, " enabled = 0 ")
            ) {
                $this->err = 'User disabled';
                return false;
            } else {
                $this->err = 'Invalid Credentials';
                return false;
            }
        }
    }
}
