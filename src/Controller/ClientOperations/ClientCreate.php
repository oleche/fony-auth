<?php

/* Generic Create Operation
 * Developed by OSCAR LECHE
 * V.1.0
 * DESCRIPTION:
 */

namespace Geekcow\FonyAuth\Controller\ClientOperations;

use Geekcow\FonyAuth\Model\ApiClient;
use Geekcow\FonyAuth\Model\ApiClientScope;
use Geekcow\FonyAuth\Model\ApiUserAsoc;
use Geekcow\FonyAuth\Utils\ConfigurationUtils;
use Geekcow\FonyCore\Helpers\AllowCore;

class ClientCreate
{
    private $session;
    private $validScope;
    private $api_client;
    private $api_client_scopes;
    private $api_user_asoc;
    private $config;

    public $response;

    public function __construct($session)
    {
        $this->config = ConfigurationUtils::getInstance();
        $this->api_client = new ApiClient();
        $this->api_client_scopes = new ApiClientScope();
        $this->api_user_asoc = new ApiUserAsoc();


        $this->validScope = AllowCore::ADMINISTRATOR();
        $this->response = array();
        $this->session = $session;
    }

    public function doCreate()
    {
    }

    private function validateApi($user_type, $user, &$client, $asoc = 1)
    {
        $scope_to_use = "";
        if ($user_type->fetch_id(array('id' => $user->columns['type']))) {
            $scope_to_use = $user_type->columns['scope'];
        } else {
            $this->response['type'] = 'error';
            $this->response['title'] = 'User type error';
            $this->response['message'] = 'The following error has happened: ' . $this->user_type->err_data;
            $this->response['code'] = 500;
            return false;
        }
        //User specific client & secret -- this is an associated client
        //Also will register the user to the global user authentication client
        $client = sha1($user->columns['username'] . $user->columns['email'] . date("Y-m-d H:i:s"));
        $secret = sha1($client . $this->config->getAppSecret());
        $this->api_client->columns['client_id'] = $client;
        $this->api_client->columns['client_secret'] = $secret;
        $this->api_client->columns['email'] = $user->columns['email'];
        $this->api_client->columns['user_id'] = $user->columns['username'];
        $this->api_client->columns['enabled'] = 1;
        $this->api_client->columns['asoc'] = $asoc;
        $this->api_client->columns['created_at'] = date("Y-m-d H:i:s");
        $this->api_client->columns['updated_at'] = date("Y-m-d H:i:s");

        $id = $this->api_client->insert();
        if (is_numeric($id)) {
            if ($this->api_client->fetch_id(array('client_id' => $client))) {
                $this->api_client_scopes->columns['id_client'] = $client;
                $this->api_client_scopes->columns['id_scope'] = $scope_to_use;
                $idx = $this->api_client_scopes->insert();
                if (is_numeric($idx)) {
                    if (
                        $this->api_client_scopes->fetch_id(
                            array('id_client' => $client, 'id_scope' => $scope_to_use)
                        )
                    ) {
                        if (
                            $this->validateAssociation($user->columns['username'], $client) &&
                            $this->validateAssociation($user->columns['username'], $this->user_token)
                        ) {
                            return true;
                        } else {
                            return false;
                        }
                    } else {
                        $message = 'The following error has happened: ' . $this->api_client_scopes->err_data;
                        $this->response['type'] = 'error';
                        $this->response['title'] = 'Scope association validation';
                        $this->response['message'] = $message;
                        $this->response['code'] = 500;
                        return false;
                    }
                } else {
                    $message = 'The following error has happened: ' . $this->api_client_scopes->err_data;
                    $this->response['type'] = 'error';
                    $this->response['title'] = 'Scope association creation';
                    $this->response['message'] = $message;
                    $this->response['code'] = 422;
                    return false;
                }
            } else {
                $this->response['type'] = 'error';
                $this->response['title'] = 'Token error';
                $this->response['message'] = 'The following error has happened: ' . $this->api_client->err_data;
                $this->response['code'] = 500;
                return false;
            }
        } else {
            $this->response['type'] = 'error';
            $this->response['title'] = 'Create Token';
            $this->response['message'] = 'The following error has happened: ' . $this->api_client->err_data;
            $this->response['code'] = 422;
            return false;
        }
        return false;
    }

    public function validateAssociation($userid, $token)
    {
        $this->api_user_asoc->columns['client_id'] = $token;
        $this->api_user_asoc->columns['username'] = $userid;
        $idx = $this->api_user_asoc->insert();
        if ($this->api_user_asoc->fetch_id(array('client_id' => $token, 'username' => $userid))) {
            return true;
        } else {
            $this->response['type'] = 'error';
            $this->response['title'] = 'Association error';
            $this->response['message'] = 'The following error has happened: ' . $this->api_user_asoc->err_data;
            $this->response['code'] = 500;
            return false;
        }
    }


    public function setValidScope($scope)
    {
        $this->validScope = $scope;
    }
}
