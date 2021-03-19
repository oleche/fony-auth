<?php

/* Generic Create Operation
 * Developed by OSCAR LECHE
 * V.1.0
 * DESCRIPTION:
 */

namespace Geekcow\FonyAuth\Controller\ClientOperations;

use Geekcow\FonyAuth\Model\ApiClient;
use Geekcow\FonyAuth\Model\ApiClientScope;
use Geekcow\FonyAuth\Model\ApiUser;
use Geekcow\FonyAuth\Model\ApiUserAsoc;
use Geekcow\FonyAuth\Model\ApiUserType;
use Geekcow\FonyAuth\Utils\ConfigurationUtils;
use Geekcow\FonyCore\Controller\CoreOperation;

class ClientCreate extends CoreOperation
{
    private $api_client;
    private $api_client_scopes;
    private $api_user_asoc;
    private $config;

    public function __construct($session)
    {
        parent::__construct(new ApiClient(), $session);
        $this->config = ConfigurationUtils::getInstance();
        $this->api_client_scopes = new ApiClientScope();
        $this->api_user_asoc = new ApiUserAsoc();
    }

    public function doCreate()
    {
        $user = new ApiUser();
        $client = '';
        if ($user->fetch_id(array('username' => $this->session->username))) {
            if ($this->validateApi($user, $client, $this->parameters['name'], 1, true)) {
                $this->response['entity'] = array();
                $this->response['entity']['client'] = $client;
                $this->response['code'] = 200;
            }
        } else {
            $this->response['type'] = 'error';
            $this->response['title'] = 'Retrieve user';
            $this->response['message'] = 'The following error has happened: ' . $this->model->err_data;
            $this->response['code'] = 422;
        }
    }

    public function doAssign()
    {
        if ($this->validateAssociation($this->parameters['username'], $this->parameters['token'])) {
            $this->response['entity'] = array();
            $this->response['entity']['asociation'] = $this->api_user_asoc->columns;
            $this->response['code'] = 200;
        } else {
            $message = 'The following error has happened: ' . $this->api_user_asoc->err_data;
            $this->response['type'] = 'error';
            $this->response['title'] = 'Client association validation';
            $this->response['message'] = $message;
            $this->response['code'] = 500;
        }
    }

    public function validateApi($user, &$client, $name, $asoc = 1, $isUserClient = false)
    {
        $user_type = new ApiUserType();
        $scopes_to_use = array();

        if ($user_type->fetch_id(array('id' => $user->columns['type']))) {
            $scopes_to_use = explode(',', $user_type->columns['scope']);
        } else {
            $this->response['type'] = 'error';
            $this->response['title'] = 'User type error';
            $this->response['message'] = 'The following error has happened: ' . $user_type->err_data;
            $this->response['code'] = 500;
            return false;
        }
        //User specific client & secret -- this is an associated client
        //Also will register the user to the global user authentication client
        $client = sha1($user->columns['username'] . $user->columns['email'] . date("Y-m-d H:i:s"));
        $secret = sha1($client . $this->config->getAppSecret());
        $this->model->columns['client_id'] = $client;
        $this->model->columns['client_secret'] = $secret;
        $this->model->columns['name'] = $name;
        $this->model->columns['email'] = $user->columns['email'];
        $this->model->columns['user_id'] = $user->columns['username'];
        $this->model->columns['enabled'] = 1;
        $this->model->columns['asoc'] = $asoc;
        $this->model->columns['created_at'] = date("Y-m-d H:i:s");
        $this->model->columns['updated_at'] = date("Y-m-d H:i:s");

        $id = $this->model->insert();
        if (is_numeric($id)) {
            if ($this->model->fetch_id(array('client_id' => $client))) {
                $all_scopes_created = false;
                foreach ($scopes_to_use as $scope_to_use) {
                    $this->api_client_scopes->columns['id_client'] = $client;
                    $this->api_client_scopes->columns['id_scope'] = $scope_to_use;
                    $idx = $this->api_client_scopes->insert();
                    if (is_numeric($idx)) {
                        if (
                            $this->api_client_scopes->fetch_id(
                                array('id_client' => $client, 'id_scope' => $scope_to_use)
                            )
                        ) {
                            $all_scopes_created = true;
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
                }
                if ($all_scopes_created){
                    if ($isUserClient) {
                        return $this->validateAssociation($user->columns['username'], $client);
                    }
                    return (
                        $this->validateAssociation($user->columns['username'], $client) &&
                        $this->validateAssociation($user->columns['username'], $this->config->getUserClient())
                    );
                }
                return false;
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
            $this->response['message'] = 'The following error has happened: ' . $this->model->err_data;
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
}
