<?php

/* Generic Create Operation
 * Developed by OSCAR LECHE
 * V.1.0
 * DESCRIPTION:
 */

namespace Geekcow\FonyAuth\Controller\UserOperations;

use Geekcow\FonyAuth\Model\ApiUser;
use Geekcow\FonyAuth\Model\ApiUserType;
use Geekcow\FonyAuth\Utils\ConfigurationUtils;
use Geekcow\FonyCore\Helpers\AllowCore;

class UserCreate
{
    public $response;

    private $user;
    private $user_type;
    private $allowed_roles;

    //THE USER TOKEN IS THE CLIENT ASSOCIATED TO GENERATE LOGIN OPERATIONS
    private $user_token = '';

    public function __construct($allowed_roles)
    {
        $config = ConfigurationUtils::getInstance();
        $this->user_token = $config->getUserClient();

        $this->user = new ApiUser();
        $this->user_type = new ApiUserType();

        $this->response = array();
        $this->allowed_roles = $allowed_roles;
    }

    public function createUser($scope, $asoc = 1)
    {
        $username = md5(strtolower($_POST['email']));
        $fullname = $_POST['name'] . ' ' . ((isset($_POST['lastname'])) ? $_POST['lastname'] : "");
        if ($this->userExists($username)) {
            $this->response['type'] = 'error';
            $this->response['title'] = 'Create user';
            $this->response['message'] = 'User already exist';
            $this->response['code'] = 409;
        } else {
            if ($this->validatePassword() && $this->validateScope($scope)) {
                $this->response = array();
                $password = sha1($_POST['password']);
                $this->user->columns['username'] = strtolower($username);
                $this->user->columns['name'] = $_POST['name'];
                $this->user->columns['lastname'] = (isset($_POST['lastname'])) ? $_POST['lastname'] : "";
                $this->user->columns['email'] = $_POST['email'];
                $this->user->columns['phone'] = (isset($_POST['phone'])) ? $_POST['phone'] : "";
                $this->user->columns['type'] = $_POST['type'];
                $this->user->columns['avatar'] = "";
                $this->user->columns['avatar_path'] = "";
                $this->user->columns['password'] = (isset($password)) ? $password : "";
                $this->user->columns['enabled'] = 1;
                $this->user->columns['verified'] = 1;
                $this->user->columns['verification'] = "";
                $this->user->columns['created_at'] = date("Y-m-d H:i:s");
                $this->user->columns['updated_at'] = date("Y-m-d H:i:s");

                $id = $this->user->insert();
                if (is_numeric($id)) {
                    $client = '';
                    if ($this->validateApi($this->user_type, $this->user, $client, $asoc)) {
                        if ($this->user->fetch_id(array('username' => $username))) {
                            $this->broadcastMessage($user->columns['type'], $user->columns['verification']);
                            $this->response['entidad'] = $this->user->columns;
                            $this->response['code'] = 200;
                        } else {
                            $this->response['type'] = 'error';
                            $this->response['title'] = 'Display user';
                            $this->response['message'] = 'The following error has happened: ' . $this->user->err_data;
                            $this->response['code'] = 500;
                        }
                    } else {
                        $this->removeUser($user->columns['username']);
                        $this->response = $this->client_create->response;
                    }
                } else {
                    $this->response['type'] = 'error';
                    $this->response['title'] = 'Create user';
                    $this->response['message'] = 'The following error has happened: ' . $this->user->err_data;
                    $this->response['code'] = 422;
                }
            }
        }
    }

    //Private Methods
    private function validatePassword()
    {
        $valid = false;
        if (isset($_POST['password']) && $_POST['password'] != "") {
            $valid = true;
        }
        if (!$valid) {
            $this->response['type'] = 'error';
            $this->response['title'] = 'Create User';
            $this->response['message'] = 'Not assigned authentication';
            $this->response['code'] = 422;
        }
        return $valid;
    }

    private function validateScope($scope)
    {
        if (!AllowCore::isAllowed($scope, $this->allowed_roles)) {
            $this->response = AllowCore::denied($scope);
            return false;
        }
        return true;
    }

    private function userExists($user)
    {
        $validation = $this->user->fetch_id(array('username' => $user));

        if (!$validation) {
            $this->response['type'] = 'error';
            $this->response['title'] = 'User';
            $this->response['message'] = 'User does not exist';
            $this->response['code'] = 422;
        }

        return $validation;
    }


    private function broadcastMessage($type, $verification)
    {
        //custom email sending
        return true;
    }

    private function removeUser($id)
    {
        if ($this->user->fetch_id(array("username" => $id))) {
            if (!$this->user->delete()) {
                $this->response['error_on_error'] = 'User could not be eliminated';
            }
        }
    }
}
