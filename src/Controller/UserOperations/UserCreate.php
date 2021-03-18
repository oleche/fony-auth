<?php

/* Generic Create Operation
 * Developed by OSCAR LECHE
 * V.1.0
 * DESCRIPTION:
 */

namespace Geekcow\FonyAuth\Controller\UserOperations;

use Geekcow\FonyAuth\Controller\ClientOperations\ClientCreate;
use Geekcow\FonyCore\Controller\CoreOperation;

class UserCreate extends CoreOperation
{
    private $client_create;

    public function __construct($model, $session, $id = null)
    {
        parent::__construct($model, $session);

        $this->client_create = new ClientCreate($session);
    }

    public function createUser($asoc = 1)
    {
        $username = md5(strtolower($_POST['email']));
        $fullname = $_POST['name'] . ' ' . ((isset($_POST['lastname'])) ? $_POST['lastname'] : "");
        if ($this->userExists($username)) {
            $this->response['type'] = 'error';
            $this->response['title'] = 'Create user';
            $this->response['message'] = 'User already exist';
            $this->response['code'] = 409;
        } else {
            if ($this->validatePassword()) {
                $this->response = array();
                $password = sha1($_POST['password']);
                $this->model->columns['username'] = strtolower($username);
                $this->model->columns['name'] = $_POST['name'];
                $this->model->columns['lastname'] = (isset($_POST['lastname'])) ? $_POST['lastname'] : "";
                $this->model->columns['email'] = $_POST['email'];
                $this->model->columns['phone'] = (isset($_POST['phone'])) ? $_POST['phone'] : "";
                $this->model->columns['type'] = $_POST['type'];
                $this->model->columns['avatar'] = "";
                $this->model->columns['avatar_path'] = "";
                $this->model->columns['password'] = (isset($password)) ? $password : "";
                $this->model->columns['enabled'] = 1;
                $this->model->columns['verified'] = 1;
                $this->model->columns['verification'] = "";
                $this->model->columns['created_at'] = date("Y-m-d H:i:s");
                $this->model->columns['updated_at'] = date("Y-m-d H:i:s");

                $id = $this->model->insert();
                if (is_numeric($id)) {
                    $client = '';
                    $client_name = 'CLIENT: ' . $fullname;
                    if ($this->client_create->validateApi($this->model, $client, $client_name, $asoc)) {
                        if ($this->model->fetch_id(array('username' => $username))) {
                            $this->response['entity'] = array();
                            $this->response['entity']['user'] = $this->model->columns;
                            $this->response['entity']['client'] = $client;
                            $this->response['code'] = 200;
                        } else {
                            $this->response['type'] = 'error';
                            $this->response['title'] = 'Display user';
                            $this->response['message'] = 'The following error has happened: ' . $this->model->err_data;
                            $this->response['code'] = 500;
                        }
                    } else {
                        $this->removeUser($this->model->columns['username']);
                        $this->response = $this->client_create->getResponse();
                    }
                } else {
                    $this->response['type'] = 'error';
                    $this->response['title'] = 'Create user';
                    $this->response['message'] = 'The following error has happened: ' . $this->model->err_data;
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

    private function userExists($user)
    {
        $validation = $this->model->fetch_id(array('username' => $user));

        if (!$validation) {
            $this->response['type'] = 'error';
            $this->response['title'] = 'User';
            $this->response['message'] = 'User does not exist';
            $this->response['code'] = 422;
        }

        return $validation;
    }

    private function removeUser($id)
    {
        if ($this->model->fetch_id(array("username" => $id))) {
            if (!$this->model->delete()) {
                $this->response['error_on_error'] = 'User could not be eliminated';
            }
        }
    }
}
