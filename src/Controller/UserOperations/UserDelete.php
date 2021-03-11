<?php

namespace Geekcow\FonyAuth\Controller\UserOperations;

use Geekcow\FonyCore\Controller\CoreOperation;

class UserDelete extends CoreOperation
{
    private $userid;
    public function __construct($model, $session, $id = null)
    {
        parent::__construct($model, $session);
        $this->userid = $id;
    }

    public function doRemove()
    {
        if ($this->validateUser($this->userid)) {
            if ($this->removeUser($this->userid)) {
                $this->response['message'] = 'User removed';
                $this->response['code'] = 200;
            }
        }
    }

    public function removeUser($id)
    {
        if ($this->model->fetch_id(array("username" => $id))) {
            if (!$this->model->delete()) {
                $this->response['type'] = 'error';
                $this->response['title'] = 'User';
                $this->response['message'] = 'The following error has happened: ' . $this->model->err_data;
                $this->response['code'] = 422;
                return false;
            }
            return true;
        }
        return false;
    }
}
