<?php

namespace Geekcow\FonyAuth\Controller\UserActions;

use Geekcow\FonyAuth\Controller\UserOperations\UserPut;
use Geekcow\FonyAuth\Controller\UserOperations\UserUpload;
use Geekcow\FonyCore\Controller\CoreActions;
use Geekcow\FonyCore\Controller\CoreActionsInterface;

class UserPutActions extends CoreActions implements CoreActionsInterface
{

    public function __construct()
    {
        parent::__construct();
    }

    public function default($id = null)
    {
        if ($this->validateFields($_POST, 'api/user/:id', 'PUT')) {
            $user_put = new UserPut($this->session, $id);
            $user_put->setValidScope($this->allowed_roles);
            $user_put->putUser();
            $this->response = $user_put->response;
        }
        return true;
    }

    public function upload($id)
    {
        if ($this->validateUpload($this->file)) {
            $user_put = new UserUpload($this->session, $id);
            $user_put->setValidScope($this->allowed_roles);
            $user_put->put($this->file);
            $this->response = $user_put->response;
        }
    }

    public function password($id)
    {
        if ($this->validateFields($_POST, 'api/user/:id/password', 'PUT')) {
            $status_put = new UserPut($this->session, $id);
            $status_put->setValidScope($this->allowed_roles);
            $status_put->changePassword();
            $this->response = $status_put->response;
        }
    }

    public function enable($id)
    {
        $status_put = new UserPut($this->session, $id);
        $status_put->setValidScope($this->allowed_roles);
        $status_put->enable();
        $this->response = $status_put->response;
    }

    public function disable($id)
    {
        $status_put = new UserPut($this->session, $id);
        $status_put->setValidScope($this->allowed_roles);
        $status_put->disable();
        $this->response = $status_put->response;
    }
}
