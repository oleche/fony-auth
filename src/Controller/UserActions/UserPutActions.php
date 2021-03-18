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
        if ($this->validateFields($this->request, $this->form_endpoint, 'PUT')) {
            $user_put = new UserPut($this->session, $id);
            $user_put->setParameters($this->request);
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
            $user_put->setParameters($this->request);
            $user_put->setValidScope($this->allowed_roles);
            $user_put->put($this->file);
            $this->response = $user_put->response;
        }
    }

    public function password($id)
    {
        if ($this->validateFields($_POST, $this->form_endpoint, 'PUT')) {
            $user_put = new UserPut($this->session, $id);
            $user_put->setParameters($this->request);
            $user_put->setValidScope($this->allowed_roles);
            $user_put->changePassword();
            $this->response = $user_put->response;
        }
    }

    public function enable($id)
    {
        $user_put = new UserPut($this->session, $id);
        $user_put->setParameters($this->request);
        $user_put->setValidScope($this->allowed_roles);
        $user_put->enable();
        $this->response = $user_put->response;
    }

    public function disable($id)
    {
        $user_put = new UserPut($this->session, $id);
        $user_put->setParameters($this->request);
        $user_put->setValidScope($this->allowed_roles);
        $user_put->disable();
        $this->response = $user_put->response;
    }
}
