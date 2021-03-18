<?php

namespace Geekcow\FonyAuth\Controller\UserActions;

use Geekcow\FonyAuth\Controller\UserOperations\UserDelete;
use Geekcow\FonyAuth\Model\ApiUser;
use Geekcow\FonyCore\Controller\CoreActions;
use Geekcow\FonyCore\Controller\CoreActionsInterface;

class UserDeleteActions extends CoreActions implements CoreActionsInterface
{
    public function __construct()
    {
        parent::__construct();
    }

    public function default($id = null)
    {
        $model = new ApiUser();
        $user_delete = new UserDelete($model, $this->session, $id);
        if ($this->session->session_level > 1) {
            $user_delete->checkUser();
        }
        $user_delete->doRemove();
        $this->response = $user_delete->getResponse();

    }
}
