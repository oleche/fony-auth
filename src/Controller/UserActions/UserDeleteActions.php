<?php

namespace Geekcow\FonyAuth\Controller\UserActions;

use Geekcow\FonyAuth\Controller\UserOperations\UserDelete;
use Geekcow\FonyCore\Controller\CoreActions;
use Geekcow\FonyCore\Controller\CoreActionsInterface;

class UserDeleteActions extends CoreActions implements CoreActionsInterface
{

    public function default($id = null)
    {
        $user_delete = new UserDelete($this->session, $id);
        $user_delete->removeUser($id);
        $this->response = $user_delete->getResponse();
        return true;
    }
}
