<?php

namespace Geekcow\FonyAuth\Controller\ClientActions;

use Geekcow\FonyCore\Controller\CoreActions;
use Geekcow\FonyCore\Controller\CoreActionsInterface;

class ClientDeleteActions extends CoreActions implements CoreActionsInterface
{

    public function default()
    {
        $this->response['code'] = 501;
        $this->response['msg'] = "Not Implemented";
    }
}
