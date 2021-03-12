<?php

namespace Geekcow\FonyAuth\Controller\ClientActions;

use Geekcow\FonyAuth\Controller\ClientOperations\ClientCreate;
use Geekcow\FonyCore\Controller\CoreActions;
use Geekcow\FonyCore\Controller\CoreActionsInterface;

class ClientPostActions extends CoreActions implements CoreActionsInterface
{

    public function __construct()
    {
        parent::__construct();
    }

    //Client creation
    public function default()
    {
        if (!$this->validateScope($this->session->session_scopes)) {
            return false;
        }

        if ($this->validateFields($_POST, 'api/client/', 'POST')) {
            $client_post = new ClientCreate($this->session);
            $client_post->doCreate();
            $this->response = $client_post->getResponse();
            return true;
        }
        return false;
    }

    public function assign()
    {
        if ($this->validateFields($_POST, 'api/client/assign', 'POST')) {
            $client_post = new ClientCreate($this->session);
            $client_post->doAssign();
            $this->response = $client_post->getResponse();
            return true;
        }
        return false;
    }
}
