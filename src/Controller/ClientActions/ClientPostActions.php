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
        if ($this->validate_fields($_POST, 'api/client/', 'POST')) {
            $client_post = new ClientCreate($this->session);
            $client_post->setValidScope($this->allowed_roles);
            $client_post->doCreate();
            $this->response = $client_post->response;
        }
        return true;
    }

    public function assign()
    {
        if ($this->validate_fields($_POST, 'api/client/assign', 'POST')) {
        }
    }
}
