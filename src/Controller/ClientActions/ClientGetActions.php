<?php

namespace Geekcow\FonyAuth\Controller\ClientActions;

use Geekcow\FonyAuth\Model\ApiClient;
use Geekcow\FonyCore\Controller\CoreActions;
use Geekcow\FonyCore\Controller\CoreActionsInterface;
use Geekcow\FonyCore\Controller\GenericOperations\GenericGet;

class ClientGetActions extends CoreActions implements CoreActionsInterface
{

    public function default($id = null)
    {
        if (!$this->validateScope($this->session->session_scopes)) {
            return false;
        }

        $model = new ApiClient();
        $client_get = new GenericGet($model, $this->session, $id);
        if ($this->session->session_level > 1){
            $client_get->checkUser();
        }
        $client_get->get();
        $this->response = $client_get->getResponse();
        $this->pagination_link = $client_get->getPaginationLink();
    }
}
