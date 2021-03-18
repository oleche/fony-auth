<?php

/* API user controller
 * Developed by OSCAR LECHE
 * V.1.0
 * DESCRIPTION: User controller
 */

namespace Geekcow\FonyAuth\Controller;

use Geekcow\FonyAuth\Controller\UserActions\UserDeleteActions;
use Geekcow\FonyAuth\Controller\UserActions\UserGetActions;
use Geekcow\FonyAuth\Controller\UserActions\UserPutActions;
use Geekcow\FonyAuth\Controller\UserOperations\UserCreate;
use Geekcow\FonyAuth\Model\ApiUser;
use Geekcow\FonyAuth\Utils\ConfigurationUtils;
use Geekcow\FonyCore\Controller\ApiMethods;
use Geekcow\FonyCore\Controller\BaseController;
use Geekcow\FonyCore\Helpers\AllowCore;

class UserController extends BaseController implements ApiMethods
{
    public function __construct()
    {
        parent::__construct();
    }

    //CREATE
    public function doPOST($args = array(), $verb = null)
    {
        if (!$this->validation_fail) {
            if (!$this->validateScope($this->session->session_scopes)) {
                return false;
            }

            if (is_array($args) && empty($args) && empty($verb)) {
                if ($this->validateFields($this->request, $this->form_endpoint, 'POST')) {
                    $user_create = new UserCreate(new ApiUser(), $this->session);
                    $user_create->createUser();
                    //TODO: Broadcaster idea: allow the controller to implement classes that will serve as
                    // broadcasters that react after the execution of each call.
                    // It should also be implemented in the execute() method.
                    // $this-broadcast();
                    $this->broadcastMessage(
                        $user_create->getModel()->columns['type'],
                        $user_create->getModel()->columns['verification']
                    );
                    $this->response = $user_create->getResponse();
                }
            } else {
                $this->response['type'] = 'error';
                $this->response['title'] = 'User';
                $this->response['code'] = 404;
                $this->response['message'] = "Invalid URL";
            }
        }
        $this->filterResponse(['notes']);
    }

    //READ INFORMATION
    public function doGET($args = array(), $verb = null)
    {
        if (!$this->validation_fail) {
            if (!$this->validateScope($this->session->session_scopes)) {
                return false;
            }

            $user_get_action = new UserGetActions();
            $this->executeActionFlow($args, $verb, $user_get_action);
        }

        if (
            $this->session->username != $verb &&
            !AllowCore::isAllowed(
                $this->session->session_scopes,
                $this->allowed_roles
            )
        ) {
            $this->filterResponse(
                ['notes', 'password', 'email', 'avatar_path', 'phone', 'enabled', 'verification', 'updated_at']
            );
        } else {
            $this->filterResponse(['notes', 'password']);
        }
    }

    //TEND TO HAVE MULTIPLE METHODS
    public function doPUT($args = array(), $verb = null, $file = null)
    {
        if (!$this->validation_fail) {
            if (!$this->validateScope($this->session->session_scopes)) {
                return false;
            }

            $user_put_actions = new UserPutActions();
            $this->executeActionFlow($args, $verb, $user_put_actions, $file);
        }

        if (
            $this->session->username != $verb &&
            !AllowCore::isAllowed(
                $this->session->session_scopes,
                $this->allowed_roles
            )
        ) {
            $this->filterResponse(
                [
                    'notes',
                    'password',
                    'email',
                    'avatar_path',
                    'phone',
                    'enabled',
                    'verification',
                    'created_at',
                    'updated_at'
                ]
            );
        } else {
            $this->filterResponse(['notes', 'password']);
        }
    }

    //DELETES ONE SINGLE ENTRY
    public function doDELETE($args = array(), $verb = null)
    {
        if (!$this->validation_fail) {
            if (!$this->validateScope($this->session->session_scopes)) {
                return false;
            }

            $user_delete_actions = new UserDeleteActions();
            if (is_array($args) && empty($args)) {
                $user_delete_actions->setSession($this->session);
                $user_delete_actions->setRoles($this->allowed_roles);
                $this->setExecutableClass($user_delete_actions);
                $this->setActionVerb($verb);
                $this->execute();
            } else {
                $this->response['type'] = 'error';
                $this->response['title'] = 'User';
                $this->response['code'] = 404;
                $this->response['message'] = "Invalid URL";
            }
        }
        $this->filterResponse(['notes']);
    }
}
