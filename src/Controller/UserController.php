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
        $configfile = ConfigurationUtils::getInstance(MY_DOC_ROOT . "/src/config/config.ini");
        parent::__construct($configfile);
    }

    //CREATE
    public function doPOST($args = array(), $verb = null)
    {
        if (!$this->validation_fail) {
            if (!$this->validateScope($this->session->session_scopes)) {
                return false;
            }

            if (is_array($args) && empty($args)) {
                if ($this->validate_fields($_POST, 'v1/user', 'POST')) {
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
            $user_get_action->setSession($this->session);
            $user_get_action->setRoles($this->allowed_roles);
            $this->setExecutableClass($user_get_action);
            if (is_array($args) && empty($args)) {
                $this->setActionId($verb);
                $this->execute();
            } else {
                $this->setActionId($verb);
                $this->setActionVerb($args[0]);
                $this->execute(true);
            }
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
            $user_put_actions = new UserPutActions();
            $user_put_actions->setSession($this->session);
            $user_put_actions->setRoles($this->allowed_roles);
            $user_put_actions->setFile($file);
            $this->setExecutableClass($user_put_actions);
            if (is_array($args) && empty($args)) {
                $this->setActionId($verb);
                $this->execute();
            } else {
                $this->setActionId($verb);
                $this->setActionVerb($args[0]);
                $this->execute(true);
            }
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

            $user_put_actions = new UserDeleteActions();
            $user_put_actions->setSession($this->session);
            $user_put_actions->setRoles($this->allowed_roles);
            $this->setExecutableClass($user_put_actions);
            if (is_array($args) && empty($args)) {
                $this->setActionId($verb);
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
