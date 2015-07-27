<?php
/* Copyright (C) 2015 Lars Vierbergen  <lars@vbgn.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *      \file       htdocs/core/login/functions_oauth.php
 *      \ingroup    core
 *      \brief      Authentication functions for OAuth mode
 */

use fkooman\Guzzle\Plugin\BearerAuth\BearerAuth;
use fkooman\Guzzle\Plugin\BearerAuth\Exception\BearerErrorResponseException;
use fkooman\OAuth\Client\Api;
use fkooman\OAuth\Client\Callback;
use fkooman\OAuth\Client\ClientConfig;
use fkooman\OAuth\Client\Context;
use fkooman\OAuth\Client\Exception\AuthorizeException;
use fkooman\OAuth\Client\Exception\CallbackException;
use fkooman\OAuth\Client\SessionStorage;
use Guzzle\Http\Client;

require DOL_DOCUMENT_ROOT . '/../vendor/autoload.php';
require_once DOL_DOCUMENT_ROOT . '/user/class/usergroup.class.php';
require_once DOL_DOCUMENT_ROOT . '/core/lib/usergroups.lib.php';

/**
 * Check validity of user/password/entity
 * If test is ko, reason must be filled into $_SESSION["dol_loginmesg"]
 *
 * @param    string $usertotest Login
 * @param    string $passwordtotest Password
 * @param   int $entitytotest Number of instance (always 1 if module multicompany not enabled)
 * @return    string                    Login if OK, '' if KO
 */
function check_user_password_oauth($usertotest, $passwordtotest, $entitytotest)
{
    global $db, $conf, $langs;

    dol_syslog("functions_oauth::check_user_password_oauth");

    // Set up configuration for OAuth client
    $clientConfig = new ClientConfig(array(
        'authorize_endpoint' => $conf->global->MAIN_AUTHENTICATION_OAUTH_AUTHORIZE_URL,
        'client_id' => $conf->global->MAIN_AUTHENTICATION_OAUTH_CLIENT_ID,
        'client_secret' => $conf->global->MAIN_AUTHENTICATION_OAUTH_CLIENT_SECRET,
        'token_endpoint' => $conf->global->MAIN_AUTHENTICATION_OAUTH_TOKEN_URL,
        'redirect_uri' => $conf->global->MAIN_AUTHENTICATION_OAUTH_REDIRECT_URL,
    ));

    $tokenStorage = new SessionStorage();
    $client = new Client();
    $api = new Api("authserver", $clientConfig, $tokenStorage, $client);
    $context = new Context("u", array("profile:username", "profile:realname", "profile:groups"));

    // If we have a response, handle it
    if (isset($_GET['code']) || isset($_GET['error'])) {
        try {
            $callback = new Callback("authserver", $clientConfig, $tokenStorage, $client);
            $callback->handleCallback($_GET);
        } catch (AuthorizeException $ex) {
            $_SESSION['dol_loginmesg'] = "OAuth login failed: " . $ex->getMessage();
            goto fail;
        } catch (CallbackException $ex) {
            $_SESSION['dol_loginmesg'] = "OAuth login failed: " . $ex->getMessage();
            goto fail;
        }
    }

    // Try to fetch an access token. If none exists: try authorization.
    $accessToken = $api->getAccessToken($context);
    if ($accessToken === false) {
        header('HTTP/1.1 302 Found');
        header('Location: ' . $api->getAuthorizeUri($context));
        exit;
    }

    try {
        // Add Authorization header
        $client->addSubscriber(new BearerAuth($accessToken->getAccessToken()));

        // Fetch the user data
        $response = $client->get($conf->global->MAIN_AUTHENTICATION_OAUTH_USERINFO_URL)
            ->send()
            ->json();
    } catch (BearerErrorResponseException $e) {
        if ($e->getBearerReason() === "invalid_token") {
            // Our token is invalid, remove and retry authentication
            $api->deleteAccessToken($context);
            $api->deleteRefreshToken($context);

            header('HTTP/1.1 302 Found');
            header('Location: ' . $api->getAuthorizeUri($context));
            exit;
        }

        $_SESSION['dol_loginmesg'] = 'OAuth login failed: ' . $e->getMessage();
        goto fail;
    }

    /*
     * Filter the returned groups: only groups starting with dolibarr_ are preserved.
     * The starting string dolibarr_ is stripped
     */
    $groups = array_map(
        function ($group) {
            return substr($group, strlen('dolibarr_'));
        },
        array_filter($response['groups'], function ($group) {
            return strpos($group, 'dolibarr_') === 0;
        })
    );

    // If the user is not member of Authserver group dolibarr_users, kick 'em out.
    if (!in_array('user', $groups)) {
        $_SESSION['dol_loginmesg'] = 'You are not authorized to use this application.';
        goto fail;
    }

    // Create DAO objects for users and groups
    $user = new User($db);
    $userGroup = new UserGroup($db);

    // Find a user with the same GUID as our freshly authenticated user
    $sql = "SELECT rowid FROM " . MAIN_DB_PREFIX . "user";
    $sql .= " WHERE ldap_sid = '" . $db->escape($response['guid']) . "'";

    $resql = $db->query($sql);
    if ($resql) {
        $obj = $db->fetch_object($resql);
        if (!$db->begin())
            goto rollback;

        // This user already exists, fetch it into the object
        if ($obj) {
            if ($user->fetch($obj->rowid) <= 0)
                goto rollback;
        }

        // Update simple fields
        $user->lastname = $response['name'];
        $user->login = $response['username'];
        $user->admin = in_array('%sysops', $response['groups']);


        if ($obj) {
            // User already exists, update the object.
            if ($user->update($user) < 0) {
                goto rollback;
            }
        } else {
            // User does not yet exist. Create it
            $id = $user->create($user);
            if ($id < 0)
                goto rollback;

            // Set authentication GUID on the new user
            if (!$db->query("UPDATE " . MAIN_DB_PREFIX . "user SET ldap_sid = '" . $db->escape($response['guid']) . "' WHERE rowid = " . $id))
                goto rollback;
        }

        // Get the Dolibarr groups the user is member of, and index them by name
        $currentGroups = $userGroup->listGroupsForUser($user->id);
        $currentMemberGroups = array();
        foreach ($currentGroups as $group) {
            $currentMemberGroups[$group->name] = $group;
        }
        /* @var $currentMemberGroups UserGroup[] */

        // Remove user from Dolibarr groups when he is no longer member of the corresponding Authserver group
        // If this fails, abort the login
        foreach ($currentMemberGroups as $group) {
            if (!in_array($group->name, $groups)) {
                if ($user->RemoveFromGroup($group->id, $group->entity) < 0) {
                    dol_syslog('functions_oauth::check_user_password_oauth: Cannot remove member from no longer authorized group. Access denied.', LOG_ALERT);
                    goto rollback;
                }
            }
        }

        // Add user to Dolibarr groups that correspond to the Authserver groups, but he is not yet member of
        foreach ($groups as $group) {
            if (isset($currentMemberGroups[$group]))
                continue;
            // Check if a group with this name exists
            // Braindead: The UserGroup::fetch() function does not give any indication whether
            // the group actually exists or not. It will keep using the previous values when the group does
            // not exist, which will result in constraint violations (when trying to add the same group twice), or
            // SQL errors (when the first group does not exists, and $userGroup->id is null)
            // That's why the name of the usergroup is checked once again against the name we expect it to be.
            if ($userGroup->fetch('', $group) > 0 && $userGroup->name === $group) {
                if ($user->SetInGroup($userGroup->id, $userGroup->entity) < 0) {
                    dol_syslog('functions_oauth::check_user_password_oauth: Cannot add member to new authorized group. Continuing without.', LOG_ERR);
                }
            } else {
                dol_syslog('functions_oauth::check_user_password_oauth: Group ' . $group . ' does not exist.', LOG_WARNING);
            }
        }
        if (!$db->commit())
            goto rollback;
    }

    header('Location: ' . $_SERVER['PHP_SELF']);

    return $user->login;
rollback:
    $_SESSION['dol_loginmesg'] = 'OAuth login failed. Contact the sysadmin';
    dol_syslog('functions_oauth::check_user_password_oauth: Database error: ' . $db->error(), LOG_EMERG);
    $db->rollback();
fail:
    $api->deleteAccessToken($context);
    $api->deleteRefreshToken($context);
    header('Location: ' . $_SERVER['PHP_SELF']);
    return false;
}

