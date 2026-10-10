<?php
/**
 * BOZKURT PANEL (BPANEL) — example WHMCS provisioning module.
 *
 * Copy this directory to <whmcs>/modules/servers/bpanel/ and add a server of
 * type "BPANEL" in WHMCS: Hostname = the panel hostname, Port = 2087 (admin
 * realm), Access Hash = an API token created in BPANEL (Security -> API tokens)
 * for a staff user that holds accounts.create/write/password/login_as.
 * Product module settings: "Package ID" (BPANEL package id).
 *
 * Licence: Apache-2.0, like BPANEL. This is an EXAMPLE adapter: review it
 * before production use. See docs/integrations/whmcs.md.
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

function bpanel_MetaData()
{
    return [
        'DisplayName' => 'BPANEL',
        'APIVersion' => '1.1',
        'RequiresServer' => true,
        'DefaultSSLPort' => '2087',
        'ServiceSingleSignOnLabel' => 'Log in to BPANEL',
    ];
}

function bpanel_ConfigOptions()
{
    return [
        'Package ID' => ['Type' => 'text', 'Size' => '6', 'Description' => 'BPANEL package id (Packages page)'],
        'Language' => ['Type' => 'dropdown', 'Options' => 'en,tr', 'Default' => 'en'],
    ];
}

/** Calls the BPANEL admin API; returns [httpCode, decodedBody]. */
function bpanel_api(array $params, $method, $path, $body = null)
{
    $host = $params['serverhostname'] ?: $params['serverip'];
    $port = $params['serverport'] ?: 2087;
    $url = 'https://' . $host . ':' . $port . '/api/v1' . $path;
    $ch = curl_init($url);
    $headers = [
        'Authorization: Bearer ' . trim($params['serveraccesshash']),
        'Accept: application/json',
    ];
    if ($body !== null) {
        $headers[] = 'Content-Type: application/json';
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
    }
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 120,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $raw = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    logModuleCall('bpanel', $method . ' ' . $path, $body, $raw, null, [trim($params['serveraccesshash']), $params['password'] ?? '']);
    if ($raw === false) {
        return [0, ['error' => 'connection_failed', 'message' => $err]];
    }
    return [$code, json_decode($raw, true) ?: []];
}

function bpanel_result(array $r)
{
    list($code, $data) = $r;
    if ($code >= 200 && $code < 300) {
        return 'success';
    }
    $msg = isset($data['error']) ? $data['error'] : ('HTTP ' . $code);
    if (!empty($data['message'])) {
        $msg .= ': ' . $data['message'];
    }
    return $msg;
}

/** Finds the BPANEL account id of the WHMCS service by username. */
function bpanel_account_id(array $params)
{
    list($code, $data) = bpanel_api($params, 'GET', '/admin/accounts?q=' . rawurlencode($params['username']));
    if ($code !== 200 || !is_array($data)) {
        return null;
    }
    foreach ($data as $acct) {
        if (isset($acct['username']) && $acct['username'] === $params['username']) {
            return (int) $acct['id'];
        }
    }
    return null;
}

function bpanel_CreateAccount(array $params)
{
    $body = [
        'username' => $params['username'],
        'domain' => $params['domain'],
        'password' => $params['password'],
        'email' => $params['clientsdetails']['email'],
        'package_id' => (int) $params['configoption1'],
        'lang' => $params['configoption2'] ?: 'en',
    ];
    return bpanel_result(bpanel_api($params, 'POST', '/admin/accounts', $body));
}

function bpanel_SuspendAccount(array $params)
{
    $id = bpanel_account_id($params);
    if (!$id) {
        return 'account_not_found';
    }
    $reason = $params['suspendreason'] ?: 'Suspended by billing';
    return bpanel_result(bpanel_api($params, 'POST', '/admin/accounts/' . $id . '/suspend', ['reason' => $reason]));
}

function bpanel_UnsuspendAccount(array $params)
{
    $id = bpanel_account_id($params);
    return $id ? bpanel_result(bpanel_api($params, 'POST', '/admin/accounts/' . $id . '/unsuspend', [])) : 'account_not_found';
}

/**
 * Termination is a step-up (re-authenticated) action in BPANEL: an API token
 * cannot terminate. The module suspends the account and asks staff to finish
 * the termination in the panel (docs/integrations/whmcs.md).
 */
function bpanel_TerminateAccount(array $params)
{
    $id = bpanel_account_id($params);
    if (!$id) {
        return 'account_not_found';
    }
    $r = bpanel_api($params, 'POST', '/admin/accounts/' . $id . '/suspend', ['reason' => 'Terminated in billing - remove in BPANEL']);
    if (bpanel_result($r) !== 'success' && $r[0] !== 409) {
        return bpanel_result($r);
    }
    return 'Suspended. BPANEL requires a re-authenticated staff session to terminate: finish it in BPANEL > List Accounts.';
}

function bpanel_ChangePackage(array $params)
{
    $id = bpanel_account_id($params);
    return $id ? bpanel_result(bpanel_api($params, 'PUT', '/admin/accounts/' . $id . '/package', ['package_id' => (int) $params['configoption1']])) : 'account_not_found';
}

function bpanel_ChangePassword(array $params)
{
    $id = bpanel_account_id($params);
    return $id ? bpanel_result(bpanel_api($params, 'POST', '/admin/accounts/' . $id . '/password', ['password' => $params['password']])) : 'account_not_found';
}

function bpanel_ServiceSingleSignOn(array $params)
{
    $id = bpanel_account_id($params);
    if (!$id) {
        return ['success' => false, 'errorMsg' => 'account_not_found'];
    }
    list($code, $data) = bpanel_api($params, 'POST', '/admin/accounts/' . $id . '/login', []);
    if ($code === 200 && !empty($data['url'])) {
        return ['success' => true, 'redirectTo' => $data['url']];
    }
    return ['success' => false, 'errorMsg' => isset($data['error']) ? $data['error'] : 'HTTP ' . $code];
}

function bpanel_TestConnection(array $params)
{
    list($code, $data) = bpanel_api($params, 'GET', '/admin/billing');
    if ($code === 200) {
        return ['success' => true, 'error' => ''];
    }
    return ['success' => false, 'error' => isset($data['error']) ? $data['error'] : 'HTTP ' . $code];
}
