<?php
/**
 * Example receiver for BPANEL webhooks (account lifecycle events) — e.g. to
 * mirror suspensions done in the panel back into WHMCS or another system.
 *
 * Configure a webhook in BPANEL (Webhooks) with the events "account.*" and
 * put its signing secret in BPANEL_WEBHOOK_SECRET. The signature is
 * X-BPanel-Signature: sha256=HEX(HMAC-SHA256(secret, timestamp + "." + body)).
 * Licence: Apache-2.0. EXAMPLE code — adapt the handle() function.
 */

$secret = getenv('BPANEL_WEBHOOK_SECRET') ?: '';
$body = file_get_contents('php://input');
$ts = isset($_SERVER['HTTP_X_BPANEL_TIMESTAMP']) ? $_SERVER['HTTP_X_BPANEL_TIMESTAMP'] : '';
$sig = isset($_SERVER['HTTP_X_BPANEL_SIGNATURE']) ? $_SERVER['HTTP_X_BPANEL_SIGNATURE'] : '';

if ($secret === '' || $ts === '' || abs(time() - (int) $ts) > 300) {
    http_response_code(400);
    exit('stale or unsigned');
}
$want = 'sha256=' . hash_hmac('sha256', $ts . '.' . $body, $secret);
if (!hash_equals($want, $sig)) {
    http_response_code(401);
    exit('bad signature');
}

$event = json_decode($body, true);
if (!is_array($event) || empty($event['type'])) {
    http_response_code(400);
    exit('bad payload');
}

function handle(array $event)
{
    $data = isset($event['data']) ? $event['data'] : [];
    $user = isset($data['username']) ? $data['username'] : '';
    switch ($event['type']) {
        case 'account.suspended':
        case 'account.unsuspended':
        case 'account.terminated':
        case 'account.created':
        case 'account.package_changed':
        case 'account.password_changed':
        case 'account.ip_changed':
            // Example: append to a log; replace with a WHMCS localAPI call
            // (e.g. UpdateClientProduct) in a real integration.
            error_log('bpanel ' . $event['type'] . ' ' . $user);
            break;
        default:
            break;
    }
}

handle($event);
http_response_code(204);
