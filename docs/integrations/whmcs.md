# WHMCS and other billing systems

BPANEL ships no billing system of its own. It integrates with WHMCS (and
anything that can call a REST API and receive webhooks — Blesta, HostBill,
FOSSBilling, custom code) through two free mechanisms:

1. **Provisioning** — the billing system calls the BPANEL admin API with an
   API token (`Authorization: Bearer …`, admin port 2087).
2. **Lifecycle events** — BPANEL publishes account events that a webhook
   subscription delivers, signed, to the billing side.

`GET /api/v1/admin/billing` (Billing (WHMCS) page in the admin panel) lists
both, so a module can self-check (`TestConnection`).

## Provisioning endpoints

| WHMCS function | Method | Endpoint |
| --- | --- | --- |
| CreateAccount | POST | `/api/v1/admin/accounts` (`username, domain, password, email, package_id, lang`) |
| SuspendAccount | POST | `/api/v1/admin/accounts/{id}/suspend` (`reason`) |
| UnsuspendAccount | POST | `/api/v1/admin/accounts/{id}/unsuspend` |
| TerminateAccount | DELETE | `/api/v1/admin/accounts/{id}` — **needs a re-authenticated session** (see below) |
| ChangePackage | PUT | `/api/v1/admin/accounts/{id}/package` (`package_id`) |
| ChangePassword | POST | `/api/v1/admin/accounts/{id}/password` (`password`) |
| ServiceSingleSignOn | POST | `/api/v1/admin/accounts/{id}/login` → one-time login URL (60 s) |
| Usage / lookup | GET | `/api/v1/admin/accounts?q=<username>` |

Create the token for a dedicated staff user. A `server_admin` (or a reseller,
for its own customers) holds `accounts.create`, `accounts.write`,
`accounts.password` and `accounts.login_as`.

**Termination** is a step-up action (`requireRecentAuth`): API tokens cannot
terminate accounts. This is deliberate — a leaked billing token must not be
able to delete every site. The example module suspends the account and tells
staff to finish the termination in BPANEL.

## Lifecycle events (webhooks)

Events: `account.created`, `account.suspended`, `account.unsuspended`,
`account.terminated`, `account.package_changed`, `account.password_changed`,
`account.ip_changed`. Each carries `account_id` and `data.username`.

Create a webhook (admin → Webhooks) with the event filter `account.*`.
Deliveries are retried with backoff and signed:

```
X-BPanel-Event: account.suspended
X-BPanel-Timestamp: 1767225600
X-BPanel-Signature: sha256=HEX(HMAC-SHA256(secret, timestamp + "." + body))
```

## Example code (Apache-2.0)

- `examples/whmcs/modules/servers/bpanel/bpanel.php` — a WHMCS server module
  (CreateAccount, Suspend/Unsuspend, Terminate (suspend + notice),
  ChangePackage, ChangePassword, single sign-on, TestConnection).
- `examples/whmcs/webhook-receiver/bpanel_webhook.php` — verifies the webhook
  signature and dispatches events.

These are **examples**: they are syntax-checked (`php -l`) in the release E2E
run but were not run against a licensed WHMCS installation (WHMCS is
proprietary and not part of the test environment). Review before production.
