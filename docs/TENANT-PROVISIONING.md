# Tenant Provisioning

Creating a tenancy is the highest-privilege operation this server exposes: a tenancy is the
unit that everything else attaches to, so an attacker who can mint one has established a
foothold that looks legitimate to every downstream application. It is therefore the one
operation that **cannot be performed by software**.

## The rule

> No application identity can provision a tenancy under any circumstances. A tenancy is
> created only when a named human submits the request from an interactive session **and** a
> quorum of operators, holding key material distributed to them physically, have each signed
> that exact request offline.

Two independent controls enforce this, and both must pass:

| Control | Answers | Defeated only by |
|---|---|---|
| **Human-principal check** | "Did a person initiate this, or did a program?" | Stealing an admin's interactive session |
| **M-of-N signature quorum** | "Did the required operators approve *this specific* request?" | Stealing M private keys from M different humans |

Neither is sufficient alone, which is the point. A stolen admin token gets you nothing without
the keys. A stolen key gets you nothing without a human session and a second key holder.

---

## What is protected

Every mutating tenant operation:

| Endpoint | Gated |
|---|---|
| `POST /api/admin/tenants` | ✅ |
| `PUT /api/admin/tenants/{id}` | ✅ |
| `DELETE /api/admin/tenants/{id}` | ✅ |
| `POST /api/admin/tenants/{id}/activate` | ✅ |
| `POST /api/admin/tenants/{id}/deactivate` | ✅ |
| `GET /api/admin/tenants` | ❌ — reading the registry does not confer control |

Delete is gated alongside create deliberately. An attacker who can delete a tenancy and
recreate it under their own control has taken the registry just as effectively as one who can
create at will, so gating creation alone would be a half-measure.

---

## Why the public keys are not in the database

`TenantProvisioning:Keys` is bound from configuration — appsettings, environment, user-secrets,
or your secret store — and never from the database.

A registry whose trust anchor is stored inside the registry is not protected. If the enrolled
public keys lived in a table, anyone who reached the database (SQL injection, a leaked
connection string, a restored backup, a careless migration) would simply insert their own
public key and then sign anything they liked, and every signature check would pass and every
audit entry would look correct. Putting the anchor in configuration means bypassing the control
requires compromising the deployment pipeline itself.

The same reasoning is why this is not a "disable" flag. There is no setting that turns the
check off. If fewer usable keys are configured than `RequiredSignatures`, provisioning is
**denied** — an unconfigured server refuses to provision rather than falling back to
"an admin token is good enough."

---

## Setting it up

### 1. Each operator generates their own keypair

Run this **on the holder's own machine**, ideally offline. The private key must never be
copied to the server, committed, emailed, or pasted into chat.

```bash
./tools/provision-keygen.sh ops-alice "Alice Nguyen"
```

This writes `ops-alice.key` (private, mode 400 — hers alone) and `ops-alice.pub`, and prints
the config entry to hand back. Only the public half ever leaves her machine.

Hand the private key to its holder the way the threat model demands: on removable media,
in person, or generated on a hardware token that never exports it. If two "independent"
signers received their keys over the same Slack thread, you have one key, not two.

### 2. Enrol the public keys on the server

```jsonc
"TenantProvisioning": {
  "RequiredSignatures": 2,
  "MaxClockSkewSeconds": 300,
  "Keys": [
    {
      "KeyId": "ops-alice",
      "Holder": "Alice Nguyen",
      "PublicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...\n-----END PUBLIC KEY-----"
    },
    {
      "KeyId": "ops-bob",
      "Holder": "Bob Chen",
      "PublicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...\n-----END PUBLIC KEY-----"
    }
  ]
}
```

PEM or bare base64 SPKI are both accepted. Keys may carry `NotBefore` / `NotAfter` for planned
rotation, and `Disabled: true` to revoke a holder immediately.

**Enrol at least one more key than `RequiredSignatures`.** With exactly two keys and a
threshold of two, one operator on leave or one lost laptop means nobody can provision anything.
Three keys at a threshold of two is the smallest configuration that is both safe and operable.

`Holder` is recorded in the audit log. Make it a person's name, never a team or a role — the
entire value of this control is that it names individuals who can be asked what they approved.

---

## Making a provisioning request

### What gets signed

```
PIXSMITH-TENANT-PROVISION-v1
POST
/api/admin/tenants
<nonce>
<unix-timestamp>
<sha256-hex of the exact request body bytes>
```

Every field that determines the effect of the request is covered. Change the tenant name, the
HTTP verb, or the target id, and the signatures stop verifying. A signature therefore authorizes
**one specific action**, not "whatever the bearer wants" — it cannot be captured and redirected.

### The flow

**Alice** starts. She writes the exact body bytes that will be sent and signs them:

```bash
printf '%s' '{"name":"Acme Corp","description":"Acme tenancy"}' > body.json
./tools/provision-sign.sh ops-alice ops-alice.key POST /api/admin/tenants body.json
```

It prints a nonce, a timestamp, and her signature header.

**Bob** signs the same body with Alice's nonce and timestamp — he should read the body first,
because that is the entire point of him being a second signer:

```bash
./tools/provision-sign.sh ops-bob ops-bob.key POST /api/admin/tenants body.json <nonce> <timestamp>
```

**An administrator** submits both signatures from their interactive session:

```bash
curl -X POST https://localhost:7100/api/admin/tenants \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Provision-Nonce: $NONCE" \
  -H "X-Provision-Timestamp: $TIMESTAMP" \
  -H "X-Provision-Signature: ops-alice:$SIG_ALICE" \
  -H "X-Provision-Signature: ops-bob:$SIG_BOB" \
  --data-binary @body.json
```

Use `--data-binary`, not `-d`. The body is hashed byte-for-byte; `-d` strips newlines and will
silently produce a body that does not match what was signed.

The whole exchange must complete inside `MaxClockSkewSeconds` (default 300). This is a
coordination window, not a security boundary — the single-use nonce is what actually stops
replay — but it does mean the operators need to be signing at roughly the same time, which is
itself a useful property.

---

## What each defence stops

| Attack | Result | Why |
|---|---|---|
| Machine token with `admin` scope creates a tenancy | **403** | Client-credentials tokens carry no `role` claim and their subject is a client ID, not a user |
| Compromised admin token, no signatures | **403** | Quorum unsatisfied |
| One operator acts alone | **403** | 1 of 2 signatures |
| Same key presented twice | **403** | Quorum counts *distinct* key IDs |
| Unenrolled key signs | **403** | Key ID not in the configuration anchor |
| Attacker claims a real key ID with their own private key | **403** | Signature verifies against the enrolled public key |
| Valid request captured and replayed | **403** | Nonce is single-use, enforced by a unique index |
| Valid signatures redirected at a different body or verb | **403** | Body hash, method, and path are inside the signed payload |
| Attacker sends garbage to burn a coordinated nonce | Nonce survives | Nonces are consumed only after signatures verify |
| Admin's role revoked, token still valid | **403** | Role is re-checked against the store, not read from the token |

Every one of these is covered by a test in
`tests/PixSmith.Authorization.UnitTests/Services/ProvisioningAuthorizerTests.cs`, and all were
additionally exercised against a live server over HTTP.

---

## Audit

Every attempt, authorized or denied, writes an `AuditLogs` row:

```
tenant.provision.authorized | POST /api/admin/tenants — Signed by: ops-alice, ops-bob
tenant.provision.denied     | POST /api/admin/tenants — This provisioning nonce has already been used.
```

Because signatures are over the request content, the audit trail is more than a log entry: given
the body and the enrolled public keys, you can prove after the fact which individuals approved a
specific tenancy. Retain the request bodies alongside the log if you need that property to hold
in a dispute.

---

## Consequences you should know about

**The admin UI can no longer change tenants.** The Blazor Tenants page can still list them, but
create / edit / delete / activate now return 403 and the page explains why. Producing signatures
in a browser would require the private keys to reach the browser, which would defeat the control.
If you want a smoother workflow, the right shape is a UI that *prepares* the canonical payload
and displays the nonce and timestamp for operators to sign offline — never one that signs.

**Rotation is a config change plus a restart.** Set `NotAfter` on the outgoing key, add the new
one, deploy. Keep the retired key enrolled but `Disabled` rather than deleting the entry, so old
audit records still resolve to a named holder.

**This does not protect the OIDC client registry.** `POST /api/admin/oidc-apps` is still governed
only by the `AdminAccess` policy, which a machine token holding `admin` scope satisfies. If
registering a client is comparable in blast radius to creating a tenancy in your threat model —
and it may well be, since a client is how an application gets tokens — the same
`[RequireProvisioningSignature]` attribute can be applied to those endpoints. That is a
deliberate decision left to you, not an oversight.

**Consider disabling the password grant for administrators.** The human check verifies the
principal is a real user with a live `Admin` role, but a token obtained through the password
grant also satisfies it — and that grant is exactly the one an application can perform with
stored credentials. Removing `GrantTypes.Password` from any client an admin uses would make
"interactive session" mean strictly what it says.
