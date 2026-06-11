# OpenAI ChatGPT SSO Setup Notes

This document records the production setup used for the `gptsso` OIDC identity provider.

## Production URLs

- IdP issuer: `https://auth.oai-gpt.com`
- Discovery endpoint: `https://auth.oai-gpt.com/.well-known/openid-configuration`
- Authorization endpoint: `https://auth.oai-gpt.com/authorize`
- Token endpoint: `https://auth.oai-gpt.com/token`
- JWKS endpoint: `https://auth.oai-gpt.com/.well-known/jwks.json`
- Userinfo endpoint: `https://auth.oai-gpt.com/userinfo`

## Server Deployment

The app is deployed on the Ubuntu server as:

```text
/opt/gptsso
```

It runs as a systemd service:

```bash
sudo systemctl status gptsso
sudo systemctl restart gptsso
sudo journalctl -u gptsso -f
```

Caddy reverse proxies HTTPS traffic:

```text
auth.oai-gpt.com -> 127.0.0.1:3001
```

The production `.env` is stored at:

```text
/opt/gptsso/.env
```

The generated client/admin secrets are also backed up at:

```text
/home/ubuntu/gptsso-secrets.txt
```

Do not commit either file.

## DNS

Create an A record:

```text
auth.oai-gpt.com -> 43.155.164.244
```

For ChatGPT domain verification, add the TXT record shown by the OpenAI Admin Console to the root domain:

```text
Name: @
Type: TXT
Value: openai-domain-verification=...
```

## OpenAI Admin Console Setup

Open:

```text
https://chatgpt.com/admin/identity
```

Then open the global admin console:

```text
Identity & access -> Admin Console
```

### 1. Verify domain

In the global admin console:

```text
Identity & access -> Access -> Domains
```

Add and verify:

```text
oai-gpt.com
```

### 2. Configure SSO

In the global admin console:

```text
Identity & access -> Access -> Single Sign-On (SSO)
```

Create a Custom OIDC connection.

Use:

```text
Identity provider name: GPTSSO OIDC
Client ID: chatgpt
Client Secret: value of OIDC_CLIENT_SECRET from /home/ubuntu/gptsso-secrets.txt
Discovery Endpoint: https://auth.oai-gpt.com/.well-known/openid-configuration
Scopes: openid email profile
```

When OpenAI shows the login redirect URI, copy it into:

```text
ALLOWED_REDIRECT_URIS=...
```

Then restart:

```bash
sudo systemctl restart gptsso
```

Current configured redirect URI:

```text
https://external.auth.openai.com/sso/oidc/Qu9HjereRyZ8pn8WY5mGclg5J/callback
```

### 3. Required claims

OpenAI maps these attributes:

```text
email -> email
firstName -> given_name
idpId -> sub
lastName -> family_name
```

The IdP returns all required claims in the ID token.

### 4. Test and activate

Use OpenAI's `Test sign-in` button from the connection page. A successful test should show a session like:

```text
email: testuser@oai-gpt.com
status: Test successful
```

After testing, activate the connection.

### 5. Enable ChatGPT SSO

In:

```text
Identity & access -> Access -> Single Sign-On (SSO)
```

Set:

```text
ChatGPT SSO settings: Required
```

`Optional` allows SSO, but users entering `user@oai-gpt.com` on the regular ChatGPT login page may not be forced to the IdP.

### 6. Account provisioning

To allow new SSO users to join without manual invites, open:

```text
https://chatgpt.com/admin/identity
```

Then enable:

```text
User Provisioning -> Automatic Account Creation
```

If this is off, users signed in by the IdP may see:

```text
Your Identity Provider signed you in as user@oai-gpt.com, but that email has not been added to your ChatGPT workspace.
```

In that case, either enable automatic account creation or manually invite the email under Members.

## User Login Flow

With ChatGPT SSO set to Required:

```text
1. User opens https://chatgpt.com
2. User enters username@oai-gpt.com
3. ChatGPT redirects to https://auth.oai-gpt.com/login
4. User enters username and invite code
5. IdP returns username@oai-gpt.com to OpenAI
6. ChatGPT completes login
```

Users should enter only the username on the IdP page, not the full email.

Example:

```text
ChatGPT email: zhangsan@oai-gpt.com
IdP username: zhangsan
IdP invite code: OAI-...
```

## Invite Code Types

### Standard invite

Created without `reusable=true` and without an assigned username.

Behavior:

```text
First username to use the code binds the code.
Only the same username can use it later.
Other usernames are rejected.
```

### Assigned username invite

Created with a `username` field.

Behavior:

```text
Only the assigned username can use this invite.
```

### Reusable invite

Created with:

```text
reusable=true
max_uses=10   # optional
```

Behavior:

```text
Different usernames can use the same invite code.
The code does not bind to one user.
If max_uses is set, each new username consumes one use.
The same username signing in again does not consume another use.
```

Current reusable invite:

```text
OAI-REUSE-2026
```

## Admin API

The web admin dashboard is:

```text
https://auth.oai-gpt.com/coco
```

Use the `ADMIN_TOKEN` stored in `/home/ubuntu/gptsso-secrets.txt` to sign in. The dashboard supports creating standard, assigned-user, and reusable invite codes with optional usage limits, exporting CSV, and enabling IP-based registration/login rate limiting.

List invites and users:

```bash
ADMIN_TOKEN=$(grep '^ADMIN_TOKEN=' /opt/gptsso/.env | cut -d= -f2-)
curl http://127.0.0.1:3001/coco/invites \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

Create a standard invite:

```bash
curl -X POST http://127.0.0.1:3001/coco/invites \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  --data-urlencode "code=OAI-XXXX-YYYY"
```

Create an assigned invite:

```bash
curl -X POST http://127.0.0.1:3001/coco/invites \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  --data-urlencode "code=OAI-XXXX-YYYY" \
  --data-urlencode "username=zhangsan"
```

Create a reusable invite:

```bash
curl -X POST http://127.0.0.1:3001/coco/invites \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  --data-urlencode "code=OAI-REUSE-2026" \
  --data-urlencode "reusable=true"
```

Create a reusable invite that can be used by up to 10 different usernames:

```bash
curl -X POST http://127.0.0.1:3001/coco/invites \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  --data-urlencode "code=OAI-REUSE-10" \
  --data-urlencode "reusable=true" \
  --data-urlencode "max_uses=10"
```

## Security Hardening

The service currently applies these protections:

```text
HTTPS through Caddy
Strict security headers and CSP
No-store caching on login/admin pages
Signed HttpOnly admin session cookie
CSRF checks for the IdP login form
CSRF checks for browser admin POST actions
Admin login failure lockout by IP
32 KB request body limit
Production startup checks for strong secrets and redirect URI allowlist
Optional IP-based rate limiting for /login submissions
```

Keep these files private and never commit them:

```text
/opt/gptsso/.env
/home/ubuntu/gptsso-secrets.txt
/opt/gptsso/data/oidc-private-key.pem
```

Recommended operational settings:

```text
Use a long random ADMIN_TOKEN
Keep ChatGPT SSO settings set to Required when enforcing SSO
Enable Automatic Account Creation only if new SSO users should join automatically
Turn on registration rate limiting before distributing reusable invite codes
Use firewall or WAF rules if the service receives public abuse traffic
```

## Troubleshooting

Check service health:

```bash
sudo systemctl status gptsso
curl -fsS https://auth.oai-gpt.com/.well-known/openid-configuration
```

Follow logs:

```bash
sudo journalctl -u gptsso -f
```

Expected normal login flow:

```text
GET /.well-known/openid-configuration -> 200
GET /authorize -> 302
GET /login -> 200
POST /login -> 302
POST /token -> 200
```

If only discovery is requested, OpenAI has not started the authorization flow yet. Re-check SSO activation, ChatGPT SSO setting, and the login path.

If login reaches the IdP but OpenAI says the email is not in the workspace, enable Automatic Account Creation or invite that email manually.
