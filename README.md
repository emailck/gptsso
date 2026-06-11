# GPT SSO OIDC IdP

This is a minimal OpenID Connect identity provider for a ChatGPT Business Custom OIDC setup. Users sign in with a fixed username plus an invite code. On first successful login, the invite code is bound to that username and the IdP returns a stable OIDC identity.

It includes:

- OIDC discovery, authorize, token, and JWKS endpoints
- RS256 `id_token` signing
- Persistent users, invite codes, and signing key in `data/`
- Username plus invite-code binding
- Admin API for creating and listing invite codes
- Web admin dashboard with signed session cookies and CSRF protection
- Optional IP-based login/register rate limiting
- Optional redirect URI allowlist

## Run

```bash
npm run dev
```

The service starts on `http://localhost:3000`.

Default development values:

- Client ID: `chatgpt`
- Client secret: `dev-secret-change-me`
- Discovery URL: `http://localhost:3000/.well-known/openid-configuration`
- Invite codes: `ALPHA-2026`, `BETA-2026`
- Email domain: `example.com`
- Admin token: `dev-admin-token-change-me`

## Environment

Copy `.env.example` to `.env`, then change the values:

```bash
copy .env.example .env
notepad .env
npm run dev
```

`VERIFIED_DOMAIN` must match a domain verified in the ChatGPT admin identity settings.

Use HTTPS in production. `ISSUER` must be the exact public origin users and ChatGPT can reach. The service writes persistent state to `data/store.json` and the OIDC signing key to `data/oidc-private-key.pem`.

## ChatGPT Custom OIDC fields

Use these values when configuring Custom OIDC:

- Issuer / discovery URL: `https://auth.your-domain.com/.well-known/openid-configuration`
- Client ID: value of `OIDC_CLIENT_ID`
- Client secret: value of `OIDC_CLIENT_SECRET`
- Scopes: `openid email profile`

Copy the redirect URI provided by ChatGPT into `ALLOWED_REDIRECT_URIS` before going live. Use the exact URL shown in the OpenAI setup wizard.

The full production OpenAI setup process is documented in [docs/openai-sso-setup.md](docs/openai-sso-setup.md).

## Admin API

Web admin dashboard:

```text
https://auth.your-domain.com/coco
```

Use `ADMIN_TOKEN` to sign in. The dashboard can list/search invites, create standard invites, create assigned-username invites, create reusable invites with an optional usage limit, delete invites, and export CSV.

List invite codes and users:

```powershell
Invoke-RestMethod `
  -Uri "http://localhost:3000/coco/invites" `
  -Headers @{ Authorization = "Bearer dev-admin-token-change-me" }
```

Create an invite code:

```powershell
Invoke-RestMethod `
  -Uri "http://localhost:3000/coco/invites" `
  -Method Post `
  -Headers @{ Authorization = "Bearer dev-admin-token-change-me" } `
  -Body @{ code = "TEAM-001" }
```

Create a generated invite code:

```powershell
Invoke-RestMethod `
  -Uri "http://localhost:3000/coco/invites" `
  -Method Post `
  -Headers @{ Authorization = "Bearer dev-admin-token-change-me" }
```

Generated codes use a random four-part format such as `K7QD-9MWH-P3TX-AB52`.

Create a reusable invite code that can be used by up to 10 different usernames:

```powershell
Invoke-RestMethod `
  -Uri "http://localhost:3000/coco/invites" `
  -Method Post `
  -Headers @{ Authorization = "Bearer dev-admin-token-change-me" } `
  -Body @{ code = "TEAM-REUSE"; reusable = "true"; max_uses = "10" }
```

Delete an invite code:

```powershell
Invoke-RestMethod `
  -Uri "http://localhost:3000/coco/delete-invite" `
  -Method Post `
  -Headers @{ Authorization = "Bearer dev-admin-token-change-me" } `
  -Body @{ code = "TEAM-REUSE" }
```

## Login behavior

Rules:

- New username plus available invite code: create user and bind invite.
- Existing username plus that user's bound invite code: allow login.
- Invite already bound to another user: reject.
- Username already bound through another invite: reject.
- Reusable invite with `max_uses`: each new username consumes one use; the same username signing in again does not consume another use.

The OIDC `sub` and email are stable. For username `zhangsan` and `VERIFIED_DOMAIN=your-domain.com`, the token contains:

```json
{
  "email": "zhangsan@your-domain.com",
  "email_verified": true,
  "preferred_username": "zhangsan"
}
```

## Production notes

- Change `OIDC_CLIENT_SECRET` and `ADMIN_TOKEN`.
- Put the app behind HTTPS.
- Keep `ALLOWED_REDIRECT_URIS` configured. In production the app refuses to start without it.
- Keep `ADMIN_TOKEN` long and random. The admin dashboard has login lockout, CSRF protection, no-store caching, and strict security headers, but the token is still the main admin secret.
- Enable the registration rate limit from `/coco` before sharing reusable invite codes publicly.
- Back up `data/`, especially `oidc-private-key.pem`. If the key changes, ChatGPT must refetch JWKS and existing sessions may fail validation.
- Replace the JSON store with a database before high-volume use or multi-instance deployment.
- For stronger edge protection, add provider-level firewall/WAF rules in front of the server.
