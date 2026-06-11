import crypto from "node:crypto";
import http from "node:http";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = join(fileURLToPath(new URL(".", import.meta.url)), "..");
await loadEnvFile(join(rootDir, ".env"));

const port = Number(process.env.PORT || 3000);
const issuer = process.env.ISSUER || `http://localhost:${port}`;
const verifiedDomain = process.env.VERIFIED_DOMAIN || "example.com";
const clientId = process.env.OIDC_CLIENT_ID || "chatgpt";
const clientSecret = process.env.OIDC_CLIENT_SECRET || "dev-secret-change-me";
const allowedRedirectUris = parseCsv(process.env.ALLOWED_REDIRECT_URIS || "");
const adminToken = process.env.ADMIN_TOKEN || "dev-admin-token-change-me";
const dataDir = process.env.DATA_DIR || join(rootDir, "data");
const dataFile = join(dataDir, "store.json");
const keyFile = join(dataDir, "oidc-private-key.pem");
const privateKey = await loadOrCreatePrivateKey();
const publicKey = crypto.createPublicKey(privateKey);
const publicJwk = publicKey.export({ format: "jwk" });
const keyId = crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("base64url").slice(0, 24);
publicJwk.kid = keyId;
publicJwk.use = "sig";
publicJwk.alg = "RS256";

const store = await loadStore();
const users = new Map(store.users.map((user) => [user.id, user]));
const inviteCodes = new Map(store.invites.map((invite) => [invite.code, invite]));
const authRequests = new Map();
const authorizationCodes = new Map();

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, issuer);

    if (req.method === "GET" && url.pathname === "/") {
      redirect(res, "/login");
      return;
    }

    if (req.method === "GET" && url.pathname === "/styles.css") {
      await serveStatic(res, "public/styles.css");
      return;
    }

    if (req.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
      sendJson(res, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        scopes_supported: ["openid", "email", "profile"],
        token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
        claims_supported: ["sub", "email", "email_verified", "name", "preferred_username"]
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/.well-known/jwks.json") {
      sendJson(res, { keys: [publicJwk] });
      return;
    }

    if (req.method === "GET" && url.pathname === "/authorize") {
      handleAuthorize(req, res, url);
      return;
    }

    if (req.method === "GET" && url.pathname === "/login") {
      const requestId = parseCookies(req).auth_request;
      const hasRequest = requestId && authRequests.has(requestId);
      sendHtml(res, renderLoginPage({ error: null, username: "", hasRequest }));
      return;
    }

    if (req.method === "POST" && url.pathname === "/login") {
      await handleLogin(req, res);
      return;
    }

    if (req.method === "POST" && url.pathname === "/token") {
      await handleToken(req, res);
      return;
    }

    if (req.method === "GET" && url.pathname === "/admin/invites") {
      if (!requireAdmin(req, res)) return;
      sendJson(res, {
        invites: [...inviteCodes.entries()].map(([code, invite]) => ({ code, ...invite })),
        users: [...users.values()]
      });
      return;
    }

    if (req.method === "POST" && url.pathname === "/admin/invites") {
      if (!requireAdmin(req, res)) return;
      await handleCreateInvite(req, res);
      return;
    }

    sendText(res, 404, "Not found");
  } catch (error) {
    console.error(error);
    sendText(res, 500, "Internal server error");
  }
});

server.listen(port, () => {
  console.log(`OIDC IdP running at ${issuer}`);
  console.log(`Client ID: ${clientId}`);
  console.log(`Discovery URL: ${issuer}/.well-known/openid-configuration`);
  console.log("Client secret and admin token loaded from environment");
});

function handleAuthorize(req, res, url) {
  const query = Object.fromEntries(url.searchParams.entries());
  const validation = validateAuthorizeRequest(query);
  if (validation.error) {
    sendText(res, 400, validation.error);
    return;
  }

  const requestId = crypto.randomUUID();
  authRequests.set(requestId, {
    clientId: query.client_id,
    redirectUri: query.redirect_uri,
    scope: query.scope || "openid email profile",
    state: query.state,
    nonce: query.nonce
  });

  setCookie(res, "auth_request", requestId, {
    httpOnly: true,
    sameSite: "Lax",
    secure: issuer.startsWith("https://"),
    maxAge: 10 * 60
  });
  redirect(res, "/login");
}

async function handleLogin(req, res) {
  const requestId = parseCookies(req).auth_request;
  const authRequest = authRequests.get(requestId);
  const body = await readFormBody(req);
  const username = normalizeUsername(body.username);
  const inviteCode = normalizeInviteCode(body.invite_code);

  if (!authRequest) {
    sendHtml(
      res,
      renderLoginPage({
        error: "登录请求已过期，请从 ChatGPT 重新发起 SSO。",
        username,
        hasRequest: false
      }),
      400
    );
    return;
  }

  const result = await bindUserToInvite(username, inviteCode);
  if (result.error) {
    sendHtml(res, renderLoginPage({ error: result.error, username, hasRequest: true }), 400);
    return;
  }

  const code = crypto.randomBytes(32).toString("base64url");
  authorizationCodes.set(code, {
    userId: result.user.id,
    clientId: authRequest.clientId,
    redirectUri: authRequest.redirectUri,
    nonce: authRequest.nonce,
    scope: authRequest.scope,
    expiresAt: Date.now() + 5 * 60 * 1000
  });
  authRequests.delete(requestId);
  clearCookie(res, "auth_request");

  const redirectUrl = new URL(authRequest.redirectUri);
  redirectUrl.searchParams.set("code", code);
  if (authRequest.state) {
    redirectUrl.searchParams.set("state", authRequest.state);
  }
  redirect(res, redirectUrl.toString());
}

async function handleToken(req, res) {
  const body = await readFormBody(req);
  const auth = parseClientAuth(req, body);
  if (auth.clientId !== clientId || auth.clientSecret !== clientSecret) {
    sendJson(res, { error: "invalid_client" }, 401);
    return;
  }

  if (body.grant_type !== "authorization_code") {
    sendJson(res, { error: "unsupported_grant_type" }, 400);
    return;
  }

  const codeRecord = authorizationCodes.get(body.code);
  if (!codeRecord || codeRecord.expiresAt < Date.now()) {
    sendJson(res, { error: "invalid_grant" }, 400);
    return;
  }

  if (codeRecord.clientId !== auth.clientId || codeRecord.redirectUri !== body.redirect_uri) {
    sendJson(res, { error: "invalid_grant" }, 400);
    return;
  }

  authorizationCodes.delete(body.code);
  const user = users.get(codeRecord.userId);
  const now = Math.floor(Date.now() / 1000);
  const idToken = signJwt(
    {
      iss: issuer,
      aud: auth.clientId,
      sub: user.oidcSub,
      iat: now,
      exp: now + 3600,
      email: user.email,
      email_verified: true,
      name: user.username,
      preferred_username: user.username,
      nonce: codeRecord.nonce
    },
    { alg: "RS256", kid: keyId }
  );

  sendJson(res, {
    access_token: crypto.randomBytes(32).toString("base64url"),
    token_type: "Bearer",
    expires_in: 3600,
    id_token: idToken
  });
}

async function handleCreateInvite(req, res) {
  const body = await readFormBody(req);
  const code = normalizeInviteCode(body.code || generateInviteCode());
  const expiresAt = body.expires_at ? new Date(body.expires_at).toISOString() : null;

  if (!/^[A-Z0-9-]{6,64}$/.test(code)) {
    sendJson(res, { error: "code must be 6-64 chars: A-Z, 0-9, or hyphen" }, 400);
    return;
  }
  if (inviteCodes.has(code)) {
    sendJson(res, { error: "invite already exists" }, 409);
    return;
  }
  if (expiresAt && Number.isNaN(Date.parse(expiresAt))) {
    sendJson(res, { error: "expires_at must be a valid date" }, 400);
    return;
  }

  const invite = {
    code,
    status: "available",
    boundUserId: null,
    expiresAt,
    usedAt: null,
    createdAt: new Date().toISOString()
  };
  inviteCodes.set(code, invite);
  await saveStore();
  sendJson(res, invite, 201);
}

function validateAuthorizeRequest(query) {
  if (query.response_type !== "code") {
    return { error: "response_type must be code" };
  }
  if (query.client_id !== clientId) {
    return { error: "unknown client_id" };
  }
  if (!query.redirect_uri) {
    return { error: "redirect_uri is required" };
  }
  if (allowedRedirectUris.length > 0 && !allowedRedirectUris.includes(query.redirect_uri)) {
    return { error: "redirect_uri is not allowed" };
  }
  if (!String(query.scope || "").split(" ").includes("openid")) {
    return { error: "scope must include openid" };
  }
  return {};
}

async function bindUserToInvite(username, inviteCode) {
  if (!/^[a-zA-Z0-9._-]{3,40}$/.test(username)) {
    return { error: "用户名只能包含字母、数字、点、下划线和短横线，长度 3-40 位。" };
  }

  const invite = inviteCodes.get(inviteCode);
  if (!invite) {
    return { error: "邀请码不存在。" };
  }
  if (invite.expiresAt && invite.expiresAt < Date.now()) {
    return { error: "邀请码已过期。" };
  }

  const userId = stableUserId(username);
  const existingUser = users.get(userId);

  if (invite.boundUserId && invite.boundUserId !== userId) {
    return { error: "这个邀请码已经绑定了其他用户。" };
  }
  if (existingUser && invite.boundUserId === userId) {
    return { user: existingUser };
  }
  if (existingUser && invite.boundUserId !== userId) {
    return { error: "这个用户名已经绑定过其他邀请码。" };
  }

  const user = {
    id: userId,
    username,
    email: `${username}@${verifiedDomain}`.toLowerCase(),
    oidcSub: userId,
    createdAt: new Date().toISOString()
  };
  users.set(userId, user);
  invite.status = "bound";
  invite.boundUserId = userId;
  invite.usedAt = new Date().toISOString();
  await saveStore();
  return { user };
}

function stableUserId(username) {
  return `user_${crypto.createHash("sha256").update(username.toLowerCase()).digest("hex").slice(0, 24)}`;
}

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeInviteCode(value) {
  return String(value || "").trim().toUpperCase();
}

function parseClientAuth(req, body) {
  const authHeader = req.headers.authorization || "";
  if (authHeader.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    return {
      clientId: decoded.slice(0, separator),
      clientSecret: decoded.slice(separator + 1)
    };
  }

  return {
    clientId: body.client_id,
    clientSecret: body.client_secret
  };
}

function requireAdmin(req, res) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!constantTimeEqual(token, adminToken)) {
    sendJson(res, { error: "unauthorized" }, 401);
    return false;
  }
  return true;
}

function constantTimeEqual(actual, expected) {
  const actualBuffer = Buffer.from(actual);
  const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length) return false;
  return crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

function signJwt(payload, header) {
  const encodedHeader = base64urlJson(header);
  const encodedPayload = base64urlJson(payload);
  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(data), privateKey).toString("base64url");
  return `${data}.${signature}`;
}

function base64urlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

async function readFormBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  const rawBody = Buffer.concat(chunks).toString("utf8");
  const contentType = req.headers["content-type"] || "";
  if (contentType.includes("application/json")) {
    return JSON.parse(rawBody || "{}");
  }
  return Object.fromEntries(new URLSearchParams(rawBody).entries());
}

async function loadStore() {
  await mkdir(dataDir, { recursive: true });
  if (!existsSync(dataFile)) {
    const initialStore = {
      users: [],
      invites: [
        makeInvite("ALPHA-2026"),
        makeInvite("BETA-2026")
      ]
    };
    await writeJsonAtomic(dataFile, initialStore);
    return initialStore;
  }

  const parsed = JSON.parse(await readFile(dataFile, "utf8"));
  return {
    users: Array.isArray(parsed.users) ? parsed.users : [],
    invites: Array.isArray(parsed.invites) ? parsed.invites : []
  };
}

async function loadEnvFile(filePath) {
  if (!existsSync(filePath)) return;
  const content = await readFile(filePath, "utf8");
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const separator = trimmed.indexOf("=");
    if (separator === -1) continue;
    const key = trimmed.slice(0, separator).trim();
    const rawValue = trimmed.slice(separator + 1).trim();
    if (!key || process.env[key] !== undefined) continue;
    process.env[key] = rawValue.replace(/^["']|["']$/g, "");
  }
}

async function saveStore() {
  await writeJsonAtomic(dataFile, {
    users: [...users.values()],
    invites: [...inviteCodes.values()]
  });
}

async function writeJsonAtomic(filePath, value) {
  const tempFile = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tempFile, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  await rename(tempFile, filePath);
}

async function loadOrCreatePrivateKey() {
  await mkdir(dataDir, { recursive: true });
  if (existsSync(keyFile)) {
    return crypto.createPrivateKey(await readFile(keyFile, "utf8"));
  }

  const { privateKey: generatedKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = generatedKey.export({ type: "pkcs8", format: "pem" });
  await writeFile(keyFile, pem, { encoding: "utf8", mode: 0o600 });
  return generatedKey;
}

function makeInvite(code) {
  return {
    code,
    status: "available",
    boundUserId: null,
    expiresAt: null,
    usedAt: null,
    createdAt: new Date().toISOString()
  };
}

function generateInviteCode() {
  return `INV-${crypto.randomBytes(6).toString("base64url").toUpperCase()}`;
}

function parseCsv(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  return Object.fromEntries(
    header
      .split(";")
      .map((cookie) => cookie.trim())
      .filter(Boolean)
      .map((cookie) => {
        const separator = cookie.indexOf("=");
        return [cookie.slice(0, separator), decodeURIComponent(cookie.slice(separator + 1))];
      })
  );
}

function setCookie(res, name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.secure) parts.push("Secure");
  if (options.maxAge) parts.push(`Max-Age=${options.maxAge}`);
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, name) {
  res.setHeader("Set-Cookie", `${name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax`);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function sendJson(res, body, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body, null, 2));
}

function sendHtml(res, body, status = 200) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(body);
}

function sendText(res, status, body) {
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8" });
  res.end(body);
}

async function serveStatic(res, relativePath) {
  const filePath = join(rootDir, relativePath);
  const content = await readFile(filePath);
  const type = extname(filePath) === ".css" ? "text/css; charset=utf-8" : "text/plain; charset=utf-8";
  res.writeHead(200, { "Content-Type": type });
  res.end(content);
}

function renderLoginPage({ error, username, hasRequest }) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>企业 SSO 登录</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body>
  <main class="shell">
    <section class="brand-panel" aria-label="企业访问">
      <div class="brand-mark">SSO</div>
      <h1>企业账号登录</h1>
      <p>使用分配给你的用户名和邀请码完成身份绑定。</p>
    </section>

    <section class="login-panel" aria-label="登录表单">
      <div class="panel-heading">
        <p class="eyebrow">Identity Provider</p>
        <h2>登录到 ChatGPT</h2>
      </div>

      ${error ? `<div class="alert" role="alert">${escapeHtml(error)}</div>` : ""}
      ${!hasRequest ? `<div class="alert muted" role="status">请从 ChatGPT SSO 登录流程进入此页面。</div>` : ""}

      <form method="post" action="/login" autocomplete="off">
        <label for="username">用户名</label>
        <input id="username" name="username" value="${escapeHtml(username)}" placeholder="zhangsan" required minlength="3" maxlength="40" pattern="[A-Za-z0-9._-]{3,40}" />

        <label for="invite_code">邀请码</label>
        <input id="invite_code" name="invite_code" placeholder="ALPHA-2026" required />

        <button type="submit" ${hasRequest ? "" : "disabled"}>继续登录</button>
      </form>
    </section>
  </main>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
