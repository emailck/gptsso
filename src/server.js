import crypto from "node:crypto";
import http from "node:http";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = join(fileURLToPath(new URL(".", import.meta.url)), "..");
await loadEnvFile(join(rootDir, ".env"));

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "127.0.0.1";
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
const accessTokens = new Map();

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, issuer);
    logRequest(req, url);
    logResponse(req, res, url);

    if (req.method === "GET" && url.pathname === "/") {
      redirect(res, "/login");
      return;
    }

    if (req.method === "GET" && url.pathname === "/styles.css") {
      await serveStatic(res, "public/styles.css");
      return;
    }

    if (req.method === "GET" && url.pathname === "/admin.css") {
      await serveStatic(res, "public/admin.css");
      return;
    }

    if (req.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
      sendJson(res, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        response_types_supported: ["code"],
        response_modes_supported: ["query"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256", "plain"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        scopes_supported: ["openid", "email", "profile"],
        token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
        claims_supported: ["sub", "email", "email_verified", "given_name", "family_name", "name", "preferred_username"]
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

    if (req.method === "GET" && url.pathname === "/userinfo") {
      handleUserinfo(req, res);
      return;
    }

    if (req.method === "GET" && url.pathname === "/admin") {
      handleAdminPage(req, res, url);
      return;
    }

    if (req.method === "GET" && url.pathname === "/admin/export.csv") {
      handleAdminExport(req, res, url);
      return;
    }

    if (req.method === "POST" && url.pathname === "/admin/login") {
      await handleAdminLogin(req, res);
      return;
    }

    if (req.method === "POST" && url.pathname === "/admin/logout") {
      clearCookie(res, "admin_session");
      redirect(res, "/admin");
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

server.listen(port, host, () => {
  console.log(`OIDC IdP running at ${issuer} on ${host}:${port}`);
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
    nonce: query.nonce,
    codeChallenge: query.code_challenge,
    codeChallengeMethod: query.code_challenge_method || "plain"
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
    codeChallenge: authRequest.codeChallenge,
    codeChallengeMethod: authRequest.codeChallengeMethod,
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
  if (!verifyPkce(codeRecord, body.code_verifier)) {
    sendJson(res, { error: "invalid_grant", error_description: "PKCE verification failed" }, 400);
    return;
  }

  authorizationCodes.delete(body.code);
  const user = users.get(codeRecord.userId);
  const accessToken = crypto.randomBytes(32).toString("base64url");
  accessTokens.set(accessToken, {
    userId: user.id,
    expiresAt: Date.now() + 3600 * 1000
  });
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
      given_name: user.givenName || user.username,
      family_name: user.familyName || "User",
      preferred_username: user.username,
      nonce: codeRecord.nonce
    },
    { alg: "RS256", kid: keyId }
  );

  sendJson(res, {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    id_token: idToken
  });
}

function handleUserinfo(req, res) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  const record = accessTokens.get(token);
  if (!record || record.expiresAt < Date.now()) {
    sendJson(res, { error: "invalid_token" }, 401);
    return;
  }

  const user = users.get(record.userId);
  sendJson(res, userClaims(user));
}

async function handleCreateInvite(req, res) {
  const body = await readFormBody(req);
  const code = normalizeInviteCode(body.code || generateInviteCode());
  const assignedUsername = body.username ? normalizeUsername(body.username) : null;
  const reusable = parseBoolean(body.reusable);
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
  if (assignedUsername && !isValidUsername(assignedUsername)) {
    sendJson(res, { error: "username must be 3-40 chars: letters, numbers, dot, underscore, or hyphen" }, 400);
    return;
  }

  const invite = {
    code,
    status: "available",
    reusable,
    assignedUsername,
    boundUserId: null,
    usedCount: 0,
    expiresAt,
    usedAt: null,
    createdAt: new Date().toISOString()
  };
  inviteCodes.set(code, invite);
  await saveStore();
  if (isBrowserForm(req)) {
    redirect(res, "/admin");
    return;
  }
  sendJson(res, invite, 201);
}

async function handleAdminLogin(req, res) {
  const body = await readFormBody(req);
  if (!constantTimeEqual(String(body.admin_token || ""), adminToken)) {
    sendHtml(res, renderAdminLoginPage("Admin token 不正确。"), 401);
    return;
  }

  setCookie(res, "admin_session", signAdminSession(), {
    httpOnly: true,
    sameSite: "Lax",
    secure: issuer.startsWith("https://"),
    maxAge: 8 * 3600,
    path: "/"
  });
  redirect(res, "/admin");
}

function handleAdminPage(req, res, url) {
  if (!isAdminSessionValid(req)) {
    sendHtml(res, renderAdminLoginPage(null));
    return;
  }

  const query = normalizeAdminSearch(url.searchParams.get("q"));
  sendHtml(res, renderAdminDashboard({ query }));
}

function handleAdminExport(req, res, url) {
  if (!isAdminSessionValid(req)) {
    redirect(res, "/admin");
    return;
  }

  const query = normalizeAdminSearch(url.searchParams.get("q"));
  const csv = toCsv(adminRows(query));
  res.writeHead(200, {
    "Content-Type": "text/csv; charset=utf-8",
    "Content-Disposition": "attachment; filename=\"gptsso-invites.csv\""
  });
  res.end(csv);
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
  if (query.code_challenge_method && !["S256", "plain"].includes(query.code_challenge_method)) {
    return { error: "unsupported code_challenge_method" };
  }
  return {};
}

function verifyPkce(codeRecord, codeVerifier) {
  if (!codeRecord.codeChallenge) return true;
  if (!codeVerifier) return false;
  if (codeRecord.codeChallengeMethod === "S256") {
    const digest = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    return constantTimeEqual(digest, codeRecord.codeChallenge);
  }
  return constantTimeEqual(codeVerifier, codeRecord.codeChallenge);
}

async function bindUserToInvite(username, inviteCode) {
  if (!isValidUsername(username)) {
    return { error: "用户名只能包含字母、数字、点、下划线和短横线，长度 3-40 位。" };
  }

  const invite = inviteCodes.get(inviteCode);
  if (!invite) {
    return { error: "邀请码不存在。" };
  }
  if (invite.expiresAt && invite.expiresAt < Date.now()) {
    return { error: "邀请码已过期。" };
  }
  if (invite.assignedUsername && invite.assignedUsername !== username) {
    return { error: "这个邀请码不属于该用户名。" };
  }

  const userId = stableUserId(username);
  const existingUser = users.get(userId);

  if (!invite.reusable && invite.boundUserId && invite.boundUserId !== userId) {
    return { error: "这个邀请码已经绑定了其他用户。" };
  }
  if (existingUser && (invite.reusable || invite.boundUserId === userId)) {
    return { user: existingUser };
  }
  if (existingUser && !invite.reusable && invite.boundUserId !== userId) {
    return { error: "这个用户名已经绑定过其他邀请码。" };
  }

  const user = {
    id: userId,
    username,
    email: `${username}@${verifiedDomain}`.toLowerCase(),
    oidcSub: userId,
    givenName: username,
    familyName: "User",
    createdAt: new Date().toISOString()
  };
  users.set(userId, user);
  invite.usedCount = Number(invite.usedCount || 0) + 1;
  if (!invite.reusable) {
    invite.status = "bound";
    invite.boundUserId = userId;
  }
  invite.usedAt = new Date().toISOString();
  await saveStore();
  return { user };
}

function userClaims(user) {
  return {
    sub: user.oidcSub,
    email: user.email,
    email_verified: true,
    given_name: user.givenName || user.username,
    family_name: user.familyName || "User",
    name: user.username,
    preferred_username: user.username
  };
}

function stableUserId(username) {
  return `user_${crypto.createHash("sha256").update(username.toLowerCase()).digest("hex").slice(0, 24)}`;
}

function isValidUsername(username) {
  return /^[a-zA-Z0-9._-]{3,40}$/.test(username);
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

function isBrowserForm(req) {
  const accept = req.headers.accept || "";
  return accept.includes("text/html");
}

function requireAdmin(req, res) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!constantTimeEqual(token, adminToken) && !isAdminSessionValid(req)) {
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

function parseBoolean(value) {
  return ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());
}

function signAdminSession() {
  const payload = Buffer.from(JSON.stringify({
    exp: Math.floor(Date.now() / 1000) + 8 * 3600,
    nonce: crypto.randomBytes(12).toString("base64url")
  })).toString("base64url");
  const signature = crypto.createHmac("sha256", adminToken).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

function isAdminSessionValid(req) {
  const session = parseCookies(req).admin_session || "";
  const [payload, signature] = session.split(".");
  if (!payload || !signature) return false;
  const expected = crypto.createHmac("sha256", adminToken).update(payload).digest("base64url");
  if (!constantTimeEqual(signature, expected)) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return Number(data.exp || 0) > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

function normalizeAdminSearch(value) {
  return String(value || "").trim().toLowerCase();
}

function adminRows(query) {
  return [...inviteCodes.values()]
    .map((invite) => {
      const user = invite.boundUserId ? users.get(invite.boundUserId) : null;
      return {
        code: invite.code,
        status: invite.status || "available",
        reusable: Boolean(invite.reusable),
        assignedUsername: invite.assignedUsername || "",
        usedCount: Number(invite.usedCount || 0),
        boundUsername: user?.username || "",
        email: user?.email || "",
        usedAt: invite.usedAt || "",
        createdAt: invite.createdAt || ""
      };
    })
    .filter((row) => {
      if (!query) return true;
      return Object.values(row).some((value) => String(value).toLowerCase().includes(query));
    })
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

function logRequest(req, url) {
  const safeParams = new URLSearchParams(url.searchParams);
  if (safeParams.has("client_secret")) safeParams.set("client_secret", "[redacted]");
  if (safeParams.has("code")) safeParams.set("code", "[redacted]");
  const query = safeParams.toString();
  console.log(`${new Date().toISOString()} ${req.method} ${url.pathname}${query ? `?${query}` : ""}`);
}

function logResponse(req, res, url) {
  res.on("finish", () => {
    console.log(`${new Date().toISOString()} ${req.method} ${url.pathname} -> ${res.statusCode}`);
  });
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
  if (options.path) parts.push(`Path=${options.path}`);
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

function renderAdminLoginPage(error) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GPTSSO 管理后台</title>
  <link rel="stylesheet" href="/admin.css" />
</head>
<body class="admin-body">
  <main class="admin-login">
    <section class="admin-login-panel">
      <p class="admin-eyebrow">GPTSSO</p>
      <h1>管理后台</h1>
      <p class="admin-muted">输入服务器上的 Admin Token 继续。</p>
      ${error ? `<div class="admin-alert">${escapeHtml(error)}</div>` : ""}
      <form method="post" action="/admin/login">
        <label for="admin_token">Admin Token</label>
        <input id="admin_token" name="admin_token" type="password" autocomplete="current-password" required />
        <button type="submit">登录</button>
      </form>
    </section>
  </main>
</body>
</html>`;
}

function renderAdminDashboard({ query }) {
  const rows = adminRows(query);
  const allRows = adminRows("");
  const boundCount = allRows.filter((row) => row.boundUsername).length;
  const reusableCount = allRows.filter((row) => row.reusable).length;

  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GPTSSO 管理后台</title>
  <link rel="stylesheet" href="/admin.css" />
</head>
<body class="admin-body">
  <header class="admin-topbar">
    <div>
      <p class="admin-eyebrow">GPTSSO</p>
      <h1>邀请码管理</h1>
    </div>
    <form method="post" action="/admin/logout">
      <button class="secondary" type="submit">退出</button>
    </form>
  </header>

  <main class="admin-main">
    <section class="metrics" aria-label="统计">
      <div><span>${allRows.length}</span><p>邀请码</p></div>
      <div><span>${boundCount}</span><p>已绑定用户</p></div>
      <div><span>${reusableCount}</span><p>可重复邀请码</p></div>
      <div><span>${users.size}</span><p>用户</p></div>
    </section>

    <section class="admin-grid">
      <form class="admin-card" method="post" action="/admin/invites">
        <h2>创建邀请码</h2>
        <label for="code">邀请码</label>
        <input id="code" name="code" placeholder="留空自动生成" />

        <label for="username">指定用户名</label>
        <input id="username" name="username" placeholder="可选，例如 zhangsan" />

        <label for="expires_at">过期时间</label>
        <input id="expires_at" name="expires_at" placeholder="可选，例如 2026-12-31T00:00:00Z" />

        <label class="check-row">
          <input type="checkbox" name="reusable" value="true" />
          <span>可重复使用</span>
        </label>

        <button type="submit">创建</button>
      </form>

      <section class="admin-card">
        <h2>使用说明</h2>
        <p>普通邀请码第一次使用后会绑定用户名。指定用户名的邀请码只能给该用户名使用。可重复邀请码允许多个不同用户名使用。</p>
        <p>用户在 IdP 登录页只填用户名，不填完整邮箱；系统会自动生成 <code>用户名@${escapeHtml(verifiedDomain)}</code>。</p>
      </section>
    </section>

    <section class="admin-card table-card">
      <div class="table-actions">
        <form method="get" action="/admin">
          <input name="q" value="${escapeHtml(query)}" placeholder="搜索邀请码、用户名、邮箱" />
          <button class="secondary" type="submit">搜索</button>
        </form>
        <a class="download" href="/admin/export.csv${query ? `?q=${encodeURIComponent(query)}` : ""}">导出 CSV</a>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>邀请码</th>
              <th>类型</th>
              <th>状态</th>
              <th>指定用户名</th>
              <th>绑定用户名</th>
              <th>邮箱</th>
              <th>使用次数</th>
              <th>创建时间</th>
            </tr>
          </thead>
          <tbody>
            ${rows.map(renderAdminRow).join("") || `<tr><td colspan="8" class="empty">没有匹配结果</td></tr>`}
          </tbody>
        </table>
      </div>
    </section>
  </main>
</body>
</html>`;
}

function renderAdminRow(row) {
  const type = row.reusable ? "可重复" : row.assignedUsername ? "指定用户" : "普通";
  return `<tr>
    <td><code>${escapeHtml(row.code)}</code></td>
    <td>${escapeHtml(type)}</td>
    <td><span class="status ${row.boundUsername ? "bound" : "available"}">${row.boundUsername ? "已绑定" : "可用"}</span></td>
    <td>${escapeHtml(row.assignedUsername || "-")}</td>
    <td>${escapeHtml(row.boundUsername || "-")}</td>
    <td>${escapeHtml(row.email || "-")}</td>
    <td>${escapeHtml(String(row.usedCount))}</td>
    <td>${escapeHtml(row.createdAt || "-")}</td>
  </tr>`;
}

function toCsv(rows) {
  const header = ["code", "type", "status", "assignedUsername", "boundUsername", "email", "usedCount", "createdAt", "usedAt"];
  const lines = rows.map((row) => [
    row.code,
    row.reusable ? "reusable" : row.assignedUsername ? "assigned" : "standard",
    row.status,
    row.assignedUsername,
    row.boundUsername,
    row.email,
    row.usedCount,
    row.createdAt,
    row.usedAt
  ].map(csvCell).join(","));
  return [header.join(","), ...lines].join("\n");
}

function csvCell(value) {
  const text = String(value ?? "");
  return `"${text.replaceAll('"', '""')}"`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
