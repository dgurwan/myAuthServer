/* authServer.js — Frontend/Auth Server for Authenticated Web Messaging Demo
 *
 * Runs on: http://localhost:3000
 *
 * Responsibilities:
 * - Serves the HTML page (public/index.html)
 * - Starts OIDC Authorization Code flow (+ PKCE) via /auth/start
 * - Handles IdP callback via /auth/callback
 * - Stores authCode (+ PKCE codeVerifier, nonce, redirectUri) in session
 * - Exposes /auth/code for Genesys Messenger AuthProvider plugin
 *
 * Works with the demo IdP (oidc-provider) running at IDP_ISSUER uri
 */

const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------------------------
// CONFIG
// ---------------------------
const PORT = parseInt(process.env.PORT || "3000", 10);

// IdP (OIDC) endpoints
const IDP_ISSUER = process.env.IDP_ISSUER || "https://myidp.onrender.com";
const IDP_AUTHORIZATION_ENDPOINT =
  process.env.IDP_AUTHORIZATION_ENDPOINT || `${IDP_ISSUER}/auth`;

// OIDC client config (must match the IdP registered client)
const CLIENT_ID = process.env.OIDC_CLIENT_ID || "demo-client";
const REDIRECT_URI =
  process.env.OIDC_REDIRECT_URI || `http://localhost:${PORT}/auth/callback`;
// PKCE recommended; demo supports on/off
const USE_PKCE = (process.env.OIDC_USE_PKCE || "true").toLowerCase() === "true";

// Scopes requested (openid required; others optional)
const OIDC_SCOPE =
  process.env.OIDC_SCOPE || "openid profile email offline_access";

// Security
const SESSION_SECRET =
  process.env.SESSION_SECRET || "dev-session-secret-change-me";

// Optional: expire stored auth code quickly (seconds)
const AUTH_CODE_TTL_SECONDS = parseInt(
  process.env.AUTH_CODE_TTL_SECONDS || "120",
  10,
);

// ---------------------------
// SESSION
// ---------------------------
app.use(
  session({
    name: "sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false, // important
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false, // true if HTTPS
      path: "/", // ensure consistent cookie path
    },
  }),
);

// ---------------------------
// STATIC
// ---------------------------
app.use(express.static(path.join(__dirname, "public")));

// ---------------------------
// HELPERS
// ---------------------------

function serverLog(req, msg) {
  const ts = new Date().toISOString();
  req.session.serverLogs = req.session.serverLogs || [];
  req.session.serverLogs.push(`[${ts}] ${msg}`);

  // keep last 300 lines
  if (req.session.serverLogs.length > 300) {
    req.session.serverLogs = req.session.serverLogs.slice(-300);
  }
}

function getServerLogs(req) {
  return Array.isArray(req.session.serverLogs) ? req.session.serverLogs : [];
}

function base64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function sha256(input) {
  return crypto.createHash("sha256").update(input).digest();
}

function randomString(bytes = 32) {
  return base64url(crypto.randomBytes(bytes));
}

function nowMs() {
  return Date.now();
}

function isExpired(createdAtMs) {
  if (!createdAtMs) return true;
  return nowMs() - createdAtMs > AUTH_CODE_TTL_SECONDS * 1000;
}

// Ensure session object structure
function ensureOidc(req) {
  req.session.oidc = req.session.oidc || {};
  return req.session.oidc;
}

// ---------------------------
// ROUTES
// ---------------------------

// Health
app.get("/health", (req, res) => {
  serverLog(req, ` -> /health`);
  res.json({ ok: true });
});

/**
 * GET /auth/start
 * Starts OIDC Authorization Code flow.
 * Generates state/nonce and optional PKCE verifier+challenge; stores in session.
 * Redirects to IdP /auth.
 */
app.get("/auth/start", (req, res) => {
  serverLog(req, ` -> /auth/start `);
  const oidc = ensureOidc(req);

  oidc.state = randomString(24);
  oidc.nonce = crypto.randomUUID();

  if (USE_PKCE) {
    oidc.codeVerifier = randomString(32);
    oidc.codeChallenge = base64url(sha256(oidc.codeVerifier));
  } else {
    delete oidc.codeVerifier;
    delete oidc.codeChallenge;
  }

  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: OIDC_SCOPE,
    state: oidc.state,
    nonce: oidc.nonce,
  });

  if (USE_PKCE) {
    params.set("code_challenge", oidc.codeChallenge);
    params.set("code_challenge_method", "S256");
  }

  // SERVER-SIDE LOG (survives redirect)
  serverLog(req, `Auth start -> redirecting to IdP authorize endpoint`);
  serverLog(
    req,
    `authorize params: client_id=${CLIENT_ID} redirect_uri=${REDIRECT_URI} scope="${OIDC_SCOPE}" pkce=${USE_PKCE}`,
  );
  serverLog(req, `state=${oidc.state} nonce=${oidc.nonce}`);

  // IMPORTANT: save session before redirect to avoid losing the log lines
  req.session.save(() => {
    res.redirect(`${IDP_AUTHORIZATION_ENDPOINT}?${params.toString()}`);
  });
});

/**
 * GET /auth/callback
 * Receives OIDC redirect from IdP with ?code=...&state=...
 * Validates state; stores authCode in session for AuthProvider.getAuthCode.
 */
app.get("/auth/callback", (req, res) => {
  const { code, state, error, error_description } = req.query;
  const oidc = ensureOidc(req);

  if (error) {
    serverLog(
      req,
      `Callback error: ${String(error)} ${error_description ? `- ${String(error_description)}` : ""}`,
    );
    return res.status(400).send(`OIDC error: ${String(error)}`);
  }

  serverLog(
    req,
    `Callback received: state=${String(state || "")} code=${code ? "[present]" : "[missing]"}`,
  );

  if (!code) return res.status(400).send('Missing "code" in callback');
  if (!oidc.state)
    return res.status(400).send("No auth session. Start at /auth/start");

  if (String(state) !== String(oidc.state)) {
    serverLog(
      req,
      `State mismatch: expected=${oidc.state} got=${String(state)}`,
    );
    return res.status(400).send("State mismatch");
  }

  oidc.authCode = String(code);
  oidc.redirectUri = REDIRECT_URI;
  oidc.authCodeCreatedAt = Date.now();
  req.session.signedIn = true;

  serverLog(
    req,
    `Auth code stored in session (one-time use). Redirecting to /`,
  );

  req.session.save(() => res.redirect("/"));
});

/**
 * GET /auth/server-logs
 * retrieve logs
 */
app.get("/auth/server-logs", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ lines: getServerLogs(req) });
});

/**
 * Clear server logs
 */
app.post("/auth/server-logs/clear", (req, res) => {
  req.session.serverLogs = [];
  res.json({ ok: true });
});

/**
 * GET /auth/code
 * Called by your AuthProvider JS (running in the browser) to provide the
 * authorization code (+ redirectUri + optional codeVerifier/nonce) to Genesys Messenger.
 */
app.get("/auth/code", noStore, (req, res) => {
  const oidc = ensureOidc(req);
  serverLog(req, `/auth/code called`);

  if (!req.session.signedIn || !oidc.authCode) {
    serverLog(req, `401 Auth code not in session`);
    return res.status(401).json({ authenticated: false });
  }

  if (isExpired(oidc.authCodeCreatedAt)) {
    // Expired => force re-login
    delete oidc.authCode;
    delete oidc.authCodeCreatedAt;
    req.session.signedIn = false;
    serverLog(req, `401 Auth code expired !`);
    return res
      .status(401)
      .json({ authenticated: false, reason: "auth_code_expired" });
  }

  // Shape returned to AuthProvider.getAuthCode
  const payload = {
    authenticated: true,
    authCode: oidc.authCode,
    redirectUri: oidc.redirectUri,
    nonce: oidc.nonce,
  };

  if (USE_PKCE && oidc.codeVerifier) payload.codeVerifier = oidc.codeVerifier;

  serverLog(req, `payload : `, json(payload));

  res.json(payload);
});

/**
 * POST /auth/consume
 * Optional: mark the auth code as consumed. Authorization codes are one-time use.
 * Call this after AuthProvider hands it to Messenger.
 */
app.post("/auth/consume", (req, res) => {
  const oidc = ensureOidc(req);
  delete oidc.authCode;
  delete oidc.authCodeCreatedAt;
  res.json({ ok: true });
});

/**
 * GET /auth/status
 * Used by the UI to display "signed in" vs "signed out".
 * Always returns JSON (prevents client-side undefined errors on refresh).
 */
app.get("/auth/status", (req, res) => {
  res.json({ signedIn: Boolean(req.session && req.session.signedIn) });
});

/**
 * POST /auth/logout
 * Clears session.
 */
app.post("/auth/logout", (req, res) => {
  // remove server-side state first
  if (req.session) {
    req.session.signedIn = false;
    req.session.oidc = null;
  }

  // clear cookie on the response (must match session cookie options)
  res.clearCookie("sid", { path: "/", sameSite: "lax", secure: false });

  // destroy session in store
  req.session?.destroy((err) => {
    if (err) {
      return res
        .status(500)
        .json({ ok: false, error: "SESSION_DESTROY_FAILED" });
    }
    res.json({ ok: true });
  });
});

function noStore(_req, res, next) {
  res.set("Cache-Control", "no-store");
  next();
}

app.get("/auth/status", noStore, (req, res) => {
  res.json({ signedIn: Boolean(req.session?.signedIn) });
});

// ---------------------------
// START SERVER
// ---------------------------
app.listen(PORT, () => {
  console.log(`AuthServer running: http://localhost:${PORT}`);
  console.log(`Using IdP authorize endpoint: ${IDP_AUTHORIZATION_ENDPOINT}`);
  console.log(`ClientId: ${CLIENT_ID}`);
  console.log(`RedirectUri: ${REDIRECT_URI}`);
  console.log(`PKCE enabled: ${USE_PKCE}`);
});
