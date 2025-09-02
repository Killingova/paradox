// server.js
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { Issuer, generators } from "openid-client";
import Redis from "ioredis";

/**
 * ENV laden + Defaults
 */
const {
  OIDC_ISSUER,
  OIDC_CLIENT_ID,
  OIDC_CLIENT_SECRET,
  OIDC_REDIRECT_URI,
  OIDC_POST_LOGOUT_REDIRECT_URI,
  COOKIE_NAME = "paradox_sid",
  COOKIE_SECURE = "false",     // DEV: false, PROD: true
  COOKIE_SAMESITE = "Lax",     // DEV: Lax, PROD: Strict (oder None + Secure)
  REDIS_URL = "redis://redis:6379",
  SESSION_TTL_SECONDS = "604800", // 7 Tage
  PORT = "3000",
} = process.env;

const bool = (v) => String(v).toLowerCase() === "true";
const makeId = (n = 32) => crypto.randomBytes(n).toString("base64url");

// Soft-Validierung ENV
function assertEnv(name, val) {
  if (!val) {
    console.error(`[ENV] ${name} fehlt.`);
    process.exit(1);
  }
}
assertEnv("OIDC_ISSUER", OIDC_ISSUER);
assertEnv("OIDC_CLIENT_ID", OIDC_CLIENT_ID);
assertEnv("OIDC_REDIRECT_URI", OIDC_REDIRECT_URI);
assertEnv("OIDC_POST_LOGOUT_REDIRECT_URI", OIDC_POST_LOGOUT_REDIRECT_URI);

/**
 * Redis
 */
const redis = new Redis(REDIS_URL, { lazyConnect: true });
await redis.connect().catch((e) => {
  console.error("Redis-Verbindung fehlgeschlagen:", e);
  process.exit(1);
});

/**
 * OIDC Client via Discovery (robust)
 */
let client;
let issuer;
try {
  issuer = await Issuer.discover(`${OIDC_ISSUER}`);
  client = new issuer.Client({
    client_id: OIDC_CLIENT_ID,
    client_secret: OIDC_CLIENT_SECRET, // bei public client leer lassen / nicht setzen
    redirect_uris: [OIDC_REDIRECT_URI],
    response_types: ["code"],
  });
} catch (e) {
  console.error("OIDC Discovery/Client-Init fehlgeschlagen:", e);
  process.exit(1);
}

/**
 * Express
 */
const app = express();
app.set("trust proxy", 1); // wichtig, wenn TLS vor Express endet (NGINX)
app.use(express.json());
app.use(cookieParser());

/**
 * Hilfs-Middlewares
 */
function safeJsonParse(raw) {
  try { return raw ? JSON.parse(raw) : null; } catch { return null; }
}

async function loadSession(req, _res, next) {
  try {
    const sid = req.cookies[COOKIE_NAME];
    if (!sid) return next();
    const raw = await redis.get(`sess:${sid}`);
    const session = safeJsonParse(raw);
    if (session) {
      req.session = session;
      req.sid = sid;
    }
    return next();
  } catch (e) {
    return next(e);
  }
}

// sehr simpler Redis-Rate-Limiter pro IP+Pfad
function rateLimit({ keyPrefix, limit = 10, windowSec = 60 }) {
  return async (req, res, next) => {
    try {
      const key = `rl:${keyPrefix}:${req.ip}`;
      const cur = await redis.incr(key);
      if (cur === 1) await redis.expire(key, windowSec);
      if (cur > limit) return res.status(429).json({ ok: false, error: "rate_limited" });
      return next();
    } catch (e) {
      // Fällt auf "kein Limit" zurück, wenn Redis down – optional 503
      return next();
    }
  };
}

// minimaler CSRF-Check (Double-Submit Cookie + Header)
function requireCsrf(req, res, next) {
  const cookie = req.cookies["paradox_csrf"];
  const header = req.get("x-csrf-token");
  if (!cookie || !header || cookie !== header) {
    return res.status(403).json({ ok: false, error: "csrf" });
  }
  return next();
}

/**
 * Health
 */
app.get("/bff/health", (_req, res) => res.type("text").send("bff: ok\n"));

/**
 * Login: PKCE + state → Redis, Redirect zu Keycloak
 */
app.get("/bff/login", rateLimit({ keyPrefix: "login", limit: 12, windowSec: 60 }), async (_req, res, next) => {
  try {
    const state = makeId(16);
    const code_verifier = generators.codeVerifier();
    const code_challenge = generators.codeChallenge(code_verifier);

    await redis.setex(`oidc:${state}`, 300, JSON.stringify({ code_verifier }));

    const authUrl = client.authorizationUrl({
      scope: "openid profile email offline_access",
      state,
      code_challenge,
      code_challenge_method: "S256",
    });

    return res.redirect(authUrl);
  } catch (e) {
    return next(e);
  }
});

/**
 * Callback: Code tauschen → Session erzeugen → Cookies setzen
 */
app.get("/bff/callback", async (req, res, next) => {
  try {
    const params = client.callbackParams(req);
    const entry = await redis.get(`oidc:${params.state}`);
    if (!entry) return res.status(400).send("invalid state");
    const { code_verifier } = JSON.parse(entry);

    const tokenSet = await client.callback(
      OIDC_REDIRECT_URI,
      params,
      { state: params.state, code_verifier }
    );
    await redis.del(`oidc:${params.state}`);

    const claims = tokenSet.claims();

    // Session (nur nötige Daten)
    const sid = makeId(24);
    const session = {
      sub: claims.sub,
      email: claims.email,
      name: claims.name || claims.preferred_username,
      id_token: tokenSet.id_token,               // optional für Endsession
      refresh_token: tokenSet.refresh_token,     // Rotation später erweiterbar (jti)
      created_at: Date.now(),
    };

    await redis.setex(
      `sess:${sid}`,
      parseInt(SESSION_TTL_SECONDS, 10),
      JSON.stringify(session)
    );

    // httpOnly Session-Cookie
    const secure = bool(COOKIE_SECURE);
    const sameSite = COOKIE_SAMESITE; // "Lax" | "Strict" | "None"
    if (sameSite === "None" && !secure) {
      console.warn("Warnung: SameSite=None verlangt Secure=true. Bitte in PROD setzen.");
    }

    res.cookie(COOKIE_NAME, sid, {
      httpOnly: true,
      secure,
      sameSite,
      path: "/",
      maxAge: parseInt(SESSION_TTL_SECONDS, 10) * 1000,
    });

    // CSRF-Token (nicht httpOnly)
    const csrf = makeId(16);
    res.cookie("paradox_csrf", csrf, {
      httpOnly: false,
      secure,
      sameSite,
      path: "/",
      maxAge: parseInt(SESSION_TTL_SECONDS, 10) * 1000,
    });

    return res.redirect("/"); // zurück zur App
  } catch (e) {
    return next(e);
  }
});

/**
 * Me: nur via Cookie-Session
 */
app.get("/bff/me", loadSession, async (req, res) => {
  if (!req.session) return res.status(401).json({ ok: false, user: null });
  const { sub, email, name } = req.session;
  return res.json({ ok: true, user: { sub, email, name } });
});

/**
 * Refresh: Rotation aktualisiert Session
 */
app.post("/bff/refresh", requireCsrf, loadSession, async (req, res, next) => {
  if (!req.session?.refresh_token) return res.status(401).json({ ok: false });
  try {
    const refreshed = await client.refresh(req.session.refresh_token);
    req.session.refresh_token = refreshed.refresh_token || req.session.refresh_token;
    await redis.setex(
      `sess:${req.sid}`,
      parseInt(SESSION_TTL_SECONDS, 10),
      JSON.stringify(req.session)
    );
    return res.json({ ok: true });
  } catch (e) {
    try { if (req.sid) await redis.del(`sess:${req.sid}`); } catch {}
    res.clearCookie(COOKIE_NAME, { path: "/" });
    return res.status(401).json({ ok: false });
  }
});

/**
 * Logout: Session löschen + (optional) IdP-Endsession
 */
app.post("/bff/logout", requireCsrf, loadSession, async (req, res, _next) => {
  try { if (req.sid) await redis.del(`sess:${req.sid}`); } catch {}
  res.clearCookie(COOKIE_NAME, { path: "/" });
  res.clearCookie("paradox_csrf", { path: "/" });

  try {
    const end = issuer.end_session_endpoint;
    if (end && req.session?.id_token) {
      const url = new URL(end);
      url.searchParams.set("post_logout_redirect_uri", OIDC_POST_LOGOUT_REDIRECT_URI);
      url.searchParams.set("id_token_hint", req.session.id_token);
      return res.redirect(url.toString());
    }
  } catch { /* ignore */ }

  return res.redirect("/");
});

/**
 * Globaler Error-Handler
 */
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  return res.status(500).json({ ok: false, error: "internal_error" });
});

/**
 * Start
 */
app.listen(parseInt(PORT, 10), () => {
  console.log(`BFF listening on ${PORT}`);
});