// server.js – BFF (Backend-for-Frontend) für OIDC-Login via Keycloak
// Stack: Node 20 (ESM), openid-client v6 (ESM), Express 4, Redis (ioredis)

import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import * as oidc from "openid-client";     // v6: Funktions-API als Namespace
import Redis from "ioredis";

/* =========================================
 * 1) ENV & Defaults
 * ======================================= */
const {
  // OIDC / Keycloak
  OIDC_ISSUER,                    // z.B. http://keycloak:8080/auth/realms/paradoxon (DEV) | https://idp.tld/realms/...
  OIDC_CLIENT_ID,                 // z.B. bff
  OIDC_CLIENT_SECRET,             // confidential client → Secret
  OIDC_REDIRECT_URI,              // z.B. http://192.168.178.117/bff/callback
  OIDC_POST_LOGOUT_REDIRECT_URI,  // z.B. http://192.168.178.117/
  OIDC_ALLOW_INSECURE_HTTP = "false", // DEV: "true" erlaubt HTTP zum Issuer

  // Cookies & Session
  COOKIE_NAME = "paradox_sid",
  COOKIE_SECURE = "false",        // PROD: "true" (nur über HTTPS)
  COOKIE_SAMESITE = "Lax",        // PROD: "Strict" oder "None"(+Secure)
  REDIS_URL = "redis://redis:6379",
  SESSION_TTL_SECONDS = "604800", // 7 Tage

  // Server
  PORT = "3000",
} = process.env;

const bool = (v) => String(v).toLowerCase() === "true";
const makeId = (n = 32) => crypto.randomBytes(n).toString("base64url");
const safeJsonParse = (raw) => { try { return raw ? JSON.parse(raw) : null; } catch { return null; } };

// Pflicht-ENV früh prüfen (klarer Fail statt später kryptisch)
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

/* =========================================
 * 2) DEV: HTTP zu Issuer erlauben (nur lokal!)
 *    openid-client v6 verbietet HTTP standardmäßig.
 * ======================================= */
if (bool(OIDC_ALLOW_INSECURE_HTTP)) {
  // ACHTUNG: nur in DEV verwenden!
  oidc.custom.setHttpOptionsDefaults({ allowInsecureRequests: true });
}

/* =========================================
 * 3) Redis – State & Session
 * ======================================= */
const redis = new Redis(REDIS_URL, { lazyConnect: true });
await redis.connect().catch((e) => {
  console.error("Redis-Verbindung fehlgeschlagen:", e);
  process.exit(1);
});

/* =========================================
 * 4) OIDC Discovery (v6 Funktions-API)
 *    → liefert eine „Konfiguration“ (server/client Metadata + Helper)
 * ======================================= */
let conf;
try {
  const issuerUrl = new URL(String(OIDC_ISSUER));
  conf = await oidc.discovery(issuerUrl, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET);
} catch (e) {
  console.error("OIDC Discovery fehlgeschlagen:", e);
  process.exit(1);
}

/* =========================================
 * 5) Express Setup
 * ======================================= */
const app = express();
app.set("trust proxy", 1);     // wichtig hinter nginx/Proxy
app.use(express.json());
app.use(cookieParser());

/* =========================================
 * 6) Middlewares & Helpers
 * ======================================= */
async function loadSession(req, _res, next) {
  try {
    const sid = req.cookies[COOKIE_NAME];
    if (!sid) return next();
    const raw = await redis.get(`sess:${sid}`);
    const session = safeJsonParse(raw);
    if (session) { req.session = session; req.sid = sid; }
    next();
  } catch (e) { next(e); }
}

function rateLimit({ keyPrefix, limit = 10, windowSec = 60 }) {
  return async (req, res, next) => {
    try {
      const key = `rl:${keyPrefix}:${req.ip}`;
      const cur = await redis.incr(key);
      if (cur === 1) await redis.expire(key, windowSec);
      if (cur > limit) return res.status(429).json({ ok: false, error: "rate_limited" });
      next();
    } catch { next(); }
  };
}

function requireCsrf(req, res, next) {
  const cookie = req.cookies["paradox_csrf"];
  const header = req.get("x-csrf-token");
  if (!cookie || !header || cookie !== header) {
    return res.status(403).json({ ok: false, error: "csrf" });
  }
  next();
}

/* =========================================
 * 7) Health
 * ======================================= */
app.get("/bff/health", (_req, res) => res.type("text").send("bff: ok\n"));

/* =========================================
 * 8) /bff/login – Authorization Code + PKCE
 * ======================================= */
app.get("/bff/login",
  rateLimit({ keyPrefix: "login", limit: 12, windowSec: 60 }),
  async (_req, res, next) => {
    try {
      const state = makeId(16);
      const code_verifier  = oidc.randomPKCECodeVerifier();
      const code_challenge = await oidc.calculatePKCECodeChallenge(code_verifier);

      // 5 Minuten PKCE-State
      await redis.setex(`oidc:${state}`, 300, JSON.stringify({ code_verifier }));

      const url = oidc.buildAuthorizationUrl(conf, {
        redirect_uri: OIDC_REDIRECT_URI,
        scope: "openid profile email offline_access",
        state,
        code_challenge,
        code_challenge_method: "S256",
      });

      return res.redirect(url.href);
    } catch (e) { return next(e); }
  }
);

/* =========================================
 * 9) /bff/callback – Code → Tokens + Session
 * ======================================= */
app.get("/bff/callback", async (req, res, next) => {
  try {
    const currentUrl = new URL(`${req.protocol}://${req.get("host")}${req.originalUrl}`);
    const state = currentUrl.searchParams.get("state");
    if (!state) return res.status(400).send("missing state");

    const entry = await redis.get(`oidc:${state}`);
    if (!entry) return res.status(400).send("invalid state");
    const { code_verifier } = JSON.parse(entry);
    await redis.del(`oidc:${state}`);

    const tokens = await oidc.authorizationCodeGrant(conf, currentUrl, {
      pkceCodeVerifier: code_verifier,
      expectedState: state,
    });

    // Optional: UserInfo
    let user = { sub: undefined, email: undefined, name: undefined };
    try {
      const meta = conf.serverMetadata();
      if (meta.userinfo_endpoint && tokens.access_token) {
        const info = await oidc.userInfo(conf, tokens.access_token);
        user = { sub: info.sub, email: info.email, name: info.name || info.preferred_username };
      }
    } catch { /* ignore */ }

    // Session speichern
    const sid = makeId(24);
    const session = {
      sub: user.sub,
      email: user.email,
      name: user.name,
      id_token: tokens.id_token,
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      created_at: Date.now(),
    };
    await redis.setex(`sess:${sid}`, parseInt(SESSION_TTL_SECONDS, 10), JSON.stringify(session));

    // Cookies setzen
    const secure   = bool(COOKIE_SECURE);
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

    const csrf = makeId(16);
    res.cookie("paradox_csrf", csrf, {
      httpOnly: false, // Frontend muss lesen können
      secure,
      sameSite,
      path: "/",
      maxAge: parseInt(SESSION_TTL_SECONDS, 10) * 1000,
    });

    return res.redirect("/");
  } catch (e) { return next(e); }
});

/* =========================================
 * 10) /bff/me – Session-User
 * ======================================= */
app.get("/bff/me", loadSession, (req, res) => {
  if (!req.session) return res.status(401).json({ ok: false, user: null });
  const { sub, email, name } = req.session;
  return res.json({ ok: true, user: { sub, email, name } });
});

/* =========================================
 * 11) /bff/refresh – Refresh Token
 * ======================================= */
app.post("/bff/refresh", requireCsrf, loadSession, async (req, res) => {
  if (!req.session?.refresh_token) return res.status(401).json({ ok: false });
  try {
    const refreshed = await oidc.refreshTokenGrant(conf, req.session.refresh_token);
    req.session.refresh_token = refreshed.refresh_token || req.session.refresh_token;
    req.session.access_token  = refreshed.access_token  || req.session.access_token;
    await redis.setex(`sess:${req.sid}`, parseInt(SESSION_TTL_SECONDS, 10), JSON.stringify(req.session));
    return res.json({ ok: true });
  } catch {
    try { if (req.sid) await redis.del(`sess:${req.sid}`); } catch {}
    res.clearCookie(COOKIE_NAME, { path: "/" });
    res.clearCookie("paradox_csrf", { path: "/" });
    return res.status(401).json({ ok: false });
  }
});

/* =========================================
 * 12) /bff/logout – lokale Session + optional IdP-End-Session
 * ======================================= */
app.post("/bff/logout", requireCsrf, loadSession, async (req, res) => {
  try { if (req.sid) await redis.del(`sess:${req.sid}`); } catch {}
  res.clearCookie(COOKIE_NAME, { path: "/" });
  res.clearCookie("paradox_csrf", { path: "/" });

  try {
    const end = conf.serverMetadata().end_session_endpoint;
    if (end && req.session?.id_token) {
      const url = new URL(end);
      url.searchParams.set("post_logout_redirect_uri", OIDC_POST_LOGOUT_REDIRECT_URI);
      url.searchParams.set("id_token_hint", req.session.id_token);
      return res.redirect(url.toString());
    }
  } catch { /* ignore */ }

  return res.redirect("/");
});

/* =========================================
 * 13) Error-Handler
 * ======================================= */
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  return res.status(500).json({ ok: false, error: "internal_error" });
});

/* =========================================
 * 14) Start
 * ======================================= */
app.listen(parseInt(PORT, 10), () => {
  console.log(`BFF listening on ${PORT}`);
});
