// server.js – BFF (Backend-for-Frontend) für OIDC-Login via Keycloak
// Zweck: Sichere Auth im Browser ohne Tokens im LocalStorage. Cookies + Redis-Session.

import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { Issuer, generators } from "openid-client"; // OIDC-Client-Lib (PKCE, Discovery etc.)
import Redis from "ioredis"; // Session- & State-Speicher

/**
 * 1) ENV laden + Defaults
 *    Diese Variablen kommen aus .env / Docker / K8s Secrets.
 *    Sie steuern, gegen welchen IdP (Keycloak) wir sprechen und wie Cookies gesetzt werden.
 */
const {
  OIDC_ISSUER,                     // z.B. https://idp.local/realms/paradox
  OIDC_CLIENT_ID,                  // Client in Keycloak (typisch: "bff")
  OIDC_CLIENT_SECRET,              // nur für confidential clients nötig
  OIDC_REDIRECT_URI,               // z.B. https://app.local/bff/callback
  OIDC_POST_LOGOUT_REDIRECT_URI,   // Ziel nach Abmeldung am IdP
  COOKIE_NAME = "paradox_sid",     // Name des Session-Cookies
  COOKIE_SECURE = "false",          // in PROD: true (nur über HTTPS senden)
  COOKIE_SAMESITE = "Lax",          // in PROD: Strict oder None(+Secure)
  REDIS_URL = "redis://redis:6379", // Redis-Endpoint
  SESSION_TTL_SECONDS = "604800",   // 7 Tage Session-Lebensdauer
  PORT = "3000",
} = process.env;

// kleine Helfer
const bool = (v) => String(v).toLowerCase() === "true";
const makeId = (n = 32) => crypto.randomBytes(n).toString("base64url");

// Minimal-Check auf Pflicht-ENV (früher Crash statt später kryptischer Fehler)
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
 * 2) Redis – State & Session Storage
 *    - Speichert PKCE-State (während Login-Flow)
 *    - Speichert BFF-Sessions (sid → {sub, email, name, refresh_token, ...})
 */
const redis = new Redis(REDIS_URL, { lazyConnect: true });
await redis.connect().catch((e) => {
  console.error("Redis-Verbindung fehlgeschlagen:", e);
  process.exit(1);
});

/**
 * 3) OIDC Client per Discovery
 *    - Holt Endpunkte/Keys automatisch bei OIDC_ISSUER (/.well-known/openid-configuration)
 *    - Initialisiert Client für Code-Flow + PKCE
 */
let client;
let issuer;
try {
  issuer = await Issuer.discover(`${OIDC_ISSUER}`);
  client = new issuer.Client({
    client_id: OIDC_CLIENT_ID,
    client_secret: OIDC_CLIENT_SECRET, // bei Public Clients weglassen
    redirect_uris: [OIDC_REDIRECT_URI],
    response_types: ["code"], // Authorization Code Flow
  });
} catch (e) {
  console.error("OIDC Discovery/Client-Init fehlgeschlagen:", e);
  process.exit(1);
}

/**
 * 4) Express-Setup
 *    - trust proxy: wichtig, wenn vor dem BFF ein Reverse-Proxy (nginx) mit TLS steht
 *    - JSON-Parsing & Cookies
 */
const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(cookieParser());

/**
 * 5) Hilfs-Middlewares
 *    - loadSession: lädt Session aus Redis anhand des httpOnly Cookies
 *    - rateLimit: einfacher per-IP Rate Limiter (Schutz vor Brute Force/Abuse)
 *    - requireCsrf: Double-Submit Cookie + Header (Schutz für POST/PUT/DELETE)
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
      req.session = session; // user claims & refresh_token
      req.sid = sid;         // referenz für update/löschen
    }
    return next();
  } catch (e) {
    return next(e);
  }
}

function rateLimit({ keyPrefix, limit = 10, windowSec = 60 }) {
  return async (req, res, next) => {
    try {
      const key = `rl:${keyPrefix}:${req.ip}`;
      const cur = await redis.incr(key);
      if (cur === 1) await redis.expire(key, windowSec);
      if (cur > limit) return res.status(429).json({ ok: false, error: "rate_limited" });
      return next();
    } catch (e) {
      // wenn Redis down → kein Limit (alternativ 503 senden)
      return next();
    }
  };
}

function requireCsrf(req, res, next) {
  const cookie = req.cookies["paradox_csrf"];
  const header = req.get("x-csrf-token");
  if (!cookie || !header || cookie !== header) {
    return res.status(403).json({ ok: false, error: "csrf" });
  }
  return next();
}

/**
 * 6) Healthcheck – für Monitoring/K8s Probes
 */
app.get("/bff/health", (_req, res) => res.type("text").send("bff: ok\n"));

/**
 * 7) /bff/login – Start des OIDC Flows mit PKCE
 *    - Erzeugt state + code_verifier
 *    - Speichert code_verifier 5 Min in Redis (gegen CSRF/Replay)
 *    - Redirect zum IdP (Keycloak) mit code_challenge
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
 * 8) /bff/callback – tauscht Code gegen Tokens
 *    - Validiert state und liest code_verifier aus Redis
 *    - Holt tokenSet (id_token, access_token, refresh_token)
 *    - Erzeugt eigene BFF-Session (sid) und legt sie in Redis ab
 *    - Setzt httpOnly Session-Cookie + nicht-httpOnly CSRF-Cookie
 *    - Redirect zurück zur SPA (/)
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

    // Minimal-User-Session (nur notwendige Daten speichern)
    const sid = makeId(24);
    const session = {
      sub: claims.sub,
      email: claims.email,
      name: claims.name || claims.preferred_username,
      id_token: tokenSet.id_token,           // optional für End-Session am IdP
      refresh_token: tokenSet.refresh_token, // für /bff/refresh
      created_at: Date.now(),
    };

    await redis.setex(
      `sess:${sid}`,
      parseInt(SESSION_TTL_SECONDS, 10),
      JSON.stringify(session)
    );

    // httpOnly Session-Cookie → nicht per JS lesbar (XSS-Schutz)
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

    // CSRF-Token als eigenes Cookie (vom Frontend als Header zurücksenden)
    const csrf = makeId(16);
    res.cookie("paradox_csrf", csrf, {
      httpOnly: false, // Frontend muss den Wert lesen können
      secure,
      sameSite,
      path: "/",
      maxAge: parseInt(SESSION_TTL_SECONDS, 10) * 1000,
    });

    return res.redirect("/");
  } catch (e) {
    return next(e);
  }
});

/**
 * 9) /bff/me – User-Info aus der BFF-Session (kein Access-Token im Browser)
 */
app.get("/bff/me", loadSession, async (req, res) => {
  if (!req.session) return res.status(401).json({ ok: false, user: null });
  const { sub, email, name } = req.session;
  return res.json({ ok: true, user: { sub, email, name } });
});

/**
 * 10) /bff/refresh – Refresh Token Flow (Rotation optional erweiterbar)
 *     - geschützt mit CSRF + gültiger Session
 *     - holt neuen refresh_token und aktualisiert Session-TTL
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
    // Refresh fehlgeschlagen → Session löschen und Cookies leeren
    try { if (req.sid) await redis.del(`sess:${req.sid}`); } catch {}
    res.clearCookie(COOKIE_NAME, { path: "/" });
    return res.status(401).json({ ok: false });
  }
});

/**
 * 11) /bff/logout – lokale Session löschen + optional IdP-End-Session
 */
app.post("/bff/logout", requireCsrf, loadSession, async (req, res, _next) => {
  try { if (req.sid) await redis.del(`sess:${req.sid}`); } catch {}
  res.clearCookie(COOKIE_NAME, { path: "/" });
  res.clearCookie("paradox_csrf", { path: "/" });

  try {
    const end = issuer.end_session_endpoint; // Keycloak Endsession Endpoint
    if (end && req.session?.id_token) {
      const url = new URL(end);
      url.searchParams.set("post_logout_redirect_uri", OIDC_POST_LOGOUT_REDIRECT_URI);
      url.searchParams.set("id_token_hint", req.session.id_token);
      return res.redirect(url.toString());
    }
  } catch { /* ignorieren */ }

  return res.redirect("/");
});

/**
 * 12) Globaler Error-Handler – letzte Verteidigungslinie
 */
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  return res.status(500).json({ ok: false, error: "internal_error" });
});

/**
 * 13) Start – Server lauscht
 */
app.listen(parseInt(PORT, 10), () => {
  console.log(`BFF listening on ${PORT}`);
});
