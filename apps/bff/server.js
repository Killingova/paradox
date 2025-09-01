import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { Issuer, generators } from "openid-client";
import Redis from "ioredis";

/**
 * ENV laden
 */
const {
  OIDC_ISSUER,
  OIDC_CLIENT_ID,
  OIDC_CLIENT_SECRET,
  OIDC_REDIRECT_URI,
  OIDC_POST_LOGOUT_REDIRECT_URI,
  COOKIE_NAME = "paradox_sid",
  COOKIE_SECURE = "false",
  COOKIE_SAMESITE = "Lax",
  REDIS_URL = "redis://redis:6379",
  SESSION_TTL_SECONDS = "604800"
} = process.env;

/**
 * Redis
 */
const redis = new Redis(REDIS_URL);

/**
 * Hilfen
 */
const bool = (v) => String(v).toLowerCase() === "true";
const makeId = (n = 32) => crypto.randomBytes(n).toString("base64url");

/**
 * OIDC Client dynamisch via Discovery
 */
const issuer = await Issuer.discover(`${OIDC_ISSUER}`);
const client = new issuer.Client({
  client_id: OIDC_CLIENT_ID,
  client_secret: OIDC_CLIENT_SECRET,
  redirect_uris: [OIDC_REDIRECT_URI],
  response_types: ["code"]
});

/**
 * Express
 */
const app = express();
app.use(express.json());
app.use(cookieParser());

/**
 * Middleware: Session laden
 */
async function loadSession(req, res, next) {
  const sid = req.cookies[COOKIE_NAME];
  if (!sid) return next();
  const raw = await redis.get(`sess:${sid}`);
  if (raw) req.session = JSON.parse(raw);
  req.sid = sid;
  next();
}

/**
 * Health
 */
app.get("/bff/health", (_req, res) => res.type("text").send("bff: ok\n"));

/**
 * Login: PKCE + state erzeugen, in Redis parken, Redirect zu Keycloak
 */
app.get("/bff/login", async (req, res) => {
  const state = makeId(16);
  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);

  await redis.setex(
    `oidc:${state}`,
    300,
    JSON.stringify({ code_verifier })
  );

  const authUrl = client.authorizationUrl({
    scope: "openid profile email offline_access",
    state,
    code_challenge,
    code_challenge_method: "S256"
  });

  return res.redirect(authUrl);
});

/**
 * Callback: Code gegen Tokens tauschen, Session erzeugen, Cookie setzen
 */
app.get("/bff/callback", async (req, res) => {
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

  // User-Claims
  const claims = tokenSet.claims();

  // Session anlegen (nur das Nötigste speichern + Refresh)
  const sid = makeId(24);
  const session = {
    sub: claims.sub,
    email: claims.email,
    name: claims.name || claims.preferred_username,
    id_token: tokenSet.id_token,        // optional für Endsession
    refresh_token: tokenSet.refresh_token,
    created_at: Date.now()
  };

  await redis.setex(
    `sess:${sid}`,
    parseInt(SESSION_TTL_SECONDS, 10),
    JSON.stringify(session)
  );

  // httpOnly-Cookie setzen
  res.cookie(COOKIE_NAME, sid, {
    httpOnly: true,
    secure: bool(COOKIE_SECURE),
    sameSite: COOKIE_SAMESITE,
    path: "/",
    maxAge: parseInt(SESSION_TTL_SECONDS, 10) * 1000
  });

  return res.redirect("/"); // zurück zur App
});

/**
 * Me: nur via Cookie-Sid
 */
app.get("/bff/me", loadSession, async (req, res) => {
  if (!req.session) return res.status(401).json({ ok: false, user: null });
  const { sub, email, name } = req.session;
  return res.json({ ok: true, user: { sub, email, name } });
});

/**
 * Refresh: neuen Refresh holen (Rotation) und Session aktualisieren
 */
app.post("/bff/refresh", loadSession, async (req, res) => {
  if (!req.session?.refresh_token) return res.status(401).json({ ok: false });
  const { refresh_token } = req.session;

  try {
    const refreshed = await client.refresh(refresh_token);
    // Rotation: alten Refresh invalid? Keycloak rotiert; wir überschreiben
    req.session.refresh_token = refreshed.refresh_token || refresh_token;
    await redis.setex(
      `sess:${req.sid}`,
      parseInt(SESSION_TTL_SECONDS, 10),
      JSON.stringify(req.session)
    );
    return res.json({ ok: true });
  } catch (e) {
    // Refresh ungültig → Session löschen
    await redis.del(`sess:${req.sid}`);
    res.clearCookie(COOKIE_NAME, { path: "/" });
    return res.status(401).json({ ok: false });
  }
});

/**
 * Logout: Session löschen und (optional) zum IdP ausloggen
 */
app.post("/bff/logout", loadSession, async (req, res) => {
  if (req.sid) await redis.del(`sess:${req.sid}`);
  res.clearCookie(COOKIE_NAME, { path: "/" });

  // Optional: Endsession beim IdP
  try {
    const end = issuer.end_session_endpoint;
    if (end && req.session?.id_token) {
      const url = new URL(end);
      url.searchParams.set("post_logout_redirect_uri", OIDC_POST_LOGOUT_REDIRECT_URI);
      url.searchParams.set("id_token_hint", req.session.id_token);
      return res.redirect(url.toString());
    }
  } catch (_) { /* ignore */ }

  return res.redirect("/");
});

/**
 * Start
 */
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`BFF listening on ${port}`));
