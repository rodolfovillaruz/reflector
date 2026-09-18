// Verifies Google-issued OpenID Connect ID tokens (RS256) inside a Worker, no dependencies.

const JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const ISSUERS = ["https://accounts.google.com", "accounts.google.com"];
const JWKS_TTL_MS = 60 * 60 * 1000;
const CLOCK_SKEW_S = 60;

let jwksCache = { keys: null, fetchedAt: 0 };

function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function parseJson(bytes) {
  return JSON.parse(new TextDecoder().decode(bytes));
}

async function getJwks(fetchImpl, force) {
  if (!force && jwksCache.keys && Date.now() - jwksCache.fetchedAt < JWKS_TTL_MS) {
    return jwksCache.keys;
  }
  const res = await fetchImpl(JWKS_URL);
  if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);
  const { keys } = await res.json();
  jwksCache = { keys, fetchedAt: Date.now() };
  return keys;
}

function splitList(value) {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * Returns the verified email on success. Throws an Error with a short reason on failure.
 * `env.GOOGLE_CLIENT_IDS` and `env.ALLOWED_EMAILS` are comma-separated lists; both are required,
 * so a missing config denies everyone rather than admitting any Google account.
 */
export async function verifyGoogleIdToken(token, env, fetchImpl = fetch) {
  const audiences = (env.GOOGLE_CLIENT_IDS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const allowed = splitList(env.ALLOWED_EMAILS);
  if (audiences.length === 0 || allowed.length === 0) throw new Error("google auth not configured");

  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const [h, p, s] = parts;

  let header, payload;
  try {
    header = parseJson(b64urlToBytes(h));
    payload = parseJson(b64urlToBytes(p));
  } catch {
    throw new Error("malformed token");
  }
  if (header.alg !== "RS256" || !header.kid) throw new Error("unsupported token");

  let keys = await getJwks(fetchImpl, false);
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    // Google rotates keys; refetch once before rejecting an unknown kid.
    keys = await getJwks(fetchImpl, true);
    jwk = keys.find((k) => k.kid === header.kid);
  }
  if (!jwk) throw new Error("unknown signing key");

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlToBytes(s),
    new TextEncoder().encode(`${h}.${p}`),
  );
  if (!valid) throw new Error("bad signature");

  const now = Math.floor(Date.now() / 1000);
  if (!ISSUERS.includes(payload.iss)) throw new Error("bad issuer");
  if (!audiences.includes(payload.aud)) throw new Error("bad audience");
  if (typeof payload.exp !== "number" || payload.exp + CLOCK_SKEW_S < now) throw new Error("token expired");
  if (typeof payload.iat === "number" && payload.iat - CLOCK_SKEW_S > now) throw new Error("token not yet valid");
  if (payload.email_verified !== true) throw new Error("email not verified");

  const email = String(payload.email ?? "").toLowerCase();
  if (!allowed.includes(email)) throw new Error("email not allowed");
  return email;
}

export function resetJwksCacheForTests() {
  jwksCache = { keys: null, fetchedAt: 0 };
}
