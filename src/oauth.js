// Google OAuth helper endpoints for the sshborg app, using a Google "Web application" client.
//
//   GET  /oauth/callback  Google redirects here after consent; hands the code back to the app.
//   POST /oauth/token     app sends {code, code_verifier}; we add the client secret and return tokens.
//   POST /oauth/refresh   app sends {refresh_token}; we return a fresh id_token.
//
// The client secret never leaves the Worker. These routes are unauthenticated by design (the user
// has no token yet); they can only exchange credentials Google itself issued, and access to the
// SSH host is still gated by the ID-token check in google.js.

const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const APP_SCHEME = "sshborg";

const JSON_HEADERS = { "content-type": "application/json", "cache-control": "no-store" };

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function callbackPage(url) {
  const params = new URLSearchParams();
  for (const key of ["code", "state", "error"]) {
    const v = url.searchParams.get(key);
    if (v) params.set(key, v);
  }
  const query = params.toString();
  // Android Chrome reliably opens an app from an intent: URL, and refuses a bare custom-scheme redirect
  // that isn't from a user tap, so offer the intent link, auto-follow it, and keep a tap fallback.
  const intent = `intent://oauth?${query}#Intent;scheme=${APP_SCHEME};end`;
  const plain = `${APP_SCHEME}://oauth?${query}`;
  const html = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Return to SSHBorg</title>
<body style="font-family:system-ui,sans-serif;text-align:center;padding:3rem 1rem">
<p>Returning to SSHBorg…</p>
<p><a href="${escapeHtml(intent)}" style="font-size:1.2rem">Open SSHBorg</a></p>
<p style="color:#666;font-size:.85rem"><a href="${escapeHtml(plain)}">Trouble? Try this link</a></p>
<script>location.replace(${JSON.stringify(intent).replace(/</g, "\\u003c")});</script>`;
  return new Response(html, {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer" },
  });
}

async function exchange(env, fields, fetchImpl) {
  const body = new URLSearchParams({
    client_id: env.GOOGLE_OAUTH_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    ...fields,
  });
  const res = await fetchImpl(TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // Only pass through Google's short error code (the app needs "invalid_grant"), nothing else.
    return json({ error: typeof data.error === "string" ? data.error : "token_request_failed" }, res.status === 400 ? 400 : 502);
  }
  return data;
}

async function readJson(request) {
  try {
    const data = await request.json();
    return data && typeof data === "object" ? data : {};
  } catch {
    return {};
  }
}

/** Returns a Response for /oauth/* paths, or null if the request is not an OAuth route. */
export async function handleOAuth(request, env, fetchImpl = fetch) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/oauth/")) return null;

  if (!env.GOOGLE_OAUTH_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
    return json({ error: "oauth not configured" }, 503);
  }

  if (url.pathname === "/oauth/callback" && request.method === "GET") {
    return callbackPage(url);
  }

  if (request.method !== "POST") return json({ error: "not found" }, 404);

  if (url.pathname === "/oauth/token") {
    const { code, code_verifier } = await readJson(request);
    if (typeof code !== "string" || typeof code_verifier !== "string" || !code || !code_verifier) {
      return json({ error: "invalid_request" }, 400);
    }
    const result = await exchange(
      env,
      {
        grant_type: "authorization_code",
        code,
        code_verifier,
        redirect_uri: `${url.origin}/oauth/callback`,
      },
      fetchImpl,
    );
    if (result instanceof Response) return result;
    if (!result.id_token || !result.refresh_token) return json({ error: "no_refresh_token" }, 502);
    return json({ id_token: result.id_token, refresh_token: result.refresh_token });
  }

  if (url.pathname === "/oauth/refresh") {
    const { refresh_token } = await readJson(request);
    if (typeof refresh_token !== "string" || !refresh_token) return json({ error: "invalid_request" }, 400);
    const result = await exchange(env, { grant_type: "refresh_token", refresh_token }, fetchImpl);
    if (result instanceof Response) return result;
    if (!result.id_token) return json({ error: "token_request_failed" }, 502);
    return json({ id_token: result.id_token });
  }

  return json({ error: "not found" }, 404);
}
