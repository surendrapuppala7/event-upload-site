// ==============================
// CORS + Security
// ==============================
function getAllowedOrigin(req, env) {
  const origin = req.headers.get("Origin") || "";
  const allow = (env.ALLOWED_ORIGIN || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  if (!allow.length) return "";
  return allow.includes(origin) ? origin : "";
}

function corsHeadersFor(req, env, mode) {
  if (mode === "public") {
    return {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Vary": "Origin",
    };
  }

  const allowed = getAllowedOrigin(req, env);
  if (!allowed) return {};

  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin",
  };
}

const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cache-Control": "no-store",
};

function jsonResponse(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      ...headers,
      ...securityHeaders,
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

function textResponse(text, status = 200, headers = {}) {
  return new Response(text, {
    status,
    headers: { ...headers, ...securityHeaders },
  });
}

function getIP(req) {
  return (
    req.headers.get("CF-Connecting-IP") ||
    (req.headers.get("X-Forwarded-For") || "").split(",")[0].trim() ||
    "unknown"
  );
}

// ==============================
// Rate limiting (KV)
// ==============================
async function rateLimit(env, key, limit, windowSeconds) {
  const bucket = Math.floor(Date.now() / 1000 / windowSeconds);
  const k = `${key}:${bucket}`;
  const cur = Number(await env.RATE_LIMIT.get(k)) || 0;
  if (cur >= limit) return false;

  await env.RATE_LIMIT.put(k, String(cur + 1), {
    expirationTtl: windowSeconds + 5,
  });
  return true;
}

// ==============================
// Helpers
// ==============================
function normalizeEmail(e) {
  return String(e || "").trim().toLowerCase().slice(0, 320);
}

function clamp(s, n) {
  return String(s || "").trim().slice(0, n);
}

function normalizeEventIdInput(raw) {
  return clamp(raw, 64);
}

function buildEventIdVariants(raw) {
  const base = String(raw || "").trim();
  if (!base) return [];

  const upper = base.toUpperCase();
  const alnum = upper.replace(/[^A-Z0-9]/g, "");

  const variants = [base, upper, alnum];
  if (alnum.startsWith("EVT") && alnum.length > 3) {
    variants.push(`EVT-${alnum.slice(3)}`);
  }

  // unique
  return Array.from(new Set(variants.filter(Boolean)));
}

async function findEvent(env, eventIdRaw) {
  const variants = buildEventIdVariants(eventIdRaw);
  for (const id of variants) {
    const ev = await getEvent(env, id);
    if (ev) return { event: ev, id };
  }
  return { event: null, id: eventIdRaw };
}

function getCookie(req, name) {
  const cookie = req.headers.get("Cookie") || "";
  // safe-ish cookie parsing
  const parts = cookie.split(";").map(p => p.trim());
  for (const p of parts) {
    if (p.startsWith(name + "=")) return p.slice(name.length + 1);
  }
  return "";
}

function generateSessionToken() {
  // long random token
  return crypto.randomUUID() + crypto.randomUUID();
}

async function getEvent(env, eventId) {
  return await env.DB.prepare("SELECT * FROM events WHERE id = ?")
    .bind(eventId)
    .first();
}

async function getEventAdmin(env, eventId, email) {
  return await env.DB.prepare(
    "SELECT * FROM event_admins WHERE event_id = ? AND lower(email) = ?"
  )
    .bind(eventId, normalizeEmail(email))
    .first();
}

async function requireUserSession(env, req) {
  const token = getCookie(req, "user_session");
  if (!token) return null;

  const s = await env.DB.prepare(
    "SELECT * FROM user_sessions WHERE token = ?"
  )
    .bind(token)
    .first();

  if (!s) return null;
  if (new Date(s.expires_at) <= new Date()) return null;

  return s;
}

async function deleteUserSession(env, token) {
  if (!token) return;
  await env.DB.prepare("DELETE FROM user_sessions WHERE token = ?")
    .bind(token)
    .run();
}

async function isUserAuthorizedForEvent(env, email, eventId) {
  const ev = await getEvent(env, eventId);
  if (!ev) return false;
  if (await isStaffUser(env, email)) return true;
  if (normalizeEmail(ev.owner) === normalizeEmail(email)) return true;
  const admin = await getEventAdmin(env, eventId, normalizeEmail(email));
  return !!admin;
}

async function isStaffUser(env, email) {
  const row = await env.DB.prepare(
    "SELECT role FROM staff_users WHERE lower(email) = ?"
  )
    .bind(normalizeEmail(email))
    .first();
  return !!row;
}

function generateEventCode(length = 6) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let code = "";
  for (let i = 0; i < length; i++) {
    code += alphabet[bytes[i] % alphabet.length];
  }
  return code;
}

async function generateUniqueEventId(env, attempts = 8) {
  for (let i = 0; i < attempts; i++) {
    const candidate = generateEventCode(6);
    const existing = await getEvent(env, candidate);
    if (!existing) return candidate;
  }
  return "EVT-" + crypto.randomUUID().slice(0, 8).toUpperCase();
}

// Decide which endpoints are public vs private for CORS
function endpointMode(path) {
  // public reads + uploads + oauth navigations
  if (
    path === "/" ||
    path === "/media" ||
    path === "/api/get-event" ||
    path.startsWith("/oauth/")
  ) {
    return "public";
  }
  return "private";
}

// ==============================
// OAUTH HELPERS
// ==============================
// Must match EXACTLY what you put in Google Console.
function getOAuthRedirect(env) {
  const envRedirect = (env.GOOGLE_OAUTH_REDIRECT || "").trim();
  return envRedirect || "https://event-upload-api.surendra-david-puppala.workers.dev/oauth/callback";
}

function getAppOrigin(env, req) {
  const envOrigin = (env.APP_ORIGIN || "").trim();
  if (envOrigin) return envOrigin.replace(/\/$/, "");

  const allow = (env.ALLOWED_ORIGIN || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);
  if (allow.length) return allow[0].replace(/\/$/, "");

  return new URL(req.url).origin;
}

function getGoogleClientId(env) {
  return (env.GOOGLE_OAUTH_CLIENT_ID || env.GOOGLE_CLIENT_ID || "").trim();
}

function getGoogleClientSecret(env) {
  return (env.GOOGLE_OAUTH_CLIENT_SECRET || env.GOOGLE_CLIENT_SECRET || "").trim();
}

function buildAdminCookie(token, maxAgeSeconds, env) {
  const sameSite = (env.COOKIE_SAMESITE || "Lax").trim();
  const attrs = [
    "HttpOnly",
    "Secure",
    `SameSite=${sameSite}`,
    "Path=/",
  ];
  if (typeof maxAgeSeconds === "number") attrs.push(`Max-Age=${maxAgeSeconds}`);
  return `admin_session=${token}; ${attrs.join("; ")}`;
}

function buildUserCookie(token, maxAgeSeconds, env) {
  const sameSite = (env.COOKIE_SAMESITE || "Lax").trim();
  const attrs = [
    "HttpOnly",
    "Secure",
    `SameSite=${sameSite}`,
    "Path=/",
  ];
  if (typeof maxAgeSeconds === "number") attrs.push(`Max-Age=${maxAgeSeconds}`);
  return `user_session=${token}; ${attrs.join("; ")}`;
}

// ==============================
// WORKER
// ==============================
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const mode = endpointMode(url.pathname);
    const cors = corsHeadersFor(req, env, mode);
    const ip = getIP(req);

    // Preflight
    if (req.method === "OPTIONS") {
      // If private and origin not allowed, deny
      if (mode === "private" && !cors["Access-Control-Allow-Origin"]) {
        return textResponse("CORS forbidden", 403, securityHeaders);
      }
      return new Response(null, {
        status: 204,
        headers: { ...cors, ...securityHeaders },
      });
    }

    // ==============================
    // GOOGLE OAUTH START (User)
    // GET /oauth/start or /oauth/user/start
    // ==============================
    if (
      req.method === "GET" &&
      (url.pathname === "/oauth/start" || url.pathname === "/oauth/user/start")
    ) {
      const ok = await rateLimit(env, `oauth-user-start:${ip}`, 30, 60);
      if (!ok) return textResponse("Too many requests", 429, cors);

      let redirectEventId = "";
      const eventIdRaw = normalizeEventIdInput(url.searchParams.get("eventId"));
      if (eventIdRaw) {
        const found = await findEvent(env, eventIdRaw);
        if (found.event) redirectEventId = found.id;
      }

      const state = crypto.randomUUID();
      await env.OAUTH_STATE.put(
        state,
        JSON.stringify({ type: "user", eventId: redirectEventId }),
        { expirationTtl: 300 }
      );

      const oauthRedirect = getOAuthRedirect(env);
      const clientId = getGoogleClientId(env);
      const qs = new URLSearchParams({
        client_id: clientId,
        redirect_uri: oauthRedirect,
        response_type: "code",
        scope: "openid email",
        state,
        prompt: "select_account",
      });

      return Response.redirect(
        "https://accounts.google.com/o/oauth2/v2/auth?" + qs.toString(),
        302
      );
    }

    // ==============================
    // GOOGLE OAUTH CALLBACK (User)
    // GET /oauth/callback?code=...&state=...
    // ==============================
    if (req.method === "GET" && url.pathname === "/oauth/callback") {
      const ok = await rateLimit(env, `oauth-callback:${ip}`, 60, 60);
      if (!ok) return textResponse("Too many requests", 429, cors);

      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      if (!code || !state) return textResponse("Invalid OAuth", 400, cors);

      const stored = await env.OAUTH_STATE.get(state);
      if (!stored) return textResponse("OAuth expired", 400, cors);
      await env.OAUTH_STATE.delete(state);

      const payload = JSON.parse(stored);
      const redirectEventId = payload?.eventId || "";

      // Exchange code for tokens
      const oauthRedirect = getOAuthRedirect(env);
      const clientId = getGoogleClientId(env);
      const clientSecret = getGoogleClientSecret(env);
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          grant_type: "authorization_code",
          redirect_uri: oauthRedirect,
        }),
      });

      const tokens = await tokenRes.json().catch(() => ({}));
      if (!tokenRes.ok || !tokens.id_token) {
        return textResponse("OAuth token exchange failed", 401, cors);
      }

      // Validate id_token
      const infoRes = await fetch(
        "https://oauth2.googleapis.com/tokeninfo?id_token=" +
          encodeURIComponent(tokens.id_token)
      );
      const info = await infoRes.json().catch(() => ({}));

      if (info.aud !== clientId || info.email_verified !== "true") {
        return textResponse("Untrusted account", 403, cors);
      }

      const email = normalizeEmail(info.email);
      const token = generateSessionToken();
      const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString();

      await env.DB.prepare(`
        INSERT INTO user_sessions
          (token, email, expires_at, created_at, provider)
        VALUES (?, ?, ?, ?, 'google')
      `)
        .bind(token, email, expires, new Date().toISOString())
        .run();

      const appOrigin = getAppOrigin(env, req);
      let redirectUrl = `${appOrigin}/manage-events.html`;

      if (redirectEventId) {
        const okEvent = await isUserAuthorizedForEvent(env, email, redirectEventId);
        if (okEvent) {
          redirectUrl = `${appOrigin}/gallery.html?eventId=${encodeURIComponent(redirectEventId)}`;
        }
      }

      return new Response(null, {
        status: 302,
        headers: {
          ...securityHeaders,
          "Set-Cookie": buildUserCookie(token, 3600, env),
          "Location": redirectUrl,
        },
      });
    }

    // ==============================
    // USER SESSION
    // ==============================
    if (req.method === "GET" && url.pathname === "/api/user/me") {
      const sess = await requireUserSession(env, req);
      if (!sess) return jsonResponse({ error: "Unauthorized" }, 401, cors);
      return jsonResponse({ email: sess.email }, 200, cors);
    }

    if (req.method === "GET" && url.pathname === "/api/user/events") {
      const sess = await requireUserSession(env, req);
      if (!sess) return jsonResponse({ error: "Unauthorized" }, 401, cors);

      const email = normalizeEmail(sess.email);
      const result = await env.DB.prepare(`
        SELECT id, name, owner, created_at, 'owner' AS role
        FROM events
        WHERE lower(owner) = ?
        UNION ALL
        SELECT e.id, e.name, e.owner, e.created_at, 'admin' AS role
        FROM events e
        JOIN event_admins a ON a.event_id = e.id
        WHERE lower(a.email) = ? AND lower(e.owner) != ?
        ORDER BY created_at DESC
      `)
        .bind(email, email, email)
        .all();

      return jsonResponse({ events: result.results || [] }, 200, cors);
    }

    if (req.method === "POST" && url.pathname === "/api/user/create-event") {
      const ok = await rateLimit(env, `user-create-event:${ip}`, 20, 60);
      if (!ok) return jsonResponse({ error: "Too many requests" }, 429, cors);

      const sess = await requireUserSession(env, req);
      if (!sess) return jsonResponse({ error: "Unauthorized" }, 401, cors);

      const body = await req.json().catch(() => null);
      const name = clamp(body?.name, 120);
      if (!name) return jsonResponse({ error: "name required" }, 400, cors);

      const owner = normalizeEmail(sess.email);
      const existing = await env.DB.prepare(
        "SELECT COUNT(*) as count FROM events WHERE lower(owner) = ?"
      )
        .bind(owner)
        .first();

      const count = Number(existing?.count || 0);
      if (count >= 1) {
        return jsonResponse({ error: "free_limit_reached" }, 403, cors);
      }

      const eventId = await generateUniqueEventId(env);
      const createdAt = new Date().toISOString();

      try {
        await env.DB.prepare(
          "INSERT INTO events (id, name, owner, created_at, active) VALUES (?, ?, ?, ?, 1)"
        )
          .bind(eventId, name, owner, createdAt)
          .run();
      } catch (err) {
        await env.DB.prepare(
          "INSERT INTO events (id, name, owner, created_at) VALUES (?, ?, ?, ?)"
        )
          .bind(eventId, name, owner, createdAt)
          .run();
      }

      return jsonResponse({ eventId }, 200, cors);
    }

    if (req.method === "POST" && url.pathname === "/api/user/logout") {
      const ok = await rateLimit(env, `user-logout:${ip}`, 60, 60);
      if (!ok) return textResponse("Too many requests", 429, cors);

      const token = getCookie(req, "user_session");
      await deleteUserSession(env, token);

      return new Response(null, {
        status: 204,
        headers: {
          ...securityHeaders,
          ...cors,
          "Set-Cookie": buildUserCookie("", 0, env),
        },
      });
    }

    // ==============================
    // STAFF: LIST EVENTS (admin/support)
    // GET /api/staff/events?q=...
    // ==============================
    if (req.method === "GET" && url.pathname === "/api/staff/events") {
      const ok = await rateLimit(env, `staff-events:${ip}`, 60, 60);
      if (!ok) return jsonResponse({ error: "Too many requests" }, 429, cors);

      const sess = await requireUserSession(env, req);
      if (!sess) return jsonResponse({ error: "Unauthorized" }, 401, cors);
      const isStaff = await isStaffUser(env, sess.email);
      if (!isStaff) return jsonResponse({ error: "Forbidden" }, 403, cors);

      const q = String(url.searchParams.get("q") || "").trim().toLowerCase();
      let result;
      if (q) {
        const like = `%${q}%`;
        result = await env.DB.prepare(`
          SELECT id, name, owner, created_at, active
          FROM events
          WHERE lower(id) LIKE ?
             OR lower(name) LIKE ?
             OR lower(owner) LIKE ?
          ORDER BY created_at DESC
          LIMIT 200
        `)
          .bind(like, like, like)
          .all();
      } else {
        result = await env.DB.prepare(`
          SELECT id, name, owner, created_at, active
          FROM events
          ORDER BY created_at DESC
          LIMIT 200
        `).all();
      }

      return jsonResponse({ events: result.results || [] }, 200, cors);
    }

    // Backward-compatible logout alias
    if (req.method === "POST" && url.pathname === "/api/event-admin/logout") {
      const ok = await rateLimit(env, `user-logout:${ip}`, 60, 60);
      if (!ok) return textResponse("Too many requests", 429, cors);

      const token = getCookie(req, "user_session");
      await deleteUserSession(env, token);

      return new Response(null, {
        status: 204,
        headers: {
          ...securityHeaders,
          ...cors,
          "Set-Cookie": buildUserCookie("", 0, env),
        },
      });
    }

    // ==============================
    // EVENT ADMIN LIST FILES (cookie auth)
    // POST /api/event-admin/list-files  { eventId }
    // ==============================
    if (req.method === "POST" && url.pathname === "/api/event-admin/list-files") {
      const ok = await rateLimit(env, `admin-list:${ip}`, 120, 60);
      if (!ok) return jsonResponse({ error: "Too many requests" }, 429, cors);

      const body = await req.json().catch(() => null);
      const eventIdRaw = normalizeEventIdInput(body?.eventId);
      if (!eventIdRaw) return jsonResponse({ error: "eventId required" }, 400, cors);
      const found = await findEvent(env, eventIdRaw);
      if (!found.event) return jsonResponse({ error: "event not found" }, 404, cors);

      const sess = await requireUserSession(env, req);
      if (!sess) return jsonResponse({ error: "Unauthorized" }, 401, cors);
      const allowed = await isUserAuthorizedForEvent(env, sess.email, found.id);
      if (!allowed) return jsonResponse({ error: "Forbidden" }, 403, cors);

      const list = await env.EVENT_BUCKET.list({ prefix: `${found.id}/` });
      const files = (list.objects || []).map(o => ({
        name: o.key.split("/")[1] || o.key,
        size: o.size,
        uploaded: o.uploaded,
      }));

      return jsonResponse({ files }, 200, cors);
    }

    // ==============================
    // EVENT ADMIN DELETE FILE (owner/admin/staff)
    // POST /api/event-admin/delete-file  { eventId, file }
    // ==============================
    if (req.method === "POST" && url.pathname === "/api/event-admin/delete-file") {
      const ok = await rateLimit(env, `admin-delete:${ip}`, 120, 60);
      if (!ok) return jsonResponse({ error: "Too many requests" }, 429, cors);

      const body = await req.json().catch(() => null);
      const eventIdRaw = normalizeEventIdInput(body?.eventId);
      const file = clamp(body?.file, 200);
      if (!eventIdRaw || !file) return jsonResponse({ error: "eventId and file required" }, 400, cors);
      if (file.includes("..") || file.includes("/")) return jsonResponse({ error: "invalid file" }, 400, cors);

      const found = await findEvent(env, eventIdRaw);
      if (!found.event) return jsonResponse({ error: "event not found" }, 404, cors);

      const sess = await requireUserSession(env, req);
      if (!sess) return jsonResponse({ error: "Unauthorized" }, 401, cors);
      const allowed = await isUserAuthorizedForEvent(env, sess.email, found.id);
      if (!allowed) return jsonResponse({ error: "Forbidden" }, 403, cors);

      await env.EVENT_BUCKET.delete(`${found.id}/${file}`);
      return jsonResponse({ ok: true }, 200, cors);
    }

    // ==============================
    // GET EVENT DETAILS (public)
    // GET /api/get-event?eventId=EVT-XXXX
    // ==============================
    if (req.method === "GET" && url.pathname === "/api/get-event") {
      const ok = await rateLimit(env, `get-event:${ip}`, 120, 60);
      if (!ok) return jsonResponse({ error: "Too many requests" }, 429, cors);

      const eventIdRaw = normalizeEventIdInput(url.searchParams.get("eventId"));
      if (!eventIdRaw) return jsonResponse({ error: "eventId required" }, 400, cors);

      const found = await findEvent(env, eventIdRaw);
      const ev = found.event;
      if (!ev) return jsonResponse({ error: "event not found" }, 404, cors);

      return jsonResponse(
        {
          id: ev.id,
          name: ev.name,
          owner: ev.owner,
          created_at: ev.created_at,
          active: ev.active,
          description: ev.description || "",
          event_date: ev.event_date || "",
          location: ev.location || "",
          cover_image_name: ev.cover_image_name || "",
        },
        200,
        cors
      );
    }

    // ==============================
    // MEDIA (public)
    // GET /media?eventId=...&file=...
    // ==============================
    if (req.method === "GET" && url.pathname === "/media") {
      const ok = await rateLimit(env, `media:${ip}`, 240, 60);
      if (!ok) return textResponse("Too many requests", 429, cors);

      const eventIdRaw = normalizeEventIdInput(url.searchParams.get("eventId"));
      const file = clamp(url.searchParams.get("file"), 200);

      if (!eventIdRaw || !file) return textResponse("Missing eventId or file", 400, cors);
      if (file.includes("..")) return textResponse("Invalid file", 400, cors);

      const found = await findEvent(env, eventIdRaw);
      if (!found.event) return textResponse("Event not found", 404, cors);

      const obj = await env.EVENT_BUCKET.get(`${found.id}/${file}`);
      if (!obj) return textResponse("File not found", 404, cors);

      return new Response(obj.body, {
        status: 200,
        headers: {
          ...securityHeaders,
          ...cors,
          "Content-Type": obj.httpMetadata?.contentType || "application/octet-stream",
          "Cache-Control": "public, max-age=3600",
        },
      });
    }

    // ==============================
    // GUEST UPLOAD (public)
    // POST /
    // ==============================
    if (req.method === "POST" && url.pathname === "/") {
      const ipOk = await rateLimit(env, `upload-ip:${ip}`, 60, 60);
      if (!ipOk) return textResponse("Upload rate limit exceeded", 429, cors);

      const formData = await req.formData();
      const file = formData.get("file");
      const eventIdRaw = normalizeEventIdInput(formData.get("eventId"));

      if (!file || !eventIdRaw) return textResponse("Missing fields", 400, cors);

      const found = await findEvent(env, eventIdRaw);
      const ev = found.event;
      if (!ev) return textResponse("Event not found", 404, cors);
      if (ev.active === 0) {
        return textResponse("Event inactive", 403, cors);
      }

      const bytes = await file.arrayBuffer();
      const extRaw = (file.name || "").split(".").pop() || "bin";
      const ext = extRaw.toLowerCase().replace(/[^a-z0-9]/g, "");
      const cleanName = `${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`;
      const key = `${found.id}/${cleanName}`;

      await env.EVENT_BUCKET.put(key, bytes, {
        httpMetadata: { contentType: file.type || "application/octet-stream" },
      });

      return textResponse("OK", 200, cors);
    }

    // ==============================
    // HEALTH
    // ==============================
    return textResponse("Event upload API is alive", 200, cors);
  },
};
