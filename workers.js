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
    "SELECT * FROM event_admins WHERE event_id = ? AND email = ?"
  )
    .bind(eventId, email)
    .first();
}

async function requireAdminSession(env, req, eventId) {
  const token = getCookie(req, "admin_session");
  if (!token) return null;

  const s = await env.DB.prepare(
    "SELECT * FROM event_admin_sessions WHERE token = ?"
  )
    .bind(token)
    .first();

  if (!s) return null;
  if (s.event_id !== eventId) return null;
  if (new Date(s.expires_at) <= new Date()) return null;

  return s;
}

// Decide which endpoints are public vs private for CORS
function endpointMode(path) {
  // public reads + uploads + oauth navigations
  if (
    path === "/" ||
    path === "/media" ||
    path === "/api/get-event" ||
    path === "/api/create-event" ||   // TEMP: so your site works
    path === "/api/list-events" ||    // TEMP: so your site works
    path.startsWith("/oauth/")
  ) {
    return "public";
  }
  return "private";
}

// ==============================
// OAUTH CONSTANTS (FIXES invalid_client)
// ==============================
// Must match EXACTLY what you put in Google Console.
const OAUTH_REDIRECT =
  "https://event-upload-api.surendra-david-puppala.workers.dev/oauth/callback";

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
    // GOOGLE OAUTH START (Admin)
    // GET /oauth/start?eventId=EVT-XXXX
    // ==============================
    if (req.method === "GET" && url.pathname === "/oauth/start") {
      const ok = await rateLimit(env, `oauth-start:${ip}`, 30, 60);
      if (!ok) return textResponse("Too many requests", 429, cors);

      const eventId = clamp(url.searchParams.get("eventId"), 64);
      if (!eventId) return textResponse("Missing eventId", 400, cors);

      const ev = await getEvent(env, eventId);
      if (!ev?.active) return textResponse("Event not found", 404, cors);

      const state = crypto.randomUUID();
      await env.OAUTH_STATE.put(
        state,
        JSON.stringify({ eventId }),
        { expirationTtl: 300 }
      );

      const qs = new URLSearchParams({
        client_id: env.GOOGLE_OAUTH_CLIENT_ID,
        redirect_uri: OAUTH_REDIRECT, // FIXED
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
    // GOOGLE OAUTH CALLBACK (Admin)
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

      const { eventId } = JSON.parse(stored);

      // Exchange code for tokens
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: env.GOOGLE_OAUTH_CLIENT_ID,
          client_secret: env.GOOGLE_OAUTH_CLIENT_SECRET,
          code,
          grant_type: "authorization_code",
          redirect_uri: OAUTH_REDIRECT, // FIXED
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

      if (info.aud !== env.GOOGLE_OAUTH_CLIENT_ID || info.email_verified !== "true") {
        return textResponse("Untrusted account", 403, cors);
      }

      const email = normalizeEmail(info.email);
      const admin = await getEventAdmin(env, eventId, email);
      if (!admin) return textResponse("Not authorized", 403, cors);

      // Create session
      const token = generateSessionToken();
      const expires = new Date(Date.now() + 30 * 60 * 1000).toISOString();

      await env.DB.prepare(`
        INSERT INTO event_admin_sessions
          (token, event_id, email, expires_at, created_at, provider)
        VALUES (?, ?, ?, ?, ?, 'google')
      `)
        .bind(token, eventId, email, expires, new Date().toISOString())
        .run();

      // Cookie + redirect to gallery (same site as the worker domain)
      return new Response(null, {
        status: 302,
        headers: {
          ...securityHeaders,
          "Set-Cookie": `admin_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1800`,
          "Location": `/gallery.html?eventId=${encodeURIComponent(eventId)}`,
        },
      });
    }

    // ==============================
    // EVENT ADMIN LOGOUT
    // POST /api/event-admin/logout
    // ==============================
    if (req.method === "POST" && url.pathname === "/api/event-admin/logout") {
      const ok = await rateLimit(env, `admin-logout:${ip}`, 60, 60);
      if (!ok) return textResponse("Too many requests", 429, cors);

      const token = getCookie(req, "admin_session");
      if (token) {
        await env.DB.prepare("DELETE FROM event_admin_sessions WHERE token = ?")
          .bind(token)
          .run();
      }

      return new Response(null, {
        status: 204,
        headers: {
          ...securityHeaders,
          ...cors,
          "Set-Cookie": "admin_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
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
      const eventId = clamp(body?.eventId, 64);
      if (!eventId) return jsonResponse({ error: "eventId required" }, 400, cors);

      const sess = await requireAdminSession(env, req, eventId);
      if (!sess) return jsonResponse({ error: "Unauthorized" }, 401, cors);

      const list = await env.EVENT_BUCKET.list({ prefix: `${eventId}/` });
      const files = (list.objects || []).map(o => ({
        name: o.key.split("/")[1] || o.key,
        size: o.size,
        uploaded: o.uploaded,
      }));

      return jsonResponse({ files }, 200, cors);
    }

    // ==============================
    // CREATE EVENT (TEMP: public)
    // POST /api/create-event  { name, owner }
    // ==============================
    if (req.method === "POST" && url.pathname === "/api/create-event") {
      const ok = await rateLimit(env, `create-event:${ip}`, 20, 60);
      if (!ok) return jsonResponse({ error: "Too many requests" }, 429, cors);

      const body = await req.json().catch(() => null);
      const name = clamp(body?.name, 120);
      const owner = normalizeEmail(body?.owner);

      if (!name || !owner) return jsonResponse({ error: "name and owner required" }, 400, cors);

      const eventId = "EVT-" + crypto.randomUUID().slice(0, 8);
      const createdAt = new Date().toISOString();

      await env.DB.prepare(
        "INSERT INTO events (id, name, owner, created_at, active) VALUES (?, ?, ?, ?, 1)"
      )
        .bind(eventId, name, owner, createdAt)
        .run();

      return jsonResponse({ eventId }, 200, cors);
    }

    // ==============================
    // LIST EVENTS (TEMP: public)
    // GET /api/list-events?owner=email
    // ==============================
    if (req.method === "GET" && url.pathname === "/api/list-events") {
      const ok = await rateLimit(env, `list-events:${ip}`, 60, 60);
      if (!ok) return jsonResponse({ error: "Too many requests" }, 429, cors);

      const owner = normalizeEmail(url.searchParams.get("owner"));
      if (!owner) return jsonResponse({ error: "owner required" }, 400, cors);

      const result = await env.DB.prepare(
        "SELECT id, name, owner, created_at, active FROM events WHERE owner = ? ORDER BY created_at DESC"
      )
        .bind(owner)
        .all();

      return jsonResponse({ events: result.results || [] }, 200, cors);
    }

    // ==============================
    // GET EVENT DETAILS (public)
    // GET /api/get-event?eventId=EVT-XXXX
    // ==============================
    if (req.method === "GET" && url.pathname === "/api/get-event") {
      const ok = await rateLimit(env, `get-event:${ip}`, 120, 60);
      if (!ok) return jsonResponse({ error: "Too many requests" }, 429, cors);

      const eventId = clamp(url.searchParams.get("eventId"), 64);
      if (!eventId) return jsonResponse({ error: "eventId required" }, 400, cors);

      const ev = await getEvent(env, eventId);
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

      const eventId = clamp(url.searchParams.get("eventId"), 64);
      const file = clamp(url.searchParams.get("file"), 200);

      if (!eventId || !file) return textResponse("Missing eventId or file", 400, cors);
      if (file.includes("..")) return textResponse("Invalid file", 400, cors);

      const obj = await env.EVENT_BUCKET.get(`${eventId}/${file}`);
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
      const eventId = clamp(formData.get("eventId"), 64);

      if (!file || !eventId) return textResponse("Missing fields", 400, cors);

      const ev = await getEvent(env, eventId);
      if (!ev?.active) return textResponse("Event not found or inactive", 403, cors);

      const bytes = await file.arrayBuffer();
      const extRaw = (file.name || "").split(".").pop() || "bin";
      const ext = extRaw.toLowerCase().replace(/[^a-z0-9]/g, "");
      const cleanName = `${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`;
      const key = `${eventId}/${cleanName}`;

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
