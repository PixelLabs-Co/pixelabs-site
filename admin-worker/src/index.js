// Pixel Labs portfolio admin — Cloudflare Worker
//
// Serves the admin page and a small API at admin.pixelabs.co.
//
// Security model
//  - Cloudflare Access sits in front of this Worker and handles login
//    (one-time code to an allowed email). No password lives in code.
//  - Every request is ALSO verified here: the Access JWT's signature,
//    audience, issuer and expiry are checked, and the email must be in
//    ALLOWED_EMAILS. If Access were misconfigured or bypassed, requests
//    are still refused.
//  - The Cloudinary API secret stays on the server (a Worker secret). The
//    browser only ever receives one-time upload signatures.
//
// Configuration (Cloudflare dashboard → Worker → Settings → Variables and Secrets)
//   CLOUDINARY_CLOUD_NAME   plain text (set in wrangler.toml)
//   CLOUDINARY_API_KEY      secret
//   CLOUDINARY_API_SECRET   secret
//   ACCESS_TEAM_DOMAIN      plain text, e.g. "yourteam.cloudflareaccess.com"
//   ACCESS_AUD              plain text, the Access application's "Application Audience (AUD) Tag"
//   ALLOWED_EMAILS          plain text, comma-separated, e.g. "you@icloud.com"

import ADMIN_HTML from './admin.html';

const PORTFOLIO_TAG = 'pixelabs';
const HIDDEN_TAG = 'pl_hidden';
const VIDEO_LINK_TAG = 'video-link';
const FOLDER = 'pixelabs-portfolio';
const UPLOAD_CATEGORIES = ['photography', 'graphic-design', 'web-design'];
const VIDEO_CATEGORIES = ['video', 'photography', 'graphic-design', 'web-design'];
const MAX_TITLE = 120;

export default {
  async fetch(request, env) {
    try {
      const configError = checkConfig(env);
      if (configError) return json({ error: configError }, 500);

      const user = await verifyAccess(request, env);
      if (!user) return json({ error: 'Not authorized' }, 403);

      const url = new URL(request.url);
      const route = `${request.method} ${url.pathname}`;

      // Mutating requests must come from this page (CSRF defense on top of
      // Access's SameSite cookie).
      if (request.method === 'POST' && !sameOrigin(request, url)) {
        return json({ error: 'Bad origin' }, 403);
      }

      switch (route) {
        case 'GET /':
        case 'GET /index.html':
          return new Response(ADMIN_HTML, {
            headers: {
              'Content-Type': 'text/html; charset=utf-8',
              'Cache-Control': 'no-store',
              'X-Frame-Options': 'DENY',
              'Referrer-Policy': 'same-origin',
              'X-Robots-Tag': 'noindex, nofollow',
            },
          });
        case 'GET /api/items':
          return json({ user, items: await listItems(env) });
        case 'POST /api/sign-upload':
          return json(await signUpload(await readJson(request), env));
        case 'POST /api/add-video':
          return json(await addVideo(await readJson(request), env));
        case 'POST /api/remove':
          return json(await removeItem(await readJson(request), env));
        default:
          return json({ error: 'Not found' }, 404);
      }
    } catch (err) {
      const status = err instanceof HttpError ? err.status : 500;
      if (status === 500) console.error(err);
      return json({ error: status === 500 ? 'Server error' : err.message }, status);
    }
  },
};

// ── Access (login) verification ─────────────────────────────────

let certCache = { keys: null, fetchedAt: 0 };

async function getAccessKeys(teamDomain, force = false) {
  const fresh = Date.now() - certCache.fetchedAt < 60 * 60 * 1000;
  if (certCache.keys && fresh && !force) return certCache.keys;
  const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
  if (!res.ok) throw new Error(`Could not fetch Access certs (${res.status})`);
  const { keys } = await res.json();
  certCache = { keys, fetchedAt: Date.now() };
  return keys;
}

// Returns the signed-in email, or null if the request isn't authorized.
export async function verifyAccess(request, env, now = Date.now()) {
  const token =
    request.headers.get('Cf-Access-Jwt-Assertion') ||
    getCookie(request.headers.get('Cookie'), 'CF_Authorization');
  if (!token) return null;

  const parts = token.split('.');
  if (parts.length !== 3) return null;
  let header, payload;
  try {
    header = JSON.parse(b64urlToString(parts[0]));
    payload = JSON.parse(b64urlToString(parts[1]));
  } catch {
    return null;
  }
  if (header.alg !== 'RS256' || !header.kid) return null;

  let keys = await getAccessKeys(env.ACCESS_TEAM_DOMAIN);
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    // Keys rotate; refetch once before giving up.
    keys = await getAccessKeys(env.ACCESS_TEAM_DOMAIN, true);
    jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) return null;
  }

  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    b64urlToBytes(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  );
  if (!valid) return null;

  const nowSec = Math.floor(now / 1000);
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(env.ACCESS_AUD)) return null;
  if (payload.iss !== `https://${env.ACCESS_TEAM_DOMAIN}`) return null;
  if (typeof payload.exp !== 'number' || payload.exp < nowSec) return null;
  if (typeof payload.nbf === 'number' && payload.nbf > nowSec + 60) return null;

  const email = String(payload.email || '').toLowerCase();
  const allowed = String(env.ALLOWED_EMAILS || '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
  if (!email || !allowed.includes(email)) return null;
  return email;
}

// ── Cloudinary operations ────────────────────────────────────────

async function listItems(env) {
  const types = ['image', 'video'];
  const results = await Promise.all(types.map((t) => listByTag(env, t)));
  return results
    .flat()
    .filter((r) => !(r.tags || []).includes(HIDDEN_TAG))
    .map((r) => toItem(r, env))
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
}

async function listByTag(env, resourceType) {
  const out = [];
  let cursor = null;
  do {
    const qs = new URLSearchParams({ tags: 'true', context: 'true', max_results: '500' });
    if (cursor) qs.set('next_cursor', cursor);
    const res = await fetch(
      `https://api.cloudinary.com/v1_1/${env.CLOUDINARY_CLOUD_NAME}/resources/${resourceType}/tags/${PORTFOLIO_TAG}?${qs}`,
      { headers: { Authorization: 'Basic ' + btoa(`${env.CLOUDINARY_API_KEY}:${env.CLOUDINARY_API_SECRET}`) } }
    );
    if (res.status === 404) return out; // no resources of this type yet
    if (!res.ok) throw new Error(`Cloudinary list failed (${res.status}): ${await res.text()}`);
    const data = await res.json();
    out.push(...(data.resources || []));
    cursor = data.next_cursor || null;
  } while (cursor);
  return out;
}

function toItem(r, env) {
  const custom = (r.context && r.context.custom) || {};
  const tags = r.tags || [];
  const known = ['photography', 'graphic-design', 'video', 'web-design'];
  const base = `https://res.cloudinary.com/${env.CLOUDINARY_CLOUD_NAME}/${r.resource_type}/upload`;
  return {
    public_id: r.public_id,
    resource_type: r.resource_type,
    title: custom.title || r.public_id.split('/').pop(),
    category: custom.category || tags.find((t) => known.includes(t)) || 'photography',
    platform: custom.platform || null,
    is_video_link: tags.includes(VIDEO_LINK_TAG),
    thumb:
      r.resource_type === 'video'
        ? `${base}/so_0,w_400,c_limit/${r.public_id}.jpg`
        : `${base}/w_400,c_limit,f_auto,q_auto/${r.public_id}`,
    created_at: r.created_at,
  };
}

async function signUpload(body, env) {
  const title = cleanTitle(body.title);
  const category = pick(body.category, UPLOAD_CATEGORIES, 'category');
  const params = {
    context: contextString({ title, category }),
    folder: FOLDER,
    tags: `${PORTFOLIO_TAG},${category}`,
    timestamp: String(Math.floor(Date.now() / 1000)),
  };
  return {
    upload_url: `https://api.cloudinary.com/v1_1/${env.CLOUDINARY_CLOUD_NAME}/auto/upload`,
    api_key: env.CLOUDINARY_API_KEY,
    params,
    signature: await cloudinarySignature(params, env.CLOUDINARY_API_SECRET),
  };
}

export function parseVideoUrl(raw) {
  let u;
  try {
    u = new URL(String(raw || '').trim());
  } catch {
    return null;
  }
  const host = u.hostname.replace(/^www\.|^m\./, '');
  let id = null;
  if (host === 'youtube.com') {
    id = u.pathname === '/watch' ? u.searchParams.get('v') : (u.pathname.match(/^\/(?:shorts|embed)\/([\w-]{11})/) || [])[1];
  } else if (host === 'youtu.be') {
    id = u.pathname.slice(1, 12);
  }
  if (id && /^[\w-]{11}$/.test(id)) {
    return {
      platform: 'youtube',
      id,
      embed: `https://www.youtube.com/embed/${id}`,
      thumb: `https://img.youtube.com/vi/${id}/hqdefault.jpg`,
    };
  }
  if (host === 'vimeo.com' || host === 'player.vimeo.com') {
    const m = u.pathname.match(/(?:^|\/)(\d{5,})(?:\/|$)/);
    if (m) {
      return {
        platform: 'vimeo',
        id: m[1],
        embed: `https://player.vimeo.com/video/${m[1]}`,
        thumb: `https://vumbnail.com/${m[1]}.jpg`,
      };
    }
  }
  return null;
}

async function addVideo(body, env) {
  const title = cleanTitle(body.title);
  const category = pick(body.category, VIDEO_CATEGORIES, 'category');
  const video = parseVideoUrl(body.url);
  if (!video) throw new HttpError(400, 'Invalid URL — paste a YouTube or Vimeo link.');

  const params = {
    context: contextString({
      title,
      category,
      embed: video.embed,
      platform: video.platform,
      original_url: String(body.url).trim().slice(0, 300),
    }),
    folder: FOLDER,
    tags: `${PORTFOLIO_TAG},${category},${VIDEO_LINK_TAG}`,
    timestamp: String(Math.floor(Date.now() / 1000)),
  };
  const form = new FormData();
  for (const [k, v] of Object.entries(params)) form.append(k, v);
  form.append('file', video.thumb);
  form.append('api_key', env.CLOUDINARY_API_KEY);
  form.append('signature', await cloudinarySignature(params, env.CLOUDINARY_API_SECRET));

  const res = await fetch(`https://api.cloudinary.com/v1_1/${env.CLOUDINARY_CLOUD_NAME}/image/upload`, {
    method: 'POST',
    body: form,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new HttpError(502, (data.error && data.error.message) || 'Could not save video.');
  return { public_id: data.public_id };
}

async function removeItem(body, env) {
  const publicId = String(body.public_id || '');
  if (!publicId || publicId.length > 255) throw new HttpError(400, 'Missing item id.');
  const resourceType = pick(body.resource_type || 'image', ['image', 'video'], 'resource type');

  // Only allow hiding items that are actually part of the portfolio.
  const check = await fetch(
    `https://api.cloudinary.com/v1_1/${env.CLOUDINARY_CLOUD_NAME}/resources/${resourceType}/upload/${publicId
      .split('/')
      .map(encodeURIComponent)
      .join('/')}`,
    { headers: { Authorization: 'Basic ' + btoa(`${env.CLOUDINARY_API_KEY}:${env.CLOUDINARY_API_SECRET}`) } }
  );
  if (check.status === 404) throw new HttpError(404, 'Item not found.');
  if (!check.ok) throw new Error(`Cloudinary lookup failed (${check.status})`);
  const resource = await check.json();
  if (!(resource.tags || []).includes(PORTFOLIO_TAG)) throw new HttpError(400, 'Not a portfolio item.');

  // Tag as hidden (reversible) — the public site already filters this tag out.
  const params = {
    command: 'add',
    public_ids: publicId,
    tag: HIDDEN_TAG,
    timestamp: String(Math.floor(Date.now() / 1000)),
  };
  const res = await fetch(`https://api.cloudinary.com/v1_1/${env.CLOUDINARY_CLOUD_NAME}/${resourceType}/tags`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      command: params.command,
      public_ids: [publicId],
      tag: params.tag,
      timestamp: params.timestamp,
      api_key: env.CLOUDINARY_API_KEY,
      signature: await cloudinarySignature(params, env.CLOUDINARY_API_SECRET),
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new HttpError(502, (data.error && data.error.message) || 'Could not remove item.');
  return { removed: publicId };
}

// ── Helpers ──────────────────────────────────────────────────────

// Cloudinary signature: SHA-1 of "k1=v1&k2=v2..." (keys sorted, raw values)
// followed by the API secret, hex-encoded.
export async function cloudinarySignature(params, secret) {
  const toSign = Object.keys(params)
    .filter((k) => params[k] !== undefined && params[k] !== null && params[k] !== '')
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join('&');
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(toSign + secret));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Cloudinary context values must escape "|" and "=".
export function contextString(obj) {
  return Object.entries(obj)
    .map(([k, v]) => `${k}=${String(v).replace(/([|=])/g, '\\$1')}`)
    .join('|');
}

function cleanTitle(v) {
  const t = String(v || '').replace(/[\u0000-\u001f]/g, ' ').trim();
  if (!t) throw new HttpError(400, 'Please enter a title.');
  if (t.length > MAX_TITLE) throw new HttpError(400, `Title must be ${MAX_TITLE} characters or fewer.`);
  return t;
}

function pick(v, allowed, name) {
  if (!allowed.includes(v)) throw new HttpError(400, `Invalid ${name}.`);
  return v;
}

function checkConfig(env) {
  const required = [
    'CLOUDINARY_CLOUD_NAME',
    'CLOUDINARY_API_KEY',
    'CLOUDINARY_API_SECRET',
    'ACCESS_TEAM_DOMAIN',
    'ACCESS_AUD',
    'ALLOWED_EMAILS',
  ];
  const missing = required.filter((k) => !env[k]);
  return missing.length ? `Admin is not configured yet. Missing: ${missing.join(', ')}` : null;
}

function sameOrigin(request, url) {
  const origin = request.headers.get('Origin');
  return origin === url.origin;
}

async function readJson(request) {
  const len = Number(request.headers.get('Content-Length') || 0);
  if (len > 10_000) throw new HttpError(413, 'Request too large.');
  try {
    return await request.json();
  } catch {
    throw new HttpError(400, 'Invalid JSON.');
  }
}

function getCookie(header, name) {
  if (!header) return null;
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return rest.join('=');
  }
  return null;
}

function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
function b64urlToString(s) {
  return new TextDecoder().decode(b64urlToBytes(s));
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
