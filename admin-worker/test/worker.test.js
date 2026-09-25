// Run with: node --test test/
// Loads src/index.js with the HTML import stubbed, then exercises auth and
// Cloudinary signing against a fake Access key and a mocked fetch.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
let mod, dir;
const TEAM = 'pixellabs.cloudflareaccess.com';
const AUD = 'test-aud-123';
const env = {
  CLOUDINARY_CLOUD_NAME: 'pixellabs',
  CLOUDINARY_API_KEY: 'key123',
  CLOUDINARY_API_SECRET: 'abcd',
  ACCESS_TEAM_DOMAIN: TEAM,
  ACCESS_AUD: AUD,
  ALLOWED_EMAILS: 'Owner@icloud.com, second@example.com',
};

let keyPair, jwk, otherKeyPair;
const calls = [];
const realFetch = globalThis.fetch;

before(async () => {
  const src = await readFile(join(here, '../src/index.js'), 'utf8');
  dir = await mkdtemp(join(tmpdir(), 'plw-'));
  const file = join(dir, 'index.mjs');
  await writeFile(file, src.replace("import ADMIN_HTML from './admin.html';", "const ADMIN_HTML = '<html>admin</html>';"));
  mod = await import(file);

  const gen = () =>
    crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify']
    );
  keyPair = await gen();
  otherKeyPair = await gen();
  jwk = { ...(await crypto.subtle.exportKey('jwk', keyPair.publicKey)), kid: 'k1' };

  globalThis.fetch = async (url, init = {}) => {
    url = String(url);
    calls.push({ url, init });
    if (url === `https://${TEAM}/cdn-cgi/access/certs`) return Response.json({ keys: [jwk] });
    if (url.includes('/resources/image/tags/pixelabs'))
      return Response.json({
        resources: [
          { public_id: 'pixelabs-portfolio/a', resource_type: 'image', tags: ['pixelabs', 'photography'], context: { custom: { title: 'A', category: 'photography' } }, created_at: '2026-01-01T00:00:00Z' },
          { public_id: 'pixelabs-portfolio/hidden', resource_type: 'image', tags: ['pixelabs', 'pl_hidden'], created_at: '2026-02-01T00:00:00Z' },
          { public_id: 'yt', resource_type: 'image', tags: ['pixelabs', 'video', 'video-link'], context: { custom: { title: 'Film', category: 'video', platform: 'youtube' } }, created_at: '2026-03-01T00:00:00Z' },
        ],
      });
    if (url.includes('/resources/video/tags/pixelabs')) return new Response('{}', { status: 404 });
    if (url.includes('/resources/image/upload/pixelabs-portfolio/a')) return Response.json({ tags: ['pixelabs'] });
    if (url.includes('/resources/image/upload/other')) return Response.json({ tags: ['something-else'] });
    if (url.endsWith('/image/tags')) return Response.json({ public_ids: ['x'] });
    if (url.endsWith('/image/upload')) return Response.json({ public_id: 'new-video' });
    return new Response('unexpected ' + url, { status: 500 });
  };
});

after(async () => {
  globalThis.fetch = realFetch;
  await rm(dir, { recursive: true, force: true });
});

const b64url = (buf) => Buffer.from(buf).toString('base64url');
async function makeJwt(payload, { key = keyPair.privateKey, kid = 'k1' } = {}) {
  const h = b64url(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT' }));
  const p = b64url(JSON.stringify(payload));
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(sig)}`;
}
const now = () => Math.floor(Date.now() / 1000);
const good = (over = {}) => ({ aud: [AUD], iss: `https://${TEAM}`, email: 'owner@icloud.com', exp: now() + 600, iat: now(), ...over });

function req(path, { token, method = 'GET', body, origin = 'https://admin.pixelabs.co' } = {}) {
  const headers = {};
  if (token) headers['Cf-Access-Jwt-Assertion'] = token;
  if (body) headers['Content-Type'] = 'application/json';
  if (method === 'POST' && origin) headers['Origin'] = origin;
  return new Request('https://admin.pixelabs.co' + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
}

test('Cloudinary signature matches documented example', async () => {
  // From Cloudinary's "Generating authentication signatures" docs.
  const sig = await mod.cloudinarySignature(
    { eager: 'w_400,h_300,c_pad|w_260,h_200,c_crop', public_id: 'sample_image', timestamp: '1315060510' },
    'abcd'
  );
  assert.equal(sig, 'bfd09f95f331f558cbd1320e67aa8d488770583e');
});

test('rejects requests with no token', async () => {
  const res = await mod.default.fetch(req('/'), env);
  assert.equal(res.status, 403);
});

test('rejects bad tokens: wrong key, wrong aud, expired, wrong issuer, unlisted email, garbage', async () => {
  const bad = [
    await makeJwt(good(), { key: otherKeyPair.privateKey }),
    await makeJwt(good({ aud: ['other'] })),
    await makeJwt(good({ exp: now() - 10 })),
    await makeJwt(good({ iss: 'https://evil.cloudflareaccess.com' })),
    await makeJwt(good({ email: 'stranger@example.com' })),
    await makeJwt(good(), { kid: 'unknown' }),
    'not.a.jwt',
    'garbage',
  ];
  for (const token of bad) {
    const res = await mod.default.fetch(req('/api/items', { token }), env);
    assert.equal(res.status, 403, `token should be rejected: ${token.slice(0, 30)}`);
  }
});

test('refuses to run if not configured', async () => {
  const res = await mod.default.fetch(req('/'), { ...env, ACCESS_AUD: '' });
  assert.equal(res.status, 500);
  assert.match((await res.json()).error, /ACCESS_AUD/);
});

test('serves admin page to an allowed user (email case-insensitive)', async () => {
  const token = await makeJwt(good({ email: 'OWNER@icloud.com' }));
  const res = await mod.default.fetch(req('/', { token }), env);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), '<html>admin</html>');
  assert.equal(res.headers.get('X-Frame-Options'), 'DENY');
});

test('also accepts the CF_Authorization cookie', async () => {
  const token = await makeJwt(good());
  const r = new Request('https://admin.pixelabs.co/', { headers: { Cookie: `foo=1; CF_Authorization=${token}` } });
  assert.equal((await mod.default.fetch(r, env)).status, 200);
});

test('lists items, hiding pl_hidden ones, newest first', async () => {
  const token = await makeJwt(good());
  const res = await mod.default.fetch(req('/api/items', { token }), env);
  const data = await res.json();
  assert.equal(res.status, 200);
  assert.equal(data.user, 'owner@icloud.com');
  assert.deepEqual(data.items.map((i) => i.public_id), ['yt', 'pixelabs-portfolio/a']);
  assert.equal(data.items[0].is_video_link, true);
  const listCall = calls.find((c) => c.url.includes('/resources/image/tags/pixelabs'));
  assert.equal(listCall.init.headers.Authorization, 'Basic ' + btoa('key123:abcd'));
});

test('sign-upload returns a valid signature and never leaks the secret', async () => {
  const token = await makeJwt(good());
  const res = await mod.default.fetch(
    req('/api/sign-upload', { token, method: 'POST', body: { title: 'Logo | v=2', category: 'graphic-design' } }),
    env
  );
  const text = await res.text();
  assert.equal(res.status, 200);
  assert.ok(!text.includes('abcd'), 'secret must not be in response');
  const data = JSON.parse(text);
  assert.equal(data.params.context, 'title=Logo \\| v\\=2|category=graphic-design');
  assert.equal(data.params.tags, 'pixelabs,graphic-design');
  assert.equal(data.params.folder, 'pixelabs-portfolio');
  assert.equal(data.signature, await mod.cloudinarySignature(data.params, 'abcd'));
  assert.equal(data.api_key, 'key123');
});

test('sign-upload validates input', async () => {
  const token = await makeJwt(good());
  for (const body of [{ title: '', category: 'photography' }, { title: 'x', category: 'evil' }, { title: 'x'.repeat(200), category: 'photography' }]) {
    const res = await mod.default.fetch(req('/api/sign-upload', { token, method: 'POST', body }), env);
    assert.equal(res.status, 400);
  }
});

test('POST from another origin is refused (CSRF)', async () => {
  const token = await makeJwt(good());
  for (const origin of ['https://evil.example', null]) {
    const res = await mod.default.fetch(
      req('/api/remove', { token, method: 'POST', origin, body: { public_id: 'pixelabs-portfolio/a' } }),
      env
    );
    assert.equal(res.status, 403);
  }
});

test('remove tags a portfolio item as hidden with a signed request', async () => {
  const token = await makeJwt(good());
  calls.length = 0;
  const res = await mod.default.fetch(
    req('/api/remove', { token, method: 'POST', body: { public_id: 'pixelabs-portfolio/a', resource_type: 'image' } }),
    env
  );
  assert.equal(res.status, 200);
  const tagCall = calls.find((c) => c.url.endsWith('/image/tags'));
  const body = JSON.parse(tagCall.init.body);
  assert.deepEqual(body.public_ids, ['pixelabs-portfolio/a']);
  assert.equal(body.tag, 'pl_hidden');
  assert.equal(
    body.signature,
    await mod.cloudinarySignature({ command: 'add', public_ids: 'pixelabs-portfolio/a', tag: 'pl_hidden', timestamp: body.timestamp }, 'abcd')
  );
});

test('remove refuses non-portfolio assets', async () => {
  const token = await makeJwt(good());
  const res = await mod.default.fetch(req('/api/remove', { token, method: 'POST', body: { public_id: 'other' } }), env);
  assert.equal(res.status, 400);
});

test('video URL parsing', () => {
  assert.equal(mod.parseVideoUrl('https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=1').id, 'dQw4w9WgXcQ');
  assert.equal(mod.parseVideoUrl('https://youtu.be/dQw4w9WgXcQ').id, 'dQw4w9WgXcQ');
  assert.equal(mod.parseVideoUrl('https://youtube.com/shorts/dQw4w9WgXcQ').id, 'dQw4w9WgXcQ');
  assert.equal(mod.parseVideoUrl('https://vimeo.com/76979871').embed, 'https://player.vimeo.com/video/76979871');
  assert.equal(mod.parseVideoUrl('https://evil.com/?v=dQw4w9WgXcQ'), null);
  assert.equal(mod.parseVideoUrl('javascript:alert(1)'), null);
});

test('add-video uploads the thumbnail with a signed request', async () => {
  const token = await makeJwt(good());
  calls.length = 0;
  const res = await mod.default.fetch(
    req('/api/add-video', { token, method: 'POST', body: { url: 'https://youtu.be/dQw4w9WgXcQ', title: 'Film', category: 'video' } }),
    env
  );
  assert.equal(res.status, 200);
  const up = calls.find((c) => c.url.endsWith('/image/upload'));
  const form = up.init.body;
  assert.equal(form.get('file'), 'https://img.youtube.com/vi/dQw4w9WgXcQ/hqdefault.jpg');
  assert.equal(form.get('tags'), 'pixelabs,video,video-link');
  const params = Object.fromEntries(['context', 'folder', 'tags', 'timestamp'].map((k) => [k, form.get(k)]));
  assert.equal(form.get('signature'), await mod.cloudinarySignature(params, 'abcd'));
});

test('unknown routes 404', async () => {
  const token = await makeJwt(good());
  assert.equal((await mod.default.fetch(req('/nope', { token }), env)).status, 404);
});
