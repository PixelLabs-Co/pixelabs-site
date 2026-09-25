# Pixel Labs portfolio admin

A Cloudflare Worker that serves the portfolio admin at **admin.pixelabs.co**.

- **Login:** Cloudflare Access sends a one-time code to your email. No password is stored anywhere.
- **Server side:** The Worker keeps the Cloudinary API secret. It checks your login on every request, then signs uploads and removals.
- **Removing** an item tags it `pl_hidden` in Cloudinary, and the public site hides it for everyone. It's reversible: delete the tag in Cloudinary to bring the item back.

This folder is excluded from the GitHub Pages site (see `/_config.yml`).

## One-time setup

### 1. Cloudinary: lock down uploads
1. **Settings → API Keys**: copy your **API Key** and **API Secret**.
2. **Settings → Upload → Upload presets → `pl_default`**: change **Signing mode** to **Signed**, or delete the preset. Until you do, anyone can upload to your account.
3. **Settings → Security → Restricted media types**: make sure **Resource list** stays *unchecked*, because the public portfolio uses it.

### 2. Cloudflare: create the Worker from this repo
1. **Workers & Pages → Create → Import a repository** → pick `PixelLabs-Co/pixelabs-site`.
2. Set **Root directory** to `admin-worker`. The build and deploy commands can stay at their defaults (`npx wrangler deploy`).
3. Deploy. `wrangler.toml` attaches the Worker to `admin.pixelabs.co` and turns off the `workers.dev` address.

### 3. Cloudflare Access: add the login
1. **Zero Trust → Access → Applications → Add an application → Self-hosted**.
2. Application domain: `admin.pixelabs.co`.
3. Add a policy: **Action: Allow**, **Include → Emails →** your email address.
4. Login method: **One-time PIN** (the default).
5. Save, then open the application and copy its **Application Audience (AUD) Tag**.
6. Note your team domain: **Zero Trust → Settings → Custom Pages**, e.g. `yourteam.cloudflareaccess.com`.

### 4. Worker variables
**Workers & Pages → pixelabs-admin → Settings → Variables and Secrets**:

| Name | Type | Value |
|---|---|---|
| `CLOUDINARY_API_KEY` | Secret | from step 1 |
| `CLOUDINARY_API_SECRET` | Secret | from step 1 |
| `ACCESS_TEAM_DOMAIN` | Text | e.g. `yourteam.cloudflareaccess.com` |
| `ACCESS_AUD` | Text | AUD tag from step 3 |
| `ALLOWED_EMAILS` | Text | your email (comma-separate to add more) |

Then open **https://admin.pixelabs.co**. The Worker refuses every request until all five values are set.

## Development

```
npm test          # runs the tests in test/ (Node 20+, no install needed)
npm run deploy    # manual deploy with wrangler, if not using Git builds
```
