# Nodes server deployment

- Source: https://github.com/lichao199208/Nodes (desensitized fork of kingenbomb/Nodes)
- Commit: `1216835354d0c68b768b59ce137b75f40fe3e9ac`
- Install root: `/opt/nodes`
- Image: `nodes:1216835-yunxin4-dashboard`
- Interactive launcher: `/usr/local/bin/nodes`

The project provides both an interactive CLI and an authenticated Web dashboard.
CLI browser mode runs Chromium in an isolated Xvfb display. Generated accounts,
proxy data, and Web task state persist under `/opt/nodes/data`.

Before the first registration run, edit `/opt/nodes/config.local.json` and set a
valid `yyds_api_key`. The file is mode `0600` and mounted read-only in the
container.

## Linux compatibility patch

Chromium 152 rejects the repository's Manifest V2 extension. The server release
keeps the original as `turnstilePatch/manifest.json.upstream-v2` and uses a
Manifest V3 declaration with the same content script in the page's main world.
No registration logic was changed.

The image uses a small entrypoint that starts Xvfb and waits for its Unix socket.
This avoids the `xvfb-run` readiness-signal hang observed on the server's CentOS 7
kernel.

## Mail provider

The `yunxin1` release adds the self-hosted Yunxin HTTPS mail API as the active
provider while retaining YYDS compatibility. The API key is stored only in
`/opt/nodes/config.local.json` with mode `0600`.

## Turnstile provider

The `yunxin2-2captcha` release uses the 2Captcha API v2 proxyless Turnstile
task by default. It sends the ProxyScrape sign-up URL and sitekey to
`createTask`, then polls `getTaskResult` every five seconds. The original
browser solver remains available with `captcha_provider: browser`.

The 2Captcha key is stored only in `/opt/nodes/config.local.json` with mode
`0600`; environment variables can override all captcha settings.

## Premium trial onboarding

ProxyScrape no longer creates a Premium DC subaccount as a side effect of email
verification. After verification, the client checks trial eligibility, claims
the free trial once, refreshes `/me`, and then downloads the 100 proxies from
the newly created subaccount. An already claimed trial is never claimed again.

## Web dashboard

The `yunxin4-dashboard` release adds an authenticated responsive dashboard.
It supports starting one task at a time, live task progress, redacted account
status, protected credential-file downloads, and task history. State-changing
requests require a session-bound CSRF token. Login failures are rate limited,
cookies are Secure/HttpOnly/SameSite=Strict, and access tokens never appear in
JSON APIs.

Gunicorn runs as a single worker with eight threads so the in-process task store
has one owner. Nginx terminates TLS on port `8443` without changing the existing
port `443` site.

## 2026-09-17 deployment record

- Active release: `/opt/nodes/releases/1216835-yunxin4-dashboard`
- Previous release: `/opt/nodes/releases/1216835-yunxin3-onboarding`
- Image: `nodes:1216835-yunxin4-dashboard`
- Dashboard: `https://YOUR_DASHBOARD_HOST:8443`
- Automated tests: 16 passed inside the Linux image
- Browser tests: desktop and 390x844 mobile viewports both passed against the
  public HTTPS deployment; navigation, form states, and horizontal overflow were
  checked without starting a real registration task
- Security validation: TLS verified; unauthenticated API returned 401; session
  cookie included Secure, HttpOnly, and SameSite=Strict; CSP and no-store were
  present; invalid CSRF-protected task input was rejected
- End-to-end validation: the first Turnstile token was rejected upstream and the
  built-in retry succeeded with the second token
- Registration validation: one account registered, received its mail code, and
  completed email verification
- Onboarding validation: the free Premium DC trial was claimed, an `AccountID`
  was created, and 100 unique HTTP proxy URLs were exported
- Credential-bearing account and proxy output files are created with mode `0600`
- Validation outputs: `account/accounts_20260917_131641.jsonl` and
  `node/proxies_20260917_131641.txt`

Run:

```bash
nodes
```

Rollback or removal:

```bash
cd /opt/nodes
docker compose stop dashboard dashboard-proxy
docker compose rm -f dashboard dashboard-proxy
cp backups/pre-dashboard-20260917215500/compose.yml compose.yml
cp backups/pre-dashboard-20260917215500/config.local.json config.local.json
chmod 600 config.local.json
ln -sfn releases/1216835-yunxin3-onboarding current
```
