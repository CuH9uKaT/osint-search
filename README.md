# OSINT Search — final

Flask + pinned Sherlock 0.16.0 web UI for checking a username against public sites in the bundled `data.json`.

## What is already protected

- Background Job + live polling results
- Server-side STOP using the Sherlock process group
- Session-bound jobs
- One global Sherlock job on the free Render service
- IP + session rate limiting
- Password authentication + CSRF
- Pinned local `data.json`; NSFW is excluded
- CSV / JSON / TXT export
- Mobile UI + PWA
- `/healthz` and `/api/diag`

## Search modes

- 📱 Social — curated social/profile platforms from the bundled catalog
- 💬 Community — forums and communities
- 🎮 Gaming — gaming platforms and trackers
- 💻 Developer — coding/dev/CTF/tech platforms
- 🌐 Full — every non-NSFW site in the bundled catalog

The displayed site counts come from the actual bundled `data.json`, not hard-coded totals.

## Mode-specific timeouts

| Mode | Site timeout | Overall timeout |
|---|---:|---:|
| Social | 10 s | 120 s |
| Community | 10 s | 150 s |
| Gaming | 10 s | 150 s |
| Developer | 12 s | 180 s |
| Full | 12 s | 240 s |

All values can be overridden in Render with `SOCIAL_SITE_TIMEOUT`, `SOCIAL_SEARCH_TIMEOUT`, etc.

## Sherlock workers note

`SHERLOCK_WORKERS` is accepted as a configuration value (default 20, capped at 40) for forward compatibility. **Sherlock 0.16.0 itself does not expose a `--workers` CLI option; its internal request pool is fixed at 20 workers.** The application therefore does not pass an unsupported flag. The diagnostic log reports both the requested value and the effective 20-worker value.

## Startup smoke test

On startup the service logs:

- Sherlock version
- `data.json` presence and SHA-256 prefix
- usable / excluded counts
- category counts
- requested/effective worker setting

If the catalog is missing or invalid, search endpoints return 503 instead of silently running with an unknown catalog.

## Render deployment

1. Connect the GitHub repository as a Render Docker Web Service.
2. Set `APP_PASSWORD` to a strong private password.
3. Keep the generated `SECRET_KEY`.
4. Leave the mode-specific defaults unless you have a reason to change them.
5. Health check: `/healthz`.
6. Pushes to `main` trigger a new deployment.

After deployment, open the site and start with **📱 Соцмережі**. Use **🌐 Повний** when you really need the full catalog; on the free Render plan it can take roughly 1–3 minutes and may be affected by cold starts and site-side blocking.

## Manual Render smoke test

After the first deployment:

1. Start a **Full** search.
2. Wait about 15 seconds.
3. Press **Стоп**.
4. Confirm that the status becomes **Скасовано** and already-found results remain.
5. Open **⚙️ Diagnostics** and confirm the catalog and Sherlock version are reported.

This STOP test must be performed on the actual Render service because process-group behaviour depends on the production process/container environment.

## Privacy / interpretation

A Sherlock match means the public page passed Sherlock's site-specific check. It does not prove that a particular account belongs to a particular person. Verify matches independently and use only information you are authorized to access.
