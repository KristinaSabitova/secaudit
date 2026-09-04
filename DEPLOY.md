# Deploying secaudit web

The stack is two containers: the FastAPI app (which also serves the dashboard)
and PostgreSQL. The app listens on loopback only; the host's existing reverse
proxy terminates TLS and forwards to it.

```
GitHub ──push webhook──┐
                       ▼
browser ──HTTPS──> reverse proxy ──> 127.0.0.1:8811 ──> app ──> postgres
                    (host)                              │
                                                        └──> git clone + audit backend
```

## Prerequisites on the server

- Docker with the compose plugin (`docker compose version`)
- A DNS record for the subdomain pointing at the host
- A reverse proxy already terminating TLS for the other services

## First deploy

1. Create the directory and secrets file **on the server**:

   ```sh
   sudo mkdir -p /srv/secaudit && sudo chown "$USER" /srv/secaudit
   cd /srv/secaudit
   ```

   Write `/srv/secaudit/.env` from `.env.example`. Generate the secrets there;
   they never leave the server and are never committed:

   ```sh
   echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)"     >> .env
   echo "GITHUB_WEBHOOK_SECRET=$(openssl rand -hex 32)" >> .env
   echo "ANTHROPIC_API_KEY=sk-ant-..."                  >> .env   # paste yours
   chmod 600 .env
   ```

2. From your laptop, check connectivity, then deploy:

   ```sh
   export SECAUDIT_SSH_HOST=kris@<server>
   ./deploy.sh --check
   ./deploy.sh
   ```

   `deploy.sh` rsyncs the working tree (never `.env`), rebuilds, restarts, and
   polls `/api/health` until the service answers.

3. Create a DNS **A record** for `secaudit.<domain>` pointing at the server,
   and wait for it to resolve. Certificate issuance fails without it:

   ```sh
   dig +short secaudit.<domain> A
   ```

4. Issue the certificate. With the certbot container this stack's proxy already
   uses, over the ACME webroot it serves on port 80:

   ```sh
   cd <proxy stack dir>
   docker compose run --rm certbot certonly \
     --webroot -w /var/www/certbot -d secaudit.<domain>
   ```

5. Add the server block to the proxy's nginx config.

   The proxy is itself a container on `PROXY_NETWORK`, which the app joins, so
   it reaches the app by container name. It must **not** use `127.0.0.1`: that
   is the proxy container's own loopback, not the host's.

   Two things below are easy to get wrong and both are security controls:

   * **`add_header` replaces, it does not accumulate.** A single `add_header`
     in this `server` block discards every header inherited from `http {}`.
     Whatever the set is, repeat it here in full.
   * **Rate limits belong on the dashboard too, not only on the webhook.** A
     `POST /api/audits` makes this server clone a repository and start an
     audit process, so writes are limited far more tightly than reads.

   ```nginx
   # At http level, next to the other upstreams:
   upstream secaudit { server secaudit-app:8000; }

   limit_req_zone $binary_remote_addr zone=secaudit_hook:1m rate=30r/m;
   # The dashboard polls every few seconds, so reads are loose; writes are the
   # ones that cost this server a clone and an audit, so they are keyed
   # separately and left empty (= not counted) for the read methods.
   map $request_method $secaudit_write_key {
       default   $binary_remote_addr;
       GET       "";
       HEAD      "";
   }
   limit_req_zone $secaudit_write_key zone=secaudit_write:1m rate=12r/m;
   limit_req_zone $binary_remote_addr zone=secaudit_web:1m  rate=240r/m;

   server {
       listen 443 ssl;
       http2 on;
       server_name secaudit.<domain>;

       ssl_certificate     /etc/letsencrypt/live/secaudit.<domain>/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/secaudit.<domain>/privkey.pem;
       ssl_protocols TLSv1.2 TLSv1.3;

       # The whole set, repeated here on purpose: one add_header in this block
       # drops everything inherited from http {}. The dashboard is served
       # entirely from web/static — no CDN, no remote fonts, no inline script
       # or style, and fetches only to /api on this same origin — so 'self' is
       # the whole policy.
       add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
       add_header X-Frame-Options "SAMEORIGIN" always;
       add_header X-Content-Type-Options "nosniff" always;
       add_header Referrer-Policy "strict-origin-when-cross-origin" always;
       add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
       add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'" always;

       # GitHub splits large deliveries, but a push with many commits still
       # goes past nginx's default 1m.
       client_max_body_size 5m;

       location = /api/webhook/github {
           limit_req zone=secaudit_hook burst=10 nodelay;
           proxy_pass http://secaudit;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $remote_addr;
           proxy_set_header X-Forwarded-Proto $scheme;
           proxy_read_timeout 30s;
       }

       location / {
           limit_req zone=secaudit_web   burst=60 nodelay;
           limit_req zone=secaudit_write burst=5  nodelay;
           proxy_pass http://secaudit;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $remote_addr;
           proxy_set_header X-Forwarded-Proto $scheme;
           proxy_read_timeout 60s;
       }
   }
   ```

   `X-Forwarded-Proto` is not decoration: without it the app sees plain HTTP
   from the proxy and issues the session cookie without the `Secure` flag. Set
   `SECAUDIT_PUBLIC_URL` as well, so neither that flag nor the OAuth callback
   is derived from a header the client sends.

   To publish only the webhook and keep the dashboard off the internet, replace
   the `location /` block above with `return 404;` and reach the dashboard over
   an SSH tunnel instead — see [Reaching the dashboard](#reaching-the-dashboard).

   Validate before reloading, so a typo cannot take the other sites down:

   ```sh
   docker exec <proxy container> nginx -t && docker exec <proxy container> nginx -s reload
   ```

   Verify the headers actually arrive, on a 200 and on a 404 — an `add_header`
   in the wrong block is silent:

   ```sh
   curl -sSI https://secaudit.<domain>/ | grep -i -E 'content-security|x-frame|nosniff'
   ```

## Subsequent deploys

```sh
./deploy.sh
```

Migrations run from the entrypoint on every start and are idempotent.

## Reaching the dashboard

The app binds to loopback on the server and the proxy publishes only the
webhook, so the dashboard is not exposed. Forward the port over SSH instead:

```sh
./deploy.sh --tunnel        # then open http://127.0.0.1:8811
```

That runs `ssh -N -L 8811:127.0.0.1:8811`, so the traffic never leaves the
encrypted connection and the UI stays off the public internet entirely.

## Connecting the GitHub webhook

In the repository: **Settings → Webhooks → Add webhook**.

| Field | Value |
| --- | --- |
| Payload URL | `https://secaudit.<domain>/api/webhook/github` |
| Content type | either works — `application/json` or `application/x-www-form-urlencoded` |
| Secret | the `GITHUB_WEBHOOK_SECRET` from the server's `.env` |
| Events | *Just the push event* |

GitHub sends a `ping` immediately; a green tick with `{"status":"pong"}` means
the signature checks out. If it shows 401, the secret does not match. A 503
means the app started without `GITHUB_WEBHOOK_SECRET` set.

Pushes to branches queue an audit. Tag pushes and branch deletions answer 200
with `{"status":"ignored"}` and do no work.

## Verifying a deployment

```sh
curl -s https://secaudit.<domain>/api/health
```

`status` is `ok` only when git is present, the database answers, and the audit
backend has credentials. `degraded` still serves, so check which flag is false.

To exercise the whole path, push a commit to a connected repository and watch
the audit appear on the dashboard, or submit a repository URL from the form.

## Running it on your own machine instead

`./run-local.sh` starts the dashboard on loopback with the `claude-code`
backend, so audits run through the `claude` binary already signed in on that
machine — a Claude subscription, no API key, nothing billed per audit. State
lives in `~/.secaudit/`.

That mode sets `SECAUDIT_SINGLE_USER`, which makes every request the named
owner and skips sign-in entirely. **It authenticates nobody**, so it is only
sound while the port stays on loopback; the hosted instance is the one with
accounts. A subscription cannot be used by the hosted instance at all: the
`claude` binary authenticates a person on a machine, not a server on their
behalf.

## Running a hosted instance's audits on your own machine

A Claude subscription authenticates a person on a machine, not a server on
their behalf, so the hosted instance can never use `claude-code` itself.
A **runner** bridges that: pick `claude-code` in the backend panel and the
server stops executing your audits, leaving them queued for a runner you
control. Nothing but the findings leaves your machine.

1. In the backend panel, choose `claude-code` and save, then
   **create runner token** — it is shown once and stored only as a hash.
2. On the machine that has `claude` signed in:

   ```sh
   export SECAUDIT_RUNNER_TOKEN=...
   ./secaudit-runner.py https://secaudit.<domain>
   ```

That token is also what the MCP server authenticates with (see the README): it
stands in for a browser session on the API, so it reaches everything that
account can reach, not just the runner endpoints. **delete runner token**
revokes it for both.

It polls every 15 seconds and audits only what belongs to your account; an
admin's runner also takes the ones a webhook queued, which belong to nobody.
A claim that goes stale (the machine slept, the process was killed) is handed
out again after 45 minutes, so an interrupted runner cannot strand an audit.

The obvious limit: audits only run while that machine is awake and the script
is running. Queued work waits, it does not fail.

## Choosing the audit backend

The usual way is the **backend panel in the dashboard**: paste an API key and
secaudit works with it. The backend is inferred from the key's prefix —
`sk-ant-…` selects `anthropic-api`, `sk-…` selects `openai-api` — or pick one
explicitly for Ollama and claude-code, which need no key.

The key is encrypted with `SECAUDIT_SECRET_KEY` before it is stored, is never
returned to the browser, and is republished to the audit process on restart.
Rotating `SECAUDIT_SECRET_KEY` makes an already-stored key unreadable; the
panel says so rather than failing silently, and you enter the key again.

**A Claude Pro or Max subscription is not an API credential**, and neither is
ChatGPT Plus. Those cover claude.ai and Claude Code; API access is billed
separately and issued from the provider's console. The only backend that runs
on a subscription is `claude-code`, which shells out to a `claude` binary
already logged in on that machine — workable for a local or single-user
install, not for a hosted service.

`SECAUDIT_BACKEND` and friends in `.env` still work and act as the deployment
default; whatever is saved from the dashboard takes precedence. `/api/health`
reports whether the effective choice is usable — naming the missing variable,
or the Ollama URL it could not reach.

For the free, local option, three things have to line up. Ollama needs a
**generative** model pulled: an embeddings model such as `bge-m3` will make the
backend report as unready, because it cannot produce findings. `SECAUDIT_OLLAMA_URL`
has to be reachable **from inside the container**, so `localhost` never works —
use `http://host.docker.internal:11434` for an Ollama on the host, or the
container name if it shares a docker network with this stack. And the machine
needs the memory: roughly 5 GB of free RAM for an 8B model. A 1-2 GB model like
`qwen2.5-coder:1.5b` fits a small VPS, but expect it to fail the JSON contract
more often, which surfaces as audits ending in `error`.

Switching backend is `.env` plus `docker compose up -d app`; nothing is rebuilt.

## Operational notes

- **Audits run in-process.** They are FastAPI background tasks in the app
  container, not a separate worker, so a burst of pushes competes for the same
  threadpool. If that becomes a problem the queue is the thing to extract.
- **Restarts abandon in-flight audits.** Anything left `pending` or `running`
  is marked as an error on the next startup rather than sitting there forever.
- **Only public GitHub repositories.** Clone URLs are validated against
  `https://github.com/<owner>/<repo>`; there is no credential for private
  repositories, and cloning one will fail.
- **The dashboard is unauthenticated.** Anyone who reaches the subdomain can
  queue audits and read findings. Put it behind whatever the other services use
  for access control if that matters.
- **Logs**: `docker compose -p secaudit logs -f app`.
- **Database backup**: `docker compose exec db pg_dump -U secaudit secaudit`.
