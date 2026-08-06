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

3. Point the reverse proxy at `127.0.0.1:8811`. For nginx:

   **Only the webhook path is published.** The dashboard and the rest of the
   API have no authentication, so nothing but `/api/webhook/github` — which
   authenticates every request by HMAC signature — is reachable from the
   internet. See [Reaching the dashboard](#reaching-the-dashboard) below.

   nginx:

   ```nginx
   # Rate limit the one public endpoint. Declare the zone at http level:
   #   limit_req_zone $binary_remote_addr zone=secaudit_hook:1m rate=30r/m;
   server {
       server_name secaudit.<domain>;

       location = /api/webhook/github {
           limit_req zone=secaudit_hook burst=10 nodelay;
           proxy_pass http://127.0.0.1:8811;
           proxy_set_header Host $host;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }

       location / {
           return 404;
       }
   }
   ```

   Caddy:

   ```caddy
   secaudit.<domain> {
       @hook path /api/webhook/github
       handle @hook {
           reverse_proxy 127.0.0.1:8811
       }
       handle {
           respond 404
       }
   }
   ```

   For the certificate: `sudo certbot --nginx -d secaudit.<domain>`, or whatever
   issues certificates for the other services. Caddy handles TLS by itself.

   If you later want the dashboard reachable from a browser anywhere, add HTTP
   basic auth to the `location /` block rather than opening it up.

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
