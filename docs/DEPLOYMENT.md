# Deployment

How playbook-runner runs in production. In the homelab, the
`playbook_runner` role in `ansible_playbooks` does all of this on VM1; this
page is the reference for what that role sets up and why.

---

## The container

```bash
podman run -d --name playbook-runner \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --memory=512m --memory-swap=512m \
  --pids-limit=300 \
  --mount type=tmpfs,destination=/run/playbook-runner,tmpfs-size=256m,tmpfs-mode=0700,U=true,noexec,nosuid,nodev \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
  --secret playbook_runner_master_key,target=/run/secrets/playbook_runner_master_key,uid=10001,gid=10001,mode=0400 \
  -v /var/lib/playbook-runner:/var/lib/playbook-runner:Z \
  -e PR_TIMEZONE=America/New_York \
  -e PR_TRUSTED_PROXIES=<traefik address> \
  ghcr.io/matthewdavidmiller/playbook-runner@sha256:<digest>
```

| Flag | Why |
|---|---|
| `--read-only` | Nothing in the image is ever modified at runtime. |
| `--cap-drop=ALL`, `no-new-privileges` | The server runs as uid 10001 and needs no capabilities; it listens on 8080. |
| `--memory` = `--memory-swap` | No swap, so decrypted secrets in memory are never paged to disk. |
| tmpfs `/run/playbook-runner` | Every run's scratch directory: the clone, the decrypted inventory, the ssh-agent socket. Also the runner user's home. Never touches a disk. |
| `--secret ...master_key` | The master key, outside the data volume and its backups. |
| `-v /var/lib/playbook-runner` | Persistent state: records, sealed blobs, run logs. Owned by uid 10001, mode 0700. |

The container needs outbound access to the git server and to every managed
host over SSH, and inbound access only from Traefik on port 8080.

## Configuration

Environment variables, all optional except where noted:

| Variable | Default | Meaning |
|---|---|---|
| `PR_LISTEN` | `0.0.0.0:8080` (image) | Listener address |
| `PR_DATA_DIR` | `/var/lib/playbook-runner` | Persistent state |
| `PR_WORK_DIR` | `/run/playbook-runner` | Run scratch space; must be a tmpfs |
| `PR_MASTER_KEY_FILE` | `/run/secrets/playbook_runner_master_key` | 64 hex digits |
| `PR_ADMIN_PASSWORD_FILE` | unset | Seeds the admin password on first start |
| `PR_TRUSTED_PROXIES` | unset | Comma-separated proxy IPs whose `X-Forwarded-For` is believed (for login throttling) |
| `PR_SECURE_COOKIES` | `true` | Leave on behind HTTPS |
| `PR_SESSION_HOURS` | `12` | Session lifetime |
| `PR_TIMEZONE` | `UTC` | Zone schedules are written in and times are shown in |
| `PR_KEEP_RUNS` | `500` | Finished runs kept |

## The master key

Every stored secret and inventory is sealed with AES-256-GCM under keys
derived from one 256-bit master key. Generate it once:

```bash
podman run --rm --entrypoint playbook-runner ghcr.io/matthewdavidmiller/playbook-runner@sha256:<digest> gen-key
```

Store it in two places: the Ansible inventory that deploys the runner (it
becomes the Podman secret), and Vaultwarden. **Without it, the data volume's
secrets and inventories cannot be recovered**, which is the point: a copy of
the volume or its backups holds only ciphertext.

The server refuses to start with a key other than the one the data directory
was written with.

### Rotating it

With the server stopped:

```bash
podman run --rm \
  -v /var/lib/playbook-runner:/var/lib/playbook-runner:Z \
  -v ./old.key:/keys/old:ro,Z -v ./new.key:/keys/new:ro,Z \
  -e PR_OLD_MASTER_KEY_FILE=/keys/old -e PR_MASTER_KEY_FILE=/keys/new \
  <image> rekey
```

`rekey` is safe to repeat if it is interrupted. Then replace the Podman
secret with the new key and start the server.

## First start

On first start, with no admin password, the server logs a one-time setup
token:

```text
playbook-runner: no admin password is set; open /setup with setup token 0f3c...
```

Open the site, enter the token, and choose the password. Alternatively set
`PR_ADMIN_PASSWORD_FILE` to a file holding the password (the role passes it
as a second Podman secret), and setup is skipped.

To reset a forgotten password:

```bash
echo 'new password here' | podman exec -i playbook-runner playbook-runner passwd
podman restart playbook-runner
```

## Behind Traefik

Route the site's hostname to the container's port 8080 over an internal
Podman network, as every other VM1 service does. Keep the management-network
IP allowlist on the route; the application's own login is the second layer,
not the only one. Set `PR_TRUSTED_PROXIES` to Traefik's static address on
that network so login throttling sees client addresses rather than
Traefik's.

## Backups

Back up `/var/lib/playbook-runner` while the server is running; every file is
replaced atomically, so a copy is always consistent per file. Everything in
it is encrypted with the master key (the secrets and inventories, the
records, the run records and logs, and the admin password hash), so a backup
is ciphertext without the key. Back up the master key separately
(Vaultwarden). Restoring is copying the directory back, owned by
10001:10001, mode 0700, and starting the server with the same key.

## Upgrading from before 0.3.0

Version 0.3.0 seals the record collections, run records, run logs, and the
admin password hash, which earlier versions kept as plain text. The first
start of 0.3.0 seals them in place; nothing needs doing. Older versions
cannot read sealed files, so take a backup before upgrading if you may want
to go back. A repository saved with a token in its URL stops working until it
is edited to an ssh URL with a deploy key (the log names it at startup).

`playbook-runner passwd` now needs `PR_MASTER_KEY_FILE`, because the hash it
writes is sealed. Running it inside the container, as above, already has it.

## Ansible collections

Collections are built into the image (`runtime/collections.yml`) and are
never downloaded at run time, so a run needs no access to Ansible Galaxy and
always uses the reviewed, scanned set. Before each run, if the playbook
repository has `collections/requirements.yml`, the runner resolves it
against the built-in collections with
`ansible-galaxy collection install --offline`. If they do not satisfy it,
the run fails before anything executes, with the resolver's reason in the
log:

```text
the collections built into this playbook-runner image do not satisfy
collections/requirements.yml; update runtime/collections.yml in
playbook-runner and release a new image
```

To change collections, update `runtime/collections.yml` to match the
playbook repository, `make release`, and pin the new image.

## Health

`playbook-runner healthcheck` (the image's `HEALTHCHECK`) exits 0 when the
server answers `GET /healthz`.
