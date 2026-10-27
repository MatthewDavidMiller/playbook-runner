# Design

The architecture and security model of playbook-runner. For using it see
[USAGE.md](USAGE.md); for running it see [DEPLOYMENT.md](DEPLOYMENT.md).

## What it is for

A homelab runs Ansible playbooks from a git repository: on demand, and on a
weekly schedule that patches and reboots its hosts. That needs a place to keep
the inventory variables, vault passwords, and SSH keys safely, run a playbook
with them, and show what happened. playbook-runner does that and nothing
more. It has no database, no users beyond one administrator, no plugins, and
no free-form command lines, so there is little to configure wrongly and little
to attack.

It follows the conventions of the sibling `rpi-omt-client` project: no
third-party crates, OpenSSL's libcrypto reached through hand-written FFI,
strict lints, and every build and test inside a toolbox image.

## Workspace

A Cargo workspace (edition 2024). `Cargo.lock` lists workspace members only,
and `scripts/check-rust.sh` fails the build otherwise.

| Crate | Purpose |
|---|---|
| `pr-sys` | The only crate with `unsafe`. FFI to libcrypto (AES-256-GCM, HKDF, PBKDF2, HMAC, SHA-256, random, constant-time compare, memory cleansing) and a few POSIX calls |
| `pr-crypto` | Safe wrappers: seal and open, key derivation, `MasterKey` and `SubKey` that are wiped on drop |
| `pr-common` | Bounded file and buffer IO, strict JSON, base64, OpenSSH key parsing, time formatting, randomness |
| `pr-store` | The data directory: typed records, sealed blobs, sealed files, sealed run logs, validation, rekeying |
| `pr-sched` | Cron parsing, plain-English descriptions, the schedule builder, time zones (TZif and POSIX TZ) |
| `pr-runner` | The run engine: git clone, the ansible-playbook supervisor, log redaction, the job queue, the scheduler |
| `pr-web` | The HTTP/1.1 server, authentication, the pages, and the `playbook-runner` binary |

## The interface

Server-rendered HTML with no JavaScript, under a content security policy that
forbids scripts, inline styles, and third-party origins. A running run's page
refreshes with a meta refresh; the log frame is laid out from the bottom so a
reload lands on the newest output without a script, and the page links carry a
changing query so the browser reloads instead of jumping within the page. TLS
is not in the program: Traefik terminates HTTPS and forwards to port 8080 over
an internal network.

## The data directory

`/var/lib/playbook-runner/`, mode 0700, owned by a non-root user:

```text
keycheck                   which master key this data belongs to (one-way)
<collection>.json          secrets, inventories, repositories, templates,
                           schedules, repository snapshots: sealed
blobs/<kind>-<id>          the secret and inventory values: sealed
admin.password             the administrator's PBKDF2 hash: sealed
known_hosts                public host keys
runs/<n>.json, runs/<n>.log   run records and logs: sealed
```

Every write replaces a whole file atomically (stage, fsync, rename, fsync the
directory), so a crash leaves each file old or new. Collections are small and
cached in memory; every change goes through one store under one lock, so the
cache cannot go stale.

### Sealing

All encryption is AES-256-GCM through libcrypto. One 256-bit master key is
the root; each purpose derives its own key with HKDF-SHA256, so no key is used
for two jobs.

- **Blobs** (vault passwords, SSH keys, inventories) are sealed under the
  store key with the kind and record id in the authenticated data, so a blob
  copied onto another record fails to open.
- **Files** (collections, run records, the admin hash) are sealed whole under
  a second key with the file's name in the authenticated data.
- **Run logs** are appended while a run goes and read while it is still going,
  so they are sealed in records. Each holds a few KiB of text and is
  authenticated with the run number and its own byte offset, so a record moved
  within a log, or a log moved to another run, fails. A record's length is
  written on both sides, so the tail is read by walking back from the end. A
  crash can leave a partial record at the end; readers skip it.
- Files written by older versions are plain text. They are read as such and
  sealed when the server starts.

`playbook-runner rekey` moves everything from one master key to another, and
is safe to repeat. The server refuses to start with a key other than the one
the data was written with.

## Secret handling

- **The master key** is 32 random bytes kept in two places: the Ansible
  inventory that deploys the runner and Vaultwarden. It reaches the container
  as a Podman secret on a tmpfs and is never in the data volume or its
  backups, so a copy of the volume is ciphertext.
- **Write-only interface.** Secrets and inventories can be created, replaced,
  and deleted but never displayed; pages show names, times, sizes, and SSH key
  fingerprints. Plaintext buffers are wiped with `OPENSSL_cleanse` when done.
- **At run time** vault passwords go to ansible over inherited pipes
  (`--vault-id label@/dev/fd/N`) and never touch a disk. SSH keys are loaded
  into a per-run `ssh-agent` from stdin. The inventory is decrypted to a 0600
  file in the run's scratch directory on a `noexec` tmpfs and removed when the
  run ends. The container has no swap, so none of it is paged out.
  `StrictHostKeyChecking=yes` is used with the managed `known_hosts`.
- **Logs.** Output is masked before it is written: the vault passwords, each
  line of the SSH keys, and inventory values whose variable names look like
  secrets. The last is a best effort, since the project reads no YAML; it backs
  up `no_log`, it does not replace it. Logs are also sealed on disk.
- **No credentials in URLs.** A git URL with a token or password is refused
  when saved and is not used if an older record has one. Private repositories
  use an ssh URL and a deploy key.
- **Authentication.** One administrator, PBKDF2-SHA256 at 600,000 iterations.
  Sessions are random 256-bit identifiers kept in memory under an HMAC, with
  CSRF tokens, same-origin checks on every POST, constant-time comparisons,
  and login throttling per client. Cookies are `Secure; HttpOnly;
  SameSite=Strict`. Traefik adds an IP allowlist in front.

## A run

1. The job leaves the queue and becomes current in one step (so a template
   never looks idle between the two).
2. A scratch directory is made on the tmpfs, with a private home.
3. The deploy key and SSH keys are loaded into a private `ssh-agent`.
4. The repository is cloned shallow, with hooks disabled and the `ext`
   transport refused. A URL carrying a credential stops the run here.
5. If the clone has `collections/requirements.yml`, it is resolved
   `--offline` against the collections baked into the image. A mismatch fails
   the run before anything executes; nothing is ever downloaded.
6. The decrypted inventory is written, the vault passwords are put on pipes,
   and `ansible-playbook` starts in its own process group.
7. Output is masked and written to the sealed log as it arrives.
8. On cancel or timeout the group gets SIGTERM, then SIGKILL after a grace
   period. The scratch directory is deleted either way.

Runs execute one at a time. Playbooks in a homelab usually touch the same
hosts, and the update playbook reboots them, so overlapping runs would be a
hazard. The scheduler checks once a minute, considers only the time since its
last check, and skips an occurrence whose template is still queued or running.
Runs left unfinished by a stopped server are marked interrupted on the next
start.

## The container image

A two-stage `Containerfile`, both stages on an official Alpine image pinned by
digest (the same digest the toolbox uses; the lint step enforces it).

- **Build:** the repository-pinned Rust toolchain, installed by a
  checksum-verified script, with OpenSSL's static libraries, produces a
  static-pie musl binary with libcrypto linked in.
- **Runtime:** `git`, `openssh-client`, `tzdata`, Python with ansible-core
  installed from hash-pinned wheels (`pip --require-hashes`), and the Ansible
  collections from `runtime/collections.yml`. The user is non-root; the image
  is meant to run `--read-only`, `--cap-drop=ALL`, `no-new-privileges`, with
  the memory cap and tmpfs mounts described in [DEPLOYMENT.md](DEPLOYMENT.md).
- **Release:** `make release` runs the full gate and the image tests, pushes
  to GHCR, tags the version, and creates the GitHub release. No CI service.

## Testing

- `make test` runs shellcheck, rustfmt, checks that the dependency graph has
  only workspace members and the native libraries are only libcrypto and the C
  library, that `unsafe` is only in `pr-sys`, clippy at pedantic with
  `unwrap`, `expect`, and `panic` denied, and every test.
- Unit tests cover the cryptography against published vectors, the sealed
  formats (tampering, relocation, wrong key, torn writes, old plain files,
  rekey), the cron and time-zone logic including daylight saving, the log
  redactor, and the report parser.
- End-to-end tests start the real server and the real run engine against a
  local git repository and `ansible-playbook`: a vault-encrypted variable
  through the pipe, the SSH agent, masking, cancel, the offline collection
  check, sync, and a check that nothing the application stores is readable
  without the key.
- `make test-image` builds the image and runs it, and the end-to-end tests
  inside it, with the same flags production uses.

## Not goals

No database, multiple users, role-based access, webhooks, or notifications; no
parallel runs; no editing of playbooks; no downloading of collections at run
time; no free-form ansible arguments. Each would widen what has to be trusted,
and the homelab does not need them.
