# Design

The architecture, secret-handling model, and stage plan for playbook-runner.

## Context
VM1 runs Semaphore (`public.ecr.aws/semaphore/server`) to hold the homelab inventory, run
`ansible_playbooks` playbooks and run the weekly `update_homelab_vms.yml` schedule. It is a third-party
image with a Postgres DB, a backend network membership, an egress network and its own backup job. We
use only a small part of it. Replacing it with **playbook-runner** gives us a small first-party Rust
program that does exactly what we need. It follows the conventions of `rpi-omt-client`: no crates,
OpenSSL libcrypto reached through hand-written FFI, strict lints, and a toolbox-image build.

Decisions already made: name `playbook-runner`; private GitHub repo, MIT licensed; secrets encrypted with
Alpine libcrypto through FFI; playbooks pulled by git over SSH; runtime on the official
`docker.io/library/alpine` image.

## Architecture

**Workspace** (Cargo workspace, edition 2024; lints and
release profile copied from `../rpi-omt-client/Cargo.toml`; `Cargo.lock` lists workspace members only):

| Crate | Purpose | Reuse from rpi-omt-client |
|---|---|---|
| `pr-sys` | FFI: libcrypto (EVP AES-256-GCM, HKDF, PBKDF2, RAND_bytes, CRYPTO_memcmp, OPENSSL_cleanse), POSIX `dup2`/`setsid`/`kill` | `crates/omt-sys` (openssl + posix modules, ABI tests) |
| `pr-crypto` | Safe wrappers, no `unsafe` | `crates/omt-crypto/src/lib.rs` |
| `pr-common` | JSON, atomic file IO, rand, time formatting, buffer wiping | `crates/omt-common` (`json`, `fsio`, `rand`, `timefmt`, `buf`) |
| `pr-store` | Data-dir layout, typed records, encrypted keystore | new |
| `pr-sched` | 5-field cron parser and next-fire calculation, TZif reader for DST-correct local time | new |
| `pr-runner` | git fetch, ansible-playbook spawn, log capture, cancel, job queue | new |
| `pr-web` | Plain HTTP/1.1 server (Traefik terminates TLS), templates, auth, pages; `playbook-runner` binary | `crates/omt-web` (`http.rs` without TLS, `auth.rs`, `templates_gen.rs`, `static/style.css`, `templates/base.html`) |

**UI pages** (server-rendered, no JavaScript; a run page that is still running refreshes itself with meta refresh):
Dashboard (recent runs, next scheduled runs) · Templates (repo + playbook + inventory + vault
secrets + SSH key + fixed options: limit, tags, check mode; argv only, no free-form args) · Schedules
(cron, timezone, enabled, next run) · Runs (status, live log, cancel) · Inventories (paste or upload a
YAML variables file; checked with `ansible-inventory --list`) · Secrets (vault passwords, SSH keys) ·
Repositories (git URL, branch, deploy-key secret) · Known hosts · Settings (admin password, run retention).

**Data** `/var/lib/playbook-runner/` (0700, non-root uid): JSON records written atomically, encrypted blobs,
`runs/<id>.log`. No database. That removes the Postgres DB, the user and the backend network.

## Secret handling (best practice within the constraints)
- **Master key**: 32 random bytes kept in the external inventory and in Vaultwarden. Ansible provisions it as a
  **Podman secret**, mounted at `/run/secrets/` (tmpfs). It is never in the data volume or its backups,
  so a stolen backup holds ciphertext only.
- **At rest**: AES-256-GCM. The per-purpose key is HKDF-SHA256(master, "playbook-runner v1 <kind>").
  Each write gets a fresh random 96-bit nonce, and AAD = kind + record id + format version, so a ciphertext
  cannot be moved to another record. The header carries a key id so `playbook-runner rekey` can rotate keys.
  Inventories are encrypted too, since they hold credentials.
- **Write-only UI**: secrets can be created, replaced and deleted, but never shown again (the page shows name,
  timestamps and the SSH key fingerprint). They are never logged. Plaintext buffers are wiped with `OPENSSL_cleanse`.
- **At run time**: vault passwords go to ansible through inherited pipes (`--vault-id <label>@/dev/fd/N`),
  never to disk. SSH keys are loaded into a per-run `ssh-agent` with `ssh-add -` from stdin. The inventory is
  decrypted to a 0600 file in a per-run directory on a `noexec` tmpfs and deleted when the run ends. The container
  has no swap (`--memory-swap` = `--memory`). Known lines are redacted from logs. `StrictHostKeyChecking=yes`
  with the managed known_hosts.
- **Web auth**: one admin, PBKDF2-SHA256 at 600k iterations; sessions stored as HMACs, CSRF tokens, constant-time
  compare (port of `omt-web/src/auth.rs`); login throttling. Cookies are `Secure; HttpOnly; SameSite=Strict`; strict CSP.
  Traefik keeps an IP allowlist in front of the app.

## Container image
Multi-stage `Containerfile`, with both base images pinned by digest:
- Builder: the same official Alpine image, with the repository-pinned Rust toolchain installed by the checksum-verified
  `scripts/install-rust.sh` (rather than trusting a second base image for the compiler) + `openssl-dev openssl-libs-static`,
  producing a static-pie musl binary with libcrypto linked in.
- Runtime: official `docker.io/library/alpine:<ver>` + `git openssh-client python3`, with ansible-core installed
  through pip `--require-hashes` into `/opt/venv` and the collections from `ansible_playbooks/collections/requirements.yml`
  baked in (runs never download collections; a repository's `collections/requirements.yml` is resolved
  `--offline` against them before each run, and a mismatch fails the run). Non-root USER, `--read-only`, `--cap-drop=ALL`, `no-new-privileges`, tmpfs `/tmp` and `/run`.
- `make release` builds the image, pushes it to GHCR and creates a GitHub Release (as in rpi-omt-client, no Actions).
- `make test-image` runs the image with VM1's flags and runs the end-to-end test binaries inside it. See
  [DEPLOYMENT.md](DEPLOYMENT.md).

## Stages (each ends in something we can test)

**Stage 0: Repo scaffold**
- `mkdir playbook-runner`, `git init`, MIT `LICENSE`, `README.md`, `AGENTS.md`, `CLAUDE.md`, `.gitignore`, workspace `Cargo.toml`,
  `rust-toolchain.toml`, toolbox Containerfile, `Makefile` (`install`, `lint`, `test`), and a script that fails if
  `Cargo.lock` contains any non-workspace package.
- `gh repo create MatthewDavidMiller/playbook-runner --private --source . --remote origin`, initial commit, push.
- Test: `make test` passes on the empty crates; the repo exists on GitHub and is private.

**Stage 1: Crypto and common foundations**: `pr-sys`, `pr-crypto`, `pr-common` ported and trimmed.
- Test: NIST AES-GCM and RFC 5869 HKDF vectors, PBKDF2 vectors, round-trip, tamper/AAD-mismatch rejection, ABI tests.

**Stage 2: HTTP server, auth, UI shell**: `pr-web` serving login, first-run admin setup, logout, an empty dashboard,
security headers, and the styling adapted from omt-web.
- Test: integration tests in the style of `omt-web/tests/web.rs`; `cargo run` locally, then log in from a browser, check that CSRF is enforced and that throttling works.

**Stage 3: Store and keystore**: `pr-store` plus the Secrets, Inventories, Repositories and Known hosts pages.
- Test: unit tests; a test that greps the data dir to prove no plaintext secret or inventory text is on disk;
  a startup without the master key fails closed.

**Stage 4: Run engine**: `pr-runner` plus the Templates page, the Run button, the run log page and cancel (process-group kill).
It runs one job at a time from a FIFO queue, and on startup marks runs left "running" as "interrupted".
- Test: in a dev container, a test repo served by a local sshd container; a playbook with `connection: local` that reads a
  vault-encrypted var (proves the fd pipe works); an SSH key with a passphrase-free agent; cancel mid-run.

**Stage 5: Scheduler**: `pr-sched` plus the Schedules page and run retention. Missed runs during downtime are skipped, not backfilled.
- Test: cron unit tests, including DST transitions for America/New_York; a one-minute schedule fires in the dev container.

**Stage 6: Production image**: Containerfile, `make image`, `make release`.
- Test: run the image with the exact VM1 flags (`--read-only --cap-drop=ALL --security-opt=no-new-privileges:true --memory=384m`) and repeat the Stage 4 checks.

**Stage 7: ansible_playbooks integration** (repo conventions in its `AGENTS.md`):
- New `roles/playbook_runner/` modeled on `roles/vaultwarden/`: input assert, defaults, podman secret for the master key,
  the `container_network` include for `playbook_runner_container_net` plus an egress network, static IPs, launch script,
  systemd unit, and a backup of the data dir into the existing backup flow.
- Add a Traefik route in `proxy_config` with an IP allowlist. Lock the image through `scripts/promote_artifacts.py` (add support
  for a first-party GHCR source if needed). Add guards in `tests/test_ansible_regressions.py`. Update docs (architecture, services,
  security, dr-restore, variables).
- Deploy next to Semaphore under a new hostname.
- Test: `make test` and `make test-full`; run `vm1.yml --check` from playbook-runner.

**Stage 8: Cutover**: recreate the inventory and the weekly `update_homelab_vms.yml` schedule, run one full update and reboot cycle
(this proves the interrupted-run handling and the `container_network_migration` delay still work), then remove `roles/semaphore`,
its DB and user, network, lock entry, backup and docs, and update the ADRs that name Semaphore as the scheduler and inventory source.

## Verification
At the end of each stage: `make test` in playbook-runner. Stages 7 and 8 also run `make test` and `make test-full` in ansible_playbooks.
The end-to-end check is the scheduled weekly update completing from playbook-runner, with Semaphore removed.
