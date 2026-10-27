# Agent Instructions

Workflow instructions for coding agents working in this repository. The
architecture and security model live in [docs/DESIGN.md](docs/DESIGN.md);
read it before changing anything. [docs/USAGE.md](docs/USAGE.md) and
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) describe the behaviour users and
operators rely on; update them with any change to it.

## Non-Negotiables

- **No third-party crates.** `Cargo.lock` lists workspace members only, and
  `scripts/check-rust.sh` fails the build otherwise. Write what you need, or
  port it from the sibling `rpi-omt-client` repository, which follows the same
  rule.
- **libcrypto is the only third-party library.** Never implement a
  cryptographic primitive; bind OpenSSL's in `crates/pr-sys` and wrap it in
  `crates/pr-crypto`.
- **`unsafe` lives only in `pr-sys`.** Every other crate root carries
  `#![forbid(unsafe_code)]`, and the gate checks it.
- **Secrets never reach disk in plaintext, logs, or the UI.** Vault
  passwords, SSH keys, and inventories are encrypted at rest, write-only in
  the interface, and handed to child processes over pipes or agents.
- **Every input is bounded.** `clippy.toml` refuses the unbounded std
  readers; use the bounded replacements in `pr-common`.
- **Images are pinned by digest.** Base images in `Containerfile` and
  `tools/toolbox/Dockerfile` are official images referenced by digest.

## Validation

Every gate runs inside the toolbox image; rootless Podman is the only host
prerequisite. Never install a toolchain or linter on the host to satisfy a
gate.

```bash
make install   # once per clone
make test      # the full pre-commit gate
```

Run `make test` before reporting a change complete. Never pass `--no-verify`
to `git commit`.

## Commits

Only commit when asked. Commit messages are a short imperative subject
followed by a body explaining what was wrong, what changed, and why, wrapped
at 72 columns, no emoji.
