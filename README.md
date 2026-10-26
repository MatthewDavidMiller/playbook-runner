# playbook-runner

playbook-runner is a small, first-party web application that runs Ansible
playbooks on demand and on a schedule. It replaces Semaphore in the homelab
(see the `ansible_playbooks` repository), covering exactly what that workflow
uses: playbook templates, cron schedules, run logs, inventory variable files,
and encrypted vault passwords and SSH keys.

Everything is first-party Rust with no third-party crates. OpenSSL's
libcrypto, reached through hand-written declarations in `crates/pr-sys`, is
the only third-party library linked. The shipped image runs on the official
Alpine Linux base image.

## Status

Built in stages, each one testable on its own. See
[docs/DESIGN.md](docs/DESIGN.md) for the architecture, the secret-handling
model, and the stage plan.

| Stage | Scope | State |
|---|---|---|
| 0 | Repository scaffold, toolbox, gates | done |
| 1 | libcrypto FFI, crypto wrappers, common helpers | done |
| 2 | HTTP server, auth, UI shell | done |
| 3 | Store, keystore, secrets/inventory/repository pages | done |
| 4 | Run engine, templates, run logs | planned |
| 5 | Scheduler | planned |
| 6 | Production image | planned |
| 7 | ansible_playbooks role integration | planned |
| 8 | Cutover from Semaphore | planned |

## Build and test

Rootless Podman is the only prerequisite. Every compiler and linter lives in
the toolbox image.

```bash
make install   # once: build the toolbox and install the pre-commit hook
make test      # the full gate
make dev       # run the server at http://127.0.0.1:8080 (state in ./data)
```

`make dev` prints a one-time setup token on first start; open
http://127.0.0.1:8080, enter it, and choose the admin password.

## License

Copyright (c) 2026 Matthew David Miller.
[Licensed under the MIT License.](LICENSE)
