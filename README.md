# playbook-runner

A small web application that runs Ansible playbooks on demand and on a
schedule. It keeps the inventory, vault passwords, and SSH keys encrypted,
runs one playbook at a time from a git repository, and shows each run's
result and log.

- **Templates** pick a repository, a playbook (from a dropdown filled by
  syncing the repository), an inventory, vault passwords, and an SSH key.
- **Schedules** are built from simple choices or a cron expression and read
  back in plain English ("Every Monday at 5:00 PM").
- **Runs** show where a failed run stopped, the per-host recap, and a live
  log you can follow or pause.
- **Everything stored is encrypted** with one master key: secrets,
  inventories, records, run history, and logs. A backup is ciphertext.

It is first-party Rust with no third-party crates. OpenSSL's libcrypto, bound
by hand in `crates/pr-sys`, is the only third-party library linked. The image
is built on the official Alpine Linux image, with ansible-core and its
collections baked in, so a run never downloads anything.

## Documentation

| Page | For |
|---|---|
| [docs/USAGE.md](docs/USAGE.md) | Setting it up and using the interface |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Container flags, configuration, the master key, backups, upgrading |
| [docs/DESIGN.md](docs/DESIGN.md) | Architecture and the security model |
| [AGENTS.md](AGENTS.md) | Rules for working on the code |

## Try it

Rootless Podman is the only prerequisite; every compiler and linter runs in a
toolbox image.

```bash
make install   # once: build the toolbox and install the git hook
make dev       # serve http://127.0.0.1:8080, state in ./data
make test      # the full gate
```

`make dev` prints a one-time setup token on first start; open the address,
enter it, and choose the admin password. `make help` lists the other targets
(`image`, `test-image`, `release`).

## License

Copyright (c) 2026 Matthew David Miller.
[Licensed under the MIT License.](LICENSE)
