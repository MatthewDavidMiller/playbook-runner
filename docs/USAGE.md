# Using playbook-runner

A first-time walkthrough, in the order the pieces depend on each other. For
running the server itself, see [DEPLOYMENT.md](DEPLOYMENT.md).

## Sign in

On first start there is no password. Open the site and enter the one-time
setup token the server printed (`podman logs playbook-runner`), then choose
an admin password of 12 to 128 characters. If the deployment seeded a
password, sign in with it. **Settings** changes it later, which ends every
session.

## Set up, in this order

1. **Secrets.** Add each vault password (with the `--vault-id` label it
   answers to; `default` unless your playbooks use others) and each SSH
   private key. Keys must be unencrypted OpenSSH keys. Values are write-only:
   after saving, the page shows only the name and, for keys, the fingerprint.
   To change a value, replace it.
2. **Known hosts.** The runner checks SSH host keys strictly and never
   accepts unknown ones. Paste the host keys of the git server and of every
   machine you manage (`ssh-keyscan -t ed25519 host` prints them).
3. **Repositories.** Give the git URL and branch. A public repository can use
   an `https://` URL. A private one needs an `ssh://` or `git@host:path` URL
   and a **deploy key**: add the key as a secret, choose it here, and add its
   public half to the repository. A URL may not contain a token or password;
   the form refuses one.
4. **Sync.** On the repository's page, **Sync playbooks** clones it and
   lists the playbooks it contains, so templates can offer them in a
   dropdown. Run it again after the repository gains a playbook.
5. **Inventories.** Paste the inventory YAML, including its variables. It is
   checked with `ansible-inventory --graph` before saving, then encrypted.
   Like secrets, it is not shown again.
6. **Templates.** Choose a repository (step one), then the playbook, the
   inventory, the vault secrets, and the SSH key. Optional settings are a
   host limit, tags, skip-tags, check mode, diff, verbosity, and a timeout.
   There is no free-form argument field.
7. **Schedules.** Pick a template and a frequency: hourly, daily, weekly on
   chosen days, monthly, or a custom cron expression. The page describes it
   in words and lists the next three runs. Times are in the server's time
   zone (`PR_TIMEZONE`). If the template is still running when a schedule
   fires, that occurrence is skipped; runs missed while the server was down
   are not made up.

## Runs

**Run** on a template queues it. Runs go one at a time, in order, because
playbooks on the same hosts should not overlap. Cancelling a queued run is
immediate; cancelling a running one stops ansible and everything it started.

The run page shows:

- the status and, for a failure, the step it stopped at (cloning, checking
  collections, or running the playbook);
- a per-host recap, and each failed task linked to its highlighted line in
  the log;
- the log, which refreshes every few seconds while the run is going.

The log frame **follows the end** by default, so each refresh shows the newest
output. **Pause updates** stops the refresh so you can scroll and select
text; **Resume updates** or **Refresh once** brings it back. **Stop
following the end** keeps refreshing but opens the log at the top. A
finished run does not refresh. **Download log** saves the whole log.

A run that was going when the server stopped, for example across the reboot
that finishes a patch cycle, is marked **interrupted**. The newest 500 runs
are kept (`PR_KEEP_RUNS`).

## What the runner does for each run

It clones the repository fresh into a scratch directory, checks the built-in
collections against the repository's `collections/requirements.yml`, writes
the decrypted inventory there, hands vault passwords to ansible over pipes,
loads the SSH key into a private `ssh-agent`, runs `ansible-playbook`, and
deletes the scratch directory. See [DESIGN.md](DESIGN.md#a-run).

## The log and secrets

The log masks the vault passwords, each line of the SSH key, and inventory
values whose names look like secrets (`ansible_become_pass`, `api_token`).
The last is a best effort. A playbook that prints a secret under another name
would still show it, so keep `no_log: true` on tasks that handle secrets.

## About

The **About** page shows the version, the ansible-core, collections, git, and
OpenSSH the image contains, the license, and third-party notices.
