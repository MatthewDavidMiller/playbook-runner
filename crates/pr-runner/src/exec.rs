//! Executing one run, start to finish, in a private scratch directory:
//!
//! 1. `<work>/<run>/` (mode 0700) holds everything the run touches. In
//!    production `<work>` is a tmpfs, so decrypted files never reach a disk.
//! 2. A dedicated `ssh-agent` is started with its socket in that directory,
//!    and the SSH keys are loaded with `ssh-add -` from a pipe.
//! 3. The repository branch is cloned with host keys checked against the
//!    managed known_hosts file.
//!    If the repository declares `collections/requirements.yml`, the
//!    collections built into the image must satisfy it: `ansible-galaxy
//!    collection install --offline` resolves it against what is installed,
//!    nothing is ever downloaded, and its output path is the scratch space. A mismatch fails the run before
//!    anything executes, rather than running with stale collections.
//! 4. The inventory is decrypted to a 0600 file.
//! 5. `ansible-playbook` runs in its own process group with a clean
//!    environment. Each vault password reaches it on an inherited pipe named
//!    as `--vault-id <label>@/dev/fd/<n>`; it is never written to a file.
//! 6. Output is copied to the run log with every secret value masked.
//! 7. The agent is stopped and the directory deleted, whatever happened.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use pr_common::{Error, Result, fsio};
use pr_crypto::SecretBytes;
use pr_store::{Inventory, Repository, Secret, SecretKind, Store, Template};
use pr_sys::posix::{SIGKILL, SIGTERM, inherit_fds, send_signal};

use crate::redact::{self, Redactor};

/// Descriptor numbers the vault pipes are mapped to in the child. High
/// enough never to collide with the descriptors the parent happens to hold.
const VAULT_FD_BASE: i32 = 200;
const MAX_VAULT_SECRETS: usize = 16;
const TERM_GRACE: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(200);
const GIT_TIMEOUT: Duration = Duration::from_mins(5);
const COLLECTION_CHECK_TIMEOUT: Duration = Duration::from_mins(2);
/// Where a repository declares the collections its playbooks need.
const COLLECTION_REQUIREMENTS: [&str; 2] =
    ["collections/requirements.yml", "collections/requirements.yaml"];
const THREAD_STACK: usize = 256 * 1024;

/// What the caller needs to know about a finished run.
#[derive(Debug, Default)]
pub struct Outcome {
    pub exit_code: Option<i64>,
    pub commit: String,
    pub cancelled: bool,
    pub timed_out: bool,
    /// Set when the run failed before or outside ansible-playbook.
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct ExecConfig {
    pub work_dir: PathBuf,
    /// The PATH children run with.
    pub path: String,
    pub timezone: String,
}

/// The resolved inputs for one run.
struct Inputs {
    template: Template,
    repository: Repository,
    inventory: SecretBytes,
    /// (vault id label, password)
    vaults: Vec<(String, SecretBytes)>,
    /// Private keys to load into the agent.
    keys: Vec<SecretBytes>,
}

fn resolve(store: &Store, template_id: &str) -> Result<Inputs> {
    let template = store
        .get::<Template>(template_id)?
        .ok_or_else(|| Error::new("the template no longer exists"))?;
    let repository = store
        .get::<Repository>(&template.repository)?
        .ok_or_else(|| Error::new("the template's repository no longer exists"))?;
    store
        .get::<Inventory>(&template.inventory)?
        .ok_or_else(|| Error::new("the template's inventory no longer exists"))?;
    let inventory = store.get_blob("inventory", &template.inventory)?;
    if template.vault_secrets.len() > MAX_VAULT_SECRETS {
        return Err(Error::new("too many vault passwords"));
    }
    let mut vaults = Vec::new();
    for id in &template.vault_secrets {
        let secret = store
            .get::<Secret>(id)?
            .filter(|s| s.kind == SecretKind::VaultPassword)
            .ok_or_else(|| Error::new("a vault password secret no longer exists"))?;
        vaults.push((secret.vault_id.clone(), store.get_blob("secret", id)?));
    }
    let mut keys = Vec::new();
    for id in [&repository.deploy_key, &template.ssh_key] {
        if id.is_empty() {
            continue;
        }
        store
            .get::<Secret>(id)?
            .filter(|s| s.kind == SecretKind::SshKey)
            .ok_or_else(|| Error::new("an SSH key secret no longer exists"))?;
        keys.push(store.get_blob("secret", id)?);
    }
    Ok(Inputs { template, repository, inventory, vaults, keys })
}

/// The ansible-playbook arguments after the program name. Every option that
/// takes an operator-supplied value is written `--opt=value`, so a value can
/// never be read as another option.
pub fn playbook_args(t: &Template, check_override: bool, vault_ids: &[String]) -> Vec<String> {
    let mut args = vec!["-i".to_owned(), "../inventory.yml".to_owned()];
    for (i, label) in vault_ids.iter().enumerate() {
        args.push(format!(
            "--vault-id={label}@/dev/fd/{}",
            VAULT_FD_BASE + i32::try_from(i).unwrap_or(0)
        ));
    }
    if !t.limit.is_empty() {
        args.push(format!("--limit={}", t.limit));
    }
    if !t.tags.is_empty() {
        args.push(format!("--tags={}", t.tags));
    }
    if !t.skip_tags.is_empty() {
        args.push(format!("--skip-tags={}", t.skip_tags));
    }
    if t.check_mode || check_override {
        args.push("--check".to_owned());
    }
    if t.diff {
        args.push("--diff".to_owned());
    }
    let v = usize::try_from(t.verbosity.clamp(0, 4)).unwrap_or(0);
    if v > 0 {
        args.push(format!("-{}", "v".repeat(v)));
    }
    args.push("--".to_owned());
    args.push(t.playbook.clone());
    args
}

/// A run's scratch directory, removed on drop.
pub(crate) struct Scratch(pub(crate) PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        // The inventory is overwritten before removal; on a tmpfs this is
        // belt and braces, on a disk it is the best available.
        let inventory = self.0.join("inventory.yml");
        if let Ok(meta) = fs::metadata(&inventory)
            && let Ok(mut f) = OpenOptions::new().write(true).open(&inventory)
        {
            let zeros = vec![0_u8; usize::try_from(meta.len()).unwrap_or(0)];
            let _ = f.write_all(&zeros);
            let _ = f.sync_all();
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A child process killed (with its process group) on drop.
pub(crate) struct Supervised(Child);

impl Drop for Supervised {
    fn drop(&mut self) {
        if let Ok(None) = self.0.try_wait() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

pub(crate) fn log_line(log: &mut File, text: &str) {
    let _ = writeln!(log, "[playbook-runner] {text}");
}

fn quote_for_ssh_command(path: &Path) -> Result<String> {
    let s = path.to_str().ok_or_else(|| Error::new("the data path is not UTF-8"))?;
    if s.contains('\'') {
        return Err(Error::new("the data path must not contain a single quote"));
    }
    Ok(format!("'{s}'"))
}

/// The environment every child starts from: nothing inherited but PATH.
fn base_command(program: &str, cfg: &ExecConfig, home: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear()
        .env("PATH", &cfg.path)
        .env("HOME", home)
        .env("LANG", "C.UTF-8")
        .env("TZ", &cfg.timezone)
        .stdin(Stdio::null());
    cmd
}

/// Runs a short helper to completion with a deadline, its output appended
/// to the log while it runs.
fn run_helper(
    mut cmd: Command,
    log: &File,
    redactor: &Redactor,
    deadline: Duration,
    cancel: &AtomicBool,
) -> Result<ExitStatus> {
    let (reader, writer) = std::io::pipe()?;
    cmd.stdout(writer.try_clone()?).stderr(writer).process_group(0);
    let child = cmd
        .spawn()
        .map_err(|e| Error::new(format!("cannot start {}: {e}", cmd.get_program().display())))?;
    // Closes the parent's copies of the write end, so the reader sees EOF.
    drop(cmd);
    let mut log_copy = log.try_clone()?;
    thread::scope(|scope| {
        let pump = thread::Builder::new()
            .name("helper-log".to_owned())
            .stack_size(THREAD_STACK)
            .spawn_scoped(scope, move || redact::pump(reader, &mut log_copy, redactor, 0));
        let status = supervise(child, deadline, cancel);
        if let Ok(handle) = pump {
            let _ = handle.join();
        }
        status.map(|(s, _)| s)
    })
}

/// Waits for `child` (a process group leader), escalating SIGTERM then
/// SIGKILL to the whole group on cancel or deadline. Returns the status and
/// whether it was stopped early.
fn supervise(child: Child, deadline: Duration, cancel: &AtomicBool) -> Result<(ExitStatus, bool)> {
    let mut child = Supervised(child);
    let pgid = -i32::try_from(child.0.id()).map_err(|_| Error::new("process id out of range"))?;
    let start = Instant::now();
    let mut term_sent: Option<Instant> = None;
    loop {
        if let Some(status) = child.0.try_wait()? {
            // Reap stragglers left in the group.
            let _ = send_signal(pgid, SIGKILL);
            return Ok((status, term_sent.is_some()));
        }
        let stop = cancel.load(Ordering::Acquire) || start.elapsed() > deadline;
        match term_sent {
            None if stop => {
                let _ = send_signal(pgid, SIGTERM);
                term_sent = Some(Instant::now());
            }
            Some(t) if t.elapsed() > TERM_GRACE => {
                let _ = send_signal(pgid, SIGKILL);
            }
            _ => {}
        }
        thread::sleep(POLL);
    }
}

pub(crate) fn start_agent(
    cfg: &ExecConfig,
    dir: &Path,
    keys: &[SecretBytes],
    log: &mut File,
) -> Result<Option<(Supervised, PathBuf)>> {
    if keys.is_empty() {
        return Ok(None);
    }
    let socket = dir.join("agent.sock");
    let mut cmd = base_command("ssh-agent", cfg, &dir.join("home"));
    cmd.arg("-D")
        .arg("-a")
        .arg(&socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let agent =
        Supervised(cmd.spawn().map_err(|e| Error::new(format!("cannot start ssh-agent: {e}")))?);
    let ready = Instant::now();
    while !socket.exists() {
        if ready.elapsed() > Duration::from_secs(5) {
            return Err(Error::new("ssh-agent did not start"));
        }
        thread::sleep(Duration::from_millis(20));
    }
    for key in keys {
        let mut add = base_command("ssh-add", cfg, &dir.join("home"));
        add.arg("-q")
            .arg("-")
            .env("SSH_AUTH_SOCK", &socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child =
            add.spawn().map_err(|e| Error::new(format!("cannot start ssh-add: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(key.expose());
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            let message = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            return Err(Error::new(format!("ssh-add refused a key: {message}")));
        }
    }
    log_line(log, &format!("loaded {} SSH key(s) into a private agent", keys.len()));
    Ok(Some((agent, socket)))
}

/// Shallow-clones `repo` into `<dir>/repo` and returns the commit, with
/// host keys checked against the managed known_hosts and the agent at
/// `socket` (if any) offering the deploy key. `<dir>/home` must exist.
#[allow(clippy::too_many_arguments)]
pub(crate) fn clone_repository(
    store: &Store,
    cfg: &ExecConfig,
    dir: &Path,
    repo: &Repository,
    socket: Option<&Path>,
    log: &mut File,
    redactor: &Redactor,
    cancel: &AtomicBool,
) -> Result<String> {
    let known_hosts = store.known_hosts_path();
    if !known_hosts.exists() {
        fsio::atomic_replace(&known_hosts, b"", 16)?;
    }
    let ssh_command = format!(
        "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={}",
        quote_for_ssh_command(&known_hosts)?
    );
    let home = dir.join("home");
    log_line(log, &format!("cloning {} (branch {})", repo.url, repo.branch));
    let mut git = base_command("git", cfg, &home);
    git.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "advice.detachedHead=false",
        "clone",
        "--quiet",
        "--depth=1",
        "--single-branch",
        "--no-tags",
    ])
    .arg(format!("--branch={}", repo.branch))
    .arg("--")
    .arg(&repo.url)
    .arg(dir.join("repo"))
    .env("GIT_SSH_COMMAND", &ssh_command)
    .env("GIT_TERMINAL_PROMPT", "0")
    .env("GIT_CONFIG_NOSYSTEM", "1");
    if let Some(socket) = socket {
        git.env("SSH_AUTH_SOCK", socket);
    }
    let status = run_helper(git, log, redactor, GIT_TIMEOUT, cancel)?;
    if cancel.load(Ordering::Acquire) {
        return Err(Error::new("cancelled during clone"));
    }
    if !status.success() {
        return Err(Error::new("git clone failed"));
    }
    let head = base_command("git", cfg, &home)
        .args(["-C"])
        .arg(dir.join("repo"))
        .args(["rev-parse", "HEAD"])
        .stderr(Stdio::null())
        .output()?;
    let commit: String = String::from_utf8_lossy(&head.stdout).trim().chars().take(40).collect();
    log_line(log, &format!("commit {commit}"));
    Ok(commit)
}

/// Executes the run. `log` is the run's log file; `cancel` is polled.
pub fn execute(
    store: &Store,
    cfg: &ExecConfig,
    number: u64,
    template_id: &str,
    check_override: bool,
    log: &mut File,
    cancel: &Arc<AtomicBool>,
) -> Outcome {
    let mut outcome = Outcome::default();
    if let Err(e) =
        execute_inner(store, cfg, number, template_id, check_override, log, cancel, &mut outcome)
    {
        log_line(log, &format!("error: {}", e.message()));
        e.message().clone_into(&mut outcome.error);
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
fn execute_inner(
    store: &Store,
    cfg: &ExecConfig,
    number: u64,
    template_id: &str,
    check_override: bool,
    log: &mut File,
    cancel: &Arc<AtomicBool>,
    outcome: &mut Outcome,
) -> Result<()> {
    let inputs = resolve(store, template_id)?;
    let redactor = Redactor::new(inputs.vaults.iter().map(|(_, p)| p.expose().to_vec()));

    fsio::mkdir_all(&cfg.work_dir, 0o700)?;
    let dir = cfg.work_dir.join(format!("run-{number}"));
    let _ = fs::remove_dir_all(&dir);
    fsio::mkdir_all(&dir, 0o700)?;
    let scratch = Scratch(dir.clone());
    let home = dir.join("home");
    fsio::mkdir_all(&home, 0o700)?;
    fsio::mkdir_all(dir.join("tmp"), 0o700)?;

    let agent = start_agent(cfg, &dir, &inputs.keys, log)?;
    let known_hosts = store.known_hosts_path();
    let socket = agent.as_ref().map(|(_, socket)| socket.as_path());
    match clone_repository(store, cfg, &dir, &inputs.repository, socket, log, &redactor, cancel) {
        Ok(commit) => outcome.commit = commit,
        Err(e) => {
            outcome.cancelled = cancel.load(Ordering::Acquire);
            return Err(e);
        }
    }

    let playbook = dir.join("repo").join(&inputs.template.playbook);
    if !fs::symlink_metadata(&playbook).is_ok_and(|m| m.is_file()) {
        return Err(Error::new(format!(
            "{} is not a file in the repository",
            inputs.template.playbook
        )));
    }

    check_collections(cfg, &dir, log, &redactor, cancel, outcome)?;

    // Inventory.
    let mut inventory_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("inventory.yml"))?;
    inventory_file.write_all(inputs.inventory.expose())?;
    drop(inventory_file);

    // Vault pipes: each password is written whole (far below the pipe
    // buffer) and the write end closed, so ansible reads it then EOF.
    let mut vault_fds: Vec<OwnedFd> = Vec::new();
    let mut labels = Vec::new();
    for (label, password) in &inputs.vaults {
        let (reader, mut writer) = std::io::pipe()?;
        writer.write_all(password.expose())?;
        drop(writer);
        vault_fds.push(OwnedFd::from(reader));
        labels.push(label.clone());
    }

    let args = playbook_args(&inputs.template, check_override, &labels);
    log_line(log, &format!("ansible-playbook {}", args.join(" ")));
    let mut cmd = base_command("ansible-playbook", cfg, &home);
    cmd.args(&args)
        .current_dir(dir.join("repo"))
        .env("ANSIBLE_FORCE_COLOR", "0")
        .env("ANSIBLE_NOCOLOR", "1")
        .env("ANSIBLE_HOST_KEY_CHECKING", "True")
        .env("ANSIBLE_RETRY_FILES_ENABLED", "False")
        .env("ANSIBLE_LOCAL_TEMP", dir.join("tmp"))
        .env("PYTHONUNBUFFERED", "1")
        .env(
            "ANSIBLE_SSH_ARGS",
            format!(
                "-o ControlMaster=auto -o ControlPersist=60s -o StrictHostKeyChecking=yes -o UserKnownHostsFile={}",
                quote_for_ssh_command(&known_hosts)?
            ),
        );
    if let Some((_, socket)) = &agent {
        cmd.env("SSH_AUTH_SOCK", socket);
    }
    let mapping: Vec<(&OwnedFd, i32)> = vault_fds
        .iter()
        .enumerate()
        .map(|(i, fd)| (fd, VAULT_FD_BASE + i32::try_from(i).unwrap_or(0)))
        .collect();
    inherit_fds(&mut cmd, &mapping)?;
    let (reader, writer) = std::io::pipe()?;
    cmd.stdout(writer.try_clone()?).stderr(writer).process_group(0);
    let child =
        cmd.spawn().map_err(|e| Error::new(format!("cannot start ansible-playbook: {e}")))?;
    // Dropping the command closes the parent's copies of the write end and
    // of the vault pipes, so the log reader sees EOF when ansible exits.
    drop(cmd);
    drop(mapping);
    drop(vault_fds);

    let mut log_copy = log.try_clone()?;
    let deadline = Duration::from_secs(
        u64::try_from(inputs.template.timeout_minutes.max(1)).unwrap_or(60) * 60,
    );
    let (status, stopped) = thread::scope(|scope| {
        let pump = thread::Builder::new()
            .name("run-log".to_owned())
            .stack_size(THREAD_STACK)
            .spawn_scoped(scope, || redact::pump(reader, &mut log_copy, &redactor, 0));
        let result = supervise(child, deadline, cancel);
        if let Ok(handle) = pump {
            let _ = handle.join();
        }
        result
    })?;
    outcome.exit_code = status.code().map(i64::from);
    if stopped {
        if cancel.load(Ordering::Acquire) {
            outcome.cancelled = true;
            log_line(log, "cancelled");
        } else {
            outcome.timed_out = true;
            outcome.error = format!("timed out after {} minutes", inputs.template.timeout_minutes);
            log_line(log, &outcome.error);
        }
    }
    log_line(
        log,
        &format!(
            "ansible-playbook exited with {}",
            status.code().map_or_else(|| "a signal".to_owned(), |c| c.to_string())
        ),
    );
    drop(agent);
    drop(scratch);
    Ok(())
}

/// Fails the run when the image's built-in collections do not satisfy the
/// repository's `collections/requirements.yml`. The resolution is
/// `--offline`, so it only compares; it never reaches Galaxy and installs
/// nothing. It runs in the clone so the repository's ansible.cfg
/// `collections_path` applies, exactly as it will for the playbook, but with
/// `-p` aimed at the run's scratch space: ansible-galaxy creates its output
/// directory even when there is nothing to install, and that must not be
/// inside the clone, where it could shadow a configured path.
fn check_collections(
    cfg: &ExecConfig,
    dir: &Path,
    log: &mut File,
    redactor: &Redactor,
    cancel: &AtomicBool,
    outcome: &mut Outcome,
) -> Result<()> {
    let repo = dir.join("repo");
    let Some(requirements) = COLLECTION_REQUIREMENTS
        .iter()
        .find(|r| fs::symlink_metadata(repo.join(r)).is_ok_and(|m| m.is_file()))
    else {
        return Ok(());
    };
    log_line(log, &format!("checking the built-in collections against {requirements} (offline)"));
    let mut cmd = base_command("ansible-galaxy", cfg, &dir.join("home"));
    cmd.args(["collection", "install", "--offline", "-r", requirements, "-p"])
        .arg(dir.join("galaxy-check"))
        .current_dir(&repo)
        .env("ANSIBLE_NOCOLOR", "1")
        .env("ANSIBLE_LOCAL_TEMP", dir.join("tmp"));
    let status = run_helper(cmd, log, redactor, COLLECTION_CHECK_TIMEOUT, cancel)?;
    if cancel.load(Ordering::Acquire) {
        outcome.cancelled = true;
        return Err(Error::new("cancelled during the collection check"));
    }
    if !status.success() {
        return Err(Error::new(format!(
            "the collections built into this playbook-runner image do not satisfy {requirements}; \
             update runtime/collections.yml in playbook-runner and release a new image"
        )));
    }
    Ok(())
}

/// Checks that ansible can read an inventory, with nothing decrypted:
/// `ansible-inventory --graph` against a private copy. `Ok(None)` means
/// ansible is not installed here, so the check was skipped.
pub fn check_inventory(cfg: &ExecConfig, content: &str) -> Result<Option<()>> {
    fsio::mkdir_all(&cfg.work_dir, 0o700)?;
    let dir = cfg.work_dir.join(format!("check-{}", pr_common::rand::random_hex(8)?));
    fsio::mkdir_all(&dir, 0o700)?;
    let scratch = Scratch(dir.clone());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("inventory.yml"))?;
    file.write_all(content.as_bytes())?;
    drop(file);
    let mut cmd = base_command("ansible-inventory", cfg, &dir);
    cmd.args(["--graph", "-i", "inventory.yml"])
        .current_dir(&dir)
        .env("ANSIBLE_INVENTORY_UNPARSED_FAILED", "True")
        .env("ANSIBLE_INVENTORY_ENABLED", "yaml,ini")
        .env("ANSIBLE_LOCAL_TEMP", &dir)
        .env("ANSIBLE_NOCOLOR", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    drop(scratch);
    if output.status.success() {
        return Ok(Some(()));
    }
    let detail: String = String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(6)
        .collect::<Vec<_>>()
        .join(" ");
    Err(Error::new(format!(
        "ansible could not parse the inventory: {}",
        detail.replace(dir.to_string_lossy().as_ref(), "")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template() -> Template {
        Template {
            id: "0123456789abcdef".into(),
            name: "T".into(),
            repository: String::new(),
            playbook: "site.yml".into(),
            inventory: String::new(),
            vault_secrets: Vec::new(),
            ssh_key: String::new(),
            limit: "vm1".into(),
            tags: "a,b".into(),
            skip_tags: String::new(),
            check_mode: false,
            diff: true,
            verbosity: 2,
            timeout_minutes: 60,
            created: 0,
            updated: 0,
        }
    }

    #[test]
    fn arguments_bind_values_to_their_options() {
        let args = playbook_args(&template(), true, &["default".into(), "prod".into()]);
        assert_eq!(
            args,
            [
                "-i",
                "../inventory.yml",
                "--vault-id=default@/dev/fd/200",
                "--vault-id=prod@/dev/fd/201",
                "--limit=vm1",
                "--tags=a,b",
                "--check",
                "--diff",
                "-vv",
                "--",
                "site.yml"
            ]
        );
    }
}
