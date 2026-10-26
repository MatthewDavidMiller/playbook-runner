//! End-to-end runs against localhost: a real git clone of a local repository,
//! a real ansible-playbook that must decrypt a vaulted variable through the
//! inherited pipe, a real ssh-agent holding the key, log redaction, and
//! cancellation.
//!
//! These need git, ansible-core, and openssh-client, which the toolbox
//! carries. Run them through `make test`.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::format_push_string
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pr_crypto::MasterKey;
use pr_runner::{ExecConfig, Runner, Status};
use pr_store::{Inventory, Repository, Secret, SecretKind, Store, Template};

const VAULT_PASSWORD: &str = "vault-pass-canary-5772";
const INVENTORY_PASSWORD: &str = "inventory-pass-canary-9041";

struct Fixture {
    root: PathBuf,
    store: Arc<Store>,
    runner: Arc<Runner>,
    vault_id: String,
    key_id: String,
    key_fingerprint: String,
    repo_id: String,
    inventory_id: String,
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(["-c", "user.name=test", "-c", "user.email=test@example.invalid"])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", dir)
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?}");
}

/// `ansible-vault encrypt_string` of `value` under the test password.
fn vaulted(root: &Path, value: &str) -> String {
    let pw = root.join("pw");
    fs::write(&pw, VAULT_PASSWORD).unwrap();
    let out = Command::new("ansible-vault")
        .args(["encrypt_string", "--vault-password-file"])
        .arg(&pw)
        .args([value, "--name", "secret_var"])
        .env("HOME", root)
        .env("ANSIBLE_LOCAL_TEMP", root.join("tmp"))
        .output()
        .unwrap();
    fs::remove_file(&pw).unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("pr-run-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("tmp")).unwrap();

        // A repository with three playbooks.
        let repo = root.join("repo.git");
        fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        fs::write(
            repo.join("site.yml"),
            format!(
                "- hosts: all\n  gather_facts: false\n  vars:\n{}\n  tasks:\n\
                 \x20   - ansible.builtin.debug:\n        msg: \"decrypted={{{{ secret_var }}}}\"\n\
                 \x20   - ansible.builtin.debug:\n        msg: \"leak={{{{ leak }}}}\"\n\
                 \x20   - ansible.builtin.debug:\n        msg: \"become={{{{ ansible_become_pass }}}}\"\n\
                 \x20   - ansible.builtin.debug:\n        msg: \"blob={{{{ blob }}}}\"\n\
                 \x20   - ansible.builtin.command: ssh-add -l\n      environment:\n        SSH_AUTH_SOCK: \"{{{{ lookup('env', 'SSH_AUTH_SOCK') }}}}\"\n\
                 \x20     changed_when: false\n      register: agent\n\
                 \x20   - ansible.builtin.debug:\n        msg: \"agent={{{{ agent.stdout }}}}\"\n",
                vaulted(&root, "plain-value-from-vault")
                    .lines()
                    .map(|l| format!("    {l}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )
        .unwrap();
        fs::write(
            repo.join("slow.yml"),
            "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.command: sleep 120\n",
        )
        .unwrap();
        fs::write(
            repo.join("fail.yml"),
            "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.fail:\n        msg: deliberate\n",
        )
        .unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "playbooks"]);

        let key = MasterKey::from_hex(&[b'5'; 64]).unwrap();
        let store = Arc::new(Store::open(&root.join("data"), &key).unwrap());
        let t = 1;
        let vault_id = pr_store::new_id().unwrap();
        store.put_blob("secret", &vault_id, VAULT_PASSWORD.as_bytes()).unwrap();
        store
            .put(Secret {
                id: vault_id.clone(),
                name: "Vault".into(),
                kind: SecretKind::VaultPassword,
                vault_id: "default".into(),
                fingerprint: String::new(),
                created: t,
                updated: t,
            })
            .unwrap();
        let key_id = pr_store::new_id().unwrap();
        let ssh_key = pr_common::testkey::generate("").unwrap();
        store.put_blob("secret", &key_id, ssh_key.private.as_bytes()).unwrap();
        store
            .put(Secret {
                id: key_id.clone(),
                name: "Key".into(),
                kind: SecretKind::SshKey,
                vault_id: String::new(),
                fingerprint: String::new(),
                created: t,
                updated: t,
            })
            .unwrap();
        let repo_id = pr_store::new_id().unwrap();
        store
            .put(Repository {
                id: repo_id.clone(),
                name: "Repo".into(),
                url: repo.to_string_lossy().into_owned(),
                branch: "main".into(),
                deploy_key: String::new(),
                created: t,
                updated: t,
            })
            .unwrap();
        let inventory_id = pr_store::new_id().unwrap();
        let python = String::from_utf8(
            Command::new("sh").args(["-c", "command -v python3"]).output().unwrap().stdout,
        )
        .unwrap();
        let inventory = format!(
            "all:\n  hosts:\n    localhost:\n      ansible_connection: local\n      ansible_python_interpreter: {}\n  vars:\n    leak: \"{VAULT_PASSWORD}\"\n    ansible_become_pass: \"{INVENTORY_PASSWORD}\"\n    blob: \"{}\"\n",
            python.trim(),
            ssh_key.private.replace('\n', "\\n")
        );
        store.put_blob("inventory", &inventory_id, inventory.as_bytes()).unwrap();
        store
            .put(Inventory {
                id: inventory_id.clone(),
                name: "Local".into(),
                size: 0,
                created: t,
                updated: t,
            })
            .unwrap();

        let cfg = ExecConfig {
            work_dir: root.join("work"),
            path: std::env::var("PATH").unwrap(),
            timezone: "UTC".into(),
        };
        let runner = Runner::new(Arc::clone(&store), &root.join("data"), cfg, 50).unwrap();
        runner.start().unwrap();
        Self {
            root,
            store,
            runner,
            vault_id,
            key_id,
            key_fingerprint: ssh_key.fingerprint,
            repo_id,
            inventory_id,
        }
    }

    fn template(&self, playbook: &str, timeout_minutes: i64) -> String {
        let id = pr_store::new_id().unwrap();
        self.store
            .put(Template {
                id: id.clone(),
                name: format!("T {playbook} {id}"),
                repository: self.repo_id.clone(),
                playbook: playbook.into(),
                inventory: self.inventory_id.clone(),
                vault_secrets: vec![self.vault_id.clone()],
                ssh_key: self.key_id.clone(),
                limit: String::new(),
                tags: String::new(),
                skip_tags: String::new(),
                check_mode: false,
                diff: false,
                verbosity: 0,
                timeout_minutes,
                created: 1,
                updated: 1,
            })
            .unwrap();
        id
    }

    fn wait(&self, number: u64, until: impl Fn(Status) -> bool) -> pr_runner::Run {
        let start = Instant::now();
        loop {
            let run = self.runner.runs().get(number).unwrap().unwrap();
            if until(run.status) {
                return run;
            }
            assert!(
                start.elapsed() < Duration::from_secs(120),
                "run {number} stuck in {:?}",
                run.status
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn log(&self, number: u64) -> String {
        self.runner.read_log(number, 1 << 20).unwrap().0
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_run_decrypts_through_the_pipe_uses_the_agent_and_masks_secrets() {
    let f = Fixture::new("success");
    let template = f.template("site.yml", 10);
    let run = f.runner.enqueue(&template, "manual", false).unwrap();
    let done = f.wait(run.number, |s| !s.is_active());
    let log = f.log(run.number);
    assert_eq!(done.status, Status::Succeeded, "{log}");
    assert_eq!(done.exit_code, Some(0));
    assert_eq!(done.commit.len(), 40);
    assert!(log.contains("decrypted=plain-value-from-vault"), "{log}");
    assert!(log.contains("leak=********"), "{log}");
    assert!(!log.contains(VAULT_PASSWORD), "{log}");
    // Inventory values that look like secrets and the lines of the SSH key
    // are masked even when a playbook prints them.
    assert!(log.contains("become=********"), "{log}");
    assert!(!log.contains(INVENTORY_PASSWORD), "{log}");
    assert!(log.contains("blob="), "{log}");
    assert!(!log.contains("b3BlbnNzaC1rZXktdjE"), "the SSH key body reached the log: {log}");
    // On disk the log is sealed.
    let raw = fs::read(f.root.join("data/runs").join(format!("{}.log", run.number))).unwrap();
    assert!(raw.starts_with(b"PRL1"));
    assert!(!String::from_utf8_lossy(&raw).contains("decrypted="));
    assert!(log.contains(&f.key_fingerprint), "{log}");
    assert!(log.contains("--vault-id=default@/dev/fd/200"));
    // The scratch directory is gone, and with it the decrypted inventory.
    assert_eq!(fs::read_dir(f.root.join("work")).unwrap().count(), 0);
}

#[test]
fn a_failing_playbook_is_recorded_as_failed() {
    let f = Fixture::new("failure");
    let template = f.template("fail.yml", 10);
    let run = f.runner.enqueue(&template, "manual", false).unwrap();
    let done = f.wait(run.number, |s| !s.is_active());
    assert_eq!(done.status, Status::Failed);
    assert_eq!(done.exit_code, Some(2));
    assert!(f.log(run.number).contains("deliberate"));
}

#[test]
fn a_missing_playbook_fails_before_ansible_runs() {
    let f = Fixture::new("missing");
    let template = f.template("absent.yml", 10);
    let run = f.runner.enqueue(&template, "manual", false).unwrap();
    let done = f.wait(run.number, |s| !s.is_active());
    assert_eq!(done.status, Status::Failed);
    assert!(done.error.contains("absent.yml is not a file"), "{}", done.error);
}

#[test]
fn runs_queue_in_order_and_cancel_stops_the_whole_process_group() {
    let f = Fixture::new("cancel");
    let slow = f.template("slow.yml", 10);
    let first = f.runner.enqueue(&slow, "manual", false).unwrap();
    let second = f.runner.enqueue(&slow, "manual", false).unwrap();
    f.wait(first.number, |s| s == Status::Running);
    assert_eq!(f.runner.runs().get(second.number).unwrap().unwrap().status, Status::Queued);
    // Cancelling a queued run is immediate.
    f.runner.cancel(second.number).unwrap();
    assert_eq!(f.runner.runs().get(second.number).unwrap().unwrap().status, Status::Cancelled);
    // Give ansible time to reach the sleep, then cancel the running one.
    let start = Instant::now();
    while !f.log(first.number).contains("TASK [ansible.builtin.command]") {
        assert!(start.elapsed() < Duration::from_secs(60));
        std::thread::sleep(Duration::from_millis(200));
    }
    std::thread::sleep(Duration::from_secs(1));
    f.runner.cancel(first.number).unwrap();
    let done = f.wait(first.number, |s| !s.is_active());
    assert_eq!(done.status, Status::Cancelled);
    assert!(start.elapsed() < Duration::from_secs(60), "cancel took too long");
    // No sleep 120 survives in the cancelled process group.
    let ps = Command::new("ps").args(["-o", "args"]).output().unwrap();
    assert!(!String::from_utf8_lossy(&ps.stdout).contains("sleep 120"));
}

#[test]
fn the_inventory_check_rejects_unparseable_files() {
    let f = Fixture::new("inventory");
    assert!(f.runner.check_inventory("all:\n  hosts:\n    vm1:\n").unwrap().is_some());
    let err = f.runner.check_inventory("all: [unclosed\n").unwrap_err();
    assert!(err.message().contains("could not parse"), "{err}");
}

#[test]
fn the_scheduler_queues_due_runs_once_and_skips_busy_templates() {
    use pr_runner::scheduler::{next_run, tick};
    use pr_store::Schedule;
    let f = Fixture::new("schedule");
    let slow = f.template("slow.yml", 10);
    let id = pr_store::new_id().unwrap();
    let schedule = Schedule {
        id: id.clone(),
        name: "Every minute".into(),
        template: slow.clone(),
        cron: "* * * * *".into(),
        enabled: true,
        check_mode: false,
        created: 1,
        updated: 1,
    };
    f.store.put(schedule.clone()).unwrap();
    let zone = pr_sched::Zone::utc();
    let now = pr_common::timefmt::unix_seconds();
    assert!(next_run(&schedule, &zone, now).is_some_and(|n| n > now && n <= now + 60));
    // Nothing is due in an interval with no minute boundary.
    let boundary = now - now.rem_euclid(60);
    assert!(tick(&f.runner, &f.store, &zone, boundary + 1, boundary + 30).is_empty());
    let queued = tick(&f.runner, &f.store, &zone, now - 120, now);
    assert_eq!(queued.len(), 1);
    let run = f.runner.runs().get(queued[0]).unwrap().unwrap();
    assert_eq!(run.trigger, format!("schedule:{id}"));
    // While that run is active, the next occurrence is skipped.
    assert!(tick(&f.runner, &f.store, &zone, now - 120, now).is_empty());
    f.runner.cancel(queued[0]).unwrap();
    f.wait(queued[0], |s| !s.is_active());
    // A disabled schedule never fires.
    f.store.put(Schedule { enabled: false, ..schedule }).unwrap();
    assert!(tick(&f.runner, &f.store, &zone, now - 120, now).is_empty());
}

/// Writes `files` into the fixture repository and commits them.
fn commit(f: &Fixture, files: &[(&str, &str)]) {
    let repo = f.root.join("repo.git");
    for (path, content) in files {
        let path = repo.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "update"]);
}

#[test]
fn collection_requirements_are_checked_offline_against_the_image() {
    let f = Fixture::new("collections");
    // A repository that pins a collection its own collections_path provides,
    // standing in for the collections built into the image.
    commit(
        &f,
        &[
            ("ansible.cfg", "[defaults]\ncollections_path = ./collections\n"),
            (
                "collections/ansible_collections/testns/testcoll/galaxy.yml",
                "namespace: testns\nname: testcoll\nversion: 1.2.3\nreadme: README.md\nauthors: [test]\n",
            ),
            (
                "collections/requirements.yml",
                "collections:\n  - name: testns.testcoll\n    version: \">=1.0.0,<2.0.0\"\n",
            ),
        ],
    );
    let template = f.template("site.yml", 10);
    let run = f.runner.enqueue(&template, "manual", false).unwrap();
    let done = f.wait(run.number, |s| !s.is_active());
    let log = f.log(run.number);
    assert_eq!(done.status, Status::Succeeded, "{log}");
    assert!(log.contains(
        "checking the built-in collections against collections/requirements.yml (offline)"
    ));

    // A requirement the image cannot meet stops the run before ansible-playbook.
    commit(
        &f,
        &[(
            "collections/requirements.yml",
            "collections:\n  - name: testns.testcoll\n    version: 2.0.0\n",
        )],
    );
    let run = f.runner.enqueue(&template, "manual", false).unwrap();
    let done = f.wait(run.number, |s| !s.is_active());
    let log = f.log(run.number);
    assert_eq!(done.status, Status::Failed, "{log}");
    assert!(done.error.contains("do not satisfy collections/requirements.yml"), "{}", done.error);
    assert!(log.contains("testns.testcoll:2.0.0"), "the resolver's reason is in the log: {log}");
    assert!(!log.contains("ansible-playbook -i"), "the playbook never started: {log}");
}
