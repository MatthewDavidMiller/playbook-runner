//! Syncing a repository: a shallow clone, the same way a run clones, to
//! list the playbooks it contains for the template form's dropdown.
//!
//! The clone lives in its own scratch directory under the work dir and is
//! deleted as soon as the playbooks are listed; only the list and the commit
//! are kept, as a [`RepoSnapshot`].

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use pr_common::{Error, Result, fsio, rand, timefmt};
use pr_store::{RepoSnapshot, Repository, Secret, SecretKind, Store};

use crate::exec::{ExecConfig, Scratch, clone_repository, start_agent};
use crate::redact::Redactor;

/// Directories never searched for playbooks: role and collection content,
/// VCS metadata, and the usual non-playbook trees.
const SKIP_DIRS: [&str; 9] = [
    "roles",
    "collections",
    "group_vars",
    "host_vars",
    "tests",
    "docs",
    "molecule",
    "node_modules",
    "files",
];
const MAX_DEPTH: usize = 3;
const MAX_FILES: usize = 2000;
const MAX_PLAYBOOK_BYTES: usize = 256 * 1024;
const MAX_PLAYBOOKS: usize = 500;

/// Whether YAML text looks like a playbook: a top-level list whose items
/// are plays (`hosts:`) or playbook imports, as opposed to a task list or a
/// variables file. A heuristic by design; the template form also takes any
/// path typed in by hand.
pub fn looks_like_playbook(text: &str) -> bool {
    let mut lines = text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#') && *l != "---");
    if !lines.next().is_some_and(|first| first.starts_with("- ") || first == "-") {
        return false;
    }
    text.lines().any(|line| {
        let item = line.strip_prefix("- ").unwrap_or_else(|| line.strip_prefix("  ").unwrap_or(""));
        let item = item.trim_start_matches("- ");
        item.starts_with("hosts:")
            || item.starts_with("import_playbook:")
            || item.starts_with("ansible.builtin.import_playbook:")
    })
}

/// Playbook paths under `root`, relative and sorted, top level first.
pub fn find_playbooks(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut seen_files = 0;
    let mut stack = vec![(root.to_path_buf(), 0_usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            seen_files += 1;
            if seen_files > MAX_FILES || found.len() >= MAX_PLAYBOOKS {
                break;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(kind) = entry.file_type() else { continue };
            let path = entry.path();
            if kind.is_dir() {
                if depth + 1 < MAX_DEPTH
                    && !name.starts_with('.')
                    && !SKIP_DIRS.contains(&name.as_str())
                {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            // Symlinks are never followed: kind is the link's own type.
            let yaml = Path::new(&name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml"));
            if !kind.is_file() || !yaml {
                continue;
            }
            let Ok(Some(text)) = fsio::read_text(&path, MAX_PLAYBOOK_BYTES) else { continue };
            if !looks_like_playbook(&text) {
                continue;
            }
            if let Ok(relative) = path.strip_prefix(root)
                && let Some(relative) = relative.to_str()
                && pr_store::validate::playbook(relative).is_ok()
            {
                found.push(relative.to_owned());
            }
        }
    }
    found.sort_by_key(|p| (p.matches('/').count(), p.to_lowercase()));
    found
}

/// Clones `repository_id` and records the playbooks it contains. On a clone
/// failure the error carries git's own message.
pub fn sync_repository(
    store: &Store,
    cfg: &ExecConfig,
    repository_id: &str,
) -> Result<RepoSnapshot> {
    let repo = store
        .get::<Repository>(repository_id)?
        .ok_or_else(|| Error::new("the repository does not exist"))?;
    let mut keys = Vec::new();
    if !repo.deploy_key.is_empty() {
        store
            .get::<Secret>(&repo.deploy_key)?
            .filter(|s| s.kind == SecretKind::SshKey)
            .ok_or_else(|| Error::new("the repository's deploy key no longer exists"))?;
        keys.push(store.get_blob("secret", &repo.deploy_key)?);
    }
    fsio::mkdir_all(&cfg.work_dir, 0o700)?;
    let dir = cfg.work_dir.join(format!("sync-{}", rand::random_hex(8)?));
    fsio::mkdir_all(&dir, 0o700)?;
    let scratch = Scratch(dir.clone());
    fsio::mkdir_all(dir.join("home"), 0o700)?;
    let log_path = dir.join("sync.log");
    let mut log: File =
        OpenOptions::new().create_new(true).append(true).mode(0o600).open(&log_path)?;
    let agent = start_agent(cfg, &dir, &keys, &mut log)?;
    let socket = agent.as_ref().map(|(_, socket)| socket.as_path());
    let cancel = AtomicBool::new(false);
    let cloned =
        clone_repository(store, cfg, &dir, &repo, socket, &mut log, &Redactor::new([]), &cancel);
    drop(agent);
    let commit = match cloned {
        Ok(commit) => commit,
        Err(e) => {
            // git's own message is the useful part; the runner's lines are not.
            let detail: Vec<String> = fsio::read_text(&log_path, 64 * 1024)
                .ok()
                .flatten()
                .unwrap_or_default()
                .lines()
                .filter(|l| !l.starts_with("[playbook-runner]") && !l.trim().is_empty())
                .take(6)
                .map(str::to_owned)
                .collect();
            return Err(if detail.is_empty() {
                e
            } else {
                Error::new(format!("{}: {}", e.message(), detail.join(" ")))
            });
        }
    };
    let snapshot = RepoSnapshot {
        id: repo.id,
        commit,
        playbooks: find_playbooks(&dir.join("repo")),
        synced_at: timefmt::unix_seconds(),
    };
    drop(scratch);
    store.put(snapshot.clone())?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn playbooks_are_told_apart_from_task_and_variable_files() {
        assert!(looks_like_playbook("---\n- name: Configure\n  hosts: vm1\n  roles: [a]\n"));
        assert!(looks_like_playbook("# comment\n- hosts: all\n  tasks: []\n"));
        assert!(looks_like_playbook(
            "---\n- import_playbook: homelab_vms.yml\n- import_playbook: reboot_vms.yml\n"
        ));
        assert!(looks_like_playbook("- ansible.builtin.import_playbook: x.yml\n"));
        assert!(!looks_like_playbook(
            "---\n- name: A task\n  ansible.builtin.debug:\n    msg: hi\n"
        ));
        assert!(!looks_like_playbook("---\nfoo: bar\nhosts: nope\n"));
        assert!(!looks_like_playbook(""));
        // A task that mentions hosts deeper down is still a task list.
        assert!(!looks_like_playbook(
            "- name: t\n  ansible.builtin.lineinfile:\n    path: /etc/hosts\n      hosts: x\n"
        ));
    }

    #[test]
    fn discovery_walks_the_tree_and_skips_roles() {
        let root = std::env::temp_dir().join(format!("pr-sync-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for (path, text) in [
            ("site.yml", "- hosts: all\n  tasks: []\n"),
            ("update.yaml", "- import_playbook: site.yml\n"),
            ("plays/web.yml", "- hosts: web\n"),
            ("roles/x/tasks/main.yml", "- hosts: all\n"),
            ("vars.yml", "a: 1\n"),
            ("tasks/x.yml", "- name: t\n  debug: {}\n"),
            (".github/workflow.yml", "- hosts: all\n"),
        ] {
            let p = root.join(path);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, text).unwrap();
        }
        assert_eq!(find_playbooks(&root), ["site.yml", "update.yaml", "plays/web.yml"]);
        fs::remove_dir_all(&root).unwrap();
    }
}
