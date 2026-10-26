//! Validation for every operator-supplied value that later reaches a
//! command line, a file ansible reads, or a page. Values are passed to child
//! processes as separate argv entries, never through a shell, but a value
//! starting with `-` could still be read as an option, so those are refused
//! too.

use pr_common::{Error, Result};

pub const NAME_MAX: usize = 64;
pub const INVENTORY_MAX: usize = 512 * 1024;
pub const SECRET_MAX: usize = 16 * 1024;

fn fail<T>(message: &str) -> Result<T> {
    Err(Error::new(message))
}

/// A display name: 1-64 characters, no control characters.
pub fn name(s: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty() || s.chars().count() > NAME_MAX || s.chars().any(char::is_control) {
        return fail("Names must be 1-64 characters without control characters.");
    }
    Ok(s.to_owned())
}

/// A `--vault-id` label: letters, digits, `.`, `_`, `-`.
pub fn vault_id(s: &str) -> Result<String> {
    let s = s.trim();
    let s = if s.is_empty() { "default" } else { s };
    if s.len() > 64
        || s.starts_with('-')
        || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return fail("The vault ID may use letters, digits, '.', '_', and '-'.");
    }
    Ok(s.to_owned())
}

/// Whether a git URL carries a credential: any user information on an
/// `https://` URL (a token is often the "user name"), or a password on an
/// `ssh://` URL. A plain `git@host` user name is not a credential.
pub fn url_has_credentials(url: &str) -> bool {
    let Some((scheme, rest)) = url.trim().split_once("://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let Some((userinfo, _)) = authority.rsplit_once('@') else { return false };
    scheme.eq_ignore_ascii_case("https")
        || scheme.eq_ignore_ascii_case("http")
        || userinfo.contains(':')
}

/// A git remote: `ssh://`, `https://`, scp-style `user@host:path`, or an
/// absolute local path (for testing). Transport helpers (`ext::`, `fd::`)
/// and anything that could parse as an option are refused.
pub fn git_url(s: &str) -> Result<String> {
    let s = s.trim();
    let bad_chars = s.chars().any(|c| c.is_whitespace() || c.is_control());
    if s.is_empty() || s.len() > 512 || bad_chars || s.starts_with('-') || s.contains("::") {
        return fail("Enter a git URL such as git@github.com:owner/repo.git.");
    }
    let scp_like = !s.contains("://")
        && s.split_once(':').is_some_and(|(host, path)| {
            host.contains('@') && !host.contains('/') && !path.is_empty()
        });
    if url_has_credentials(s) {
        return fail(
            "Do not put a token or password in the URL; it would be stored with the repository \
             record and written to run logs. For a private repository use an ssh:// or \
             git@host:path URL with a deploy key secret.",
        );
    }
    let ok = s.starts_with("ssh://") || s.starts_with("https://") || s.starts_with('/') || scp_like;
    if !ok {
        return fail("Use an ssh://, https://, or user@host:path git URL.");
    }
    Ok(s.to_owned())
}

/// A branch or tag name, within git's ref rules.
pub fn branch(s: &str) -> Result<String> {
    let s = s.trim();
    let s = if s.is_empty() { "main" } else { s };
    let chars_ok = s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b));
    if s.len() > 200
        || !chars_ok
        || s.starts_with(['-', '/', '.'])
        || s.ends_with(['/', '.'])
        || s.contains("..")
        || s.contains("//")
        || s.to_ascii_lowercase().ends_with(".lock")
    {
        return fail("Enter a branch name such as main.");
    }
    Ok(s.to_owned())
}

/// A playbook path inside the repository: relative, no `..`, a YAML file.
pub fn playbook(s: &str) -> Result<String> {
    let s = s.trim().trim_start_matches("./");
    let chars_ok = s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b));
    let yaml = std::path::Path::new(s)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml"));
    if s.is_empty()
        || s.len() > 255
        || !chars_ok
        || !yaml
        || s.starts_with(['/', '-', '.'])
        || s.split('/').any(|part| part.is_empty() || part == "..")
    {
        return fail("Enter the playbook's path in the repository, such as site.yml.");
    }
    Ok(s.to_owned())
}

/// An ansible host pattern for --limit, or "" for none.
pub fn limit(s: &str) -> Result<String> {
    let s = s.trim();
    let ok = s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.:,*!&[]-~@".contains(&b));
    if s.len() > 512 || !ok || s.starts_with('-') {
        return fail("The limit must be an ansible host pattern such as vm1 or web:&prod.");
    }
    Ok(s.to_owned())
}

/// A comma-separated tag list, or "" for none.
pub fn tags(s: &str) -> Result<String> {
    let s = s.trim();
    let ok = s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.,-".contains(&b));
    if s.len() > 512 || !ok || s.starts_with('-') {
        return fail("Tags are comma-separated names of letters, digits, '_', '.', and '-'.");
    }
    Ok(s.to_owned())
}

/// Inventory text: UTF-8 (already, as a &str), bounded, no NUL, and with
/// Windows line endings normalized.
pub fn inventory(s: &str) -> Result<String> {
    let s = s.replace("\r\n", "\n");
    if s.trim().is_empty() {
        return fail("The inventory is empty.");
    }
    if s.len() > INVENTORY_MAX {
        return fail("The inventory is larger than 512 KiB.");
    }
    if s.contains('\0') {
        return fail("The inventory contains a NUL character.");
    }
    Ok(s)
}

/// A secret value: bounded and non-empty. A vault password loses one
/// trailing newline (as ansible does when it reads a password file).
pub fn secret_value(s: &str) -> Result<&str> {
    if s.is_empty() || s.len() > SECRET_MAX || s.contains('\0') {
        return fail("The secret must be 1 byte to 16 KiB with no NUL characters.");
    }
    Ok(s)
}

/// known_hosts text: every non-blank, non-comment line must look like
/// `<hosts> <keytype> <base64>` (optionally after a `@marker`).
pub fn known_hosts(s: &str) -> Result<String> {
    let mut out = String::with_capacity(s.len() + 1);
    for (n, line) in s.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        if line.starts_with('@') {
            fields.next();
        }
        let (Some(_hosts), Some(kind), Some(key)) = (fields.next(), fields.next(), fields.next())
        else {
            return Err(Error::new(format!("known_hosts line {} is incomplete.", n + 1)));
        };
        let kind_ok =
            kind.starts_with("ssh-") || kind.starts_with("ecdsa-") || kind.starts_with("sk-");
        if !kind_ok
            || pr_common::base64::decode(key.as_bytes()).is_none()
            || line.chars().any(char::is_control)
        {
            return Err(Error::new(format!("known_hosts line {} is not a host key.", n + 1)));
        }
        out.push_str(line);
        out.push('\n');
    }
    if out.len() > crate::KNOWN_HOSTS_LIMIT {
        return fail("known_hosts is larger than 64 KiB.");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_in_git_urls_are_refused() {
        for bad in [
            "https://token@github.com/o/r.git",
            "https://user:pass@github.com/o/r.git",
            "https://x-access-token:abc@host/o/r",
            "ssh://git:secret@host/o/r.git",
        ] {
            assert!(url_has_credentials(bad), "{bad}");
            assert!(git_url(bad).is_err(), "{bad}");
        }
        for fine in [
            "https://github.com/o/r.git",
            "https://github.com/o/r@v1.git",
            "https://host/path?x=a@b",
            "ssh://git@github.com/o/r.git",
            "git@github.com:o/r.git",
        ] {
            assert!(!url_has_credentials(fine), "{fine}");
            assert!(git_url(fine).is_ok(), "{fine}");
        }
    }

    #[test]
    fn git_urls() {
        for ok in [
            "git@github.com:MatthewDavidMiller/ansible_playbooks.git",
            "ssh://git@github.com/owner/repo.git",
            "https://github.com/owner/repo.git",
            "/srv/git/test.git",
        ] {
            assert_eq!(git_url(ok).unwrap(), ok);
        }
        for bad in [
            "",
            "-upload-pack=x",
            "ext::sh -c x",
            "git@github.com:",
            "github.com:repo",
            "file:///x",
            "a b",
        ] {
            assert!(git_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn branches_and_vault_ids() {
        assert_eq!(branch("").unwrap(), "main");
        assert_eq!(branch("release/1.2").unwrap(), "release/1.2");
        for bad in ["-x", "a..b", "a b", "x.lock", "/x", "x/"] {
            assert!(branch(bad).is_err(), "{bad}");
        }
        assert_eq!(vault_id("").unwrap(), "default");
        assert!(vault_id("prod").is_ok());
        assert!(vault_id("-x").is_err() && vault_id("a@b").is_err());
    }

    #[test]
    fn playbooks_limits_and_tags() {
        assert_eq!(playbook("./update_homelab_vms.yml").unwrap(), "update_homelab_vms.yml");
        assert_eq!(playbook("plays/site.yaml").unwrap(), "plays/site.yaml");
        for bad in [
            "",
            "../x.yml",
            "/etc/x.yml",
            "a/../b.yml",
            "x.sh",
            "-x.yml",
            "a//b.yml",
            ".hidden.yml",
        ] {
            assert!(playbook(bad).is_err(), "{bad}");
        }
        assert!(limit("vm1,web:&prod:!db*").is_ok());
        assert!(limit("-e x").is_err() && limit("a b").is_err());
        assert!(tags("update,reboot").is_ok());
        assert!(tags("a b").is_err() && tags("-x").is_err());
    }

    #[test]
    fn names_inventories_and_known_hosts() {
        assert_eq!(name("  Homelab  ").unwrap(), "Homelab");
        assert!(name("").is_err() && name("a\nb").is_err() && name(&"x".repeat(65)).is_err());
        assert_eq!(inventory("all:\r\n  hosts: {}\r\n").unwrap(), "all:\n  hosts: {}\n");
        assert!(inventory("  ").is_err());
        let hosts = known_hosts(
            "# comment\ngithub.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n\n",
        )
        .unwrap();
        assert!(hosts.contains("github.com ssh-ed25519"));
        assert!(known_hosts("github.com").is_err());
        assert!(known_hosts("github.com rsa-sha2 AAAA").is_err());
    }
}
