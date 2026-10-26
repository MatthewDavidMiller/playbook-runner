//! The record types. None of them holds a secret value: vault passwords,
//! SSH keys, and inventory contents live in sealed blobs keyed by the
//! record's id.

use pr_common::json::Value;

use crate::jsonw::{self, Obj};

pub trait Record: Clone {
    /// The collection file under the data directory.
    const FILE: &'static str;
    /// The word used in messages ("secret", "inventory").
    const NOUN: &'static str;
    /// The blob kind holding this record's sealed value, if it has one.
    const BLOB_KIND: Option<&'static str>;

    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn write_json(&self, out: &mut String);
    fn read_json(v: &Value) -> Option<Self>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretKind {
    VaultPassword,
    SshKey,
}

impl SecretKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretKind::VaultPassword => "vault_password",
            SecretKind::SshKey => "ssh_key",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SecretKind::VaultPassword => "Vault password",
            SecretKind::SshKey => "SSH private key",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "vault_password" => Some(SecretKind::VaultPassword),
            "ssh_key" => Some(SecretKind::SshKey),
            _ => None,
        }
    }
}

/// A vault password or SSH private key. The value is write-only: it is
/// sealed into blob `secret-<id>` and never rendered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    pub id: String,
    pub name: String,
    pub kind: SecretKind,
    /// For a vault password, the `--vault-id` label it answers to.
    pub vault_id: String,
    /// For an SSH key, `SHA256:...` of its public half.
    pub fingerprint: String,
    pub created: i64,
    pub updated: i64,
}

impl Record for Secret {
    const FILE: &'static str = "secrets.json";
    const NOUN: &'static str = "secret";
    const BLOB_KIND: Option<&'static str> = Some("secret");

    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn write_json(&self, out: &mut String) {
        Obj::new(out)
            .str("id", &self.id)
            .str("name", &self.name)
            .str("kind", self.kind.as_str())
            .str("vault_id", &self.vault_id)
            .str("fingerprint", &self.fingerprint)
            .int("created", self.created)
            .int("updated", self.updated)
            .end();
    }

    fn read_json(v: &Value) -> Option<Self> {
        Some(Self {
            id: jsonw::str(v, "id")?,
            name: jsonw::str(v, "name")?,
            kind: SecretKind::parse(&jsonw::str(v, "kind")?)?,
            vault_id: jsonw::str(v, "vault_id")?,
            fingerprint: jsonw::str(v, "fingerprint")?,
            created: jsonw::int(v, "created")?,
            updated: jsonw::int(v, "updated")?,
        })
    }
}

/// An inventory: a YAML file of hosts and variables, sealed into blob
/// `inventory-<id>` because it routinely holds credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inventory {
    pub id: String,
    pub name: String,
    pub size: i64,
    pub created: i64,
    pub updated: i64,
}

impl Record for Inventory {
    const FILE: &'static str = "inventories.json";
    const NOUN: &'static str = "inventory";
    const BLOB_KIND: Option<&'static str> = Some("inventory");

    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn write_json(&self, out: &mut String) {
        Obj::new(out)
            .str("id", &self.id)
            .str("name", &self.name)
            .int("size", self.size)
            .int("created", self.created)
            .int("updated", self.updated)
            .end();
    }

    fn read_json(v: &Value) -> Option<Self> {
        Some(Self {
            id: jsonw::str(v, "id")?,
            name: jsonw::str(v, "name")?,
            size: jsonw::int(v, "size")?,
            created: jsonw::int(v, "created")?,
            updated: jsonw::int(v, "updated")?,
        })
    }
}

/// A git repository of playbooks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repository {
    pub id: String,
    pub name: String,
    pub url: String,
    pub branch: String,
    /// The id of the SSH key secret used to clone, or "" for none.
    pub deploy_key: String,
    pub created: i64,
    pub updated: i64,
}

impl Record for Repository {
    const FILE: &'static str = "repositories.json";
    const NOUN: &'static str = "repository";
    const BLOB_KIND: Option<&'static str> = None;

    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn write_json(&self, out: &mut String) {
        Obj::new(out)
            .str("id", &self.id)
            .str("name", &self.name)
            .str("url", &self.url)
            .str("branch", &self.branch)
            .str("deploy_key", &self.deploy_key)
            .int("created", self.created)
            .int("updated", self.updated)
            .end();
    }

    fn read_json(v: &Value) -> Option<Self> {
        Some(Self {
            id: jsonw::str(v, "id")?,
            name: jsonw::str(v, "name")?,
            url: jsonw::str(v, "url")?,
            branch: jsonw::str(v, "branch")?,
            deploy_key: jsonw::str(v, "deploy_key")?,
            created: jsonw::int(v, "created")?,
            updated: jsonw::int(v, "updated")?,
        })
    }
}

/// A playbook run definition: what to run, against which inventory, with
/// which secrets and options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    pub id: String,
    pub name: String,
    pub repository: String,
    /// The playbook's path inside the repository, e.g. "update_homelab_vms.yml".
    pub playbook: String,
    pub inventory: String,
    /// Vault password secret ids; each becomes one --vault-id.
    pub vault_secrets: Vec<String>,
    /// The SSH key secret ansible connects to hosts with, or "".
    pub ssh_key: String,
    pub limit: String,
    pub tags: String,
    pub skip_tags: String,
    pub check_mode: bool,
    pub diff: bool,
    /// 0-4: the number of -v flags.
    pub verbosity: i64,
    pub timeout_minutes: i64,
    pub created: i64,
    pub updated: i64,
}

impl Record for Template {
    const FILE: &'static str = "templates.json";
    const NOUN: &'static str = "template";
    const BLOB_KIND: Option<&'static str> = None;

    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn write_json(&self, out: &mut String) {
        Obj::new(out)
            .str("id", &self.id)
            .str("name", &self.name)
            .str("repository", &self.repository)
            .str("playbook", &self.playbook)
            .str("inventory", &self.inventory)
            .strs("vault_secrets", &self.vault_secrets)
            .str("ssh_key", &self.ssh_key)
            .str("limit", &self.limit)
            .str("tags", &self.tags)
            .str("skip_tags", &self.skip_tags)
            .bool("check_mode", self.check_mode)
            .bool("diff", self.diff)
            .int("verbosity", self.verbosity)
            .int("timeout_minutes", self.timeout_minutes)
            .int("created", self.created)
            .int("updated", self.updated)
            .end();
    }

    fn read_json(v: &Value) -> Option<Self> {
        Some(Self {
            id: jsonw::str(v, "id")?,
            name: jsonw::str(v, "name")?,
            repository: jsonw::str(v, "repository")?,
            playbook: jsonw::str(v, "playbook")?,
            inventory: jsonw::str(v, "inventory")?,
            vault_secrets: jsonw::strs(v, "vault_secrets")?,
            ssh_key: jsonw::str(v, "ssh_key")?,
            limit: jsonw::str(v, "limit")?,
            tags: jsonw::str(v, "tags")?,
            skip_tags: jsonw::str(v, "skip_tags")?,
            check_mode: jsonw::bool(v, "check_mode")?,
            diff: jsonw::bool(v, "diff")?,
            verbosity: jsonw::int(v, "verbosity")?,
            timeout_minutes: jsonw::int(v, "timeout_minutes")?,
            created: jsonw::int(v, "created")?,
            updated: jsonw::int(v, "updated")?,
        })
    }
}

/// Runs a template on a cron schedule, in the server's time zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub id: String,
    pub name: String,
    pub template: String,
    pub cron: String,
    pub enabled: bool,
    /// Force --check for scheduled runs.
    pub check_mode: bool,
    pub created: i64,
    pub updated: i64,
}

impl Record for Schedule {
    const FILE: &'static str = "schedules.json";
    const NOUN: &'static str = "schedule";
    const BLOB_KIND: Option<&'static str> = None;

    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn write_json(&self, out: &mut String) {
        Obj::new(out)
            .str("id", &self.id)
            .str("name", &self.name)
            .str("template", &self.template)
            .str("cron", &self.cron)
            .bool("enabled", self.enabled)
            .bool("check_mode", self.check_mode)
            .int("created", self.created)
            .int("updated", self.updated)
            .end();
    }

    fn read_json(v: &Value) -> Option<Self> {
        Some(Self {
            id: jsonw::str(v, "id")?,
            name: jsonw::str(v, "name")?,
            template: jsonw::str(v, "template")?,
            cron: jsonw::str(v, "cron")?,
            enabled: jsonw::bool(v, "enabled")?,
            check_mode: jsonw::bool(v, "check_mode")?,
            created: jsonw::int(v, "created")?,
            updated: jsonw::int(v, "updated")?,
        })
    }
}
