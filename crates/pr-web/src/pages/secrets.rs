//! Secrets: vault passwords and SSH private keys. Values are write-only —
//! they can be set and replaced but are never rendered back.

use std::fmt::Write as _;

use pr_common::{Error, Result, sshkey};
use pr_store::{Record, Repository, Secret, SecretKind, new_id, validate};

use super::{card, now, textarea, time};
use crate::app::{App, Session};
use crate::html::{self, Tone, esc};
use crate::http::{Form, Response};

const KINDS: [SecretKind; 2] = [SecretKind::VaultPassword, SecretKind::SshKey];

fn kind_options() -> Vec<(String, String)> {
    KINDS.iter().map(|k| (k.as_str().to_owned(), k.label().to_owned())).collect()
}

/// Validates a new value for a secret of `kind`; returns the bytes to seal
/// and the fingerprint to record.
fn prepare_value(kind: SecretKind, raw: &str) -> Result<(Vec<u8>, String)> {
    let raw = validate::secret_value(raw)?;
    match kind {
        SecretKind::VaultPassword => {
            let value = raw.strip_suffix('\n').unwrap_or(raw);
            let value = value.strip_suffix('\r').unwrap_or(value);
            if value.is_empty() {
                return Err(Error::new("The vault password is empty."));
            }
            Ok((value.as_bytes().to_vec(), String::new()))
        }
        SecretKind::SshKey => {
            let key = raw.replace("\r\n", "\n");
            let info = sshkey::parse_private_key(&key)?;
            let digest =
                pr_crypto::sha256(&info.public_blob).map_err(|_| Error::new("hashing failed"))?;
            let mut text = key.trim().to_owned();
            text.push('\n');
            Ok((text.into_bytes(), format!("{} {}", info.algorithm, sshkey::fingerprint(&digest))))
        }
    }
}

impl App {
    /// The names of records that use secret `id`.
    pub fn secret_users(&self, id: &str) -> Vec<String> {
        let mut users: Vec<String> = self
            .store
            .list::<Repository>()
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.deploy_key == id)
            .map(|r| format!("repository \"{}\"", r.name))
            .collect();
        users.extend(self.template_users_of_secret(id));
        users
    }

    pub fn secrets_page(&self, s: &Session) -> Response {
        let secrets = match self.store.list::<Secret>() {
            Ok(v) => v,
            Err(e) => {
                return self.page(
                    s,
                    "Secrets",
                    "secrets",
                    format!(
                        "<h1>Secrets</h1>\n<p class=\"notice notice-danger\">{}</p>",
                        esc(e.message())
                    ),
                );
            }
        };
        let mut body = String::from(
            "<h1>Secrets</h1>\n<p class=\"page-intro\">Vault passwords and SSH private keys, encrypted at rest. \
             Values are write-only: once saved they can be replaced but never viewed.</p>\n",
        );
        body.push_str(&card("list", "Stored secrets"));
        if secrets.is_empty() {
            body.push_str("<p class=\"empty-state\">No secrets yet.</p>\n");
        } else {
            body.push_str(
                "<div class=\"table-wrap\"><table class=\"data-table\">\n<thead><tr><th>Name</th><th>Type</th>\
                 <th>Vault ID / fingerprint</th><th>Updated</th><th></th></tr></thead>\n<tbody>\n",
            );
            for x in &secrets {
                let detail = match x.kind {
                    SecretKind::VaultPassword => x.vault_id.clone(),
                    SecretKind::SshKey => x.fingerprint.clone(),
                };
                let _ = writeln!(
                    body,
                    "<tr><td><a href=\"/secrets/{id}\">{}</a></td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                    esc(&x.name),
                    x.kind.label(),
                    esc(&detail),
                    time(x.updated),
                    html::action_button(
                        &format!("/secrets/{}/delete", x.id),
                        &s.csrf,
                        "Delete",
                        "button-danger"
                    ),
                    id = esc(&x.id),
                );
            }
            body.push_str("</tbody></table></div>\n");
        }
        body.push_str("</section>\n");
        body.push_str(&card("add", "Add a secret"));
        body.push_str("<form method=\"POST\" action=\"/secrets\">\n");
        body.push_str(&html::csrf_field(&s.csrf));
        body.push_str(&html::field("name", "Name", "text", "", "", true));
        body.push_str(&html::select("kind", "Type", &kind_options(), "vault_password", ""));
        body.push_str(&html::field(
            "vault_id",
            "Vault ID",
            "text",
            "default",
            "For vault passwords: the label passed as --vault-id <label>@... (\"default\" matches unlabelled vault files).",
            false,
        ));
        body.push_str(&textarea(
            "value",
            "Value",
            "",
            "The vault password, or an unencrypted OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----).",
            true,
            true,
        ));
        body.push_str(
            "<button type=\"submit\" class=\"button\">Save secret</button>\n</form>\n</section>\n",
        );
        self.page(s, "Secrets", "secrets", body)
    }

    pub fn secret_create(&self, s: &Session, form: &Form) -> Response {
        let result = (|| -> Result<String> {
            let name = validate::name(form.text("name"))?;
            let kind = SecretKind::parse(form.text("kind"))
                .ok_or_else(|| Error::new("Choose a secret type."))?;
            let vault_id = match kind {
                SecretKind::VaultPassword => validate::vault_id(form.text("vault_id"))?,
                SecretKind::SshKey => String::new(),
            };
            let (mut value, fingerprint) = prepare_value(kind, form.get("value").unwrap_or(""))?;
            let id = new_id()?;
            // The value is sealed before the record exists, so no record
            // ever points at a missing blob.
            let sealed = self.store.put_blob("secret", &id, &value);
            pr_crypto::cleanse(&mut value);
            sealed?;
            let t = now();
            let record = Secret {
                id: id.clone(),
                name,
                kind,
                vault_id,
                fingerprint,
                created: t,
                updated: t,
            };
            if let Err(e) = self.store.put(record) {
                let _ = self.store.delete::<Secret>(&id);
                return Err(e);
            }
            Ok(id)
        })();
        match result {
            Ok(_) => self.flash_redirect(s, Tone::Success, "Secret saved.", "/secrets"),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), "/secrets"),
        }
    }

    pub fn secret_page(&self, s: &Session, id: &str) -> Option<Response> {
        let x = self.store.get::<Secret>(id).ok()??;
        let mut body = format!(
            "<h1>{}</h1>\n<p class=\"page-intro\"><a href=\"/secrets\">All secrets</a></p>\n",
            esc(&x.name)
        );
        body.push_str(&card("details", "Details"));
        let _ = writeln!(
            body,
            "<dl class=\"details-list\"><dt>Type</dt><dd>{}</dd>{}<dt>Created</dt><dd>{}</dd><dt>Updated</dt><dd>{}</dd></dl>",
            x.kind.label(),
            if x.kind == SecretKind::SshKey {
                format!("<dt>Key</dt><dd><code>{}</code></dd>", esc(&x.fingerprint))
            } else {
                String::new()
            },
            time(x.created),
            time(x.updated),
        );
        let users = self.secret_users(&x.id);
        if !users.is_empty() {
            let _ =
                writeln!(body, "<p class=\"field-help\">Used by {}.</p>", esc(&users.join(", ")));
        }
        body.push_str("</section>\n");
        body.push_str(&card("edit", "Edit"));
        let _ = writeln!(body, "<form method=\"POST\" action=\"/secrets/{}\">", esc(&x.id));
        body.push_str(&html::csrf_field(&s.csrf));
        body.push_str(&html::field("name", "Name", "text", &x.name, "", true));
        if x.kind == SecretKind::VaultPassword {
            body.push_str(&html::field("vault_id", "Vault ID", "text", &x.vault_id, "", false));
        }
        body.push_str(&textarea(
            "value",
            "Replace value",
            "",
            "Leave empty to keep the current value.",
            false,
            true,
        ));
        body.push_str(
            "<button type=\"submit\" class=\"button\">Save changes</button>\n</form>\n</section>\n",
        );
        Some(self.page(s, &x.name, "secrets", body))
    }

    pub fn secret_update(&self, s: &Session, id: &str, form: &Form) -> Option<Response> {
        let mut x = self.store.get::<Secret>(id).ok()??;
        let back = format!("/secrets/{}", x.id);
        let result = (|| -> Result<()> {
            x.name = validate::name(form.text("name"))?;
            if x.kind == SecretKind::VaultPassword {
                x.vault_id = validate::vault_id(form.text("vault_id"))?;
            }
            let raw = form.get("value").unwrap_or("");
            if !raw.trim().is_empty() {
                let (mut value, fingerprint) = prepare_value(x.kind, raw)?;
                let sealed = self.store.put_blob("secret", &x.id, &value);
                pr_crypto::cleanse(&mut value);
                sealed?;
                x.fingerprint = fingerprint;
            }
            x.updated = now();
            self.store.put(x.clone())
        })();
        Some(match result {
            Ok(()) => self.flash_redirect(s, Tone::Success, "Secret updated.", &back),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), &back),
        })
    }

    pub fn secret_delete(&self, s: &Session, id: &str) -> Option<Response> {
        let x = self.store.get::<Secret>(id).ok()??;
        let users = self.secret_users(&x.id);
        if !users.is_empty() {
            let message =
                format!("\"{}\" is used by {}; change those first.", x.name, users.join(", "));
            return Some(self.flash_redirect(s, Tone::Danger, message, "/secrets"));
        }
        Some(match self.store.delete::<Secret>(&x.id) {
            Ok(()) => self.flash_redirect(
                s,
                Tone::Success,
                format!("Deleted \"{}\".", x.name),
                "/secrets",
            ),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), "/secrets"),
        })
    }

    /// (id, label) options for choosing a secret of `kind`, led by `none`.
    pub fn secret_options(&self, kind: SecretKind, none: &str) -> Vec<(String, String)> {
        let mut options = vec![(String::new(), none.to_owned())];
        for x in self.store.list::<Secret>().unwrap_or_default() {
            if x.kind == kind {
                let label = match kind {
                    SecretKind::VaultPassword => format!("{} ({})", x.name, x.vault_id),
                    SecretKind::SshKey => x.name.clone(),
                };
                options.push((x.id().to_owned(), label));
            }
        }
        options
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_normalized_and_keys_fingerprinted() {
        let (v, f) = prepare_value(SecretKind::VaultPassword, "hunter2\r\n").unwrap();
        assert_eq!((v.as_slice(), f.as_str()), (&b"hunter2"[..], ""));
        assert!(prepare_value(SecretKind::VaultPassword, "\n").is_err());
        let (v, f) = prepare_value(SecretKind::SshKey, sshkey::TEST_ONLY_KEY).unwrap();
        assert!(v.ends_with(b"-----END OPENSSH PRIVATE KEY-----\n"));
        assert_eq!(f, format!("ssh-ed25519 {}", sshkey::TEST_ONLY_KEY_FINGERPRINT));
        assert!(prepare_value(SecretKind::SshKey, "not a key").is_err());
    }
}
