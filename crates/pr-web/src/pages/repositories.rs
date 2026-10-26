//! Repositories: the git remotes playbooks are cloned from.

use std::fmt::Write as _;

use pr_common::Result;
use pr_store::{RepoSnapshot, Repository, Secret, SecretKind, new_id, validate};

use super::{card, now, time};
use crate::app::{App, Session};
use crate::html::{self, Tone, esc};
use crate::http::{Form, Response};

impl App {
    fn repository_form(
        &self,
        s: &Session,
        action: &str,
        r: Option<&Repository>,
        button: &str,
    ) -> String {
        let mut body = format!("<form method=\"POST\" action=\"{}\">\n", esc(action));
        body.push_str(&html::csrf_field(&s.csrf));
        body.push_str(&html::field("name", "Name", "text", r.map_or("", |r| &r.name), "", true));
        body.push_str(&html::field(
            "url",
            "Git URL",
            "text",
            r.map_or("", |r| &r.url),
            "For example git@github.com:owner/ansible_playbooks.git. The host must be in Known hosts.",
            true,
        ));
        body.push_str(&html::field(
            "branch",
            "Branch",
            "text",
            r.map_or("main", |r| &r.branch),
            "",
            false,
        ));
        body.push_str(&html::select(
            "deploy_key",
            "Deploy key",
            &self.secret_options(SecretKind::SshKey, "None (public repository)"),
            r.map_or("", |r| &r.deploy_key),
            "A read-only SSH deploy key stored under Secrets.",
        ));
        let _ = writeln!(
            body,
            "<button type=\"submit\" class=\"button\">{}</button>\n</form>",
            esc(button)
        );
        body
    }

    pub fn repositories_page(&self, s: &Session) -> Response {
        let items = self.store.list::<Repository>().unwrap_or_default();
        let mut body = String::from(
            "<h1>Repositories</h1>\n<p class=\"page-intro\">Git repositories holding playbooks. Each run clones \
             the configured branch fresh over SSH.</p>\n",
        );
        body.push_str(&card("list", "Repositories"));
        if items.is_empty() {
            body.push_str("<p class=\"empty-state\">No repositories yet.</p>\n");
        } else {
            body.push_str(
                "<div class=\"table-wrap\"><table class=\"data-table\">\n<thead><tr><th>Name</th><th>URL</th>\
                 <th>Branch</th><th>Updated</th><th></th></tr></thead>\n<tbody>\n",
            );
            for r in &items {
                let _ = writeln!(
                    body,
                    "<tr><td><a href=\"/repositories/{}\">{}</a></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(&r.id),
                    esc(&r.name),
                    esc(&r.url),
                    esc(&r.branch),
                    time(r.updated),
                    html::action_button(
                        &format!("/repositories/{}/delete", r.id),
                        &s.csrf,
                        "Delete",
                        "button-danger"
                    ),
                );
            }
            body.push_str("</tbody></table></div>\n");
        }
        body.push_str("</section>\n");
        body.push_str(&card("add", "Add a repository"));
        body.push_str(&self.repository_form(s, "/repositories", None, "Save repository"));
        body.push_str("</section>\n");
        self.page(s, "Repositories", "repositories", body)
    }

    fn save_repository(&self, existing: Option<Repository>, form: &Form) -> Result<()> {
        let deploy_key = form.text("deploy_key").to_owned();
        if !deploy_key.is_empty()
            && !self.store.get::<Secret>(&deploy_key)?.is_some_and(|k| k.kind == SecretKind::SshKey)
        {
            return Err(pr_common::Error::new("Choose an SSH key secret as the deploy key."));
        }
        let t = now();
        let mut r = existing.unwrap_or(Repository {
            id: new_id()?,
            name: String::new(),
            url: String::new(),
            branch: String::new(),
            deploy_key: String::new(),
            created: t,
            updated: t,
        });
        r.name = validate::name(form.text("name"))?;
        r.url = validate::git_url(form.text("url"))?;
        r.branch = validate::branch(form.text("branch"))?;
        r.deploy_key = deploy_key;
        r.updated = t;
        // A different remote or branch makes the synced playbook list stale.
        let stale = self
            .store
            .get::<Repository>(&r.id)?
            .is_some_and(|old| old.url != r.url || old.branch != r.branch);
        if stale {
            self.store.delete::<RepoSnapshot>(&r.id)?;
        }
        self.store.put(r)
    }

    pub fn repository_create(&self, s: &Session, form: &Form) -> Response {
        match self.save_repository(None, form) {
            Ok(()) => self.flash_redirect(s, Tone::Success, "Repository saved.", "/repositories"),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), "/repositories"),
        }
    }

    /// Clones the repository and records its playbooks, then returns to
    /// `back` (a template or repository page) with the result.
    pub fn repository_sync(&self, s: &Session, id: &str, form: &Form) -> Option<Response> {
        let r = self.store.get::<Repository>(id).ok()??;
        let back = form.text("back");
        let back = if back.starts_with("/templates") || back.starts_with("/repositories") {
            back.to_owned()
        } else {
            format!("/repositories/{}", r.id)
        };
        Some(match self.runner.sync_repository(&r.id) {
            Ok(snap) => self.flash_redirect(
                s,
                Tone::Success,
                format!(
                    "Synced {}: {} playbook(s) at commit {}.",
                    r.name,
                    snap.playbooks.len(),
                    snap.commit.chars().take(10).collect::<String>()
                ),
                &back,
            ),
            Err(e) => {
                self.flash_redirect(s, Tone::Danger, format!("Sync failed: {}", e.message()), &back)
            }
        })
    }

    pub fn repository_page(&self, s: &Session, id: &str) -> Option<Response> {
        let r = self.store.get::<Repository>(id).ok()??;
        let mut body = format!(
            "<h1>{}</h1>\n<p class=\"page-intro\"><a href=\"/repositories\">All repositories</a></p>\n",
            esc(&r.name)
        );
        body.push_str(&card("sync", "Playbooks"));
        match self.store.get::<RepoSnapshot>(&r.id).ok().flatten() {
            Some(snap) if snap.playbooks.is_empty() => {
                let _ = writeln!(
                    body,
                    "<p class=\"empty-state\">No playbooks found at commit <code>{}</code>.</p>",
                    esc(&snap.commit)
                );
            }
            Some(snap) => {
                let _ = writeln!(
                    body,
                    "<p class=\"field-help\">At commit <code>{}</code>, synced {}:</p>\n<ul class=\"source-list\">",
                    esc(&snap.commit),
                    time(snap.synced_at)
                );
                for p in &snap.playbooks {
                    let _ = writeln!(body, "<li><code>{}</code></li>", esc(p));
                }
                body.push_str("</ul>\n");
            }
            None => body.push_str("<p class=\"empty-state\">Not synced yet.</p>\n"),
        }
        let _ = writeln!(
            body,
            "<form method=\"POST\" action=\"/repositories/{id}/sync\">\n{}<input type=\"hidden\" name=\"back\" value=\"/repositories/{id}\">\n\
             <button type=\"submit\" class=\"button button-secondary\">Sync playbooks</button>\n</form>\n</section>",
            html::csrf_field(&s.csrf),
            id = esc(&r.id),
        );
        body.push_str(&card("edit", "Edit"));
        body.push_str(&self.repository_form(
            s,
            &format!("/repositories/{}", r.id),
            Some(&r),
            "Save changes",
        ));
        body.push_str("</section>\n");
        Some(self.page(s, &r.name, "repositories", body))
    }

    pub fn repository_update(&self, s: &Session, id: &str, form: &Form) -> Option<Response> {
        let r = self.store.get::<Repository>(id).ok()??;
        let back = format!("/repositories/{}", r.id);
        Some(match self.save_repository(Some(r), form) {
            Ok(()) => self.flash_redirect(s, Tone::Success, "Repository updated.", &back),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), &back),
        })
    }

    pub fn repository_delete(&self, s: &Session, id: &str) -> Option<Response> {
        let r = self.store.get::<Repository>(id).ok()??;
        let users = self.template_users_of_repository(&r.id);
        if !users.is_empty() {
            let message =
                format!("\"{}\" is used by {}; change those first.", r.name, users.join(", "));
            return Some(self.flash_redirect(s, Tone::Danger, message, "/repositories"));
        }
        let _ = self.store.delete::<RepoSnapshot>(&r.id);
        Some(match self.store.delete::<Repository>(&r.id) {
            Ok(()) => self.flash_redirect(
                s,
                Tone::Success,
                format!("Deleted \"{}\".", r.name),
                "/repositories",
            ),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), "/repositories"),
        })
    }
}
