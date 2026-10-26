//! Templates: what to run (repository and playbook), against what
//! (inventory), with which secrets and options. A template is run from
//! here or by a schedule.

use std::fmt::Write as _;

use pr_common::{Error, Result};
use pr_store::{
    Inventory, RepoSnapshot, Repository, Secret, SecretKind, Template, new_id, validate,
};

use super::{card, now, time};
use crate::app::{App, Session};
use crate::html::{self, Tone, esc, status_badge};
use crate::http::{Form, Response};

fn checkbox(name: &str, value: &str, label: &str, checked: bool) -> String {
    format!(
        "<label class=\"checkbox-label\"><input type=\"checkbox\" name=\"{}\" value=\"{}\"{}> {}</label>\n",
        esc(name),
        esc(value),
        if checked { " checked" } else { "" },
        esc(label)
    )
}

impl App {
    pub fn template_users_of_secret(&self, id: &str) -> Vec<String> {
        self.store
            .list::<Template>()
            .unwrap_or_default()
            .into_iter()
            .filter(|t| t.ssh_key == id || t.vault_secrets.iter().any(|v| v == id))
            .map(|t| format!("template \"{}\"", t.name))
            .collect()
    }

    pub fn template_users_of_inventory(&self, id: &str) -> Vec<String> {
        self.store
            .list::<Template>()
            .unwrap_or_default()
            .into_iter()
            .filter(|t| t.inventory == id)
            .map(|t| format!("template \"{}\"", t.name))
            .collect()
    }

    pub fn template_users_of_repository(&self, id: &str) -> Vec<String> {
        self.store
            .list::<Template>()
            .unwrap_or_default()
            .into_iter()
            .filter(|t| t.repository == id)
            .map(|t| format!("template \"{}\"", t.name))
            .collect()
    }

    /// Checks that ansible can parse an inventory. Skipped (accepted) where
    /// ansible is not installed, as in a bare development build.
    pub fn check_inventory(&self, content: &str) -> Result<()> {
        self.runner.check_inventory(content).map(|_| ())
    }

    /// The repository chooser: a GET form, kept outside the main form
    /// because forms cannot nest. Choosing reloads `action` with
    /// `?repository=<id>`, which fills the playbook dropdown.
    fn repository_chooser(&self, action: &str, selected: &str, button: &str) -> String {
        let repositories: Vec<(String, String)> = self
            .store
            .list::<Repository>()
            .unwrap_or_default()
            .into_iter()
            .map(|r| (r.id, r.name))
            .collect();
        if repositories.is_empty() {
            return "<p class=\"empty-state\">Add a repository first, under <a href=\"/repositories\">Repositories</a>.</p>\n".to_owned();
        }
        let mut out = format!("<form method=\"GET\" action=\"{}\">\n", esc(action));
        out.push_str(&html::select("repository", "Repository", &repositories, selected, ""));
        let _ = writeln!(
            out,
            "<button type=\"submit\" class=\"button button-secondary\">{}</button>\n</form>",
            esc(button)
        );
        out
    }

    /// The sync form for a repository's playbook list, with what the last
    /// sync found. `back` is where to return afterwards.
    fn sync_panel(&self, s: &Session, repository: &str, back: &str) -> String {
        let mut out = String::new();
        match self.store.get::<RepoSnapshot>(repository).ok().flatten() {
            Some(snap) => {
                let _ = writeln!(
                    out,
                    "<p class=\"field-help\">{} playbook(s) found at commit <code>{}</code>, synced {}.</p>",
                    snap.playbooks.len(),
                    esc(&snap.commit.chars().take(10).collect::<String>()),
                    time(snap.synced_at)
                );
            }
            None => out.push_str(
                "<p class=\"notice notice-warning\">This repository has not been synced yet. Sync it to choose a playbook from a list.</p>\n",
            ),
        }
        let _ = write!(
            out,
            "<form method=\"POST\" action=\"/repositories/{}/sync\">\n{}<input type=\"hidden\" name=\"back\" value=\"{}\">\n\
             <button type=\"submit\" class=\"button button-secondary\">Sync playbooks</button>\n</form>\n",
            esc(repository),
            html::csrf_field(&s.csrf),
            esc(back)
        );
        out
    }

    /// The playbook dropdown (from the last sync) and the free-form path
    /// for anything the sync did not recognise.
    fn playbook_picker(&self, repository: &str, current: &str) -> String {
        let listed = self
            .store
            .get::<RepoSnapshot>(repository)
            .ok()
            .flatten()
            .map(|s| s.playbooks)
            .unwrap_or_default();
        let in_list = listed.iter().any(|p| p == current);
        let mut options = vec![(
            String::new(),
            if listed.is_empty() {
                "No playbooks synced".to_owned()
            } else {
                "Choose a playbook".to_owned()
            },
        )];
        options.extend(listed.iter().map(|p| (p.clone(), p.clone())));
        let mut out =
            html::select("playbook", "Playbook", &options, if in_list { current } else { "" }, "");
        out.push_str(&html::field(
            "playbook_other",
            "Or another playbook path",
            "text",
            if in_list { "" } else { current },
            "Used instead of the list when filled in, e.g. a playbook the sync did not recognise.",
            false,
        ));
        out
    }

    fn template_form(
        &self,
        s: &Session,
        action: &str,
        t: Option<&Template>,
        repository: &str,
        button: &str,
    ) -> String {
        let inventories: Vec<(String, String)> = self
            .store
            .list::<Inventory>()
            .unwrap_or_default()
            .into_iter()
            .map(|i| (i.id, i.name))
            .collect();
        let mut body = format!("<form method=\"POST\" action=\"{}\">\n", esc(action));
        body.push_str(&html::csrf_field(&s.csrf));
        let _ = writeln!(
            body,
            "<input type=\"hidden\" name=\"repository\" value=\"{}\">",
            esc(repository)
        );
        body.push_str(&html::field("name", "Name", "text", t.map_or("", |t| &t.name), "", true));
        body.push_str(&self.playbook_picker(repository, t.map_or("", |t| &t.playbook)));
        body.push_str(&html::select(
            "inventory",
            "Inventory",
            &inventories,
            t.map_or("", |t| &t.inventory),
            "",
        ));
        body.push_str("<fieldset class=\"field\"><legend>Vault passwords</legend>\n");
        let vaults = self.secret_options(SecretKind::VaultPassword, "");
        if vaults.len() <= 1 {
            body.push_str(
                "<p class=\"field-help\">No vault passwords stored. Add them under Secrets.</p>\n",
            );
        }
        for (id, label) in vaults.iter().skip(1) {
            let checked = t.is_some_and(|t| t.vault_secrets.contains(id));
            body.push_str(&checkbox("vault_secrets", id, label, checked));
        }
        body.push_str("</fieldset>\n");
        body.push_str(&html::select(
            "ssh_key",
            "SSH key for hosts",
            &self.secret_options(SecretKind::SshKey, "None"),
            t.map_or("", |t| &t.ssh_key),
            "Loaded into the run's private ssh-agent; ansible connects with it.",
        ));
        body.push_str(&html::field(
            "limit",
            "Limit",
            "text",
            t.map_or("", |t| &t.limit),
            "Optional host pattern (--limit).",
            false,
        ));
        body.push_str(&html::field(
            "tags",
            "Tags",
            "text",
            t.map_or("", |t| &t.tags),
            "Optional, comma-separated (--tags).",
            false,
        ));
        body.push_str(&html::field(
            "skip_tags",
            "Skip tags",
            "text",
            t.map_or("", |t| &t.skip_tags),
            "",
            false,
        ));
        let verbosity: Vec<(String, String)> = (0..=4)
            .map(|v| {
                (
                    v.to_string(),
                    if v == 0 { "Normal".to_owned() } else { format!("-{}", "v".repeat(v)) },
                )
            })
            .collect();
        body.push_str(&html::select(
            "verbosity",
            "Verbosity",
            &verbosity,
            &t.map_or(0, |t| t.verbosity).to_string(),
            "",
        ));
        body.push_str(&html::field(
            "timeout_minutes",
            "Timeout (minutes)",
            "number",
            &t.map_or(240, |t| t.timeout_minutes).to_string(),
            "The run is stopped after this long.",
            true,
        ));
        body.push_str("<div class=\"field\">\n");
        body.push_str(&checkbox(
            "check_mode",
            "1",
            "Always run in check mode (--check)",
            t.is_some_and(|t| t.check_mode),
        ));
        body.push_str(&checkbox(
            "diff",
            "1",
            "Show differences (--diff)",
            t.is_some_and(|t| t.diff),
        ));
        body.push_str("</div>\n");
        let _ = writeln!(
            body,
            "<button type=\"submit\" class=\"button\">{}</button>\n</form>",
            esc(button)
        );
        body
    }

    pub fn templates_page(&self, s: &Session) -> Response {
        let templates = self.store.list::<Template>().unwrap_or_default();
        let recent = self.runner.runs().recent(200).unwrap_or_default();
        let mut body = String::from(
            "<h1>Templates</h1>\n<p class=\"page-intro\">A template names a playbook, the inventory it runs against, \
             and the secrets it needs. Run one now, or attach it to a schedule.</p>\n",
        );
        body.push_str(&card("list", "Templates"));
        if templates.is_empty() {
            body.push_str(
                "<p class=\"empty-state\">No templates yet. Add a repository and an inventory first, then create a template below.</p>\n",
            );
        } else {
            body.push_str(
                "<div class=\"table-wrap\"><table class=\"data-table\">\n<thead><tr><th>Name</th><th>Playbook</th>\
                 <th>Last run</th><th></th></tr></thead>\n<tbody>\n",
            );
            for t in &templates {
                let last = recent.iter().find(|r| r.template_id == t.id).map_or_else(
                    || "never".to_owned(),
                    |r| {
                        format!(
                            "<a href=\"/runs/{}\">#{}</a> {}",
                            r.number,
                            r.number,
                            status_badge(r.status.as_str())
                        )
                    },
                );
                let _ = writeln!(
                    body,
                    "<tr><td><a href=\"/templates/{id}\">{}</a></td><td><code>{}</code></td><td>{}</td><td>{}{}</td></tr>",
                    esc(&t.name),
                    esc(&t.playbook),
                    last,
                    html::action_button(&format!("/templates/{}/run", t.id), &s.csrf, "Run", ""),
                    html::action_button(
                        &format!("/templates/{}/check", t.id),
                        &s.csrf,
                        "Check",
                        "button-secondary"
                    ),
                    id = esc(&t.id),
                );
            }
            body.push_str("</tbody></table></div>\n");
        }
        body.push_str("</section>\n");
        body.push_str(&card("add", "Add a template"));
        body.push_str("<p class=\"field-help\">Choose the repository first; its playbooks fill the next form's dropdown.</p>\n");
        body.push_str(&self.repository_chooser("/templates/new", "", "Next: choose a playbook"));
        body.push_str("</section>\n");
        self.page(s, "Templates", "templates", body)
    }

    /// Step two of adding a template: the full form for one repository.
    pub fn new_template_page(&self, s: &Session, repository: Option<&str>) -> Response {
        let Some(repo) = repository.and_then(|id| self.store.get::<Repository>(id).ok().flatten())
        else {
            return self.flash_redirect(
                s,
                Tone::Warning,
                "Choose a repository for the new template.",
                "/templates",
            );
        };
        let back = format!("/templates/new?repository={}", repo.id);
        let mut body = String::from(
            "<h1>New template</h1>\n<p class=\"page-intro\"><a href=\"/templates\">All templates</a></p>\n",
        );
        body.push_str(&card("repository", "Repository"));
        body.push_str(&self.repository_chooser("/templates/new", &repo.id, "Switch repository"));
        body.push_str(&self.sync_panel(s, &repo.id, &back));
        body.push_str("</section>\n");
        body.push_str(&card("add", &format!("Template using {}", repo.name)));
        body.push_str(&self.template_form(s, "/templates", None, &repo.id, "Save template"));
        body.push_str("</section>\n");
        self.page(s, "New template", "templates", body)
    }

    fn save_template(&self, existing: Option<Template>, form: &Form) -> Result<Template> {
        let repository = form.text("repository").to_owned();
        self.store
            .get::<Repository>(&repository)?
            .ok_or_else(|| Error::new("Choose a repository."))?;
        let inventory = form.text("inventory").to_owned();
        self.store
            .get::<Inventory>(&inventory)?
            .ok_or_else(|| Error::new("Choose an inventory."))?;
        let mut vault_secrets = Vec::new();
        for id in form.all("vault_secrets") {
            let ok =
                self.store.get::<Secret>(id)?.is_some_and(|x| x.kind == SecretKind::VaultPassword);
            if !ok {
                return Err(Error::new("A chosen vault password no longer exists."));
            }
            if !vault_secrets.iter().any(|v| v == id) {
                vault_secrets.push(id.to_owned());
            }
        }
        let ssh_key = form.text("ssh_key").to_owned();
        if !ssh_key.is_empty()
            && !self.store.get::<Secret>(&ssh_key)?.is_some_and(|x| x.kind == SecretKind::SshKey)
        {
            return Err(Error::new("Choose an SSH key secret."));
        }
        let verbosity =
            form.text("verbosity").parse::<i64>().ok().filter(|v| (0..=4).contains(v)).unwrap_or(0);
        let timeout_minutes = form
            .text("timeout_minutes")
            .parse::<i64>()
            .ok()
            .filter(|m| (1..=24 * 60).contains(m))
            .ok_or_else(|| Error::new("The timeout must be 1-1440 minutes."))?;
        let t = now();
        let mut tpl = match existing {
            Some(x) => x,
            None => Template {
                id: new_id()?,
                name: String::new(),
                repository: String::new(),
                playbook: String::new(),
                inventory: String::new(),
                vault_secrets: Vec::new(),
                ssh_key: String::new(),
                limit: String::new(),
                tags: String::new(),
                skip_tags: String::new(),
                check_mode: false,
                diff: false,
                verbosity: 0,
                timeout_minutes: 240,
                created: t,
                updated: t,
            },
        };
        tpl.name = validate::name(form.text("name"))?;
        tpl.repository = repository;
        let other = form.text("playbook_other");
        let chosen = if other.is_empty() { form.text("playbook") } else { other };
        if chosen.is_empty() {
            return Err(Error::new("Choose a playbook, or type its path."));
        }
        tpl.playbook = validate::playbook(chosen)?;
        tpl.inventory = inventory;
        tpl.vault_secrets = vault_secrets;
        tpl.ssh_key = ssh_key;
        tpl.limit = validate::limit(form.text("limit"))?;
        tpl.tags = validate::tags(form.text("tags"))?;
        tpl.skip_tags = validate::tags(form.text("skip_tags"))?;
        tpl.check_mode = form.checked("check_mode");
        tpl.diff = form.checked("diff");
        tpl.verbosity = verbosity;
        tpl.timeout_minutes = timeout_minutes;
        tpl.updated = t;
        self.store.put(tpl.clone())?;
        Ok(tpl)
    }

    pub fn template_create(&self, s: &Session, form: &Form) -> Response {
        match self.save_template(None, form) {
            Ok(_) => self.flash_redirect(s, Tone::Success, "Template saved.", "/templates"),
            Err(e) => {
                let back = format!("/templates/new?repository={}", form.text("repository"));
                let back = if pr_store::is_id(form.text("repository")) {
                    back.as_str()
                } else {
                    "/templates"
                };
                self.flash_redirect(s, Tone::Danger, e.message(), back)
            }
        }
    }

    /// `repository` overrides the template's own while the operator is
    /// switching it, so the dropdown lists the new repository's playbooks.
    pub fn template_page(
        &self,
        s: &Session,
        id: &str,
        repository: Option<&str>,
    ) -> Option<Response> {
        let t = self.store.get::<Template>(id).ok()??;
        let repository = repository
            .filter(|r| self.store.get::<Repository>(r).ok().flatten().is_some())
            .unwrap_or(&t.repository)
            .to_owned();
        let back = if repository == t.repository {
            format!("/templates/{}", t.id)
        } else {
            format!("/templates/{}?repository={repository}", t.id)
        };
        let mut body = format!(
            "<h1>{}</h1>\n<p class=\"page-intro\"><a href=\"/templates\">All templates</a></p>\n",
            esc(&t.name)
        );
        body.push_str("<div class=\"button-row\">\n");
        body.push_str(&html::action_button(
            &format!("/templates/{}/run", t.id),
            &s.csrf,
            "Run now",
            "",
        ));
        body.push_str(&html::action_button(
            &format!("/templates/{}/check", t.id),
            &s.csrf,
            "Run in check mode",
            "button-secondary",
        ));
        body.push_str("</div>\n");
        let runs: Vec<_> = self
            .runner
            .runs()
            .recent(200)
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.template_id == t.id)
            .take(10)
            .collect();
        body.push_str(&card("runs", "Recent runs"));
        body.push_str(&self.runs_table(&runs));
        body.push_str("</section>\n");
        body.push_str(&card("repository", "Repository"));
        body.push_str(&self.repository_chooser(
            &format!("/templates/{}", t.id),
            &repository,
            "Switch repository",
        ));
        if repository != t.repository {
            body.push_str("<p class=\"notice notice-warning\">Not saved yet: choose a playbook from this repository below and save.</p>\n");
        }
        body.push_str(&self.sync_panel(s, &repository, &back));
        body.push_str("</section>\n");
        body.push_str(&card("edit", "Edit"));
        body.push_str(&self.template_form(
            s,
            &format!("/templates/{}", t.id),
            Some(&t),
            &repository,
            "Save changes",
        ));
        body.push_str("</section>\n");
        body.push_str("<section class=\"card danger-zone\">\n<h2>Delete</h2>\n");
        body.push_str(&html::action_button(
            &format!("/templates/{}/delete", t.id),
            &s.csrf,
            "Delete template",
            "button-danger",
        ));
        body.push_str("</section>\n");
        Some(self.page(s, &t.name, "templates", body))
    }

    pub fn template_update(&self, s: &Session, id: &str, form: &Form) -> Option<Response> {
        let t = self.store.get::<Template>(id).ok()??;
        let back = format!("/templates/{}", t.id);
        Some(match self.save_template(Some(t), form) {
            Ok(_) => self.flash_redirect(s, Tone::Success, "Template updated.", &back),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), &back),
        })
    }

    pub fn template_delete(&self, s: &Session, id: &str) -> Option<Response> {
        let t = self.store.get::<Template>(id).ok()??;
        let users = self.schedule_users_of_template(&t.id);
        if !users.is_empty() {
            let message =
                format!("\"{}\" is used by {}; change those first.", t.name, users.join(", "));
            return Some(self.flash_redirect(
                s,
                Tone::Danger,
                message,
                &format!("/templates/{}", t.id),
            ));
        }
        Some(match self.store.delete::<Template>(&t.id) {
            Ok(()) => self.flash_redirect(
                s,
                Tone::Success,
                format!("Deleted \"{}\".", t.name),
                "/templates",
            ),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), "/templates"),
        })
    }

    pub fn template_run(&self, s: &Session, id: &str, check: bool) -> Option<Response> {
        let t = self.store.get::<Template>(id).ok()??;
        Some(match self.runner.enqueue(&t.id, "manual", check) {
            Ok(run) => Response::redirect(&format!("/runs/{}", run.number)),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), "/templates"),
        })
    }
}
