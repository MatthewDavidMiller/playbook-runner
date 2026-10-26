//! Schedules: run a template on a cron expression in the server's zone.

use std::fmt::Write as _;

use pr_common::{Error, Result};
use pr_runner::scheduler::next_run;
use pr_sched::Cron;
use pr_store::{Schedule, Template, new_id, validate};

use super::{card, now, time, zone};
use crate::app::{App, Session};
use crate::html::{self, Tone, esc, status_badge};
use crate::http::{Form, Response};

const CRON_HELP: &str = "Five fields: minute hour day-of-month month day-of-week, e.g. \"0 4 * * sun\" for \
                         Sundays at 04:00, or @daily / @weekly. Times are in the server's time zone.";

fn checkbox(name: &str, label: &str, checked: bool) -> String {
    format!(
        "<label class=\"checkbox-label\"><input type=\"checkbox\" name=\"{name}\" value=\"1\"{}> {}</label>\n",
        if checked { " checked" } else { "" },
        esc(label)
    )
}

impl App {
    pub fn schedule_users_of_template(&self, id: &str) -> Vec<String> {
        self.store
            .list::<Schedule>()
            .unwrap_or_default()
            .into_iter()
            .filter(|x| x.template == id)
            .map(|x| format!("schedule \"{}\"", x.name))
            .collect()
    }

    fn template_name(&self, id: &str) -> String {
        self.store
            .get::<Template>(id)
            .ok()
            .flatten()
            .map_or_else(|| "(deleted)".to_owned(), |t| t.name)
    }

    fn next_label(x: &Schedule) -> String {
        if !x.enabled {
            return "paused".to_owned();
        }
        next_run(x, zone(), now()).map_or_else(|| "never".to_owned(), time)
    }

    /// The dashboard's upcoming-runs card.
    pub fn dashboard_schedules(&self) -> String {
        let mut upcoming: Vec<(i64, Schedule)> = self
            .store
            .list::<Schedule>()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|x| next_run(&x, zone(), now()).map(|n| (n, x)))
            .collect();
        upcoming.sort_by_key(|(n, _)| *n);
        let mut out = card("upcoming", "Upcoming scheduled runs");
        if upcoming.is_empty() {
            out.push_str("<p class=\"empty-state\">No enabled schedules. <a href=\"/schedules\">Add one</a>.</p>\n");
        } else {
            out.push_str("<dl class=\"details-list\">\n");
            for (n, x) in upcoming.iter().take(5) {
                let _ = writeln!(
                    out,
                    "<dt>{}</dt><dd><a href=\"/schedules/{}\">{}</a></dd>",
                    time(*n),
                    esc(&x.id),
                    esc(&x.name)
                );
            }
            out.push_str("</dl>\n");
        }
        out.push_str("</section>\n");
        out
    }

    fn schedule_form(
        &self,
        s: &Session,
        action: &str,
        x: Option<&Schedule>,
        button: &str,
    ) -> String {
        let templates: Vec<(String, String)> = self
            .store
            .list::<Template>()
            .unwrap_or_default()
            .into_iter()
            .map(|t| (t.id, t.name))
            .collect();
        let mut body = format!("<form method=\"POST\" action=\"{}\">\n", esc(action));
        body.push_str(&html::csrf_field(&s.csrf));
        body.push_str(&html::field("name", "Name", "text", x.map_or("", |x| &x.name), "", true));
        body.push_str(&html::select(
            "template",
            "Template",
            &templates,
            x.map_or("", |x| &x.template),
            "",
        ));
        body.push_str(&html::field(
            "cron",
            "Cron expression",
            "text",
            x.map_or("0 4 * * sun", |x| &x.cron),
            CRON_HELP,
            true,
        ));
        body.push_str("<div class=\"field\">\n");
        body.push_str(&checkbox("enabled", "Enabled", x.is_none_or(|x| x.enabled)));
        body.push_str(&checkbox(
            "check_mode",
            "Run in check mode (--check)",
            x.is_some_and(|x| x.check_mode),
        ));
        body.push_str("</div>\n");
        let _ = writeln!(
            body,
            "<button type=\"submit\" class=\"button\">{}</button>\n</form>",
            esc(button)
        );
        body
    }

    pub fn schedules_page(&self, s: &Session) -> Response {
        let items = self.store.list::<Schedule>().unwrap_or_default();
        let mut body = format!(
            "<h1>Schedules</h1>\n<p class=\"page-intro\">Run templates automatically. Times are in {}. \
             Runs missed while the server was down are skipped, not caught up, and an occurrence is \
             skipped while the template's previous run is still going.</p>\n",
            esc(zone().name())
        );
        body.push_str(&card("list", "Schedules"));
        if items.is_empty() {
            body.push_str("<p class=\"empty-state\">No schedules yet.</p>\n");
        } else {
            body.push_str(
                "<div class=\"table-wrap\"><table class=\"data-table\">\n<thead><tr><th>Name</th><th>Template</th>\
                 <th>Cron</th><th>Next run</th><th></th></tr></thead>\n<tbody>\n",
            );
            for x in &items {
                let _ = writeln!(
                    body,
                    "<tr><td><a href=\"/schedules/{}\">{}</a>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                    esc(&x.id),
                    esc(&x.name),
                    if x.check_mode { " <span class=\"badge\">check</span>" } else { "" },
                    esc(&self.template_name(&x.template)),
                    esc(&x.cron),
                    esc(&Self::next_label(x)),
                    html::action_button(
                        &format!("/schedules/{}/delete", x.id),
                        &s.csrf,
                        "Delete",
                        "button-danger"
                    ),
                );
            }
            body.push_str("</tbody></table></div>\n");
        }
        body.push_str("</section>\n");
        body.push_str(&card("add", "Add a schedule"));
        body.push_str(&self.schedule_form(s, "/schedules", None, "Save schedule"));
        body.push_str("</section>\n");
        self.page(s, "Schedules", "schedules", body)
    }

    fn save_schedule(&self, existing: Option<Schedule>, form: &Form) -> Result<()> {
        let template = form.text("template").to_owned();
        self.store.get::<Template>(&template)?.ok_or_else(|| Error::new("Choose a template."))?;
        let cron = form.text("cron").to_owned();
        let parsed = Cron::parse(&cron)?;
        if parsed.next_after(zone(), now()).is_none() {
            return Err(Error::new(format!("\"{cron}\" never fires.")));
        }
        let t = now();
        let mut x = match existing {
            Some(x) => x,
            None => Schedule {
                id: new_id()?,
                name: String::new(),
                template: String::new(),
                cron: String::new(),
                enabled: true,
                check_mode: false,
                created: t,
                updated: t,
            },
        };
        x.name = validate::name(form.text("name"))?;
        x.template = template;
        x.cron = cron;
        x.enabled = form.checked("enabled");
        x.check_mode = form.checked("check_mode");
        x.updated = t;
        self.store.put(x)
    }

    pub fn schedule_create(&self, s: &Session, form: &Form) -> Response {
        match self.save_schedule(None, form) {
            Ok(()) => self.flash_redirect(s, Tone::Success, "Schedule saved.", "/schedules"),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), "/schedules"),
        }
    }

    pub fn schedule_page(&self, s: &Session, id: &str) -> Option<Response> {
        let x = self.store.get::<Schedule>(id).ok()??;
        let mut body = format!(
            "<h1>{}</h1>\n<p class=\"page-intro\"><a href=\"/schedules\">All schedules</a></p>\n",
            esc(&x.name)
        );
        body.push_str(&card("details", "Details"));
        let _ = writeln!(
            body,
            "<dl class=\"details-list\"><dt>Template</dt><dd><a href=\"/templates/{}\">{}</a></dd><dt>Next run</dt><dd>{}</dd></dl>",
            esc(&x.template),
            esc(&self.template_name(&x.template)),
            esc(&Self::next_label(&x)),
        );
        let trigger = format!("schedule:{}", x.id);
        let runs: Vec<_> = self
            .runner
            .runs()
            .recent(500)
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.trigger == trigger)
            .take(5)
            .collect();
        if let Some(last) = runs.first() {
            let _ = writeln!(
                body,
                "<p>Last run: <a href=\"/runs/{n}\">#{n}</a> {}</p>",
                status_badge(last.status.as_str()),
                n = last.number
            );
        }
        body.push_str("</section>\n");
        body.push_str(&card("edit", "Edit"));
        body.push_str(&self.schedule_form(
            s,
            &format!("/schedules/{}", x.id),
            Some(&x),
            "Save changes",
        ));
        body.push_str("</section>\n");
        Some(self.page(s, &x.name, "schedules", body))
    }

    pub fn schedule_update(&self, s: &Session, id: &str, form: &Form) -> Option<Response> {
        let x = self.store.get::<Schedule>(id).ok()??;
        let back = format!("/schedules/{}", x.id);
        Some(match self.save_schedule(Some(x), form) {
            Ok(()) => self.flash_redirect(s, Tone::Success, "Schedule updated.", &back),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), &back),
        })
    }

    pub fn schedule_delete(&self, s: &Session, id: &str) -> Option<Response> {
        let x = self.store.get::<Schedule>(id).ok()??;
        Some(match self.store.delete::<Schedule>(&x.id) {
            Ok(()) => self.flash_redirect(
                s,
                Tone::Success,
                format!("Deleted \"{}\".", x.name),
                "/schedules",
            ),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), "/schedules"),
        })
    }
}
