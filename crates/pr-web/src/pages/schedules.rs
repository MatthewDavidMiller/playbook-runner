//! Schedules: run a template on a cron expression in the server's zone.

use std::fmt::Write as _;

use pr_common::{Error, Result};
use pr_runner::scheduler::next_run;
use pr_sched::{Cron, Frequency};
use pr_store::{Schedule, Template, new_id, validate};

use super::{card, now, time, zone};
use crate::app::{App, Session};
use crate::html::{self, Tone, esc, status_badge};
use crate::http::{Form, Response};

const CRON_HELP: &str = "For anything the choices above cannot express. Five fields: minute hour \
                         day-of-month month day-of-week, e.g. \"0 4 * * sun\", or @daily / @weekly.";
const WEEKDAYS: [&str; 7] =
    ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/// "Every Monday at 5:00 PM" for a cron expression; the expression itself
/// if it does not parse.
pub fn describe(cron: &str) -> String {
    Cron::parse(cron).map_or_else(|_| cron.to_owned(), |c| c.describe())
}

/// The friendly schedule builder, prefilled from `cron`. Without
/// JavaScript every field is shown; the frequency choice decides which ones
/// are used, and each label says which frequency it belongs to.
fn schedule_builder(cron: &str) -> String {
    let f = Frequency::from_cron(cron);
    let (time, minute, weekdays, day) = match &f {
        Frequency::Hourly { minute } => (String::from("04:00"), *minute, vec![0], 1),
        Frequency::Daily { hour, minute } => (format!("{hour:02}:{minute:02}"), 0, vec![0], 1),
        Frequency::Weekly { weekdays, hour, minute } => {
            (format!("{hour:02}:{minute:02}"), 0, weekdays.clone(), 1)
        }
        Frequency::Monthly { day, hour, minute } => {
            (format!("{hour:02}:{minute:02}"), 0, vec![0], *day)
        }
        Frequency::Custom(_) => (String::from("04:00"), 0, vec![0], 1),
    };
    let kinds: Vec<(String, String)> = [
        ("hourly", "Every hour"),
        ("daily", "Every day"),
        ("weekly", "Every week, on chosen days"),
        ("monthly", "Every month, on one day"),
        ("custom", "Custom cron expression"),
    ]
    .iter()
    .map(|(v, l)| ((*v).to_owned(), (*l).to_owned()))
    .collect();
    let mut out = String::from("<fieldset class=\"field\"><legend>When to run</legend>\n");
    out.push_str(&html::select("frequency", "Repeat", &kinds, f.kind(), ""));
    out.push_str(&html::field("time", "Time (daily, weekly, monthly)", "time", &time, "", false));
    out.push_str("<div class=\"field\"><span class=\"field-label\">Days (weekly)</span>\n");
    for (i, name) in WEEKDAYS.iter().enumerate() {
        let checked = weekdays.iter().any(|&d| d as usize == i);
        let _ = writeln!(
            out,
            "<label class=\"checkbox-label\"><input type=\"checkbox\" name=\"weekdays\" value=\"{i}\"{}> {name}</label>",
            if checked { " checked" } else { "" }
        );
    }
    out.push_str("</div>\n");
    out.push_str(&html::field(
        "day_of_month",
        "Day of the month (monthly)",
        "number",
        &day.to_string(),
        "1-31; months without that day are skipped.",
        false,
    ));
    out.push_str(&html::field(
        "minute",
        "Minutes past the hour (hourly)",
        "number",
        &minute.to_string(),
        "",
        false,
    ));
    out.push_str(&html::field("cron", "Cron expression (custom)", "text", cron, CRON_HELP, false));
    let _ = writeln!(
        out,
        "<p class=\"field-help\">Currently: <strong>{}</strong>.</p>\n</fieldset>",
        esc(&describe(cron))
    );
    out
}

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
        body.push_str(&schedule_builder(x.map_or("0 4 * * 0", |x| &x.cron)));
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
                 <th>When</th><th>Next run</th><th></th></tr></thead>\n<tbody>\n",
            );
            for x in &items {
                let _ = writeln!(
                    body,
                    "<tr><td><a href=\"/schedules/{}\">{}</a>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                    esc(&x.id),
                    esc(&x.name),
                    if x.check_mode { " <span class=\"badge\">check</span>" } else { "" },
                    esc(&self.template_name(&x.template)),
                    esc(&describe(&x.cron)),
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
        let weekdays: Vec<u32> = form.all("weekdays").filter_map(|d| d.parse().ok()).collect();
        let frequency = pr_sched::builder::from_form(
            form.text("frequency"),
            form.text("time"),
            form.text("minute"),
            &weekdays,
            form.text("day_of_month"),
            form.text("cron"),
        )?;
        let cron = frequency.to_cron();
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
        // The next three runs, so the meaning of the expression is concrete.
        let mut upcoming = Vec::new();
        let mut after = now();
        while upcoming.len() < 3 {
            match next_run(&x, zone(), after) {
                Some(n) => {
                    upcoming.push(time(n));
                    after = n;
                }
                None => break,
            }
        }
        let upcoming = if upcoming.is_empty() { Self::next_label(&x) } else { upcoming.join(", ") };
        let _ = writeln!(
            body,
            "<dl class=\"details-list\"><dt>Template</dt><dd><a href=\"/templates/{}\">{}</a></dd>\
             <dt>When</dt><dd>{}</dd><dt>Cron</dt><dd><code>{}</code></dd><dt>Next runs</dt><dd>{}</dd></dl>",
            esc(&x.template),
            esc(&self.template_name(&x.template)),
            esc(&describe(&x.cron)),
            esc(&x.cron),
            esc(&upcoming),
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
