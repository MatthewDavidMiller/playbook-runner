//! Runs: the history, one run's live log, and cancellation.

use std::fmt::Write as _;

use pr_runner::report::{Report, failed_step};
use pr_runner::{Run, Status};

use super::{card, now, time};
use crate::app::{App, Session};
use crate::html::{self, Page, Tone, esc, status_badge};
use crate::http::Response;

/// How much of a log the page shows; the full log is a download.
const LOG_TAIL: u64 = 1024 * 1024;

/// The log with failure lines marked and anchored as `#log-<line>`.
fn render_log(log: &str, report: &Report) -> String {
    let mut out = String::with_capacity(log.len() + 1024);
    for (i, line) in log.lines().enumerate() {
        if report.failures.iter().any(|f| f.line == i) {
            // display: block ends the line itself; a newline would add a blank one.
            let _ = write!(out, "<span class=\"log-failure\" id=\"log-{i}\">{}</span>", esc(line));
        } else if line.starts_with("TASK [")
            || line.starts_with("PLAY ")
            || line.starts_with("PLAY RECAP")
        {
            let _ = writeln!(out, "<span class=\"log-heading\">{}</span>", esc(line));
        } else {
            out.push_str(&esc(line));
            out.push('\n');
        }
    }
    out
}

/// The summary card: where a failed run stopped, the per-host recap, and
/// each failure linked to its line in the log.
fn summary(r: &Run, report: &Report) -> String {
    if r.status.is_active() && report.recap.is_empty() && report.failures.is_empty() {
        return String::new();
    }
    let mut out = card("summary", "Summary");
    if r.status == Status::Failed || r.status == Status::Interrupted {
        let step = if r.error.is_empty() { "Running the playbook" } else { failed_step(&r.error) };
        let _ = writeln!(out, "<p>Stopped at: <strong>{}</strong>.</p>", esc(step));
    }
    if !report.recap.is_empty() {
        out.push_str(
            "<div class=\"table-wrap\"><table class=\"data-table\">\n<thead><tr><th>Host</th><th>OK</th>\
             <th>Changed</th><th>Unreachable</th><th>Failed</th><th>Skipped</th><th>Rescued</th><th>Ignored</th></tr></thead>\n<tbody>\n",
        );
        for h in &report.recap {
            let _ = write!(
                out,
                "<tr><td>{}{}</td>",
                esc(&h.host),
                if h.has_problems() {
                    " <span class=\"state-token status-failed\">problems</span>"
                } else {
                    ""
                }
            );
            for name in ["ok", "changed", "unreachable", "failed", "skipped", "rescued", "ignored"]
            {
                let _ = write!(out, "<td>{}</td>", h.count(name));
            }
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    if report.failures.is_empty() {
        if r.status == Status::Succeeded {
            out.push_str("<p class=\"empty-state\">No failures.</p>\n");
        }
    } else {
        let _ = writeln!(
            out,
            "<h3>Failures ({})</h3>\n<ol class=\"failure-list\">",
            report.failures.len()
        );
        for f in &report.failures {
            let mut place = Vec::new();
            if !f.task.is_empty() {
                place.push(format!("task <strong>{}</strong>", esc(&f.task)));
            }
            if !f.host.is_empty() {
                place.push(format!("on <strong>{}</strong>", esc(&f.host)));
            }
            let _ = writeln!(
                out,
                "<li><a href=\"#log-{}\">{}</a>: {}</li>",
                f.line,
                if place.is_empty() { "Error".to_owned() } else { place.join(" ") },
                esc(&f.message)
            );
        }
        out.push_str("</ol>\n");
    }
    out.push_str("</section>\n");
    out
}

pub fn duration(seconds: i64) -> String {
    match seconds {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m {:02}s", s / 60, s % 60),
        s => format!("{}h {:02}m", s / 3600, s % 3600 / 60),
    }
}

fn trigger_label(trigger: &str) -> &str {
    if trigger.starts_with("schedule:") { "schedule" } else { trigger }
}

impl App {
    pub fn runs_table(&self, runs: &[Run]) -> String {
        if runs.is_empty() {
            return "<p class=\"empty-state\">No runs yet.</p>\n".to_owned();
        }
        let t = now();
        let mut out = String::from(
            "<div class=\"table-wrap\"><table class=\"data-table\">\n<thead><tr><th>Run</th><th>Template</th>\
             <th>Status</th><th>Trigger</th><th>Started</th><th>Duration</th></tr></thead>\n<tbody>\n",
        );
        for r in runs {
            let _ = writeln!(
                out,
                "<tr><td><a href=\"/runs/{n}\">#{n}</a></td><td>{}{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&r.template_name),
                if r.check_mode { " <span class=\"badge\">check</span>" } else { "" },
                status_badge(r.status.as_str()),
                esc(trigger_label(&r.trigger)),
                r.started_at.map_or_else(|| "—".to_owned(), time),
                r.duration(t).map_or_else(|| "—".to_owned(), duration),
                n = r.number,
            );
        }
        out.push_str("</tbody></table></div>\n");
        out
    }

    pub fn runs_page(&self, s: &Session) -> Response {
        let runs = self.runner.runs().recent(100).unwrap_or_default();
        let mut body = String::from(
            "<h1>Runs</h1>\n<p class=\"page-intro\">The most recent 100 runs, newest first.</p>\n",
        );
        body.push_str(&card("list", "History"));
        body.push_str(&self.runs_table(&runs));
        body.push_str("</section>\n");
        let refresh = runs.iter().any(|r| r.status.is_active()).then_some(5);
        self.page_with(
            s,
            Page { title: "Runs".into(), nav: "runs", refresh, body, ..Page::default() },
        )
    }

    pub fn run_page(&self, s: &Session, number: &str) -> Option<Response> {
        let number: u64 = number.parse().ok()?;
        let r = self.runner.runs().get(number).ok()??;
        let (log, truncated) = self.runner.read_log(number, LOG_TAIL).unwrap_or_default();
        let mut body = format!(
            "<h1>Run #{} — {}</h1>\n<p class=\"page-intro\"><a href=\"/runs\">All runs</a> · <a href=\"/templates/{}\">Template</a></p>\n",
            r.number,
            esc(&r.template_name),
            esc(&r.template_id)
        );
        let _ = writeln!(
            body,
            "<section class=\"playback-banner banner-{tone}\" aria-labelledby=\"status-heading\">\n<div>\n\
             <p class=\"eyebrow\">Status</p>\n<h2 id=\"status-heading\">{}</h2>\n<p class=\"detail\">{}</p>\n</div>\n{}</section>",
            esc(r.status.as_str()),
            esc(&if r.error.is_empty() {
                r.exit_code
                    .map_or_else(String::new, |c| format!("ansible-playbook exited with {c}"))
            } else {
                r.error.clone()
            }),
            if r.status.is_active() {
                html::action_button(
                    &format!("/runs/{}/cancel", r.number),
                    &s.csrf,
                    "Cancel run",
                    "button-danger",
                )
            } else {
                String::new()
            },
            tone = match r.status {
                pr_runner::Status::Succeeded => "success",
                pr_runner::Status::Queued | pr_runner::Status::Running => "warning",
                pr_runner::Status::Cancelled => "neutral",
                _ => "danger",
            },
        );
        body.push_str(&card("details", "Details"));
        let _ = writeln!(
            body,
            "<dl class=\"details-list\"><dt>Trigger</dt><dd>{}</dd><dt>Check mode</dt><dd>{}</dd><dt>Queued</dt><dd>{}</dd>\
             <dt>Started</dt><dd>{}</dd><dt>Finished</dt><dd>{}</dd><dt>Duration</dt><dd>{}</dd><dt>Commit</dt><dd><code>{}</code></dd></dl>\n</section>",
            esc(trigger_label(&r.trigger)),
            if r.check_mode { "yes" } else { "no" },
            time(r.queued_at),
            r.started_at.map_or_else(|| "—".to_owned(), time),
            r.finished_at.map_or_else(|| "—".to_owned(), time),
            r.duration(now()).map_or_else(|| "—".to_owned(), duration),
            esc(if r.commit.is_empty() { "—" } else { &r.commit }),
        );
        let report = pr_runner::report::parse(&log);
        body.push_str(&summary(&r, &report));
        body.push_str(&card("log", "Log"));
        if truncated {
            let _ = writeln!(
                body,
                "<p class=\"field-help\">Showing the last MiB. <a href=\"/runs/{}/log\">Download the full log</a>.</p>",
                r.number
            );
        } else if !log.is_empty() {
            let _ = writeln!(
                body,
                "<p class=\"field-help\"><a href=\"/runs/{}/log\">Download log</a></p>",
                r.number
            );
        }
        let _ = writeln!(
            body,
            "<pre class=\"run-log\">{}</pre>\n</section>",
            if log.is_empty() { esc("(no output yet)") } else { render_log(&log, &report) }
        );
        let refresh = r.status.is_active().then_some(3);
        Some(self.page_with(
            s,
            Page {
                title: format!("Run #{}", r.number),
                nav: "runs",
                refresh,
                body,
                ..Page::default()
            },
        ))
    }

    pub fn run_log_download(&self, number: &str) -> Option<Response> {
        let number: u64 = number.parse().ok()?;
        self.runner.runs().get(number).ok()??;
        let (log, _) = self.runner.read_log(number, pr_runner::redact::LOG_LIMIT + 4096).ok()?;
        Some(Response::text(200, &log).with_header(
            "Content-Disposition",
            format!("attachment; filename=\"run-{number}.log\""),
        ))
    }

    pub fn run_cancel(&self, s: &Session, number: &str) -> Option<Response> {
        let number: u64 = number.parse().ok()?;
        let back = format!("/runs/{number}");
        Some(match self.runner.cancel(number) {
            Ok(()) => self.flash_redirect(s, Tone::Success, "Cancellation requested.", &back),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), &back),
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn durations_read_naturally() {
        assert_eq!(super::duration(5), "5s");
        assert_eq!(super::duration(65), "1m 05s");
        assert_eq!(super::duration(3720), "1h 02m");
    }
}
