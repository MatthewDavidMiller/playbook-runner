//! The record pages. Each submodule adds its handlers to [`App`] and is
//! wired into the router in `app.rs`.

pub mod inventories;
pub mod known_hosts;
pub mod repositories;
pub mod secrets;

use pr_common::{Result, timefmt};

use crate::app::App;

impl App {
    // Templates arrive in Stage 4; until then nothing references a record.
    pub fn template_users_of_secret(&self, _id: &str) -> Vec<String> {
        Vec::new()
    }

    pub fn template_users_of_inventory(&self, _id: &str) -> Vec<String> {
        Vec::new()
    }

    pub fn template_users_of_repository(&self, _id: &str) -> Vec<String> {
        Vec::new()
    }

    /// Checks that ansible can parse an inventory (Stage 4).
    pub fn check_inventory(&self, _content: &str) -> Result<()> {
        Ok(())
    }
}

/// "2026-10-25 21:04 UTC" for a Unix time.
pub fn time(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let (y, m, d) = timefmt::civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", secs / 3600, secs % 3600 / 60)
}

pub fn now() -> i64 {
    timefmt::unix_seconds()
}

/// The opening of a card section with a heading.
pub fn card(id: &str, heading: &str) -> String {
    format!(
        "<section class=\"card\" aria-labelledby=\"{id}-heading\">\n<h2 id=\"{id}-heading\">{}</h2>\n",
        crate::html::esc(heading)
    )
}

/// A labelled textarea.
pub fn textarea(
    name: &str,
    label: &str,
    value: &str,
    help: &str,
    required: bool,
    code: bool,
) -> String {
    use crate::html::esc;
    let mut out = format!(
        "<div class=\"field\">\n<label for=\"{n}\">{l}</label>\n<textarea id=\"{n}\" name=\"{n}\"{c}{r} spellcheck=\"false\" autocomplete=\"off\">{v}</textarea>\n",
        n = esc(name),
        l = esc(label),
        v = esc(value),
        c = if code { " class=\"code-input\"" } else { "" },
        r = if required { " required" } else { "" },
    );
    if !help.is_empty() {
        out.push_str("<p class=\"field-help\">");
        out.push_str(&esc(help));
        out.push_str("</p>\n");
    }
    out.push_str("</div>\n");
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn times_render_in_utc() {
        assert_eq!(super::time(0), "1970-01-01 00:00 UTC");
        assert_eq!(super::time(1_761_440_640), "2025-10-26 01:04 UTC");
    }
}
