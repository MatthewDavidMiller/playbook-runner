//! The record pages. Each submodule adds its handlers to [`App`] and is
//! wired into the router in `app.rs`.

pub mod inventories;
pub mod known_hosts;
pub mod repositories;
pub mod runs;
pub mod schedules;
pub mod secrets;
pub mod templates;

use std::sync::OnceLock;

use pr_common::timefmt;
use pr_sched::Zone;

static ZONE: OnceLock<Zone> = OnceLock::new();

/// Sets the zone every page shows times in (once, at startup).
pub fn set_zone(zone: Zone) {
    let _ = ZONE.set(zone);
}

/// The display and scheduling zone; UTC until [`set_zone`] is called.
pub fn zone() -> &'static Zone {
    ZONE.get_or_init(Zone::utc)
}

/// "2026-10-25 21:04 EDT" for a Unix time, in the server's zone.
pub fn time(epoch: i64) -> String {
    zone().format(epoch)
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
