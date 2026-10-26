//! Server-rendered HTML: escaping, the page layout, and the small pieces
//! every page repeats. Every value that did not come from a string literal
//! in this crate goes through [`esc`].

use std::fmt::Write as _;

/// Escapes text for an HTML element body or a double-quoted attribute.
pub fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    esc_into(&mut out, text);
    out
}

/// [`esc`] appended to `out`. Runs of ordinary text are copied whole, so a
/// large log costs one append per special character rather than one per
/// character.
pub fn esc_into(out: &mut String, text: &str) {
    let mut plain = 0;
    for (i, b) in text.bytes().enumerate() {
        let replacement = match b {
            b'&' => "&amp;",
            b'<' => "&lt;",
            b'>' => "&gt;",
            b'"' => "&quot;",
            b'\'' => "&#39;",
            _ => continue,
        };
        out.push_str(&text[plain..i]);
        out.push_str(replacement);
        plain = i + 1;
    }
    out.push_str(&text[plain..]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Success,
    Warning,
    Danger,
}

impl Tone {
    fn class(self) -> &'static str {
        match self {
            Tone::Success => "flash-success",
            Tone::Warning => "notice-warning",
            Tone::Danger => "notice-danger",
        }
    }
}

/// The navigation, in order: (path, label, key a page passes as `nav`).
pub const NAV: &[(&str, &str, &str)] = &[
    ("/", "Dashboard", "dashboard"),
    ("/templates", "Templates", "templates"),
    ("/schedules", "Schedules", "schedules"),
    ("/runs", "Runs", "runs"),
    ("/inventories", "Inventories", "inventories"),
    ("/secrets", "Secrets", "secrets"),
    ("/repositories", "Repositories", "repositories"),
    ("/known-hosts", "Known hosts", "known-hosts"),
    ("/settings", "Settings", "settings"),
    ("/about", "About", "about"),
];

#[derive(Debug, Default)]
pub struct Page {
    pub title: String,
    /// The NAV key of the current page; "" for none.
    pub nav: &'static str,
    /// The CSRF token for the logout form; `None` hides the navigation.
    pub csrf: Option<String>,
    pub flashes: Vec<(Tone, String)>,
    /// Seconds after which the page reloads itself (a running job's log).
    pub refresh: Option<u32>,
    /// Where the reload goes instead of back to the same URL. A different
    /// query each time makes it a real reload, and a fragment lands on the
    /// part of the page the reader is following.
    pub refresh_to: Option<String>,
    /// Extra classes on <main>, e.g. " page-center".
    pub page_class: &'static str,
    /// The page body, already escaped.
    pub body: String,
}

pub fn render(page: &Page) -> String {
    let mut out = String::with_capacity(page.body.len() + 4096);
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    let _ = writeln!(out, "<title>{} — playbook-runner</title>", esc(&page.title));
    out.push_str(
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"color-scheme\" content=\"dark light\">\n\
         <link rel=\"icon\" type=\"image/svg+xml\" href=\"/static/favicon.svg\">\n",
    );
    // The version in the URL lets the stylesheet be cached for an hour and
    // still be picked up at once after an upgrade.
    let _ = writeln!(
        out,
        "<link rel=\"stylesheet\" href=\"/static/style.css?v={}\">",
        pr_common::VERSION
    );
    if let Some(seconds) = page.refresh {
        match &page.refresh_to {
            Some(to) => {
                let _ = writeln!(
                    out,
                    "<meta http-equiv=\"refresh\" content=\"{seconds};url={}\">",
                    esc(to)
                );
            }
            None => {
                let _ = writeln!(out, "<meta http-equiv=\"refresh\" content=\"{seconds}\">");
            }
        }
    }
    out.push_str(
        "</head>\n<body>\n<a class=\"skip-link\" href=\"#main-content\">Skip to main content</a>\n",
    );
    out.push_str("<header class=\"site-header\">\n<div class=\"header-inner\">\n<p class=\"brand\">playbook-runner</p>\n");
    if let Some(csrf) = &page.csrf {
        out.push_str("<nav class=\"nav-strip\" aria-label=\"Primary navigation\">\n");
        for (path, label, key) in NAV {
            let current = if *key == page.nav { " aria-current=\"page\"" } else { "" };
            let _ = writeln!(out, "<a href=\"{path}\"{current}>{label}</a>");
        }
        out.push_str(
            "</nav>\n<form class=\"header-actions\" method=\"POST\" action=\"/logout\">\n",
        );
        out.push_str(&csrf_field(csrf));
        out.push_str(
            "<button type=\"submit\" class=\"button button-secondary\">Log out</button>\n</form>\n",
        );
    }
    out.push_str("</div>\n</header>\n");
    let _ = writeln!(out, "<main id=\"main-content\" class=\"page{}\">", page.page_class);
    if !page.flashes.is_empty() {
        out.push_str(
            "<ul class=\"flash-list\" aria-live=\"polite\" aria-label=\"Action results\">\n",
        );
        for (tone, message) in &page.flashes {
            let _ = writeln!(out, "<li class=\"notice {}\">{}</li>", tone.class(), esc(message));
        }
        out.push_str("</ul>\n");
    }
    out.push_str(&page.body);
    out.push_str("\n</main>\n</body>\n</html>\n");
    out
}

pub fn csrf_field(token: &str) -> String {
    format!("<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">\n", esc(token))
}

/// A single-button POST form, for row actions such as Delete or Run.
pub fn action_button(action: &str, csrf: &str, label: &str, class: &str) -> String {
    format!(
        "<form method=\"POST\" action=\"{}\">\n{}<button type=\"submit\" class=\"button {}\">{}</button>\n</form>\n",
        esc(action),
        csrf_field(csrf),
        class,
        esc(label)
    )
}

/// A labelled text input. `kind` is the input type.
pub fn field(
    name: &str,
    label: &str,
    kind: &str,
    value: &str,
    help: &str,
    required: bool,
) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "<div class=\"field\">\n<label for=\"{n}\">{l}</label>\n<input type=\"{kind}\" id=\"{n}\" name=\"{n}\" value=\"{v}\"{r}>\n",
        n = esc(name),
        l = esc(label),
        v = esc(value),
        r = if required { " required" } else { "" },
    );
    if !help.is_empty() {
        let _ = writeln!(out, "<p class=\"field-help\">{}</p>", esc(help));
    }
    out.push_str("</div>\n");
    out
}

/// A <select> whose options are (value, label) pairs.
pub fn select(
    name: &str,
    label: &str,
    options: &[(String, String)],
    selected: &str,
    help: &str,
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "<div class=\"field\">\n<label for=\"{n}\">{l}</label>\n<select id=\"{n}\" name=\"{n}\">",
        n = esc(name),
        l = esc(label)
    );
    for (value, text) in options {
        let sel = if value == selected { " selected" } else { "" };
        let _ = writeln!(out, "<option value=\"{}\"{sel}>{}</option>", esc(value), esc(text));
    }
    out.push_str("</select>\n");
    if !help.is_empty() {
        let _ = writeln!(out, "<p class=\"field-help\">{}</p>", esc(help));
    }
    out.push_str("</div>\n");
    out
}

/// A status badge such as "succeeded" or "running".
pub fn status_badge(status: &str) -> String {
    format!("<span class=\"state-token status-{0}\">{0}</span>", esc(status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_covers_markup_and_attributes() {
        assert_eq!(
            esc("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn navigation_appears_only_with_a_session() {
        let anonymous = render(&Page { title: "Log in".into(), ..Page::default() });
        assert!(!anonymous.contains("nav-strip"));
        let signed_in = render(&Page {
            title: "Dashboard".into(),
            nav: "dashboard",
            csrf: Some("tok".into()),
            flashes: vec![(Tone::Success, "<saved>".into())],
            ..Page::default()
        });
        assert!(signed_in.contains("<a href=\"/\" aria-current=\"page\">Dashboard</a>"));
        assert!(signed_in.contains("&lt;saved&gt;"));
        assert!(signed_in.contains("value=\"tok\""));
    }
}
