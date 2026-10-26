//! About: the version, what the image runs playbooks with, the project
//! license, and third-party notices.

use std::fmt::Write as _;
use std::sync::OnceLock;

use pr_runner::about::{Toolchain, toolchain};

use super::card;
use crate::app::{App, Session};
use crate::html::esc;
use crate::http::Response;

const LICENSE: &str = include_str!("../../../../LICENSE");
const NOTICES: &str = include_str!("../../THIRD_PARTY_NOTICES.txt");
const SOURCE: &str = "https://github.com/MatthewDavidMiller/playbook-runner";

/// The image's tools do not change while the server runs, so they are
/// asked once.
static TOOLCHAIN: OnceLock<Toolchain> = OnceLock::new();

fn or_unknown(s: &str) -> &str {
    if s.is_empty() { "not found" } else { s }
}

impl App {
    pub fn about_page(&self, s: &Session) -> Response {
        let tools =
            TOOLCHAIN.get_or_init(|| toolchain(self.runner.exec_config()).unwrap_or_default());
        let mut body = String::from("<h1>About</h1>\n");
        body.push_str(&card("product", "playbook-runner"));
        let _ = writeln!(
            body,
            "<p>Runs and schedules Ansible playbooks. First-party Rust with no third-party crates; \
             secrets and inventories are encrypted at rest.</p>\n<dl class=\"details-list\">\
             <dt>Version</dt><dd>{}</dd><dt>Source</dt><dd><a href=\"{SOURCE}\">{SOURCE}</a></dd>\
             <dt>Copyright</dt><dd>Copyright (c) 2026 Matthew David Miller</dd><dt>License</dt><dd>MIT</dd></dl>\n</section>",
            esc(pr_common::VERSION),
        );
        body.push_str(&card("tools", "Runs playbooks with"));
        let collections = if tools.collections.is_empty() {
            "none found".to_owned()
        } else {
            tools
                .collections
                .iter()
                .map(|(n, v)| format!("{} {}", esc(n), esc(v)))
                .collect::<Vec<_>>()
                .join("<br>")
        };
        let _ = writeln!(
            body,
            "<dl class=\"details-list\"><dt>ansible-core</dt><dd>{}</dd><dt>Python</dt><dd>{}</dd>\
             <dt>Collections</dt><dd>{}</dd><dt>Git</dt><dd>{}</dd><dt>OpenSSH</dt><dd>{}</dd></dl>\n\
             <p class=\"field-help\">Collections are built into the image and never downloaded; a repository's \
             collections/requirements.yml is checked against them before each run.</p>\n</section>",
            esc(or_unknown(&tools.ansible_core)),
            esc(or_unknown(&tools.python)),
            collections,
            esc(or_unknown(&tools.git)),
            esc(or_unknown(&tools.openssh)),
        );
        body.push_str("<section class=\"card legal-card\" aria-labelledby=\"license-heading\">\n<h2 id=\"license-heading\">Project license</h2>\n");
        let _ = writeln!(body, "<pre class=\"legal-text\">{}</pre>\n</section>", esc(LICENSE));
        body.push_str("<section class=\"card legal-card\" aria-labelledby=\"notices-heading\">\n<h2 id=\"notices-heading\">Third-party notices</h2>\n");
        let _ = writeln!(body, "<pre class=\"legal-text\">{}</pre>\n</section>", esc(NOTICES));
        self.page(s, "About", "about", body)
    }
}
