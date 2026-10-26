//! Known hosts: the one OpenSSH known_hosts file every git clone and every
//! ansible SSH connection verifies against, with strict host key checking.

use super::{card, textarea};
use crate::app::{App, Session};
use crate::html::{self, Tone, esc};
use crate::http::{Form, Response};

impl App {
    pub fn known_hosts_page(&self, s: &Session) -> Response {
        let mut body = String::from(
            "<h1>Known hosts</h1>\n<p class=\"page-intro\">SSH host keys for the git servers and managed hosts. \
             Connections to a host not listed here are refused.</p>\n",
        );
        body.push_str(&card("edit", "known_hosts"));
        match self.store.known_hosts() {
            Ok(text) => {
                body.push_str("<form method=\"POST\" action=\"/known-hosts\">\n");
                body.push_str(&html::csrf_field(&s.csrf));
                body.push_str(&textarea(
                    "content",
                    "known_hosts entries",
                    &text,
                    "One entry per line, as ssh-keyscan prints them, e.g. the output of \
                     ssh-keyscan -t ed25519 github.com. Verify fingerprints out of band before trusting them.",
                    false,
                    true,
                ));
                body.push_str(
                    "<button type=\"submit\" class=\"button\">Save known hosts</button>\n</form>\n",
                );
            }
            Err(e) => {
                body.push_str("<p class=\"notice notice-danger\">");
                body.push_str(&esc(e.message()));
                body.push_str("</p>\n");
            }
        }
        body.push_str("</section>\n");
        self.page(s, "Known hosts", "known-hosts", body)
    }

    pub fn known_hosts_save(&self, s: &Session, form: &Form) -> Response {
        match self.store.set_known_hosts(form.get("content").unwrap_or("")) {
            Ok(()) => self.flash_redirect(s, Tone::Success, "Known hosts saved.", "/known-hosts"),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), "/known-hosts"),
        }
    }
}
