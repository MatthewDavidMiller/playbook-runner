//! Inventories: YAML files of hosts and variables, encrypted at rest.
//! Unlike secrets they are shown back for editing, since an inventory is a
//! document the operator maintains.

use std::fmt::Write as _;

use pr_common::Result;
use pr_store::{Inventory, new_id, validate};

use super::{card, now, textarea, time};
use crate::app::{App, Session};
use crate::html::{self, Tone, esc};
use crate::http::{Form, Response};

const EXAMPLE: &str = "all:\n  hosts:\n    vm1:\n      ansible_host: 192.0.2.10\n  vars:\n      ansible_user: ansible\n";

fn size_label(bytes: i64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{}.{} KiB", bytes / 1024, bytes % 1024 * 10 / 1024)
    }
}

impl App {
    pub fn inventories_page(&self, s: &Session) -> Response {
        let items = self.store.list::<Inventory>().unwrap_or_default();
        let mut body = String::from(
            "<h1>Inventories</h1>\n<p class=\"page-intro\">YAML inventory files with hosts and variables, \
             encrypted at rest and decrypted only into a run's private scratch directory.</p>\n",
        );
        body.push_str(&card("list", "Inventories"));
        if items.is_empty() {
            body.push_str("<p class=\"empty-state\">No inventories yet.</p>\n");
        } else {
            body.push_str(
                "<div class=\"table-wrap\"><table class=\"data-table\">\n<thead><tr><th>Name</th><th>Size</th>\
                 <th>Updated</th><th></th></tr></thead>\n<tbody>\n",
            );
            for x in &items {
                let _ = writeln!(
                    body,
                    "<tr><td><a href=\"/inventories/{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(&x.id),
                    esc(&x.name),
                    size_label(x.size),
                    time(x.updated),
                    html::action_button(
                        &format!("/inventories/{}/delete", x.id),
                        &s.csrf,
                        "Delete",
                        "button-danger"
                    ),
                );
            }
            body.push_str("</tbody></table></div>\n");
        }
        body.push_str("</section>\n");
        body.push_str(&card("add", "Add an inventory"));
        body.push_str("<form method=\"POST\" action=\"/inventories\">\n");
        body.push_str(&html::csrf_field(&s.csrf));
        body.push_str(&html::field("name", "Name", "text", "", "", true));
        body.push_str(&textarea(
            "content",
            "Inventory YAML",
            EXAMPLE,
            "Paste the inventory file. Up to 512 KiB.",
            true,
            true,
        ));
        body.push_str("<button type=\"submit\" class=\"button\">Save inventory</button>\n</form>\n</section>\n");
        self.page(s, "Inventories", "inventories", body)
    }

    fn save_inventory(&self, existing: Option<Inventory>, form: &Form) -> Result<Inventory> {
        let name = validate::name(form.text("name"))?;
        let content = validate::inventory(form.get("content").unwrap_or(""))?;
        self.check_inventory(&content)?;
        let t = now();
        let mut record = existing.unwrap_or(Inventory {
            id: new_id()?,
            name: String::new(),
            size: 0,
            created: t,
            updated: t,
        });
        self.store.put_blob("inventory", &record.id, content.as_bytes())?;
        let mut content = content;
        pr_common::buf::wipe_string(&mut content);
        record.name = name;
        record.size = i64::try_from(form.get("content").map_or(0, str::len)).unwrap_or(0);
        record.updated = t;
        self.store.put(record.clone())?;
        Ok(record)
    }

    pub fn inventory_create(&self, s: &Session, form: &Form) -> Response {
        match self.save_inventory(None, form) {
            Ok(_) => self.flash_redirect(s, Tone::Success, "Inventory saved.", "/inventories"),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), "/inventories"),
        }
    }

    pub fn inventory_page(&self, s: &Session, id: &str) -> Option<Response> {
        let x = self.store.get::<Inventory>(id).ok()??;
        let content = self.store.get_blob("inventory", &x.id);
        let mut body = format!(
            "<h1>{}</h1>\n<p class=\"page-intro\"><a href=\"/inventories\">All inventories</a> · updated {}</p>\n",
            esc(&x.name),
            time(x.updated)
        );
        let users = self.template_users_of_inventory(&x.id);
        if !users.is_empty() {
            let _ =
                writeln!(body, "<p class=\"field-help\">Used by {}.</p>", esc(&users.join(", ")));
        }
        body.push_str(&card("edit", "Edit"));
        match content {
            Ok(text) => {
                let _ =
                    writeln!(body, "<form method=\"POST\" action=\"/inventories/{}\">", esc(&x.id));
                body.push_str(&html::csrf_field(&s.csrf));
                body.push_str(&html::field("name", "Name", "text", &x.name, "", true));
                body.push_str(&textarea(
                    "content",
                    "Inventory YAML",
                    &String::from_utf8_lossy(text.expose()),
                    "",
                    true,
                    true,
                ));
                body.push_str(
                    "<button type=\"submit\" class=\"button\">Save changes</button>\n</form>\n",
                );
            }
            Err(e) => {
                let _ =
                    writeln!(body, "<p class=\"notice notice-danger\">{}</p>", esc(e.message()));
            }
        }
        body.push_str("</section>\n");
        Some(self.page(s, &x.name, "inventories", body))
    }

    pub fn inventory_update(&self, s: &Session, id: &str, form: &Form) -> Option<Response> {
        let x = self.store.get::<Inventory>(id).ok()??;
        let back = format!("/inventories/{}", x.id);
        Some(match self.save_inventory(Some(x), form) {
            Ok(_) => self.flash_redirect(s, Tone::Success, "Inventory updated.", &back),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), &back),
        })
    }

    pub fn inventory_delete(&self, s: &Session, id: &str) -> Option<Response> {
        let x = self.store.get::<Inventory>(id).ok()??;
        let users = self.template_users_of_inventory(&x.id);
        if !users.is_empty() {
            let message =
                format!("\"{}\" is used by {}; change those first.", x.name, users.join(", "));
            return Some(self.flash_redirect(s, Tone::Danger, message, "/inventories"));
        }
        Some(match self.store.delete::<Inventory>(&x.id) {
            Ok(()) => self.flash_redirect(
                s,
                Tone::Success,
                format!("Deleted \"{}\".", x.name),
                "/inventories",
            ),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), "/inventories"),
        })
    }
}
