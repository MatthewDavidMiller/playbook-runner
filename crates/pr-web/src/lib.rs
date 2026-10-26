//! The operator interface: a small HTTP/1.1 server, sessions and CSRF, and the
//! pages for templates, schedules, runs, inventories, and secrets.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod app;
pub mod auth;
pub mod config;
pub mod html;
pub mod http;
