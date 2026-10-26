//! Running jobs: fetching the playbook repository, starting ansible-playbook
//! with its secrets handed over on pipes, capturing the log, and cancelling.

#![forbid(unsafe_code)]
