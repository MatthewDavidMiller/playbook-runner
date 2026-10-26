//! A summary of a run's log for the run page: the per-host PLAY RECAP and
//! every failure, each with the task it happened in and the log line it is
//! on, so the page can link straight to it.
//!
//! This reads ansible's default text output. It is a reading aid only; the
//! full log is always shown beneath it.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRecap {
    pub host: String,
    /// (name, count) in ansible's order: ok, changed, unreachable, failed,
    /// skipped, rescued, ignored.
    pub counts: Vec<(String, u64)>,
}

impl HostRecap {
    pub fn count(&self, name: &str) -> u64 {
        self.counts.iter().find(|(n, _)| n == name).map_or(0, |(_, c)| *c)
    }

    pub fn has_problems(&self) -> bool {
        self.count("failed") > 0 || self.count("unreachable") > 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// 0-based line index in the text that was parsed.
    pub line: usize,
    /// The task it happened in, when one had started.
    pub task: String,
    /// The host, when the line names one.
    pub host: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub recap: Vec<HostRecap>,
    pub failures: Vec<Failure>,
}

const MAX_FAILURES: usize = 50;
const MAX_MESSAGE: usize = 300;
/// How far after an "[ERROR]:" block its host's result line may appear.
const MERGE_WINDOW: usize = 40;

/// The value of `"msg": "..."` in a result line, unescaped just enough to read.
fn json_msg(line: &str) -> Option<String> {
    let start = line.find("\"msg\": \"")? + 8;
    let mut out = String::new();
    let mut chars = line[start..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next() {
                Some('n') => out.push(' '),
                Some(other) => out.push(other),
                None => break,
            },
            c => out.push(c),
        }
    }
    Some(out)
}

fn truncate(s: &str) -> String {
    let s = s.trim();
    if s.chars().count() <= MAX_MESSAGE {
        return s.to_owned();
    }
    let mut cut: String = s.chars().take(MAX_MESSAGE).collect();
    cut.push('…');
    cut
}

/// `fatal: [host]: FAILED! => {...}`, `failed: [host] (item=x) => ...`,
/// `fatal: [host]: UNREACHABLE! => ...`: (host, rest).
fn result_failure(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix("fatal: [").or_else(|| line.strip_prefix("failed: ["))?;
    let (host, rest) = rest.split_once(']')?;
    Some((host.to_owned(), rest.to_owned()))
}

pub fn parse(log: &str) -> Report {
    let mut report = Report::default();
    let mut task = String::new();
    let mut in_recap = false;
    for (index, raw) in log.lines().enumerate() {
        let line = raw.trim_end();
        if let Some(name) =
            line.strip_prefix("TASK [").and_then(|t| t.split_once(']')).map(|(n, _)| n)
        {
            name.clone_into(&mut task);
            in_recap = false;
            continue;
        }
        if line.starts_with("PLAY RECAP") {
            in_recap = true;
            continue;
        }
        if in_recap {
            if let Some((host, counts)) = line.split_once(" : ") {
                let counts: Vec<(String, u64)> = counts
                    .split_ascii_whitespace()
                    .filter_map(|kv| {
                        let (k, v) = kv.split_once('=')?;
                        Some((k.to_owned(), v.parse().ok()?))
                    })
                    .collect();
                if !counts.is_empty() {
                    report.recap.push(HostRecap { host: host.trim().to_owned(), counts });
                    continue;
                }
            }
            if line.is_empty() {
                continue;
            }
            in_recap = false;
        }
        if report.failures.len() >= MAX_FAILURES {
            continue;
        }
        let failure = if let Some((host, rest)) = result_failure(line) {
            // A failure inside rescue/ignore_errors is still worth listing;
            // the recap says whether it mattered.
            let message =
                json_msg(&rest).unwrap_or_else(|| rest.trim_start_matches(':').trim().to_owned());
            Some((host, message))
        } else if let Some(message) = line.strip_prefix("[ERROR]: ") {
            Some((String::new(), message.to_owned()))
        } else if let Some(message) = line.strip_prefix("ERROR! ") {
            Some((String::new(), message.to_owned()))
        } else {
            line.strip_prefix("[playbook-runner] error: ")
                .map(|message| (String::new(), message.to_owned()))
        };
        if let Some((host, message)) = failure {
            // ansible-core 2.19+ announces a task failure as an "[ERROR]:"
            // block and then prints the host's result line; keep one entry,
            // the result line, which names the host.
            if !host.is_empty()
                && report.failures.last().is_some_and(|last| {
                    last.host.is_empty() && last.task == task && index - last.line <= MERGE_WINDOW
                })
            {
                report.failures.pop();
            }
            report.failures.push(Failure {
                line: index,
                task: task.clone(),
                host,
                message: truncate(&message),
            });
        }
    }
    report
}

/// Which step a run stopped at, from the runner's own error message.
pub fn failed_step(error: &str) -> &'static str {
    let e = error.to_ascii_lowercase();
    if e.contains("ssh-add") || e.contains("ssh-agent") {
        "Loading the SSH keys"
    } else if e.contains("clone") {
        "Cloning the repository"
    } else if e.contains("collections") {
        "Checking the built-in collections"
    } else if e.contains("is not a file in the repository") {
        "Finding the playbook"
    } else if e.contains("inventory")
        || e.contains("vault password")
        || e.contains("secret")
        || e.contains("template")
    {
        "Preparing the run's inputs"
    } else if e.contains("timed out") {
        "Running the playbook (time limit reached)"
    } else {
        "Running the playbook"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "\
[playbook-runner] cloning /srv/repo (branch main)
PLAY [all] *********************************************************************

TASK [Gathering Facts] *********************************************************
ok: [vm1]
fatal: [vm2]: UNREACHABLE! => {\"changed\": false, \"msg\": \"Failed to connect to the host via ssh: timed out\", \"unreachable\": true}

TASK [Update packages] *********************************************************
fatal: [vm1]: FAILED! => {\"changed\": false, \"msg\": \"Depsolve \\\"error\\\"\"}
failed: [vm1] (item=nginx) => {\"ansible_loop_var\": \"item\", \"msg\": \"No package nginx\"}
...ignoring

PLAY RECAP *********************************************************************
vm1                        : ok=4    changed=1    unreachable=0    failed=1    skipped=2    rescued=0    ignored=1
vm2                        : ok=0    changed=0    unreachable=1    failed=0    skipped=0    rescued=0    ignored=0

[playbook-runner] ansible-playbook exited with 2
";

    #[test]
    fn recap_and_failures_are_read_from_default_output() {
        let r = parse(LOG);
        assert_eq!(r.recap.len(), 2);
        assert_eq!(r.recap[0].host, "vm1");
        assert_eq!(r.recap[0].count("ok"), 4);
        assert_eq!(r.recap[0].count("failed"), 1);
        assert!(r.recap[1].has_problems());
        assert_eq!(r.failures.len(), 3);
        assert_eq!(r.failures[0].task, "Gathering Facts");
        assert_eq!(r.failures[0].host, "vm2");
        assert_eq!(r.failures[0].message, "Failed to connect to the host via ssh: timed out");
        assert_eq!(r.failures[1].task, "Update packages");
        assert_eq!(r.failures[1].message, "Depsolve \"error\"");
        assert_eq!(r.failures[2].message, "No package nginx");
        assert_eq!(LOG.lines().nth(r.failures[1].line).unwrap().split(':').next(), Some("fatal"));
    }

    #[test]
    fn runner_and_ansible_errors_are_failures_too() {
        let r = parse(
            "[ERROR]: the role 'x' was not found\n[playbook-runner] error: git clone failed\n",
        );
        assert_eq!(r.failures.len(), 2);
        assert_eq!(r.failures[0].message, "the role 'x' was not found");
        assert_eq!(r.failures[1].line, 1);
        assert_eq!(failed_step("git clone failed"), "Cloning the repository");
        assert_eq!(
            failed_step("the collections built into this playbook-runner image do not satisfy x"),
            "Checking the built-in collections"
        );
        assert_eq!(
            failed_step("timed out after 60 minutes"),
            "Running the playbook (time limit reached)"
        );
    }

    #[test]
    fn an_error_block_and_its_result_line_are_one_failure() {
        let log = "TASK [Break on purpose] ****\n[ERROR]: Task failed: Action failed: boom\nOrigin: /x.yml:5:7\n\n\
                   fatal: [localhost]: FAILED! => {\"changed\": false, \"msg\": \"boom\"}\n";
        let r = parse(log);
        assert_eq!(r.failures.len(), 1, "{r:?}");
        assert_eq!((r.failures[0].host.as_str(), r.failures[0].line), ("localhost", 4));
        // An [ERROR] with no result line after it (e.g. a parse error) stays.
        assert_eq!(parse("[ERROR]: couldn't resolve module\n").failures.len(), 1);
    }

    #[test]
    fn long_messages_are_cut() {
        let line = format!("fatal: [h]: FAILED! => {{\"msg\": \"{}\"}}", "x".repeat(1000));
        assert_eq!(parse(&line).failures[0].message.chars().count(), MAX_MESSAGE + 1);
    }
}
