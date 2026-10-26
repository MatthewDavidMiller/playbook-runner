//! Running jobs: fetching the playbook repository, starting ansible-playbook
//! with its secrets handed over on pipes, capturing the log, and cancelling.
//!
//! Runs execute one at a time, in the order they were queued, on a single
//! worker thread. Playbooks in a homelab routinely touch the same hosts
//! (and the update playbook reboots them), so running two at once would be
//! a hazard rather than a feature.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod exec;
pub mod redact;
pub mod runs;
pub mod scheduler;

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;

use pr_common::{Error, Result, timefmt};
use pr_store::{Store, Template};

pub use exec::ExecConfig;
pub use runs::{Run, RunStore, Status};

const THREAD_STACK: usize = 512 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug, Clone)]
struct Job {
    number: u64,
    template_id: String,
    check: bool,
}

#[derive(Debug)]
pub struct Runner {
    store: Arc<Store>,
    runs: RunStore,
    cfg: ExecConfig,
    queue: Mutex<VecDeque<Job>>,
    wake: Condvar,
    current: Mutex<Option<(u64, Arc<AtomicBool>)>>,
    keep_runs: usize,
}

impl Runner {
    /// Opens the run records, marks runs a previous process left unfinished
    /// as interrupted, and clears stale scratch directories.
    pub fn new(
        store: Arc<Store>,
        data_dir: &Path,
        cfg: ExecConfig,
        keep_runs: usize,
    ) -> Result<Arc<Self>> {
        let runs = RunStore::open(data_dir)?;
        let interrupted = runs.interrupt_stale(timefmt::unix_seconds())?;
        if interrupted > 0 {
            eprintln!("playbook-runner: marked {interrupted} unfinished run(s) as interrupted");
        }
        if let Ok(entries) = fs::read_dir(&cfg.work_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("run-") || name.starts_with("check-") {
                    let _ = fs::remove_dir_all(entry.path());
                }
            }
        }
        Ok(Arc::new(Self {
            store,
            runs,
            cfg,
            queue: Mutex::new(VecDeque::new()),
            wake: Condvar::new(),
            current: Mutex::new(None),
            keep_runs: keep_runs.max(10),
        }))
    }

    /// Starts the worker thread.
    pub fn start(self: &Arc<Self>) -> Result<()> {
        let me = Arc::clone(self);
        thread::Builder::new()
            .name("runner".to_owned())
            .stack_size(THREAD_STACK)
            .spawn(move || me.work())
            .map(|_| ())
            .map_err(|e| Error::new(format!("cannot start the run worker: {e}")))
    }

    pub fn runs(&self) -> &RunStore {
        &self.runs
    }

    pub fn exec_config(&self) -> &ExecConfig {
        &self.cfg
    }

    /// Queues a run of `template_id`. `trigger` is "manual" or
    /// "schedule:<id>"; `check` forces --check.
    pub fn enqueue(&self, template_id: &str, trigger: &str, check: bool) -> Result<Run> {
        let template = self
            .store
            .get::<Template>(template_id)?
            .ok_or_else(|| Error::new("the template does not exist"))?;
        let run = self.runs.create(Run {
            number: 0,
            template_id: template.id.clone(),
            template_name: template.name.clone(),
            trigger: trigger.to_owned(),
            check_mode: check || template.check_mode,
            status: Status::Queued,
            exit_code: None,
            commit: String::new(),
            queued_at: timefmt::unix_seconds(),
            started_at: None,
            finished_at: None,
            error: String::new(),
        })?;
        lock(&self.queue).push_back(Job { number: run.number, template_id: template.id, check });
        self.wake.notify_all();
        Ok(run)
    }

    /// Whether a run of `template_id` is queued or running.
    pub fn is_active(&self, template_id: &str) -> bool {
        lock(&self.queue).iter().any(|j| j.template_id == template_id)
            || lock(&self.current).as_ref().is_some_and(|(n, _)| {
                self.runs.get(*n).ok().flatten().is_some_and(|r| r.template_id == template_id)
            })
    }

    /// Cancels a queued run at once, or asks a running one to stop.
    pub fn cancel(&self, number: u64) -> Result<()> {
        {
            let mut queue = lock(&self.queue);
            if let Some(pos) = queue.iter().position(|j| j.number == number) {
                queue.remove(pos);
                drop(queue);
                let now = timefmt::unix_seconds();
                self.runs.update(number, |r| {
                    r.status = Status::Cancelled;
                    r.finished_at = Some(now);
                })?;
                return Ok(());
            }
        }
        match lock(&self.current).as_ref() {
            Some((n, flag)) if *n == number => {
                flag.store(true, Ordering::Release);
                Ok(())
            }
            _ => Err(Error::new("that run is not queued or running")),
        }
    }

    /// The tail of a run's log, at most `max` bytes, and whether earlier
    /// output was left out.
    pub fn read_log(&self, number: u64, max: u64) -> Result<(String, bool)> {
        let mut file = match File::open(self.runs.log_path(number)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((String::new(), false));
            }
            Err(e) => return Err(e.into()),
        };
        let len = file.metadata()?.len();
        let start = len.saturating_sub(max);
        file.seek(SeekFrom::Start(start))?;
        let mut buf = vec![0_u8; usize::try_from(len - start).unwrap_or(0)];
        let mut filled = 0;
        while filled < buf.len() {
            match file.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        buf.truncate(filled);
        Ok((String::from_utf8_lossy(&buf).into_owned(), start > 0))
    }

    /// Whether ansible accepts an inventory; `Ok(None)` when ansible is not
    /// installed and the check was skipped.
    pub fn check_inventory(&self, content: &str) -> Result<Option<()>> {
        exec::check_inventory(&self.cfg, content)
    }

    fn next_job(&self) -> Job {
        let mut queue = lock(&self.queue);
        loop {
            if let Some(job) = queue.pop_front() {
                return job;
            }
            queue = self.wake.wait(queue).unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn work(&self) {
        loop {
            let job = self.next_job();
            let cancel = Arc::new(AtomicBool::new(false));
            *lock(&self.current) = Some((job.number, Arc::clone(&cancel)));
            self.run_job(&job, &cancel);
            *lock(&self.current) = None;
            if let Err(e) = self.runs.prune(self.keep_runs) {
                eprintln!("playbook-runner: pruning old runs failed: {e}");
            }
        }
    }

    fn run_job(&self, job: &Job, cancel: &Arc<AtomicBool>) {
        let started = timefmt::unix_seconds();
        if let Err(e) = self.runs.update(job.number, |r| {
            r.status = Status::Running;
            r.started_at = Some(started);
        }) {
            eprintln!("playbook-runner: run {}: {e}", job.number);
            return;
        }
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.runs.log_path(job.number));
        let outcome = match log {
            Ok(mut log) => exec::execute(
                &self.store,
                &self.cfg,
                job.number,
                &job.template_id,
                job.check,
                &mut log,
                cancel,
            ),
            Err(e) => exec::Outcome {
                error: format!("cannot open the run log: {e}"),
                ..exec::Outcome::default()
            },
        };
        let status = if outcome.cancelled {
            Status::Cancelled
        } else if outcome.exit_code == Some(0) && outcome.error.is_empty() {
            Status::Succeeded
        } else {
            Status::Failed
        };
        let finished = timefmt::unix_seconds();
        let result = self.runs.update(job.number, |r| {
            r.status = status;
            r.exit_code = outcome.exit_code;
            r.commit.clone_from(&outcome.commit);
            r.error.clone_from(&outcome.error);
            r.finished_at = Some(finished);
        });
        if let Err(e) = result {
            eprintln!("playbook-runner: run {}: {e}", job.number);
        }
    }
}
