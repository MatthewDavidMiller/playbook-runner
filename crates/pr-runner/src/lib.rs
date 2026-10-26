//! Running jobs: fetching the playbook repository, starting ansible-playbook
//! with its secrets handed over on pipes, capturing the log, and cancelling.
//!
//! Runs execute one at a time, in the order they were queued, on a single
//! worker thread. Playbooks in a homelab routinely touch the same hosts
//! (and the update playbook reboots them), so running two at once would be
//! a hazard rather than a feature.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod about;
pub mod exec;
pub mod redact;
pub mod report;
pub mod runs;
pub mod scheduler;
pub mod sync;

use std::collections::VecDeque;
use std::fs;
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
    /// The running job: its number, its template, and its cancel flag.
    current: Mutex<Option<(u64, String, Arc<AtomicBool>)>>,
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
        let runs = RunStore::open(data_dir, store.sealer())?;
        let interrupted = runs.interrupt_stale(timefmt::unix_seconds())?;
        if interrupted > 0 {
            eprintln!("playbook-runner: marked {interrupted} unfinished run(s) as interrupted");
        }
        if let Ok(entries) = fs::read_dir(&cfg.work_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if ["run-", "check-", "sync-", "about-"].iter().any(|p| name.starts_with(p)) {
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
            || lock(&self.current).as_ref().is_some_and(|(_, template, _)| template == template_id)
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
            Some((n, _, flag)) if *n == number => {
                flag.store(true, Ordering::Release);
                Ok(())
            }
            _ => Err(Error::new("that run is not queued or running")),
        }
    }

    /// The tail of a run's log, at most `max` bytes, and whether earlier
    /// output was left out.
    pub fn read_log(&self, number: u64, max: u64) -> Result<(String, bool)> {
        self.runs.read_log(number, max)
    }

    /// Clones a repository and records the playbooks it contains.
    pub fn sync_repository(&self, repository_id: &str) -> Result<pr_store::RepoSnapshot> {
        sync::sync_repository(&self.store, &self.cfg, repository_id)
    }

    /// Whether ansible accepts an inventory; `Ok(None)` when ansible is not
    /// installed and the check was skipped.
    pub fn check_inventory(&self, content: &str) -> Result<Option<()>> {
        exec::check_inventory(&self.cfg, content)
    }

    /// Waits for the next queued job and makes it the current one in the same
    /// step, while the queue is still locked. Between a job leaving the queue
    /// and becoming current, a template would look idle, and the scheduler
    /// could queue it a second time.
    fn next_job(&self) -> (Job, Arc<AtomicBool>) {
        let mut queue = lock(&self.queue);
        loop {
            if let Some(job) = queue.pop_front() {
                let cancel = Arc::new(AtomicBool::new(false));
                *lock(&self.current) =
                    Some((job.number, job.template_id.clone(), Arc::clone(&cancel)));
                return (job, cancel);
            }
            queue = self.wake.wait(queue).unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn work(&self) {
        loop {
            let (job, cancel) = self.next_job();
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
        let outcome = match self.runs.log_sink(job.number) {
            Ok(log) => exec::execute(
                &self.store,
                &self.cfg,
                job.number,
                &job.template_id,
                job.check,
                &log,
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
