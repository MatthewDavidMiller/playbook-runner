//! Run records: one JSON file and one log per run under `<data>/runs/`,
//! numbered from 1.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use pr_common::json::{self, Value};
use pr_common::{Error, Result, fsio};
use pr_store::jsonw::{self, Obj};

const RECORD_LIMIT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    /// The server stopped while the run was queued or running.
    Interrupted,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Queued => "queued",
            Status::Running => "running",
            Status::Succeeded => "succeeded",
            Status::Failed => "failed",
            Status::Cancelled => "cancelled",
            Status::Interrupted => "interrupted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "queued" => Status::Queued,
            "running" => Status::Running,
            "succeeded" => Status::Succeeded,
            "failed" => Status::Failed,
            "cancelled" => Status::Cancelled,
            "interrupted" => Status::Interrupted,
            _ => return None,
        })
    }

    pub fn is_active(self) -> bool {
        matches!(self, Status::Queued | Status::Running)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub number: u64,
    pub template_id: String,
    /// The template's name when the run was queued, kept for display after
    /// the template is renamed or deleted.
    pub template_name: String,
    /// "manual" or "schedule:<schedule id>".
    pub trigger: String,
    pub check_mode: bool,
    pub status: Status,
    pub exit_code: Option<i64>,
    /// The commit the playbook ran from.
    pub commit: String,
    pub queued_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    /// A one-line reason for a failure before ansible-playbook ran.
    pub error: String,
}

impl Run {
    fn write_json(&self, out: &mut String) {
        let mut obj = Obj::new(out)
            .int("number", i64::try_from(self.number).unwrap_or(i64::MAX))
            .str("template_id", &self.template_id)
            .str("template_name", &self.template_name)
            .str("trigger", &self.trigger)
            .bool("check_mode", self.check_mode)
            .str("status", self.status.as_str())
            .str("commit", &self.commit)
            .str("error", &self.error)
            .int("queued_at", self.queued_at);
        if let Some(code) = self.exit_code {
            obj = obj.int("exit_code", code);
        }
        if let Some(t) = self.started_at {
            obj = obj.int("started_at", t);
        }
        if let Some(t) = self.finished_at {
            obj = obj.int("finished_at", t);
        }
        obj.end();
    }

    fn read_json(v: &Value) -> Option<Self> {
        Some(Self {
            number: u64::try_from(jsonw::int(v, "number")?).ok()?,
            template_id: jsonw::str(v, "template_id")?,
            template_name: jsonw::str(v, "template_name")?,
            trigger: jsonw::str(v, "trigger")?,
            check_mode: jsonw::bool(v, "check_mode")?,
            status: Status::parse(&jsonw::str(v, "status")?)?,
            exit_code: jsonw::int(v, "exit_code"),
            commit: jsonw::str(v, "commit")?,
            queued_at: jsonw::int(v, "queued_at")?,
            started_at: jsonw::int(v, "started_at"),
            finished_at: jsonw::int(v, "finished_at"),
            error: jsonw::str(v, "error")?,
        })
    }

    /// Seconds from start to finish (or to `now` while running).
    pub fn duration(&self, now: i64) -> Option<i64> {
        Some(self.finished_at.unwrap_or(now) - self.started_at?)
    }
}

#[derive(Debug)]
pub struct RunStore {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl RunStore {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let dir = data_dir.join("runs");
        fsio::mkdir_all(&dir, 0o700)?;
        Ok(Self { dir, lock: Mutex::new(()) })
    }

    fn guard(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn log_path(&self, number: u64) -> PathBuf {
        self.dir.join(format!("{number}.log"))
    }

    fn record_path(&self, number: u64) -> PathBuf {
        self.dir.join(format!("{number}.json"))
    }

    fn numbers(&self) -> Result<Vec<u64>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let name = entry?.file_name();
            if let Some(n) =
                name.to_str().and_then(|n| n.strip_suffix(".json")).and_then(|n| n.parse().ok())
            {
                out.push(n);
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    fn read(&self, number: u64) -> Result<Option<Run>> {
        let Some(text) = fsio::read_bounded(self.record_path(number), RECORD_LIMIT)? else {
            return Ok(None);
        };
        let v = json::parse(&text).map_err(|e| Error::new(format!("run {number}: {e}")))?;
        Run::read_json(&v)
            .map(Some)
            .ok_or_else(|| Error::new(format!("run {number}: malformed record")))
    }

    fn write(&self, run: &Run) -> Result<()> {
        let mut out = String::new();
        run.write_json(&mut out);
        out.push('\n');
        fsio::atomic_replace(self.record_path(run.number), out.as_bytes(), RECORD_LIMIT)
    }

    /// Records a new queued run, assigning the next number.
    pub fn create(&self, mut run: Run) -> Result<Run> {
        let _g = self.guard();
        run.number = self.numbers()?.last().copied().unwrap_or(0) + 1;
        self.write(&run)?;
        Ok(run)
    }

    pub fn get(&self, number: u64) -> Result<Option<Run>> {
        let _g = self.guard();
        self.read(number)
    }

    /// Applies `change` to a run and saves it.
    pub fn update(&self, number: u64, change: impl FnOnce(&mut Run)) -> Result<Run> {
        let _g = self.guard();
        let mut run =
            self.read(number)?.ok_or_else(|| Error::new(format!("run {number} does not exist")))?;
        change(&mut run);
        self.write(&run)?;
        Ok(run)
    }

    /// The newest `limit` runs, newest first.
    pub fn recent(&self, limit: usize) -> Result<Vec<Run>> {
        let _g = self.guard();
        let numbers = self.numbers()?;
        numbers.iter().rev().take(limit).filter_map(|&n| self.read(n).transpose()).collect()
    }

    /// Marks every run left queued or running by a previous process as
    /// interrupted; returns how many.
    pub fn interrupt_stale(&self, now: i64) -> Result<usize> {
        let _g = self.guard();
        let mut count = 0;
        for n in self.numbers()? {
            if let Some(mut run) = self.read(n)?
                && run.status.is_active()
            {
                run.status = Status::Interrupted;
                run.finished_at = Some(now);
                if run.error.is_empty() {
                    "the server stopped before the run finished".clone_into(&mut run.error);
                }
                self.write(&run)?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Deletes the oldest finished runs beyond the newest `keep`.
    pub fn prune(&self, keep: usize) -> Result<usize> {
        let _g = self.guard();
        let numbers = self.numbers()?;
        let mut removed = 0;
        if numbers.len() > keep {
            for &n in &numbers[..numbers.len() - keep] {
                if self.read(n)?.is_some_and(|r| r.status.is_active()) {
                    continue;
                }
                fsio::remove_file_durable(self.log_path(n))?;
                fsio::remove_file_durable(self.record_path(n))?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample(template: &str) -> Run {
        Run {
            number: 0,
            template_id: template.into(),
            template_name: "Update".into(),
            trigger: "manual".into(),
            check_mode: false,
            status: Status::Queued,
            exit_code: None,
            commit: String::new(),
            queued_at: 10,
            started_at: None,
            finished_at: None,
            error: String::new(),
        }
    }

    #[test]
    fn numbering_updates_interruption_and_pruning() {
        let dir = std::env::temp_dir().join(format!("pr-runs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = RunStore::open(&dir).unwrap();
        let a = store.create(sample("t")).unwrap();
        let b = store.create(sample("t")).unwrap();
        assert_eq!((a.number, b.number), (1, 2));
        store
            .update(1, |r| {
                r.status = Status::Succeeded;
                r.exit_code = Some(0);
                r.started_at = Some(11);
                r.finished_at = Some(20);
            })
            .unwrap();
        assert_eq!(store.get(1).unwrap().unwrap().duration(99), Some(9));
        assert_eq!(store.interrupt_stale(30).unwrap(), 1);
        assert_eq!(store.get(2).unwrap().unwrap().status, Status::Interrupted);
        for _ in 0..3 {
            store.create(sample("t")).unwrap();
        }
        // Runs 3-5 are queued; pruning to 2 removes only finished 1 and 2.
        assert_eq!(store.prune(2).unwrap(), 2);
        let left: Vec<u64> = store.recent(10).unwrap().iter().map(|r| r.number).collect();
        assert_eq!(left, [5, 4, 3]);
        // Numbers keep rising after pruning.
        assert_eq!(store.create(sample("t")).unwrap().number, 6);
        fs::remove_dir_all(&dir).unwrap();
    }
}
