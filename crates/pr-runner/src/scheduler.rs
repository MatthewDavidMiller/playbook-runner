//! The scheduler: once a minute, queue a run for every enabled schedule
//! whose cron expression matched since the previous check.
//!
//! Only the interval since the previous check is considered, starting from
//! when the server started, so runs missed while it was down are skipped
//! rather than all fired at once on startup. A schedule whose template is
//! still queued or running is skipped for that occurrence, so a slow run
//! never piles up behind itself.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pr_common::{Error, Result, timefmt};
use pr_sched::{Cron, Zone};
use pr_store::{Schedule, Store};

use crate::Runner;

const THREAD_STACK: usize = 256 * 1024;

/// When `schedule` next fires after `now`, if it is enabled and valid.
pub fn next_run(schedule: &Schedule, zone: &Zone, now: i64) -> Option<i64> {
    if !schedule.enabled {
        return None;
    }
    Cron::parse(&schedule.cron).ok()?.next_after(zone, now)
}

/// Queues the runs due in `(since, now]`. Returns the run numbers queued.
pub fn tick(runner: &Runner, store: &Store, zone: &Zone, since: i64, now: i64) -> Vec<u64> {
    let mut queued = Vec::new();
    for schedule in store.list::<Schedule>().unwrap_or_default() {
        let Some(due) = next_run(&schedule, zone, since) else { continue };
        if due > now {
            continue;
        }
        if runner.is_active(&schedule.template) {
            eprintln!(
                "playbook-runner: schedule \"{}\" skipped: its template is still queued or running",
                schedule.name
            );
            continue;
        }
        match runner.enqueue(
            &schedule.template,
            &format!("schedule:{}", schedule.id),
            schedule.check_mode,
        ) {
            Ok(run) => queued.push(run.number),
            Err(e) => eprintln!(
                "playbook-runner: schedule \"{}\" could not queue a run: {e}",
                schedule.name
            ),
        }
    }
    queued
}

/// Starts the scheduler thread.
pub fn start(runner: Arc<Runner>, store: Arc<Store>, zone: Zone) -> Result<()> {
    thread::Builder::new()
        .name("scheduler".to_owned())
        .stack_size(THREAD_STACK)
        .spawn(move || {
            let mut since = timefmt::unix_seconds();
            loop {
                // Wake just after each minute boundary.
                let now = timefmt::unix_seconds();
                let wait = 61 - now.rem_euclid(60);
                thread::sleep(Duration::from_secs(u64::try_from(wait).unwrap_or(30)));
                let now = timefmt::unix_seconds();
                if now > since {
                    tick(&runner, &store, &zone, since, now);
                    since = now;
                }
            }
        })
        .map(|_| ())
        .map_err(|e| Error::new(format!("cannot start the scheduler: {e}")))
}
