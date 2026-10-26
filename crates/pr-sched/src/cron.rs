//! Five-field cron expressions (minute hour day-of-month month day-of-week)
//! with lists, ranges, steps, month and weekday names, and the `@hourly`,
//! `@daily`, `@weekly`, `@monthly`, and `@yearly` macros.
//!
//! As in Vixie cron, when both day-of-month and day-of-week are restricted
//! a day matching either fires. Times are local to the schedule's zone: a
//! time skipped by a spring-forward change does not fire that day, and a
//! time repeated by a fall-back change fires once.

use pr_common::timefmt::civil_from_days;
use pr_common::{Error, Result};

use crate::zone::Zone;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cron {
    minutes: u64,
    hours: u32,
    days: u32,
    months: u16,
    weekdays: u8,
    dom_restricted: bool,
    dow_restricted: bool,
}

const MONTHS: [&str; 12] =
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
const WEEKDAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

fn value(text: &str, min: u32, max: u32, names: &[&str]) -> Option<u32> {
    if let Some(i) = names.iter().position(|n| n.eq_ignore_ascii_case(text)) {
        return u32::try_from(i).ok().map(|i| i + min);
    }
    let n: u32 = text.parse().ok().filter(|_| text.bytes().all(|b| b.is_ascii_digit()))?;
    (min..=max).contains(&n).then_some(n)
}

/// A field's set of values as a bitmask (bit n = value n). Returns the mask
/// and whether the field was restricted (anything but `*`).
fn field(text: &str, min: u32, max: u32, names: &[&str]) -> Option<(u64, bool)> {
    let mut mask = 0_u64;
    for part in text.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => (r, s.parse::<u32>().ok().filter(|&s| s >= 1 && s <= max)?),
            None => (part, 1),
        };
        let (lo, hi) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (value(a, min, max, names)?, value(b, min, max, names)?)
        } else {
            let v = value(range, min, max, names)?;
            // "5/15" means 5 through the maximum in steps of 15.
            (v, if part.contains('/') { max } else { v })
        };
        if lo > hi {
            return None;
        }
        let mut v = lo;
        while v <= hi {
            mask |= 1 << v;
            v += step;
        }
    }
    Some((mask, text != "*"))
}

impl Cron {
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let expanded = match text.to_ascii_lowercase().as_str() {
            "@hourly" => "0 * * * *".to_owned(),
            "@daily" | "@midnight" => "0 0 * * *".to_owned(),
            "@weekly" => "0 0 * * 0".to_owned(),
            "@monthly" => "0 0 1 * *".to_owned(),
            "@yearly" | "@annually" => "0 0 1 1 *".to_owned(),
            _ => text.to_owned(),
        };
        let fields: Vec<&str> = expanded.split_ascii_whitespace().collect();
        let invalid = || Error::new(format!("\"{text}\" is not a five-field cron expression"));
        let [min, hour, dom, month, dow] = fields.as_slice() else { return Err(invalid()) };
        let (minutes, _) = field(min, 0, 59, &[]).ok_or_else(invalid)?;
        let (hours, _) = field(hour, 0, 23, &[]).ok_or_else(invalid)?;
        let (days, dom_restricted) = field(dom, 1, 31, &[]).ok_or_else(invalid)?;
        let (months, _) = field(month, 1, 12, &MONTHS).ok_or_else(invalid)?;
        let (mut weekdays, dow_restricted) = field(dow, 0, 7, &WEEKDAYS).ok_or_else(invalid)?;
        // 7 is Sunday too.
        if weekdays & (1 << 7) != 0 {
            weekdays = (weekdays | 1) & 0x7f;
        }
        Ok(Self {
            minutes,
            hours: u32::try_from(hours).map_err(|_| invalid())?,
            days: u32::try_from(days).map_err(|_| invalid())?,
            months: u16::try_from(months).map_err(|_| invalid())?,
            weekdays: u8::try_from(weekdays).map_err(|_| invalid())?,
            dom_restricted,
            dow_restricted,
        })
    }

    fn day_matches(&self, day: u32, weekday: u32) -> bool {
        let dom = self.days & (1 << day) != 0;
        let dow = self.weekdays & (1 << weekday) != 0;
        match (self.dom_restricted, self.dow_restricted) {
            (true, true) => dom || dow,
            (true, false) => dom,
            (false, true) => dow,
            (false, false) => true,
        }
    }

    /// The first instant after `after` (UTC seconds) whose local time in
    /// `zone` matches, and whose local wall time is later than `after`'s.
    /// `None` if nothing matches within about four years (e.g. "31 2 *").
    pub fn next_after(&self, zone: &Zone, after: i64) -> Option<i64> {
        let after_local = after + zone.offset(after);
        // Start at the next whole minute.
        let mut t = after.div_euclid(60) * 60 + 60;
        let limit = after + 4 * 366 * 86_400;
        while t <= limit {
            let local = t + zone.offset(t);
            let days = local.div_euclid(86_400);
            let (_, month, day) = civil_from_days(days);
            let weekday = u32::try_from((days + 4).rem_euclid(7)).ok()?;
            let second_of_day = local.rem_euclid(86_400);
            let hour = u32::try_from(second_of_day / 3600).ok()?;
            let minute = u32::try_from(second_of_day % 3600 / 60).ok()?;
            if self.months & (1 << month) == 0 || !self.day_matches(day, weekday) {
                // Skip to the next local midnight.
                t += 86_400 - second_of_day;
                continue;
            }
            if self.hours & (1 << hour) == 0 {
                t += 3600 - second_of_day % 3600;
                continue;
            }
            if self.minutes & (1 << minute) != 0 && local > after_local {
                return Some(t);
            }
            t += 60;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pr_common::timefmt::days_from_civil;

    fn utc(y: i64, m: u32, d: u32, h: i64, min: i64) -> i64 {
        days_from_civil(y, m, d) * 86_400 + h * 3600 + min * 60
    }

    fn next(expr: &str, zone: &Zone, after: i64) -> String {
        zone.format(Cron::parse(expr).unwrap().next_after(zone, after).unwrap())
    }

    #[test]
    fn parsing_accepts_the_common_forms_and_rejects_the_rest() {
        for ok in [
            "* * * * *",
            "*/15 2,14 1-7 jan-mar,dec mon-fri",
            "0 4 * * 0",
            "0 4 * * 7",
            "@weekly",
            "5/10 * * * *",
        ] {
            assert!(Cron::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "* * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "5-1 * * * *",
            "*/0 * * * *",
            "@reboot",
            "a * * * *",
        ] {
            assert!(Cron::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn next_fire_times_in_utc() {
        let z = Zone::utc();
        let t = utc(2026, 10, 25, 21, 4);
        assert_eq!(next("*/15 * * * *", &z, t), "2026-10-25 21:15 UTC");
        assert_eq!(next("0 4 * * sun", &z, t), "2026-11-01 04:00 UTC");
        assert_eq!(next("@monthly", &z, t), "2026-11-01 00:00 UTC");
        assert_eq!(next("0 0 29 2 *", &z, t), "2028-02-29 00:00 UTC");
        // Day-of-month OR day-of-week when both are restricted.
        assert_eq!(next("0 12 1 * fri", &z, t), "2026-10-30 12:00 UTC");
        assert!(Cron::parse("0 0 31 2 *").unwrap().next_after(&z, t).is_none());
    }

    #[test]
    fn daylight_saving_changes() {
        let z = Zone::from_posix("EST5EDT,M3.2.0,M11.1.0").unwrap();
        // A weekly Sunday 04:00 job stays at 04:00 local across both changes.
        assert_eq!(next("0 4 * * 0", &z, utc(2026, 3, 1, 12, 0)), "2026-03-08 04:00 EDT");
        assert_eq!(next("0 4 * * 0", &z, utc(2026, 10, 26, 12, 0)), "2026-11-01 04:00 EST");
        // 02:30 does not exist on 2026-03-08; the next is the following day.
        assert_eq!(next("30 2 * * *", &z, utc(2026, 3, 7, 12, 0)), "2026-03-09 02:30 EDT");
        // 01:30 happens twice on 2026-11-01; it fires once.
        let cron = Cron::parse("30 1 * * *").unwrap();
        let first = cron.next_after(&z, utc(2026, 10, 31, 12, 0)).unwrap();
        assert_eq!(z.format(first), "2026-11-01 01:30 EDT");
        assert_eq!(z.format(cron.next_after(&z, first).unwrap()), "2026-11-02 01:30 EST");
    }
}
