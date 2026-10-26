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

/// The values set in a bitmask, ascending.
fn values(mask: u64, min: u32, max: u32) -> Vec<u32> {
    (min..=max).filter(|v| mask & (1 << v) != 0).collect()
}

/// "a", "a and b", "a, b and c".
fn join(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// "5:00 PM" for hour 17, minute 0.
pub fn clock(hour: u32, minute: u32) -> String {
    let (h, suffix) = match hour {
        0 => (12, "AM"),
        1..=11 => (hour, "AM"),
        12 => (12, "PM"),
        _ => (hour - 12, "PM"),
    };
    format!("{h}:{minute:02} {suffix}")
}

/// The step of an arithmetic run covering a whole range from its minimum,
/// e.g. 0,15,30,45 in 0..=59 is step 15.
fn uniform_step(v: &[u32], min: u32, max: u32) -> Option<u32> {
    let (&first, rest) = v.split_first()?;
    let step = rest.first()? - first;
    let uniform = v.windows(2).all(|w| w[1] - w[0] == step);
    (first == min && uniform && v.last()? + step > max).then_some(step)
}

const WEEKDAY_NAMES: [&str; 7] =
    ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const MONTH_NAMES: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

fn ordinal(n: u32) -> String {
    let suffix = match (n % 10, n % 100) {
        (1, 11) | (2, 12) | (3, 13) => "th",
        (1, _) => "st",
        (2, _) => "nd",
        (3, _) => "rd",
        _ => "th",
    };
    format!("{n}{suffix}")
}

impl Cron {
    /// A plain-English reading, e.g. "Every Monday at 5:00 PM" or "Every 15
    /// minutes". Unusual combinations fall back to listing the values, which
    /// is still exact.
    pub fn describe(&self) -> String {
        let minutes = values(self.minutes, 0, 59);
        let hours = values(u64::from(self.hours), 0, 23);
        let all_hours = hours.len() == 24;

        // The time-of-day part, and whether it already reads as "every ...".
        let (time, recurring) = match (minutes.as_slice(), all_hours) {
            (m, true) if m.len() == 60 => ("Every minute".to_owned(), true),
            (m, true) if uniform_step(m, 0, 59).is_some() => {
                (format!("Every {} minutes", uniform_step(m, 0, 59).unwrap_or(1)), true)
            }
            ([0], true) => ("Every hour, on the hour".to_owned(), true),
            ([m], true) => (format!("Every hour at {m} minutes past"), true),
            ([m], false) if uniform_step(&hours, 0, 23).is_some() => (
                format!(
                    "Every {} hours{}",
                    uniform_step(&hours, 0, 23).unwrap_or(1),
                    if *m == 0 {
                        ", on the hour".to_owned()
                    } else {
                        format!(" at {m} minutes past")
                    }
                ),
                true,
            ),
            ([m], false) if hours.len() <= 6 => {
                let times: Vec<String> = hours.iter().map(|&h| clock(h, *m)).collect();
                (format!("at {}", join(&times)), false)
            }
            _ => {
                let m: Vec<String> = minutes.iter().map(u32::to_string).collect();
                let h: Vec<String> = hours.iter().map(u32::to_string).collect();
                (format!("at minute {} past hour {}", join(&m), join(&h)), false)
            }
        };

        // The day part.
        let weekdays = values(u64::from(self.weekdays), 0, 6);
        let days = values(u64::from(self.days), 1, 31);
        let weekday_phrase = match weekdays.as_slice() {
            [1, 2, 3, 4, 5] => "weekday".to_owned(),
            [0, 6] => "Saturday and Sunday".to_owned(),
            w => join(&w.iter().map(|&d| WEEKDAY_NAMES[d as usize].to_owned()).collect::<Vec<_>>()),
        };
        let dom_phrase = format!(
            "the {} of the month",
            join(&days.iter().map(|&d| ordinal(d)).collect::<Vec<_>>())
        );
        let day = match (self.dom_restricted, self.dow_restricted) {
            (false, false) => None,
            (false, true) => Some(format!("every {weekday_phrase}")),
            (true, false) => Some(format!("on {dom_phrase}")),
            (true, true) => Some(format!("on {dom_phrase} and every {weekday_phrase}")),
        };
        let months = values(u64::from(self.months), 1, 12);
        let month = (months.len() < 12).then(|| {
            format!(
                "in {}",
                join(
                    &months
                        .iter()
                        .map(|&m| MONTH_NAMES[m as usize - 1].to_owned())
                        .collect::<Vec<_>>()
                )
            )
        });

        let mut text = match (recurring, day) {
            (true, None) => time,
            (true, Some(day)) => {
                let day =
                    day.replacen("every weekday", "on weekdays", 1).replacen("every ", "on ", 1);
                format!(
                    "{time}, {}",
                    day.replace(" and every weekday", " and weekdays")
                        .replace(" and every ", " and ")
                )
            }
            (false, None) => format!("Every day {time}"),
            (false, Some(day)) if day.starts_with("every ") => {
                let mut d = day;
                d.replace_range(..1, "E");
                format!("{d} {time}")
            }
            (false, Some(day)) => format!("{} {day}", capitalize(&time)),
        };
        if let Some(month) = month {
            text.push(' ');
            text.push_str(&month);
        }
        text
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map_or_else(String::new, |f| f.to_uppercase().chain(c).collect())
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
    fn descriptions_read_naturally() {
        let d = |e: &str| Cron::parse(e).unwrap().describe();
        assert_eq!(d("0 17 * * mon"), "Every Monday at 5:00 PM");
        assert_eq!(d("0 4 * * sun"), "Every Sunday at 4:00 AM");
        assert_eq!(d("30 6 * * *"), "Every day at 6:30 AM");
        assert_eq!(d("0 0 * * *"), "Every day at 12:00 AM");
        assert_eq!(d("0 9,17 * * mon-fri"), "Every weekday at 9:00 AM and 5:00 PM");
        assert_eq!(d("0 12 * * mon,wed,fri"), "Every Monday, Wednesday and Friday at 12:00 PM");
        assert_eq!(d("*/15 * * * *"), "Every 15 minutes");
        assert_eq!(d("*/30 * * * mon-fri"), "Every 30 minutes, on weekdays");
        assert_eq!(d("0 */2 * * sat"), "Every 2 hours, on the hour, on Saturday");
        assert_eq!(d("* * * * *"), "Every minute");
        assert_eq!(d("0 * * * *"), "Every hour, on the hour");
        assert_eq!(d("5 * * * *"), "Every hour at 5 minutes past");
        assert_eq!(d("0 */6 * * *"), "Every 6 hours, on the hour");
        assert_eq!(d("0 3 1 * *"), "At 3:00 AM on the 1st of the month");
        assert_eq!(d("0 3 1,15 * *"), "At 3:00 AM on the 1st and 15th of the month");
        assert_eq!(d("0 0 1 1 *"), "At 12:00 AM on the 1st of the month in January");
        assert_eq!(d("@weekly"), "Every Sunday at 12:00 AM");
        assert_eq!(d("0 4 * * sat,sun"), "Every Saturday and Sunday at 4:00 AM");
        assert_eq!(d("0,30 9-10 * * *"), "Every day at minute 0 and 30 past hour 9 and 10");
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
