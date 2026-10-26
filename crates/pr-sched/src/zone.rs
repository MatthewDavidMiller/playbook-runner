//! Time zones from the system's TZif files (RFC 8536), so schedules follow
//! daylight saving time.
//!
//! A TZif file lists past transitions; times after the last one follow the
//! POSIX TZ rule in its footer (e.g. `EST5EDT,M3.2.0,M11.1.0`). Alpine ships
//! "slim" files whose tables stop early and rely on that rule for every
//! future date, so the rule is implemented in full: the `Mm.w.d`, `Jn`, and
//! `n` date forms and signed or extended transition times.

use pr_common::timefmt::{civil_from_days, days_from_civil};
use pr_common::{Error, Result, fsio};

const TZIF_LIMIT: usize = 512 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalType {
    offset: i64,
    abbreviation: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleDate {
    /// Month 1-12, week 1-5 (5 = last), weekday 0-6 (Sunday = 0).
    Month(u32, u32, u32),
    /// Day 1-365, never counting February 29.
    Julian1(u32),
    /// Day 0-365, counting February 29.
    Julian0(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Dst {
    local: LocalType,
    start: (RuleDate, i64),
    end: (RuleDate, i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PosixRule {
    std: LocalType,
    dst: Option<Dst>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zone {
    name: String,
    transitions: Vec<(i64, usize)>,
    types: Vec<LocalType>,
    rule: Option<PosixRule>,
}

fn be32(b: &[u8], i: usize) -> Option<i64> {
    Some(i64::from(i32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?)))
}

fn be64(b: &[u8], i: usize) -> Option<i64> {
    Some(i64::from_be_bytes(b.get(i..i + 8)?.try_into().ok()?))
}

fn count(b: &[u8], i: usize) -> Option<usize> {
    usize::try_from(u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?)).ok()
}

/// Whether `name` is a plausible zone name: no traversal, no absolute path.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('/')
        && !name.split('/').any(|p| p.is_empty() || p == "." || p == "..")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_+-".contains(&b))
}

impl Zone {
    pub fn utc() -> Self {
        let utc = LocalType { offset: 0, abbreviation: "UTC".into() };
        Self {
            name: "UTC".into(),
            transitions: Vec::new(),
            types: vec![utc.clone()],
            rule: Some(PosixRule { std: utc, dst: None }),
        }
    }

    /// Loads `<zoneinfo>/<name>`; "UTC" needs no file.
    pub fn load(zoneinfo: &std::path::Path, name: &str) -> Result<Self> {
        if name == "UTC" || name == "Etc/UTC" {
            return Ok(Self::utc());
        }
        if !valid_name(name) {
            return Err(Error::new(format!("{name} is not a time zone name")));
        }
        let data = fsio::read_bounded(zoneinfo.join(name), TZIF_LIMIT)?.ok_or_else(|| {
            Error::new(format!("unknown time zone {name} (is tzdata installed?)"))
        })?;
        Self::parse(name, &data)
            .ok_or_else(|| Error::new(format!("{name} is not a valid TZif file")))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Parses TZif data, using the 64-bit (version 2+) block when present.
    pub fn parse(name: &str, b: &[u8]) -> Option<Self> {
        if b.get(..4)? != b"TZif" {
            return None;
        }
        let version = *b.get(4)?;
        let header = |at: usize| -> Option<[usize; 6]> {
            Some([
                count(b, at + 20)?,
                count(b, at + 24)?,
                count(b, at + 28)?,
                count(b, at + 32)?,
                count(b, at + 36)?,
                count(b, at + 40)?,
            ])
        };
        let [isut, isstd, leap, time, typ, chars] = header(0)?;
        let v1_len = time * 4 + time + typ * 6 + chars + leap * 8 + isstd + isut;
        let (at, width) = if version >= b'2' { (44 + v1_len, 8) } else { (0, 4) };
        if version >= b'2' && b.get(at..at + 4)? != b"TZif" {
            return None;
        }
        let [isut, isstd, leap, time, typ, chars] = header(at)?;
        if typ == 0 || typ > 256 || time > 10_000 {
            return None;
        }
        let mut p = at + 44;
        let mut times = Vec::with_capacity(time);
        for i in 0..time {
            times.push(if width == 8 { be64(b, p + i * 8)? } else { be32(b, p + i * 4)? });
        }
        p += time * width;
        let indices = b.get(p..p + time)?;
        p += time;
        let designations_at = p + typ * 6;
        let designations = b.get(designations_at..designations_at + chars)?;
        let mut types = Vec::with_capacity(typ);
        for i in 0..typ {
            let offset = be32(b, p + i * 6)?;
            let idx = usize::from(*b.get(p + i * 6 + 5)?);
            let abbr = designations.get(idx..)?.split(|&c| c == 0).next()?;
            types.push(LocalType {
                offset,
                abbreviation: String::from_utf8_lossy(abbr).into_owned(),
            });
        }
        p = designations_at + chars + leap * (width + 4) + isstd + isut;
        let mut transitions = Vec::with_capacity(time);
        for (t, &i) in times.iter().zip(indices) {
            let i = usize::from(i);
            if i >= types.len() {
                return None;
            }
            transitions.push((*t, i));
        }
        let rule = if version >= b'2' {
            let footer = b.get(p..)?.strip_prefix(b"\n")?;
            let end = footer.iter().position(|&c| c == b'\n')?;
            let text = std::str::from_utf8(&footer[..end]).ok()?;
            if text.is_empty() { None } else { Some(parse_posix(text)?) }
        } else {
            None
        };
        Some(Self { name: name.to_owned(), transitions, types, rule })
    }

    /// A zone from a POSIX TZ rule alone, e.g. "EST5EDT,M3.2.0,M11.1.0".
    pub fn from_posix(rule: &str) -> Option<Self> {
        let rule = parse_posix(rule)?;
        Some(Self {
            name: rule_name(&rule),
            transitions: Vec::new(),
            types: vec![rule.std.clone()],
            rule: Some(rule),
        })
    }

    fn local_type(&self, utc: i64) -> LocalType {
        match self.transitions.last() {
            Some(&(last, _)) if utc >= last && self.rule.is_some() => {}
            Some(_) => {
                let i = self.transitions.partition_point(|&(t, _)| t <= utc);
                return if i == 0 {
                    self.types
                        .iter()
                        .find(|t| !t.abbreviation.is_empty())
                        .unwrap_or(&self.types[0])
                        .clone()
                } else {
                    self.types[self.transitions[i - 1].1].clone()
                };
            }
            None => {}
        }
        match &self.rule {
            Some(rule) => rule.at(utc),
            None => self.types[self.transitions.last().map_or(0, |&(_, i)| i)].clone(),
        }
    }

    /// The UTC offset in seconds at a UTC instant.
    pub fn offset(&self, utc: i64) -> i64 {
        self.local_type(utc).offset
    }

    /// "2026-10-25 21:04 EDT" for a UTC instant.
    pub fn format(&self, utc: i64) -> String {
        let kind = self.local_type(utc);
        let local = utc + kind.offset;
        let (year, month, day) = civil_from_days(local.div_euclid(86_400));
        let seconds = local.rem_euclid(86_400);
        format!(
            "{year:04}-{month:02}-{day:02} {:02}:{:02} {}",
            seconds / 3600,
            seconds % 3600 / 60,
            kind.abbreviation
        )
    }
}

fn rule_name(rule: &PosixRule) -> String {
    match &rule.dst {
        Some(d) => format!("{}/{}", rule.std.abbreviation, d.local.abbreviation),
        None => rule.std.abbreviation.clone(),
    }
}

impl PosixRule {
    fn at(&self, utc: i64) -> LocalType {
        let Some(dst) = &self.dst else { return self.std.clone() };
        let year = civil_from_days((utc + self.std.offset).div_euclid(86_400)).0;
        // Each transition happens at a local wall time: the start in
        // standard time, the end in daylight time.
        let start = rule_day(dst.start.0, year) * 86_400 + dst.start.1 - self.std.offset;
        let end = rule_day(dst.end.0, year) * 86_400 + dst.end.1 - dst.local.offset;
        let in_dst =
            if start < end { utc >= start && utc < end } else { !(utc >= end && utc < start) };
        if in_dst { dst.local.clone() } else { self.std.clone() }
    }
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days since the epoch of a rule's date in `year`.
fn rule_day(date: RuleDate, year: i64) -> i64 {
    let jan1 = days_from_civil(year, 1, 1);
    match date {
        RuleDate::Julian0(n) => jan1 + i64::from(n),
        RuleDate::Julian1(n) => {
            let n = i64::from(n);
            jan1 + n - 1 + i64::from(is_leap(year) && n >= 60)
        }
        RuleDate::Month(m, w, d) => {
            let first = days_from_civil(year, m, 1);
            let first_weekday = (first + 4).rem_euclid(7);
            let mut day =
                first + (i64::from(d) - first_weekday).rem_euclid(7) + (i64::from(w) - 1) * 7;
            let next_month = if m == 12 {
                days_from_civil(year + 1, 1, 1)
            } else {
                days_from_civil(year, m + 1, 1)
            };
            while day >= next_month {
                day -= 7;
            }
            day
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn number(&mut self, max: u32) -> Option<u32> {
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        let n: u32 = std::str::from_utf8(&self.s[start..self.i]).ok()?.parse().ok()?;
        (n <= max).then_some(n)
    }

    fn name(&mut self) -> Option<String> {
        if self.eat(b'<') {
            let start = self.i;
            while self.peek().is_some_and(|c| c != b'>') {
                self.i += 1;
            }
            let name = std::str::from_utf8(&self.s[start..self.i]).ok()?.to_owned();
            return (self.eat(b'>') && name.len() >= 3).then_some(name);
        }
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
            self.i += 1;
        }
        let name = std::str::from_utf8(&self.s[start..self.i]).ok()?;
        (name.len() >= 3).then(|| name.to_owned())
    }

    /// [+-]hh[:mm[:ss]] in seconds, hours up to `max_hours`.
    fn time(&mut self, max_hours: u32) -> Option<i64> {
        let sign = if self.eat(b'-') {
            -1
        } else {
            self.eat(b'+');
            1
        };
        let mut seconds = i64::from(self.number(max_hours)?) * 3600;
        if self.eat(b':') {
            seconds += i64::from(self.number(59)?) * 60;
            if self.eat(b':') {
                seconds += i64::from(self.number(59)?);
            }
        }
        Some(sign * seconds)
    }

    fn date(&mut self) -> Option<(RuleDate, i64)> {
        let date = if self.eat(b'M') {
            let m = self.number(12)?;
            let ok = self.eat(b'.');
            let w = self.number(5)?;
            let ok = ok && self.eat(b'.');
            let d = self.number(6)?;
            (ok && m >= 1 && w >= 1).then_some(RuleDate::Month(m, w, d))?
        } else if self.eat(b'J') {
            RuleDate::Julian1(self.number(365).filter(|&n| n >= 1)?)
        } else {
            RuleDate::Julian0(self.number(365)?)
        };
        let time = if self.eat(b'/') { self.time(167)? } else { 7200 };
        Some((date, time))
    }
}

fn parse_posix(text: &str) -> Option<PosixRule> {
    let mut p = Parser { s: text.as_bytes(), i: 0 };
    let std_name = p.name()?;
    // POSIX offsets are west-positive; TZif and this module are east-positive.
    let std = LocalType { offset: -p.time(24)?, abbreviation: std_name };
    if p.peek().is_none() {
        return Some(PosixRule { std, dst: None });
    }
    let dst_name = p.name()?;
    let dst_offset =
        if p.peek().is_some_and(|c| c != b',') { -p.time(24)? } else { std.offset + 3600 };
    // Without explicit rules POSIX leaves the dates implementation-defined;
    // the US rules are the conventional default.
    let (start, end) = if p.eat(b',') {
        let start = p.date()?;
        if !p.eat(b',') {
            return None;
        }
        (start, p.date()?)
    } else {
        ((RuleDate::Month(3, 2, 0), 7200), (RuleDate::Month(11, 1, 0), 7200))
    };
    if p.peek().is_some() {
        return None;
    }
    Some(PosixRule {
        std,
        dst: Some(Dst {
            local: LocalType { offset: dst_offset, abbreviation: dst_name },
            start,
            end,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(y: i64, m: u32, d: u32, h: i64, min: i64) -> i64 {
        days_from_civil(y, m, d) * 86_400 + h * 3600 + min * 60
    }

    #[test]
    fn us_eastern_rule_switches_at_the_right_instants() {
        let z = Zone::from_posix("EST5EDT,M3.2.0,M11.1.0").unwrap();
        // 2026: DST from 2026-03-08 07:00Z to 2026-11-01 06:00Z.
        assert_eq!(z.offset(utc(2026, 3, 8, 6, 59)), -5 * 3600);
        assert_eq!(z.offset(utc(2026, 3, 8, 7, 0)), -4 * 3600);
        assert_eq!(z.offset(utc(2026, 11, 1, 5, 59)), -4 * 3600);
        assert_eq!(z.offset(utc(2026, 11, 1, 6, 0)), -5 * 3600);
        assert_eq!(z.format(utc(2026, 7, 4, 16, 30)), "2026-07-04 12:30 EDT");
        assert_eq!(z.format(utc(2026, 12, 25, 17, 0)), "2026-12-25 12:00 EST");
    }

    #[test]
    fn southern_hemisphere_and_other_forms() {
        // Sydney: DST from the first Sunday in October to the first in April.
        let z = Zone::from_posix("AEST-10AEDT,M10.1.0,M4.1.0/3").unwrap();
        assert_eq!(z.offset(utc(2026, 1, 15, 0, 0)), 11 * 3600);
        assert_eq!(z.offset(utc(2026, 6, 15, 0, 0)), 10 * 3600);
        let z = Zone::from_posix("<+0330>-3:30").unwrap();
        assert_eq!(z.offset(0), 3 * 3600 + 1800);
        assert!(Zone::from_posix("EST5EDT,J60/-1,300").is_some());
        for bad in ["", "E5", "EST5EDT,M13.1.0,M11.1.0", "EST5EDT,M3.2.0", "EST5x"] {
            assert!(Zone::from_posix(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn zone_names_are_confined() {
        assert!(valid_name("America/New_York") && valid_name("Etc/GMT+5"));
        for bad in ["", "/etc/passwd", "../x", "a//b", "a/./b", "a b"] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn system_tzif_files_agree_with_the_rules() {
        let dir = std::path::Path::new("/usr/share/zoneinfo");
        let z = Zone::load(dir, "America/New_York").expect("tzdata is installed in the toolbox");
        assert_eq!(z.offset(utc(2026, 3, 8, 7, 0)), -4 * 3600);
        assert_eq!(z.offset(utc(2026, 11, 1, 6, 0)), -5 * 3600);
        // Long before the slim table and long after it.
        assert_eq!(z.offset(utc(1990, 1, 1, 0, 0)), -5 * 3600);
        assert_eq!(z.offset(utc(2090, 7, 1, 0, 0)), -4 * 3600);
        assert!(Zone::load(dir, "Not/AZone").is_err());
        assert_eq!(Zone::load(dir, "UTC").unwrap().offset(0), 0);
    }
}
