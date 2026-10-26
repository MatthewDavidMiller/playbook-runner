//! The schedule builder: the form's frequency choices, converted to and
//! from a cron expression. Anything the builder cannot express is kept as a
//! custom expression, so nothing is lost by editing a schedule.

use pr_common::{Error, Result};

use crate::cron::Cron;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frequency {
    /// At `minute` past every hour.
    Hourly {
        minute: u32,
    },
    Daily {
        hour: u32,
        minute: u32,
    },
    /// On the given weekdays (0 = Sunday).
    Weekly {
        weekdays: Vec<u32>,
        hour: u32,
        minute: u32,
    },
    /// On day `day` of every month.
    Monthly {
        day: u32,
        hour: u32,
        minute: u32,
    },
    Custom(String),
}

impl Frequency {
    pub fn kind(&self) -> &'static str {
        match self {
            Frequency::Hourly { .. } => "hourly",
            Frequency::Daily { .. } => "daily",
            Frequency::Weekly { .. } => "weekly",
            Frequency::Monthly { .. } => "monthly",
            Frequency::Custom(_) => "custom",
        }
    }

    pub fn to_cron(&self) -> String {
        match self {
            Frequency::Hourly { minute } => format!("{minute} * * * *"),
            Frequency::Daily { hour, minute } => format!("{minute} {hour} * * *"),
            Frequency::Weekly { weekdays, hour, minute } => {
                let days: Vec<String> = weekdays.iter().map(u32::to_string).collect();
                format!("{minute} {hour} * * {}", days.join(","))
            }
            Frequency::Monthly { day, hour, minute } => format!("{minute} {hour} {day} * *"),
            Frequency::Custom(expr) => expr.trim().to_owned(),
        }
    }

    /// The builder choice an expression corresponds to; `Custom` when it is
    /// not one of the simple shapes.
    pub fn from_cron(expr: &str) -> Self {
        let custom = || Frequency::Custom(expr.trim().to_owned());
        let fields: Vec<&str> = expr.split_ascii_whitespace().collect();
        let [min, hour, dom, month, dow] = fields.as_slice() else { return custom() };
        let number = |s: &str, max: u32| {
            s.parse::<u32>().ok().filter(|&n| n <= max && s.bytes().all(|b| b.is_ascii_digit()))
        };
        let Some(minute) = number(min, 59) else { return custom() };
        if *month != "*" {
            return custom();
        }
        match (*hour, *dom, *dow) {
            ("*", "*", "*") => Frequency::Hourly { minute },
            (h, "*", "*") => {
                number(h, 23).map_or_else(custom, |hour| Frequency::Daily { hour, minute })
            }
            (h, "*", days) => {
                let Some(hour) = number(h, 23) else { return custom() };
                let weekdays: Option<Vec<u32>> = days.split(',').map(|d| number(d, 6)).collect();
                match weekdays {
                    Some(mut w) if !w.is_empty() => {
                        w.sort_unstable();
                        w.dedup();
                        Frequency::Weekly { weekdays: w, hour, minute }
                    }
                    _ => custom(),
                }
            }
            (h, d, "*") => match (number(h, 23), number(d, 31).filter(|&d| d >= 1)) {
                (Some(hour), Some(day)) => Frequency::Monthly { day, hour, minute },
                _ => custom(),
            },
            _ => custom(),
        }
    }
}

/// "HH:MM" from an `<input type="time">`, as (hour, minute).
pub fn parse_time(text: &str) -> Result<(u32, u32)> {
    let invalid = || Error::new("Enter a time such as 17:00.");
    let (h, m) = text.trim().split_once(':').ok_or_else(invalid)?;
    let hour: u32 = h.parse().map_err(|_| invalid())?;
    // Browsers may send seconds too ("17:00:00").
    let minute: u32 = m.get(..2).unwrap_or(m).parse().map_err(|_| invalid())?;
    if hour > 23 || minute > 59 {
        return Err(invalid());
    }
    Ok((hour, minute))
}

/// The form fields, turned into a frequency and validated as cron.
pub fn from_form(
    kind: &str,
    time: &str,
    minute: &str,
    weekdays: &[u32],
    day_of_month: &str,
    custom: &str,
) -> Result<Frequency> {
    let frequency = match kind {
        "hourly" => Frequency::Hourly {
            minute: minute
                .trim()
                .parse()
                .ok()
                .filter(|&m| m <= 59)
                .ok_or_else(|| Error::new("The minute must be 0-59."))?,
        },
        "daily" => {
            let (hour, minute) = parse_time(time)?;
            Frequency::Daily { hour, minute }
        }
        "weekly" => {
            let (hour, minute) = parse_time(time)?;
            let mut days: Vec<u32> = weekdays.iter().copied().filter(|&d| d <= 6).collect();
            days.sort_unstable();
            days.dedup();
            if days.is_empty() {
                return Err(Error::new("Choose at least one day of the week."));
            }
            Frequency::Weekly { weekdays: days, hour, minute }
        }
        "monthly" => {
            let (hour, minute) = parse_time(time)?;
            let day = day_of_month
                .trim()
                .parse()
                .ok()
                .filter(|d| (1..=31).contains(d))
                .ok_or_else(|| Error::new("The day of the month must be 1-31."))?;
            Frequency::Monthly { day, hour, minute }
        }
        _ => Frequency::Custom(custom.trim().to_owned()),
    };
    Cron::parse(&frequency.to_cron())?;
    Ok(frequency)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_choices_round_trip_through_cron() {
        for f in [
            Frequency::Hourly { minute: 5 },
            Frequency::Daily { hour: 4, minute: 30 },
            Frequency::Weekly { weekdays: vec![1, 3, 5], hour: 17, minute: 0 },
            Frequency::Monthly { day: 1, hour: 3, minute: 15 },
        ] {
            assert_eq!(Frequency::from_cron(&f.to_cron()), f, "{}", f.to_cron());
        }
        for expr in ["*/15 * * * *", "0 4 * * mon-fri", "0 0 1 1 *", "@weekly", "0 9,17 * * *"] {
            assert_eq!(Frequency::from_cron(expr), Frequency::Custom(expr.to_owned()));
        }
    }

    #[test]
    fn form_values_are_validated() {
        assert_eq!(from_form("weekly", "17:00", "", &[1], "", "").unwrap().to_cron(), "0 17 * * 1");
        assert_eq!(
            from_form("daily", "04:30:00", "", &[], "", "").unwrap().to_cron(),
            "30 4 * * *"
        );
        assert_eq!(
            from_form("monthly", "03:00", "", &[], "15", "").unwrap().to_cron(),
            "0 3 15 * *"
        );
        assert_eq!(from_form("hourly", "", "45", &[], "", "").unwrap().to_cron(), "45 * * * *");
        assert_eq!(from_form("custom", "", "", &[], "", " @daily ").unwrap().to_cron(), "@daily");
        assert!(from_form("weekly", "17:00", "", &[], "", "").is_err());
        assert!(from_form("daily", "25:00", "", &[], "", "").is_err());
        assert!(from_form("monthly", "03:00", "", &[], "32", "").is_err());
        assert!(from_form("hourly", "", "60", &[], "", "").is_err());
        assert!(from_form("custom", "", "", &[], "", "not cron").is_err());
    }
}
