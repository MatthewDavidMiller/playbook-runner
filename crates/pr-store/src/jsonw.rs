//! A minimal JSON object writer for the record files, and typed field
//! readers for the strict parser's values.

use pr_common::json::{self, Value};

/// Appends one JSON object, field by field.
#[derive(Debug)]
pub struct Obj<'a> {
    out: &'a mut String,
    first: bool,
}

impl<'a> Obj<'a> {
    pub fn new(out: &'a mut String) -> Self {
        out.push('{');
        Self { out, first: true }
    }

    fn key(&mut self, name: &str) {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        json::write_string(self.out, name);
        self.out.push(':');
    }

    #[must_use]
    pub fn str(mut self, name: &str, value: &str) -> Self {
        self.key(name);
        json::write_string(self.out, value);
        self
    }

    #[must_use]
    pub fn int(mut self, name: &str, value: i64) -> Self {
        self.key(name);
        self.out.push_str(&value.to_string());
        self
    }

    #[must_use]
    pub fn bool(mut self, name: &str, value: bool) -> Self {
        self.key(name);
        self.out.push_str(if value { "true" } else { "false" });
        self
    }

    #[must_use]
    pub fn strs(mut self, name: &str, values: &[String]) -> Self {
        self.key(name);
        self.out.push('[');
        for (i, v) in values.iter().enumerate() {
            if i > 0 {
                self.out.push(',');
            }
            json::write_string(self.out, v);
        }
        self.out.push(']');
        self
    }

    pub fn end(self) {
        self.out.push('}');
    }
}

pub fn str(v: &Value, name: &str) -> Option<String> {
    v.get(name).and_then(Value::as_str).map(str::to_owned)
}

pub fn int(v: &Value, name: &str) -> Option<i64> {
    v.get(name).and_then(Value::as_i64)
}

pub fn bool(v: &Value, name: &str) -> Option<bool> {
    v.get(name).and_then(Value::as_bool)
}

pub fn strs(v: &Value, name: &str) -> Option<Vec<String>> {
    v.get(name)?.as_array()?.iter().map(|s| s.as_str().map(str::to_owned)).collect()
}
