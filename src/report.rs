//! Settings that differ from their default, as data.

use alloc::string::{String, ToString};

/// A setting that differs from its default, in the way a dialer or listener reports it.
///
/// A library cannot know whether `plain_beyond_loopback` was a mistake or the point: a link sealed
/// by a proof inside it needs no TLS. So it returns what was set and never logs or warns about it;
/// the application that knows the use case decides how to show it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct NonDefault {
    /// The setting's name, as its builder method and accessor spell it.
    pub setting: &'static str,
    /// What it is unless chosen otherwise.
    pub default: String,
    /// What it is now.
    pub value: String,
}

impl NonDefault {
    /// A setting named `setting` whose default is `default` and whose value is `value`.
    #[must_use]
    pub fn new(setting: &'static str, default: impl ToString, value: impl ToString) -> Self {
        Self {
            setting,
            default: default.to_string(),
            value: value.to_string(),
        }
    }
}
