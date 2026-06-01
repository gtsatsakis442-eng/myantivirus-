//! Console styling for the enterprise interface.
//!
//! Colors auto-disable when stdout is not a TTY (e.g. piped/redirected) or when
//! `NO_COLOR` is set, so output stays clean in logs and CI.

use std::io::IsTerminal;
use std::sync::OnceLock;

fn enabled() -> bool {
    static E: OnceLock<bool> = OnceLock::new();
    *E.get_or_init(|| std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none())
}

fn paint(code: &str, s: &str) -> String {
    if enabled() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn bold(s: &str) -> String {
    paint("1", s)
}
pub fn dim(s: &str) -> String {
    paint("2", s)
}
pub fn red(s: &str) -> String {
    paint("1;31", s)
}
pub fn green(s: &str) -> String {
    paint("32", s)
}
pub fn yellow(s: &str) -> String {
    paint("33", s)
}
pub fn magenta(s: &str) -> String {
    paint("35", s)
}
pub fn cyan(s: &str) -> String {
    paint("36", s)
}

const INNER: usize = 56;

/// Render the branded, boxed product header.
pub fn banner(version: &str) {
    let title = "TALOS EPP  —  Endpoint Protection Platform";
    let sub = format!("Enterprise Edition  ·  v{version}");
    println!("{}", cyan(&format!("┌{}┐", "─".repeat(INNER + 2))));
    println!("{}", bold(&framed(title)));
    println!("{}", dim(&framed(&sub)));
    println!("{}", cyan(&format!("└{}┘", "─".repeat(INNER + 2))));
}

fn framed(text: &str) -> String {
    let len = text.chars().count();
    let pad = INNER.saturating_sub(len);
    format!("│ {text}{} │", " ".repeat(pad))
}

/// A section heading, e.g. "Agent Status".
pub fn section(title: &str) {
    println!("\n{}", bold(&cyan(title)));
}

/// A right-padded key/value status line.
pub fn kv(key: &str, value: &str) {
    println!("  {:<14} {value}", format!("{key}:"));
}

/// Human-friendly "time ago" from a unix timestamp (0 = never).
pub fn time_ago(then_unix: u64) -> String {
    if then_unix == 0 {
        return "never".to_string();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let secs = now.saturating_sub(then_unix);
    match secs {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=86_399 => format!("{} h ago", secs / 3600),
        _ => format!("{} d ago", secs / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colors_disabled_off_tty() {
        // In tests stdout is not a TTY, so styling is a no-op (plain text).
        assert_eq!(red("x"), "x");
        assert_eq!(bold("hi"), "hi");
    }

    #[test]
    fn time_ago_buckets() {
        assert_eq!(time_ago(0), "never");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(time_ago(now), "just now");
        assert_eq!(time_ago(now.saturating_sub(120)), "2 min ago");
        assert_eq!(time_ago(now.saturating_sub(7200)), "2 h ago");
    }
}
