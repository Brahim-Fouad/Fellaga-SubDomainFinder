use fellaga_core::model::AxfrStatus;
use fellaga_core::scanner::PassiveSourceOutcome;

pub(super) const SUMMARY_WIDTH: usize = 72;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Tone {
    Accent,
    Good,
    Warn,
    Bad,
    Dim,
    Bold,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TerminalStyle {
    pub(super) color: bool,
    pub(super) width: usize,
}

impl TerminalStyle {
    pub(super) fn auto(terminal: bool) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        let dumb_terminal = std::env::var_os("TERM").is_some_and(|value| value == "dumb");
        Self {
            color: terminal && !no_color && !dumb_terminal,
            width: std::env::var("COLUMNS")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .map(|value| value.clamp(40, 200))
                .unwrap_or(120),
        }
    }

    #[cfg(test)]
    pub(super) const fn plain() -> Self {
        Self {
            color: false,
            width: 120,
        }
    }

    #[cfg(test)]
    pub(super) const fn plain_with_width(width: usize) -> Self {
        Self {
            color: false,
            width,
        }
    }

    pub(super) fn paint(self, tone: Tone, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if !self.color {
            return text.to_owned();
        }
        let code = match tone {
            Tone::Accent => "36",
            Tone::Good => "32",
            Tone::Warn => "33",
            Tone::Bad => "31",
            Tone::Dim => "2",
            Tone::Bold => "1",
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    }

    pub(super) fn badge(self, label: &str, tone: Tone) -> String {
        self.paint(tone, format!("[{label}]"))
    }
}

pub(super) fn animation_enabled(terminal: bool, term: Option<&std::ffi::OsStr>) -> bool {
    terminal && term.is_none_or(|value| value != "dumb")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NoticeKind {
    Limit,
    Source,
    Warning,
}

impl NoticeKind {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Limit => "limit",
            Self::Source => "source",
            Self::Warning => "warning",
        }
    }

    pub(super) const fn tone(self) -> Tone {
        match self {
            Self::Limit => Tone::Warn,
            Self::Source => Tone::Warn,
            Self::Warning => Tone::Bad,
        }
    }
}

pub(super) fn classify_notice(message: &str) -> NoticeKind {
    let normalized = message.to_ascii_lowercase();
    if ((normalized.contains("budget")
        || normalized.contains("limite cumulative")
        || normalized.contains("limite --max-")
        || normalized.contains("configured limit"))
        && (normalized.contains("atteint")
            || normalized.contains("atteinte")
            || normalized.contains("dépassé")
            || normalized.contains("restant")
            || normalized.contains("reached")))
        || normalized.contains("travail dns borné")
        || normalized.contains("conservé pour --resume")
        || normalized.contains("source(s) lente(s) annulée(s)")
    {
        NoticeKind::Limit
    } else if normalized.contains("quota")
        || normalized.contains("api count exceeded")
        || normalized.contains("rate limit")
        || normalized.contains("rate-limit")
        || normalized.contains("http 429")
        || normalized.contains("anti-bot")
        || normalized.contains("auth required")
        || normalized.contains("source externe différée")
    {
        NoticeKind::Source
    } else {
        NoticeKind::Warning
    }
}

pub(super) fn should_render_passive_source(outcome: PassiveSourceOutcome, verbosity: u8) -> bool {
    match verbosity {
        0 => false,
        1 => matches!(
            outcome,
            PassiveSourceOutcome::Partial
                | PassiveSourceOutcome::Stale
                | PassiveSourceOutcome::Deferred
                | PassiveSourceOutcome::Skipped
        ),
        _ => true,
    }
}

pub(super) fn should_render_axfr(status: AxfrStatus, verbosity: u8) -> bool {
    status == AxfrStatus::Success || verbosity > 0
}

pub(super) fn is_transient_phase(name: &str, detail: &str) -> bool {
    name == "CT incrémental"
        || detail.contains("en cours depuis")
        || detail.contains("budget restant")
        || (name == "passif récursif" && detail.starts_with("zone "))
}

pub(super) fn truncate_chars(value: &str, max_chars: usize) -> String {
    let sanitized = sanitize_terminal_text(value);
    if sanitized.chars().count() <= max_chars {
        return sanitized;
    }
    if max_chars <= 1 {
        return "…".chars().take(max_chars).collect();
    }
    let mut output = sanitized.chars().take(max_chars - 1).collect::<String>();
    output.push('…');
    output
}

pub(super) fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

pub(super) fn strip_terminal_escape_sequences(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\u{1b}' {
            match characters.next() {
                Some('[') => {
                    for control in characters.by_ref() {
                        if ('@'..='~').contains(&control) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    let mut previous_escape = false;
                    for control in characters.by_ref() {
                        if control == '\u{7}' || (previous_escape && control == '\\') {
                            break;
                        }
                        previous_escape = control == '\u{1b}';
                    }
                }
                Some(_) | None => {}
            }
            continue;
        }
        if character == '\u{009b}' {
            for control in characters.by_ref() {
                if ('@'..='~').contains(&control) {
                    break;
                }
            }
            continue;
        }
        safe.push(character);
    }
    safe
}

/// Make untrusted network text safe to render in a terminal.
///
/// Provider errors occasionally contain an entire anti-bot page. Keeping the
/// HTTP context is useful, but printing markup is noisy and can include
/// terminal control characters. Preserve the prefix and replace the document
/// itself with a stable marker.
pub(crate) fn sanitize_terminal_text(value: &str) -> String {
    let value = strip_terminal_escape_sequences(value);
    let lowercase = value.to_ascii_lowercase();
    let html_start = ["<!doctype", "<html", "<head", "<body", "<script", "<title"]
        .into_iter()
        .filter_map(|marker| lowercase.find(marker))
        .min();

    let mut safe = match html_start {
        Some(index) => {
            let mut prefix = value[..index].trim_end().to_owned();
            if !prefix.is_empty() {
                prefix.push(' ');
            }
            prefix.push_str("[HTML response omitted]");
            prefix
        }
        None => value,
    };

    safe = safe
        .chars()
        .map(|character| {
            if character.is_control() || is_bidi_control(character) {
                ' '
            } else {
                character
            }
        })
        .collect();

    safe.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Wrap terminal content without losing characters. Long tokens (FQDNs,
/// hashes, TXT values) are hard-wrapped instead of ellipsized.
pub(super) fn wrap_text(value: &str, width: usize) -> Vec<String> {
    let sanitized = sanitize_terminal_text(value);
    let width = width.max(1);
    if sanitized.is_empty() {
        return vec![String::new()];
    }

    let mut lines = Vec::new();
    let mut current = String::new();
    for word in sanitized.split_whitespace() {
        let word_len = word.chars().count();
        if word_len > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let characters = word.chars().collect::<Vec<_>>();
            for chunk in characters.chunks(width) {
                lines.push(chunk.iter().collect());
            }
            continue;
        }

        let separator = usize::from(!current.is_empty());
        if current.chars().count() + separator + word_len > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

pub(super) fn prefixed_lines(
    style: TerminalStyle,
    first_prefix: &str,
    continuation_prefix: &str,
    text: &str,
    tone: Tone,
) -> Vec<String> {
    let first_width = style
        .width
        .saturating_sub(first_prefix.chars().count())
        .max(1);
    let continuation_width = style
        .width
        .saturating_sub(continuation_prefix.chars().count())
        .max(1);
    let mut output = Vec::new();
    let mut pending = wrap_text(text, first_width).into_iter();
    if let Some(first) = pending.next() {
        output.push(format!("{first_prefix}{}", style.paint(tone, first)));
    }
    for line in pending {
        // A line wrapped for the first prefix may still be wider than the
        // continuation area. Re-wrap it without dropping any content.
        for continuation in wrap_text(&line, continuation_width) {
            output.push(format!(
                "{continuation_prefix}{}",
                style.paint(tone, continuation)
            ));
        }
    }
    output
}

pub(super) fn format_number(value: impl Into<u128>) -> String {
    let digits = value.into().to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(character);
    }
    output
}

pub(super) fn format_duration(duration_ms: u128) -> String {
    if duration_ms < 1_000 {
        return format!("{duration_ms}ms");
    }
    let seconds = duration_ms / 1_000;
    if seconds < 60 {
        return format!("{:.1}s", duration_ms as f64 / 1_000.0);
    }
    if seconds < 3_600 {
        return format!("{}m{:02}s", seconds / 60, seconds % 60);
    }
    format!(
        "{}h{:02}m{:02}s",
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60
    )
}
