// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};

use crate::app::{App, LogLine};

pub fn draw(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let t = &app.theme;
    let name = app
        .sandbox_names
        .get(app.sandbox_selected)
        .map_or("-", String::as_str);

    let filter_label = app.log_source_filter.label();

    let block = Block::default()
        .title(Span::styled(format!(" Logs: {name} "), t.heading))
        .borders(Borders::ALL)
        .border_style(t.border_focused)
        .padding(Padding::horizontal(1));

    // Calculate visible area inside the block (borders + padding).
    let inner_height = area.height.saturating_sub(2) as usize;
    // Inner width = total width - 2 (borders) - 2 (horizontal padding).
    let inner_width = area.width.saturating_sub(4) as usize;
    // Store viewport height so autoscroll calculations can use it.
    app.log_viewport_height = inner_height;

    // Clamp cursor to visible range before borrowing filtered log lines.
    {
        let filtered_len = app.filtered_log_lines().len();
        let visible_count = filtered_len
            .saturating_sub(app.sandbox_log_scroll)
            .min(inner_height);
        if visible_count > 0 {
            app.log_cursor = app.log_cursor.min(visible_count - 1);
        }
    }

    // Snapshot the cursor position (already clamped above).
    let cursor_pos = app.log_cursor;

    let filtered: Vec<&LogLine> = app.filtered_log_lines();

    if filtered.is_empty() && app.sandbox_log_lines.is_empty() {
        // Still loading.
        let lines = vec![Line::from(Span::styled("Loading...", t.muted))];
        let block = block.title_bottom(Line::from(Span::styled(
            format!(" filter: {filter_label} "),
            t.muted,
        )));
        frame.render_widget(Paragraph::new(lines).block(block), area);
        return;
    }

    // Compute visual selection range (if active).
    let selection_range = app.log_selection_anchor.map(|anchor| {
        let cursor_abs = app.sandbox_log_scroll + cursor_pos;
        (anchor.min(cursor_abs), anchor.max(cursor_abs))
    });

    let lines: Vec<Line<'_>> = filtered
        .iter()
        .skip(app.sandbox_log_scroll)
        .take(inner_height)
        .enumerate()
        .map(|(i, log)| {
            let abs_idx = app.sandbox_log_scroll + i;
            let in_selection =
                selection_range.is_some_and(|(start, end)| abs_idx >= start && abs_idx <= end);
            let mut line = render_log_line(log, inner_width.saturating_sub(2), t);
            if i == cursor_pos {
                // Prepend green cursor marker and apply highlight background.
                line.spans.insert(0, Span::styled("▌ ", t.accent));
                line = line.style(t.log_cursor);
            } else if in_selection {
                line.spans.insert(0, Span::styled("▌ ", t.accent));
                line = line.style(t.log_selection);
            } else {
                line.spans.insert(0, Span::raw("  "));
            }
            line
        })
        .collect();

    // Scroll position + autoscroll indicator.
    let total = filtered.len();
    let pos = app.sandbox_log_scroll + cursor_pos + 1;
    let scroll_info = if total > 0 {
        format!(" [{pos}/{total}] ")
    } else {
        String::new()
    };

    let status_span = if let Some((start, end)) = selection_range {
        let count = end - start + 1;
        Span::styled(format!(" VISUAL ({count} lines) "), t.status_warn)
    } else if app.log_autoscroll {
        Span::styled(" ● FOLLOWING ", t.status_ok)
    } else {
        Span::styled(" ○ PAUSED ", t.status_warn)
    };

    let block = block.title_bottom(Line::from(vec![
        status_span,
        Span::styled(scroll_info, t.muted),
        Span::styled(format!(" filter: {filter_label} "), t.muted),
    ]));

    frame.render_widget(Paragraph::new(lines).block(block), area);

    // NOTE: Detail popup overlay is now rendered by draw_sandbox_screen() in
    // mod.rs using frame.size() so it renders over the full screen, not
    // constrained to this pane.
}

// ---------------------------------------------------------------------------
// Detail popup (Enter key)
// ---------------------------------------------------------------------------

pub fn draw_detail_popup(
    frame: &mut Frame<'_>,
    log: &LogLine,
    area: Rect,
    theme: &crate::theme::Theme,
) {
    let t = theme;
    // Center the popup — 80% width, up to 20 lines tall.
    let popup_width = (area.width * 4 / 5).min(area.width.saturating_sub(4));
    let popup_height = 20u16.min(area.height.saturating_sub(4));
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(" Log Detail ", t.heading))
        .borders(Borders::ALL)
        .border_style(t.accent)
        .padding(Padding::new(1, 1, 0, 0));

    let ts = format_short_time(log.timestamp_ms);

    let mut lines: Vec<Line<'_>> = vec![
        Line::from(vec![
            Span::styled("Time:    ", t.muted),
            Span::styled(ts, t.text),
        ]),
        Line::from(vec![
            Span::styled("Source:  ", t.muted),
            Span::styled(log.source.as_str(), t.text),
        ]),
        Line::from(vec![
            Span::styled("Level:   ", t.muted),
            Span::styled(log.level.as_str(), level_style(&log.level, t)),
        ]),
    ];

    if !log.target.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Target:  ", t.muted),
            Span::styled(log.target.as_str(), t.muted),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled("Message: ", t.muted),
        Span::styled(log.message.as_str(), t.text),
    ]));

    if !log.fields.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Fields:", t.muted)));

        let ordered = ordered_fields(log);
        for (k, v) in &ordered {
            if v.is_empty() {
                continue;
            }
            lines.push(Line::from(vec![
                Span::styled(format!("  {k}: "), t.muted),
                Span::styled((*v).to_string(), t.text),
            ]));
        }
    }

    // Add dismiss hint at the bottom.
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Press Esc or Enter to close",
        t.muted,
    )));

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup_area,
    );
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length((area.height.saturating_sub(height)) / 2),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area);
    let horiz = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length((area.width.saturating_sub(width)) / 2),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(vert[1]);
    horiz[1]
}

// ---------------------------------------------------------------------------
// Log line rendering (compact, truncated)
// ---------------------------------------------------------------------------

/// Render a single structured log line — no target, smart field order, truncated.
fn render_log_line<'a>(log: &'a LogLine, max_width: usize, t: &'a crate::theme::Theme) -> Line<'a> {
    let source_style = match log.source.as_str() {
        "sandbox" => t.accent,
        _ => t.muted,
    };

    let ts = format_short_time(log.timestamp_ms);

    let mut spans = vec![
        Span::styled(ts, t.muted),
        Span::raw(" "),
        Span::styled(format!("{:<7}", log.source), source_style),
        Span::raw(" "),
        Span::styled(format!("{:<5}", log.level), level_style(&log.level, t)),
        Span::raw(" "),
    ];

    // Message.
    spans.push(Span::styled(log.message.as_str(), t.text));

    // Structured fields — ordered, non-empty only.
    if !log.fields.is_empty() {
        let ordered = ordered_fields(log);
        for (k, v) in &ordered {
            if v.is_empty() {
                continue;
            }
            spans.push(Span::raw(" "));
            spans.push(Span::styled(format!("{k}="), t.muted));
            spans.push(Span::styled((*v).to_string(), t.text));
        }
    }

    // Truncate to max_width.
    truncate_line(spans, max_width, t)
}

/// Truncate a span list to fit within `max_width` characters, appending `…` if needed.
fn truncate_line<'a>(
    spans: Vec<Span<'a>>,
    max_width: usize,
    t: &'a crate::theme::Theme,
) -> Line<'a> {
    if max_width == 0 {
        return Line::from(spans);
    }

    let mut used = 0usize;
    let mut out: Vec<Span<'_>> = Vec::with_capacity(spans.len());

    for span in spans {
        let content_len = span.content.len();
        if used + content_len <= max_width {
            out.push(span);
            used += content_len;
        } else {
            // Partial fit — take what we can and append ellipsis.
            let remaining = max_width.saturating_sub(used);
            if remaining > 1 {
                // Find a safe UTF-8 boundary.
                let truncated = safe_truncate(&span.content, remaining - 1);
                let mut s = truncated.to_string();
                s.push('…');
                out.push(Span::styled(s, span.style));
            } else if remaining == 1 {
                out.push(Span::styled("…", t.muted));
            }
            break;
        }
    }

    Line::from(out)
}

/// Truncate a string to at most `max_bytes` bytes on a valid UTF-8 char boundary.
fn safe_truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ---------------------------------------------------------------------------
// Field ordering
// ---------------------------------------------------------------------------

/// Priority field order for CONNECT log lines.
const CONNECT_FIELD_ORDER: &[&str] = &[
    "action",
    "dst_host",
    "dst_port",
    "policy",
    "engine",
    "src_addr",
    "src_port",
    // Trailing process ancestry fields
    "binary",
    "binary_pid",
    "cmdline",
    "ancestors",
    "proxy_addr",
    "reason",
];

/// Priority field order for L7_REQUEST log lines.
const L7_FIELD_ORDER: &[&str] = &[
    "l7_action",
    "l7_target",
    "l7_decision",
    "dst_host",
    "dst_port",
    "l7_protocol",
    "policy",
    "l7_deny_reason",
];

/// Return fields in a smart order based on the log message type.
pub(crate) fn ordered_fields<'a>(log: &'a LogLine) -> Vec<(&'a str, &'a str)> {
    // Matches both "CONNECT" (L4-only decision) and "CONNECT_L7" (tunnel lifecycle for L7 endpoints)
    let order: Option<&[&str]> = if log.message.starts_with("CONNECT") {
        Some(CONNECT_FIELD_ORDER)
    } else if log.message.starts_with("L7_REQUEST") {
        Some(L7_FIELD_ORDER)
    } else {
        None
    };

    match order {
        Some(priority) => {
            let mut result: Vec<(&str, &str)> = Vec::with_capacity(log.fields.len());
            // Add priority fields first (in order).
            for &key in priority {
                if let Some(val) = log.fields.get(key) {
                    result.push((key, val.as_str()));
                }
            }
            // Add remaining fields alphabetically.
            let mut remaining: Vec<(&str, &str)> = log
                .fields
                .iter()
                .filter(|(k, _)| !priority.contains(&k.as_str()))
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            remaining.sort_by_key(|(k, _)| *k);
            result.extend(remaining);
            result
        }
        None => {
            // Default: alphabetical.
            let mut pairs: Vec<(&str, &str)> = log
                .fields
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            pairs.sort_by_key(|(k, _)| *k);
            pairs
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn level_style(level: &str, t: &crate::theme::Theme) -> ratatui::style::Style {
    match level {
        "ERROR" => t.status_err,
        "WARN" => t.status_warn,
        "INFO" => t.status_ok,
        _ => t.muted,
    }
}

pub(crate) fn format_short_time(epoch_ms: i64) -> String {
    if epoch_ms <= 0 {
        return String::from("--:--:--");
    }
    let secs = epoch_ms / 1000;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

/// Format a log line as plain text for clipboard copy.
///
/// Produces the same layout as `render_log_line()` but without styles or
/// truncation: `HH:MM:SS {source:<7} {level:<5} {message} [key=value ...]`
pub(crate) fn format_log_line_plain(log: &LogLine) -> String {
    let ts = format_short_time(log.timestamp_ms);
    let mut s = format!("{ts} {:<7} {:<5} {}", log.source, log.level, log.message);

    if !log.fields.is_empty() {
        let ordered = ordered_fields(log);
        for (k, v) in &ordered {
            if !v.is_empty() {
                s.push(' ');
                s.push_str(k);
                s.push('=');
                s.push_str(v);
            }
        }
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_log(message: &str, fields: Vec<(&str, &str)>) -> LogLine {
        LogLine {
            timestamp_ms: 1_700_000_000_000, // 2023-11-14 22:13:20 UTC
            level: "INFO".to_string(),
            source: "sandbox".to_string(),
            target: "test".to_string(),
            message: message.to_string(),
            fields: fields
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn plain_format_basic_line() {
        let log = make_log("hello world", vec![]);
        let result = format_log_line_plain(&log);
        assert!(result.starts_with("22:13:20 sandbox INFO  hello world"));
        assert!(!result.contains('='));
    }

    #[test]
    fn plain_format_with_fields() {
        let log = make_log(
            "CONNECT",
            vec![("dst_host", "example.com"), ("dst_port", "443")],
        );
        let result = format_log_line_plain(&log);
        assert!(result.contains("dst_host=example.com"));
        assert!(result.contains("dst_port=443"));
    }

    #[test]
    fn plain_format_skips_empty_fields() {
        let log = make_log("test", vec![("key1", "val"), ("key2", "")]);
        let result = format_log_line_plain(&log);
        assert!(result.contains("key1=val"));
        assert!(!result.contains("key2="));
    }

    #[test]
    fn plain_format_zero_timestamp() {
        let log = LogLine {
            timestamp_ms: 0,
            level: "ERROR".to_string(),
            source: "gateway".to_string(),
            target: String::new(),
            message: "fail".to_string(),
            fields: HashMap::new(),
        };
        let result = format_log_line_plain(&log);
        assert!(result.starts_with("--:--:-- gateway ERROR fail"));
    }

    #[test]
    fn plain_format_connect_field_order() {
        let log = make_log(
            "CONNECT",
            vec![
                ("binary", "/usr/bin/curl"),
                ("action", "allow"),
                ("dst_host", "example.com"),
            ],
        );
        let result = format_log_line_plain(&log);
        // "action" should appear before "dst_host" which should appear before "binary"
        let action_pos = result.find("action=").unwrap();
        let dst_pos = result.find("dst_host=").unwrap();
        let binary_pos = result.find("binary=").unwrap();
        assert!(action_pos < dst_pos);
        assert!(dst_pos < binary_pos);
    }

    #[test]
    fn plain_format_connect_l7_field_order() {
        let log = make_log(
            "CONNECT_L7",
            vec![
                ("binary", "/usr/bin/curl"),
                ("action", "allow"),
                ("dst_host", "api.example.com"),
            ],
        );
        let result = format_log_line_plain(&log);
        // CONNECT_L7 should use the same field ordering as CONNECT
        let action_pos = result.find("action=").unwrap();
        let dst_pos = result.find("dst_host=").unwrap();
        let binary_pos = result.find("binary=").unwrap();
        assert!(action_pos < dst_pos);
        assert!(dst_pos < binary_pos);
    }

    #[test]
    fn plain_format_l7_field_order() {
        let log = make_log(
            "L7_REQUEST",
            vec![
                ("policy", "default"),
                ("l7_action", "allow"),
                ("l7_target", "/api"),
            ],
        );
        let result = format_log_line_plain(&log);
        let action_pos = result.find("l7_action=").unwrap();
        let target_pos = result.find("l7_target=").unwrap();
        let policy_pos = result.find("policy=").unwrap();
        assert!(action_pos < target_pos);
        assert!(target_pos < policy_pos);
    }

    #[test]
    fn plain_format_alphabetical_fields_for_unknown_message() {
        let log = make_log("SOMETHING", vec![("zebra", "z"), ("alpha", "a")]);
        let result = format_log_line_plain(&log);
        let alpha_pos = result.find("alpha=").unwrap();
        let zebra_pos = result.find("zebra=").unwrap();
        assert!(alpha_pos < zebra_pos);
    }
}
