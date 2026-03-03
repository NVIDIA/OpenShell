// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};

use crate::app::{App, LogLine};
use crate::theme::styles;

pub fn draw(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let name = app
        .sandbox_names
        .get(app.sandbox_selected)
        .map_or("-", String::as_str);

    let filter_label = app.log_source_filter.label();

    let block = Block::default()
        .title(Span::styled(format!(" Logs: {name} "), styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::BORDER_FOCUSED)
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
        let lines = vec![Line::from(Span::styled("Loading...", styles::MUTED))];
        let block = block.title_bottom(Line::from(Span::styled(
            format!(" filter: {filter_label} "),
            styles::MUTED,
        )));
        frame.render_widget(Paragraph::new(lines).block(block), area);
        return;
    }

    let lines: Vec<Line<'_>> = filtered
        .iter()
        .skip(app.sandbox_log_scroll)
        .take(inner_height)
        .enumerate()
        .map(|(i, log)| {
            let mut line = render_log_line(log, inner_width.saturating_sub(2));
            if i == cursor_pos {
                // Prepend green cursor marker and apply highlight background.
                line.spans.insert(0, Span::styled("▌ ", styles::ACCENT));
                line = line.style(styles::LOG_CURSOR);
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

    let autoscroll_span = if app.log_autoscroll {
        Span::styled(" ● FOLLOWING ", styles::STATUS_OK)
    } else {
        Span::styled(" ○ PAUSED ", styles::STATUS_WARN)
    };

    let block = block.title_bottom(Line::from(vec![
        autoscroll_span,
        Span::styled(scroll_info, styles::MUTED),
        Span::styled(format!(" filter: {filter_label} "), styles::MUTED),
    ]));

    frame.render_widget(Paragraph::new(lines).block(block), area);

    // NOTE: Detail popup overlay is now rendered by draw_sandbox_screen() in
    // mod.rs using frame.size() so it renders over the full screen, not
    // constrained to this pane.
}

// ---------------------------------------------------------------------------
// Detail popup (Enter key)
// ---------------------------------------------------------------------------

pub fn draw_detail_popup(frame: &mut Frame<'_>, log: &LogLine, area: Rect) {
    // Center the popup — 80% width, up to 20 lines tall.
    let popup_width = (area.width * 4 / 5).min(area.width.saturating_sub(4));
    let popup_height = 20u16.min(area.height.saturating_sub(4));
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(" Log Detail ", styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::ACCENT)
        .padding(Padding::new(1, 1, 0, 0));

    let ts = format_short_time(log.timestamp_ms);

    let mut lines: Vec<Line<'_>> = vec![
        Line::from(vec![
            Span::styled("Time:    ", styles::MUTED),
            Span::styled(ts, styles::TEXT),
        ]),
        Line::from(vec![
            Span::styled("Source:  ", styles::MUTED),
            Span::styled(log.source.as_str(), styles::TEXT),
        ]),
        Line::from(vec![
            Span::styled("Level:   ", styles::MUTED),
            Span::styled(log.level.as_str(), level_style(&log.level)),
        ]),
    ];

    if !log.target.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Target:  ", styles::MUTED),
            Span::styled(log.target.as_str(), styles::MUTED),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled("Message: ", styles::MUTED),
        Span::styled(log.message.as_str(), styles::TEXT),
    ]));

    if !log.fields.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Fields:", styles::MUTED)));

        let ordered = ordered_fields(log);
        for (k, v) in &ordered {
            if v.is_empty() {
                continue;
            }
            lines.push(Line::from(vec![
                Span::styled(format!("  {k}: "), styles::MUTED),
                Span::styled((*v).to_string(), styles::TEXT),
            ]));
        }
    }

    // Add dismiss hint at the bottom.
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Press Esc or Enter to close",
        styles::MUTED,
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
fn render_log_line<'a>(log: &'a LogLine, max_width: usize) -> Line<'a> {
    let source_style = match log.source.as_str() {
        "sandbox" => styles::ACCENT,
        _ => styles::MUTED,
    };

    let ts = format_short_time(log.timestamp_ms);

    let mut spans = vec![
        Span::styled(ts, styles::MUTED),
        Span::raw(" "),
        Span::styled(format!("{:<7}", log.source), source_style),
        Span::raw(" "),
        Span::styled(format!("{:<5}", log.level), level_style(&log.level)),
        Span::raw(" "),
    ];

    // Message.
    spans.push(Span::styled(log.message.as_str(), styles::TEXT));

    // Structured fields — ordered, non-empty only.
    if !log.fields.is_empty() {
        let ordered = ordered_fields(log);
        for (k, v) in &ordered {
            if v.is_empty() {
                continue;
            }
            spans.push(Span::raw(" "));
            spans.push(Span::styled(format!("{k}="), styles::MUTED));
            spans.push(Span::styled((*v).to_string(), styles::TEXT));
        }
    }

    // Truncate to max_width.
    truncate_line(spans, max_width)
}

/// Truncate a span list to fit within `max_width` characters, appending `…` if needed.
fn truncate_line(spans: Vec<Span<'_>>, max_width: usize) -> Line<'_> {
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
                out.push(Span::styled("…", styles::MUTED));
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
fn ordered_fields<'a>(log: &'a LogLine) -> Vec<(&'a str, &'a str)> {
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

fn level_style(level: &str) -> ratatui::style::Style {
    match level {
        "ERROR" => styles::STATUS_ERR,
        "WARN" => styles::STATUS_WARN,
        "INFO" => styles::STATUS_OK,
        _ => styles::MUTED,
    }
}

fn format_short_time(epoch_ms: i64) -> String {
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
