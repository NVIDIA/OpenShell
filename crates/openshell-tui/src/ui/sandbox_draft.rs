// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network rules panel for the sandbox screen.

use crate::app::App;
use openshell_core::proto::PolicyChunk;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};

/// Draw the network rules panel (list view with highlight bar).
pub fn draw(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let t = &app.theme;
    let pending_count = app
        .draft_chunks
        .iter()
        .filter(|c| c.status == "pending")
        .count();

    let title = if pending_count > 0 {
        Line::from(vec![
            Span::styled(" Network Rules ", t.heading),
            Span::styled(format!(" {pending_count} pending "), t.badge),
            Span::raw(" "),
        ])
    } else {
        Line::from(Span::styled(" Network Rules ", t.heading))
    };

    let mut block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(t.border_focused)
        .padding(Padding::horizontal(1));

    if app.sandbox_policy_is_global {
        block = block.title_bottom(
            Line::from(Span::styled(
                " Cannot approve rules while global policy is active ",
                t.status_warn,
            ))
            .left_aligned(),
        );
    }

    if app.draft_chunks.is_empty() {
        let msg = Paragraph::new(
            "No network rules yet. Denied connections will \
             generate rules automatically.",
        )
        .block(block)
        .style(t.muted);
        frame.render_widget(msg, area);
        return;
    }

    // Calculate visible area inside the block (borders + padding).
    let inner_height = area.height.saturating_sub(2) as usize;
    app.draft_viewport_height = inner_height;

    // Clamp cursor to visible range.
    let total = app.draft_chunks.len();
    let visible_count = total.saturating_sub(app.draft_scroll).min(inner_height);
    if visible_count > 0 {
        app.draft_selected = app.draft_selected.min(visible_count - 1);
    }

    let cursor_pos = app.draft_selected;

    let lines: Vec<Line<'_>> = app
        .draft_chunks
        .iter()
        .skip(app.draft_scroll)
        .take(inner_height)
        .enumerate()
        .map(|(i, chunk)| {
            let is_selected = i == cursor_pos;

            let globally_locked = app.sandbox_policy_is_global;

            let status_style = if globally_locked {
                t.muted
            } else {
                match chunk.status.as_str() {
                    "pending" => t.status_warn,
                    "approved" => t.status_ok,
                    "rejected" => t.status_err,
                    _ => t.muted,
                }
            };

            let name_style = if globally_locked {
                t.muted
            } else if is_selected {
                t.selected
            } else if chunk.status == "rejected" {
                t.muted
            } else {
                t.text
            };

            let mut spans = Vec::new();

            // Highlight bar prefix (like logs).
            if is_selected {
                spans.push(Span::styled("▌ ", t.accent));
            } else {
                spans.push(Span::raw("  "));
            }

            // Endpoint summary (host:port).
            let endpoint_str = chunk
                .proposed_rule
                .as_ref()
                .and_then(|r| r.endpoints.first())
                .map(|ep| format!("{}:{}", ep.host, ep.port))
                .unwrap_or_default();

            spans.push(Span::styled(&chunk.rule_name, name_style));
            if !endpoint_str.is_empty() {
                spans.push(Span::styled("  ", t.muted));
                spans.push(Span::styled(endpoint_str, t.accent));
            }
            // Show binary name (just the filename, not full path) if present.
            if !chunk.binary.is_empty() {
                let bin_short = chunk.binary.rsplit('/').next().unwrap_or(&chunk.binary);
                spans.push(Span::styled("  ", t.muted));
                spans.push(Span::styled(format!("({bin_short})"), t.muted));
            }
            spans.push(Span::raw("  "));
            spans.push(Span::styled(format!("[{}]", chunk.status), status_style));
            spans.push(Span::styled(
                format!("  {:.0}%", chunk.confidence * 100.0),
                t.muted,
            ));
            if chunk.hit_count > 1 {
                spans.push(Span::styled(format!("  {}x", chunk.hit_count), t.accent));
            }

            let mut line = Line::from(spans);
            if is_selected {
                line = line.style(t.log_cursor);
            }
            line
        })
        .collect();

    // Scroll position indicator.
    let pos = app.draft_scroll + cursor_pos + 1;
    let scroll_info = format!(" [{pos}/{total}] ");

    let block = block.title_bottom(Line::from(vec![Span::styled(scroll_info, t.muted)]));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

// ---------------------------------------------------------------------------
// Detail popup (Enter key)
// ---------------------------------------------------------------------------

pub fn draw_detail_popup(
    frame: &mut Frame<'_>,
    chunk: &PolicyChunk,
    area: Rect,
    theme: &crate::theme::Theme,
) {
    let t = theme;
    let popup_width = (area.width * 4 / 5).min(area.width.saturating_sub(4));
    let popup_height = 22u16.min(area.height.saturating_sub(4));
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let status_style = match chunk.status.as_str() {
        "pending" => t.status_warn.add_modifier(Modifier::BOLD),
        "approved" => t.status_ok.add_modifier(Modifier::BOLD),
        "rejected" => t.status_err.add_modifier(Modifier::BOLD),
        _ => t.muted,
    };

    let block = Block::default()
        .title(Span::styled(format!(" {} ", chunk.rule_name), t.heading))
        .borders(Borders::ALL)
        .border_style(t.accent)
        .padding(Padding::new(1, 1, 0, 0));

    let mut lines: Vec<Line<'_>> = vec![
        Line::from(vec![
            Span::styled("Status:     ", t.muted),
            Span::styled(&chunk.status, status_style),
        ]),
        Line::from(vec![
            Span::styled("Confidence: ", t.muted),
            Span::styled(format!("{:.0}%", chunk.confidence * 100.0), t.text),
        ]),
    ];

    // Binary (denormalized from the denial).
    if !chunk.binary.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Binary:     ", t.muted),
            Span::styled(&chunk.binary, t.text),
        ]));
    }

    // Hit count (accumulated real denial count) and first/last seen.
    lines.push(Line::from(vec![
        Span::styled("Denied:     ", t.muted),
        Span::styled(
            format!(
                "{} connection{}",
                chunk.hit_count,
                if chunk.hit_count == 1 { "" } else { "s" }
            ),
            t.accent,
        ),
        Span::styled(
            format!(
                "  (first {} / last {})",
                format_short_time(chunk.first_seen_ms),
                format_short_time(chunk.last_seen_ms),
            ),
            t.muted,
        ),
    ]));

    // Endpoints.
    if let Some(ref rule) = chunk.proposed_rule {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Endpoints:", t.muted)));
        for ep in &rule.endpoints {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("-> ", t.muted),
                Span::styled(format!("{}:{}", ep.host, ep.port), t.accent),
            ]));
        }

        // Binaries.
        if !rule.binaries.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Binaries:", t.muted)));
            for b in &rule.binaries {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(&b.path, t.text),
                ]));
            }
        }
    }

    // Rationale.
    if !chunk.rationale.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Rationale:  ", t.muted),
            Span::styled(&chunk.rationale, t.text),
        ]));
    }

    // Security notes.
    if !chunk.security_notes.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            format!("! {}", chunk.security_notes),
            t.status_warn.add_modifier(Modifier::BOLD),
        )]));
    }

    // Action hints — state-aware toggle keys.
    lines.push(Line::from(""));
    let mut hint_spans: Vec<Span<'_>> = Vec::new();
    match chunk.status.as_str() {
        "pending" => {
            hint_spans.extend([
                Span::styled("[a]", t.key_hint),
                Span::styled(" Approve  ", t.text),
                Span::styled("[x]", t.key_hint),
                Span::styled(" Reject  ", t.text),
            ]);
        }
        "approved" => {
            hint_spans.extend([
                Span::styled("[x]", t.key_hint),
                Span::styled(" Revoke  ", t.text),
            ]);
        }
        "rejected" => {
            hint_spans.extend([
                Span::styled("[a]", t.key_hint),
                Span::styled(" Approve  ", t.text),
            ]);
        }
        _ => {}
    }
    hint_spans.extend([
        Span::styled("[Esc]", t.muted),
        Span::styled(" Close", t.muted),
    ]);
    lines.push(Line::from(hint_spans));

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup_area,
    );
}

// ---------------------------------------------------------------------------
// Approve-all confirmation popup ([A] key)
// ---------------------------------------------------------------------------

pub fn draw_approve_all_popup(
    frame: &mut Frame<'_>,
    chunks: &[PolicyChunk],
    area: Rect,
    theme: &crate::theme::Theme,
) {
    let t = theme;
    let count = chunks.len();
    // Height: header(1) + blank(1) + chunks(count, capped at 12) + blank(1) + hints(1) + borders(2) + padding(1)
    let list_lines = count.min(12);
    let popup_height = (7 + list_lines) as u16;
    let popup_height = popup_height.min(area.height.saturating_sub(4));
    let popup_width = (area.width * 4 / 5).min(area.width.saturating_sub(4));
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(
            " Approve All ",
            t.status_warn.add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(t.accent)
        .padding(Padding::new(1, 1, 0, 0));

    // Usable width inside borders + padding.
    let inner_width = popup_width.saturating_sub(4) as usize;

    let mut lines: Vec<Line<'_>> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("Approve ", t.text),
        Span::styled(
            format!("{count}"),
            t.status_warn.add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                " pending policy request{}?",
                if count == 1 { "" } else { "s" }
            ),
            t.text,
        ),
    ]));
    lines.push(Line::from(""));

    for (i, chunk) in chunks.iter().enumerate() {
        if i >= 12 {
            lines.push(Line::from(Span::styled(
                format!("  ... and {} more", count - 12),
                t.muted,
            )));
            break;
        }
        let endpoint_str = chunk
            .proposed_rule
            .as_ref()
            .and_then(|r| r.endpoints.first())
            .map(|ep| format!("{}:{}", ep.host, ep.port))
            .unwrap_or_default();

        // Truncate to fit within the popup width.
        // "  -> " (5) + rule_name + "  " (2) + endpoint
        let prefix_len = 5;
        let sep_len = 2;
        let budget = inner_width.saturating_sub(prefix_len + sep_len);
        let (name_str, ep_str) = if chunk.rule_name.len() + endpoint_str.len() > budget {
            let ep_budget = endpoint_str.len().min(budget / 2);
            let name_budget = budget.saturating_sub(ep_budget);
            (
                truncate_str(&chunk.rule_name, name_budget),
                truncate_str(&endpoint_str, ep_budget),
            )
        } else {
            (chunk.rule_name.clone(), endpoint_str)
        };

        let mut row_spans = vec![
            Span::styled("  -> ", t.muted),
            Span::styled(name_str, t.text),
            Span::styled("  ", t.muted),
            Span::styled(ep_str, t.accent),
        ];
        if !chunk.binary.is_empty() {
            let bin_short = chunk.binary.rsplit('/').next().unwrap_or(&chunk.binary);
            row_spans.push(Span::styled("  ", t.muted));
            row_spans.push(Span::styled(format!("({bin_short})"), t.muted));
        }
        lines.push(Line::from(row_spans));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("[y/Enter]", t.key_hint),
        Span::styled(" Approve all  ", t.text),
        Span::styled("[n/Esc]", t.key_hint),
        Span::styled(" Cancel", t.text),
    ]));

    frame.render_widget(Paragraph::new(lines).block(block), popup_area);
}

/// Truncate a string to `max_len` chars, appending "..." if truncated.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s.chars().take(max_len).collect()
    } else {
        let mut out: String = s.chars().take(max_len - 3).collect();
        out.push_str("...");
        out
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
