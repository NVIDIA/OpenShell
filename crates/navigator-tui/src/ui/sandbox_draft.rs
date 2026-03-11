// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Draft policy recommendations panel for the sandbox screen.

use crate::app::App;
use crate::theme::styles;
use navigator_core::proto::PolicyChunk;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};

/// Draw the draft recommendations panel (list view with highlight bar).
pub fn draw(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let pending_count = app
        .draft_chunks
        .iter()
        .filter(|c| c.status == "pending")
        .count();

    let title = if pending_count > 0 {
        Line::from(vec![
            Span::styled(" Draft Recommendations ", styles::HEADING),
            Span::styled(format!(" {pending_count} pending "), styles::BADGE),
            Span::raw(" "),
        ])
    } else {
        Line::from(Span::styled(" Draft Recommendations ", styles::HEADING))
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(styles::BORDER_FOCUSED)
        .padding(Padding::horizontal(1));

    if app.draft_chunks.is_empty() {
        let msg = Paragraph::new(
            "No draft recommendations yet. Denied connections will \
             generate suggestions automatically.",
        )
        .block(block)
        .style(styles::MUTED);
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

            let status_style = match chunk.status.as_str() {
                "pending" => Style::default().fg(Color::Yellow),
                "approved" => Style::default().fg(Color::Green),
                "rejected" => Style::default().fg(Color::Red),
                _ => styles::MUTED,
            };

            let name_style = if is_selected {
                styles::SELECTED
            } else {
                styles::TEXT
            };

            let mut spans = Vec::new();

            // Highlight bar prefix (like logs).
            if is_selected {
                spans.push(Span::styled("▌ ", styles::ACCENT));
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
                spans.push(Span::styled("  ", styles::MUTED));
                spans.push(Span::styled(endpoint_str, styles::ACCENT));
            }
            spans.push(Span::raw("  "));
            spans.push(Span::styled(format!("[{}]", chunk.status), status_style));
            spans.push(Span::styled(
                format!("  {:.0}%", chunk.confidence * 100.0),
                styles::MUTED,
            ));

            let mut line = Line::from(spans);
            if is_selected {
                line = line.style(styles::LOG_CURSOR);
            }
            line
        })
        .collect();

    // Scroll position indicator.
    let pos = app.draft_scroll + cursor_pos + 1;
    let scroll_info = format!(" [{pos}/{total}] ");

    let block = block.title_bottom(Line::from(vec![Span::styled(scroll_info, styles::MUTED)]));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

// ---------------------------------------------------------------------------
// Detail popup (Enter key)
// ---------------------------------------------------------------------------

pub fn draw_detail_popup(frame: &mut Frame<'_>, chunk: &PolicyChunk, area: Rect) {
    let popup_width = (area.width * 4 / 5).min(area.width.saturating_sub(4));
    let popup_height = 22u16.min(area.height.saturating_sub(4));
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let status_style = match chunk.status.as_str() {
        "pending" => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        "approved" => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        "rejected" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        _ => styles::MUTED,
    };

    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", chunk.rule_name),
            styles::HEADING,
        ))
        .borders(Borders::ALL)
        .border_style(styles::ACCENT)
        .padding(Padding::new(1, 1, 0, 0));

    let mut lines: Vec<Line<'_>> = vec![
        Line::from(vec![
            Span::styled("Status:     ", styles::MUTED),
            Span::styled(&chunk.status, status_style),
        ]),
        Line::from(vec![
            Span::styled("Confidence: ", styles::MUTED),
            Span::styled(format!("{:.0}%", chunk.confidence * 100.0), styles::TEXT),
        ]),
        Line::from(vec![
            Span::styled("Stage:      ", styles::MUTED),
            Span::styled(&chunk.stage, styles::TEXT),
        ]),
    ];

    // Endpoints.
    if let Some(ref rule) = chunk.proposed_rule {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Endpoints:", styles::MUTED)));
        for ep in &rule.endpoints {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("-> ", styles::MUTED),
                Span::styled(format!("{}:{}", ep.host, ep.port), styles::ACCENT),
            ]));
        }

        // Binaries.
        if !rule.binaries.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Binaries:", styles::MUTED)));
            for b in &rule.binaries {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(&b.path, styles::TEXT),
                ]));
            }
        }
    }

    // Rationale.
    if !chunk.rationale.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Rationale:  ", styles::MUTED),
            Span::styled(&chunk.rationale, styles::TEXT),
        ]));
    }

    // Security notes.
    if !chunk.security_notes.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            format!("! {}", chunk.security_notes),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]));
    }

    // Action hints.
    lines.push(Line::from(""));
    if chunk.status == "pending" {
        lines.push(Line::from(vec![
            Span::styled("[a]", styles::KEY_HINT),
            Span::styled(" Approve  ", styles::TEXT),
            Span::styled("[x]", styles::KEY_HINT),
            Span::styled(" Reject  ", styles::TEXT),
            Span::styled("[Esc]", styles::MUTED),
            Span::styled(" Close", styles::MUTED),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "Press Esc or Enter to close",
            styles::MUTED,
        )));
    }

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
