// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Draft policy recommendations panel for the sandbox screen.

use crate::app::App;
use crate::theme::styles;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

/// Draw the draft recommendations panel.
pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Draft Recommendations ")
        .borders(Borders::ALL)
        .border_style(styles::BORDER_FOCUSED);

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

    let mut lines: Vec<Line<'_>> = Vec::new();

    for (i, chunk) in app.draft_chunks.iter().enumerate() {
        let is_selected = i == app.draft_selected;
        let prefix = if is_selected { "▸ " } else { "  " };

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

        // Rule name + status line.
        lines.push(Line::from(vec![
            Span::raw(prefix),
            Span::styled(&chunk.rule_name, name_style),
            Span::raw("  "),
            Span::styled(format!("[{}]", chunk.status), status_style),
            Span::styled(format!("  {:.0}%", chunk.confidence * 100.0), styles::MUTED),
        ]));

        // Endpoints (if selected, show more detail).
        if is_selected {
            if let Some(ref rule) = chunk.proposed_rule {
                for ep in &rule.endpoints {
                    lines.push(Line::from(vec![
                        Span::raw("    "),
                        Span::styled("→ ", styles::MUTED),
                        Span::styled(format!("{}:{}", ep.host, ep.port), styles::ACCENT),
                    ]));
                }
            }

            // Rationale.
            if !chunk.rationale.is_empty() {
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(&chunk.rationale, styles::MUTED),
                ]));
            }

            // Security notes.
            if !chunk.security_notes.is_empty() {
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(
                        format!("⚠ {}", chunk.security_notes),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
            }
        }
    }

    let content = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: true })
        .scroll((u16::try_from(app.draft_scroll).unwrap_or(u16::MAX), 0));

    frame.render_widget(content, area);
}
