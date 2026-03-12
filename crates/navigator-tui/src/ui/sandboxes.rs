// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Padding, Paragraph, Row, Table};

use crate::app::App;

pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect, focused: bool) {
    let t = &app.theme;
    let header = Row::new(vec![
        Cell::from(Span::styled("  NAME", t.muted)),
        Cell::from(Span::styled("STATUS", t.muted)),
        Cell::from(Span::styled("CREATED", t.muted)),
        Cell::from(Span::styled("AGE", t.muted)),
        Cell::from(Span::styled("IMAGE", t.muted)),
        Cell::from(Span::styled("NOTES", t.muted)),
    ])
    .bottom_margin(1);

    let rows: Vec<Row<'_>> = (0..app.sandbox_count)
        .map(|i| {
            let name = app.sandbox_names.get(i).map_or("", String::as_str);
            let phase = app.sandbox_phases.get(i).map_or("", String::as_str);
            let created = app.sandbox_created.get(i).map_or("", String::as_str);
            let age = app.sandbox_ages.get(i).map_or("", String::as_str);
            let image = app.sandbox_images.get(i).map_or("", String::as_str);
            let notes = app.sandbox_notes.get(i).map_or("", String::as_str);
            let draft_count = app.sandbox_draft_counts.get(i).copied().unwrap_or(0);

            let phase_style = match phase {
                "Ready" => t.status_ok,
                "Provisioning" => t.status_warn,
                "Error" => t.status_err,
                _ => t.muted,
            };

            let selected = focused && i == app.sandbox_selected;
            let mut name_spans = if selected {
                vec![Span::styled("▌ ", t.accent), Span::styled(name, t.text)]
            } else {
                vec![Span::raw("  "), Span::styled(name, t.text)]
            };

            // Append notification badge when there are pending network rules.
            if draft_count > 0 {
                name_spans.push(Span::raw(" "));
                name_spans.push(Span::styled(
                    format!(
                        " {draft_count} pending rule{} ",
                        if draft_count == 1 { "" } else { "s" }
                    ),
                    t.badge,
                ));
            }

            let name_cell = Cell::from(Line::from(name_spans));

            Row::new(vec![
                name_cell,
                Cell::from(Span::styled(phase, phase_style)),
                Cell::from(Span::styled(created, t.muted)),
                Cell::from(Span::styled(age, t.muted)),
                Cell::from(Span::styled(image, t.muted)),
                Cell::from(Span::styled(notes, t.muted)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(20),
        Constraint::Percentage(10),
        Constraint::Percentage(15),
        Constraint::Percentage(8),
        Constraint::Percentage(27),
        Constraint::Percentage(20),
    ];

    let border_style = if focused { t.border_focused } else { t.border };

    let title = Line::from(vec![
        Span::styled(" Sandboxes ", t.heading),
        Span::styled("─ ", t.border),
        Span::styled(&app.gateway_name, t.muted),
        Span::styled(" ", t.muted),
    ]);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style)
        .padding(Padding::horizontal(1));

    let table = Table::new(rows, widths).header(header).block(block);

    frame.render_widget(table, area);

    if app.sandbox_count == 0 {
        let inner = Rect {
            x: area.x + 2,
            y: area.y + 2,
            width: area.width.saturating_sub(4),
            height: area.height.saturating_sub(3),
        };
        let msg = Paragraph::new(Span::styled(" No sandboxes. Press [c] to create.", t.muted));
        frame.render_widget(msg, inner);
    }
}
