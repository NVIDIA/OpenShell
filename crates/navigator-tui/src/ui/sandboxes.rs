// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Padding, Paragraph, Row, Table};

use crate::app::App;
use crate::theme::styles;

pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect, focused: bool) {
    let header = Row::new(vec![
        Cell::from(Span::styled("  NAME", styles::MUTED)),
        Cell::from(Span::styled("STATUS", styles::MUTED)),
        Cell::from(Span::styled("CREATED", styles::MUTED)),
        Cell::from(Span::styled("AGE", styles::MUTED)),
        Cell::from(Span::styled("IMAGE", styles::MUTED)),
    ])
    .bottom_margin(1);

    let rows: Vec<Row<'_>> = (0..app.sandbox_count)
        .map(|i| {
            let name = app.sandbox_names.get(i).map_or("", String::as_str);
            let phase = app.sandbox_phases.get(i).map_or("", String::as_str);
            let created = app.sandbox_created.get(i).map_or("", String::as_str);
            let age = app.sandbox_ages.get(i).map_or("", String::as_str);
            let image = app.sandbox_images.get(i).map_or("", String::as_str);

            let phase_style = match phase {
                "Ready" => styles::STATUS_OK,
                "Provisioning" => styles::STATUS_WARN,
                "Error" => styles::STATUS_ERR,
                _ => styles::MUTED,
            };

            let selected = focused && i == app.sandbox_selected;
            let name_cell = if selected {
                Cell::from(Line::from(vec![
                    Span::styled("▌ ", styles::ACCENT),
                    Span::styled(name, styles::TEXT),
                ]))
            } else {
                Cell::from(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(name, styles::TEXT),
                ]))
            };

            Row::new(vec![
                name_cell,
                Cell::from(Span::styled(phase, phase_style)),
                Cell::from(Span::styled(created, styles::MUTED)),
                Cell::from(Span::styled(age, styles::MUTED)),
                Cell::from(Span::styled(image, styles::MUTED)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(22),
        Constraint::Percentage(12),
        Constraint::Percentage(18),
        Constraint::Percentage(10),
        Constraint::Percentage(38),
    ];

    let border_style = if focused {
        styles::BORDER_FOCUSED
    } else {
        styles::BORDER
    };

    let title = Line::from(vec![
        Span::styled(" Sandboxes ", styles::HEADING),
        Span::styled("─ ", styles::BORDER),
        Span::styled(&app.cluster_name, styles::MUTED),
        Span::styled(" ", styles::MUTED),
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
        let msg = Paragraph::new(Span::styled(
            " No sandboxes. Press [c] to create.",
            styles::MUTED,
        ));
        frame.render_widget(msg, inner);
    }
}
