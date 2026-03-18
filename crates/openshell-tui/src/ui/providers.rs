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
        Cell::from(Span::styled("TYPE", t.muted)),
        Cell::from(Span::styled("CRED KEY", t.muted)),
    ])
    .bottom_margin(1);

    let rows: Vec<Row<'_>> = (0..app.provider_count)
        .map(|i| {
            let name = app.provider_names.get(i).map_or("", String::as_str);
            let ptype = app.provider_types.get(i).map_or("", String::as_str);
            let cred_key = app.provider_cred_keys.get(i).map_or("", String::as_str);

            let selected = focused && i == app.provider_selected;
            let name_cell = if selected {
                Cell::from(Line::from(vec![
                    Span::styled("> ", t.accent),
                    Span::styled(name, t.text),
                ]))
            } else {
                Cell::from(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(name, t.text),
                ]))
            };

            Row::new(vec![
                name_cell,
                Cell::from(Span::styled(ptype, t.muted)),
                Cell::from(Span::styled(cred_key, t.muted)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(40),
        Constraint::Percentage(25),
        Constraint::Percentage(35),
    ];

    let border_style = if focused { t.border_focused } else { t.border };

    // Show delete confirmation in the title area if active.
    let title = if focused && app.confirm_provider_delete {
        let name = app
            .provider_names
            .get(app.provider_selected)
            .map_or("-", String::as_str);
        Line::from(vec![
            Span::styled(" Delete '", t.status_err),
            Span::styled(name, t.status_err),
            Span::styled("'? [y/n] ", t.status_err),
        ])
    } else {
        super::global_settings::draw_tab_title(app, focused)
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style)
        .padding(Padding::horizontal(1));

    let table = Table::new(rows, widths).header(header).block(block);

    frame.render_widget(table, area);

    if app.provider_count == 0 {
        let inner = Rect {
            x: area.x + 2,
            y: area.y + 2,
            width: area.width.saturating_sub(4),
            height: area.height.saturating_sub(3),
        };
        let msg = Paragraph::new(Span::styled(" No providers. Press [c] to create.", t.muted));
        frame.render_widget(msg, inner);
    }
}
