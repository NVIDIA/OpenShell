// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Padding, Paragraph, Row, Table};

use crate::app::{App, Focus, MiddlePaneTab};

pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(50),
        ])
        .split(area);

    draw_gateway_list(frame, app, chunks[0]);

    let mid_focused = app.focus == Focus::Providers;
    match app.middle_pane_tab {
        MiddlePaneTab::Providers => {
            super::providers::draw(frame, app, chunks[1], mid_focused);
        }
        MiddlePaneTab::GlobalSettings => {
            super::global_settings::draw(frame, app, chunks[1], mid_focused);
        }
    }

    super::sandboxes::draw(frame, app, chunks[2], app.focus == Focus::Sandboxes);
}

fn draw_gateway_list(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let t = &app.theme;
    let focused = app.focus == Focus::Gateways;

    let header = Row::new(vec![
        Cell::from(Span::styled("  NAME", t.muted)),
        Cell::from(Span::styled("TYPE", t.muted)),
        Cell::from(Span::styled("STATUS", t.muted)),
        Cell::from(Span::styled("", t.muted)),
    ])
    .bottom_margin(1);

    let rows: Vec<Row<'_>> = app
        .gateways
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let is_active = entry.name == app.gateway_name;
            let is_cursor = focused && i == app.gateway_selected;

            let cursor = if is_cursor { ">" } else { " " };
            let dot = if is_active { "* " } else { "  " };
            let dot_style = if is_active { t.status_ok } else { t.muted };
            let name_style = if is_active { t.heading } else { t.text };
            let name_cell = Cell::from(Line::from(vec![
                Span::styled(cursor, t.accent),
                Span::styled(dot, dot_style),
                Span::styled(&entry.name, name_style),
            ]));

            let type_label = if entry.is_remote { "remote" } else { "local" };

            let status_cell = if is_active {
                let status_style = if app.status_text.contains("Healthy") {
                    t.status_ok
                } else if app.status_text.contains("Degraded") {
                    t.status_warn
                } else if app.status_text.contains("Unhealthy") {
                    t.status_err
                } else {
                    t.muted
                };
                Cell::from(Span::styled(&app.status_text, status_style))
            } else {
                Cell::from(Span::styled("-", t.muted))
            };

            let policy_cell = if is_active && app.global_policy_active {
                Cell::from(Span::styled(
                    format!("Global Policy Active (v{})", app.global_policy_version),
                    t.status_warn,
                ))
            } else {
                Cell::from(Span::raw(""))
            };

            Row::new(vec![
                name_cell,
                Cell::from(Span::styled(type_label, t.muted)),
                status_cell,
                policy_cell,
            ])
        })
        .collect();

    let border_style = if focused { t.border_focused } else { t.border };

    let block = Block::default()
        .title(Span::styled(" Gateways ", t.heading))
        .borders(Borders::ALL)
        .border_style(border_style)
        .padding(Padding::horizontal(1));

    let widths = [
        Constraint::Percentage(30),
        Constraint::Percentage(10),
        Constraint::Percentage(25),
        Constraint::Percentage(35),
    ];

    let table = Table::new(rows, widths).header(header).block(block);

    frame.render_widget(table, area);

    if app.gateways.is_empty() {
        let inner = Rect {
            x: area.x + 2,
            y: area.y + 2,
            width: area.width.saturating_sub(4),
            height: area.height.saturating_sub(3),
        };
        let msg = Paragraph::new(Span::styled(" No gateways found.", t.muted));
        frame.render_widget(msg, inner);
    }
}
