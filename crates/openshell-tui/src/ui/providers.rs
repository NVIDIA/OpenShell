// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Padding, Row, Table};

use crate::app::App;

pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect, focused: bool) {
    let t = &app.theme;
    if app.providers_v2_enabled {
        draw_v2(frame, app, area, focused);
        return;
    }

    let show_ws = app.all_workspaces;

    let mut header_cells = Vec::new();
    if show_ws {
        header_cells.push(Cell::from(Span::styled("WORKSPACE", t.muted)));
    }
    header_cells.extend([
        Cell::from(Span::styled("  NAME", t.muted)),
        Cell::from(Span::styled("TYPE", t.muted)),
        Cell::from(Span::styled("CRED KEY", t.muted)),
    ]);
    let header = Row::new(header_cells).bottom_margin(1);

    let rows: Vec<Row<'_>> = (0..app.provider_count)
        .map(|i| {
            let workspace = app.provider_workspaces.get(i).map_or("", String::as_str);
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

            let mut cells: Vec<Cell<'_>> = Vec::new();
            if show_ws {
                cells.push(Cell::from(Span::styled(workspace, t.muted)));
            }
            cells.extend([
                name_cell,
                Cell::from(Span::styled(ptype, t.muted)),
                Cell::from(Span::styled(cred_key, t.muted)),
            ]);

            Row::new(cells)
        })
        .collect();

    let widths: Vec<Constraint> = if show_ws {
        vec![
            Constraint::Percentage(20),
            Constraint::Percentage(30),
            Constraint::Percentage(20),
            Constraint::Percentage(30),
        ]
    } else {
        vec![
            Constraint::Percentage(40),
            Constraint::Percentage(25),
            Constraint::Percentage(35),
        ]
    };

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
        super::draw_empty_message(frame, area, " No providers. Press [c] to create.", t.muted);
    }
}

fn draw_v2(frame: &mut Frame<'_>, app: &App, area: Rect, focused: bool) {
    let t = &app.theme;
    let show_ws = app.all_workspaces;

    let mut header_cells = Vec::new();
    if show_ws {
        header_cells.push(Cell::from(Span::styled("WORKSPACE", t.muted)));
    }
    header_cells.extend([
        Cell::from(Span::styled("  NAME", t.muted)),
        Cell::from(Span::styled("PROFILE", t.muted)),
        Cell::from(Span::styled("CATEGORY", t.muted)),
        Cell::from(Span::styled("CREDS", t.muted)),
        Cell::from(Span::styled("POLICY", t.muted)),
    ]);
    let header = Row::new(header_cells).bottom_margin(1);

    let rows: Vec<Row<'_>> = app
        .provider_entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let workspace = app.provider_workspaces.get(i).map_or("", String::as_str);
            let selected = focused && i == app.provider_selected;
            let name_cell = if selected {
                Cell::from(Line::from(vec![
                    Span::styled("> ", t.accent),
                    Span::styled(entry.name(), t.text),
                ]))
            } else {
                Cell::from(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(entry.name(), t.text),
                ]))
            };

            let profile_style = if entry.profile.is_some() {
                t.text
            } else {
                t.status_warn
            };

            let mut cells: Vec<Cell<'_>> = Vec::new();
            if show_ws {
                cells.push(Cell::from(Span::styled(workspace, t.muted)));
            }
            cells.extend([
                name_cell,
                Cell::from(Span::styled(entry.profile_label(), profile_style)),
                Cell::from(Span::styled(entry.category_label(), t.muted)),
                Cell::from(Span::styled(entry.credential_summary(), t.muted)),
                Cell::from(Span::styled(entry.policy_summary(), t.muted)),
            ]);

            Row::new(cells)
        })
        .collect();

    let widths: Vec<Constraint> = if show_ws {
        vec![
            Constraint::Percentage(12),
            Constraint::Percentage(18),
            Constraint::Percentage(20),
            Constraint::Percentage(14),
            Constraint::Percentage(16),
            Constraint::Percentage(20),
        ]
    } else {
        vec![
            Constraint::Percentage(22),
            Constraint::Percentage(24),
            Constraint::Percentage(16),
            Constraint::Percentage(18),
            Constraint::Percentage(20),
        ]
    };

    let border_style = if focused { t.border_focused } else { t.border };
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
        super::draw_empty_message(frame, area, " No providers found.", t.muted);
    }
}
