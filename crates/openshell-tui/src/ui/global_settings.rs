// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Padding, Row, Table};

use super::draw_empty_message;

use crate::app::{App, MiddlePaneTab};

pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect, focused: bool) {
    let t = &app.theme;

    let header = Row::new(vec![
        Cell::from(Span::styled("  KEY", t.muted)),
        Cell::from(Span::styled("TYPE", t.muted)),
        Cell::from(Span::styled("VALUE", t.muted)),
    ])
    .bottom_margin(1);

    let rows: Vec<Row<'_>> = app
        .global_settings
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let selected = focused && i == app.global_settings_selected;
            let key_cell = if selected {
                Cell::from(Line::from(vec![
                    Span::styled("> ", t.accent),
                    Span::styled(&entry.key, t.text),
                ]))
            } else {
                Cell::from(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(&entry.key, t.text),
                ]))
            };

            let type_label = entry.kind.as_str();
            let value_display = entry.display_value();
            let value_style = if entry.value.is_some() {
                t.accent
            } else {
                t.muted
            };

            Row::new(vec![
                key_cell,
                Cell::from(Span::styled(type_label, t.muted)),
                Cell::from(Span::styled(value_display, value_style)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(35),
        Constraint::Percentage(15),
        Constraint::Percentage(50),
    ];

    let border_style = if focused { t.border_focused } else { t.border };

    let title = draw_tab_title(app, focused);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style)
        .padding(Padding::horizontal(1));

    let table = Table::new(rows, widths).header(header).block(block);
    frame.render_widget(table, area);

    if app.global_settings.is_empty() {
        draw_empty_message(frame, area, " No settings available.", t.muted);
    }

    // Draw edit overlay if active.
    if focused {
        if let Some(ref edit) = app.setting_edit
            && app.confirm_setting_set.is_none()
        {
            draw_edit_overlay(frame, app, edit, area);
        }
        if let Some(idx) = app.confirm_setting_set {
            draw_confirm_set(frame, app, idx, area);
        }
        if let Some(idx) = app.confirm_setting_delete {
            draw_confirm_delete(frame, app, idx, area);
        }
    }
}

/// Draw the tab title showing Providers | Global Settings.
pub fn draw_tab_title(app: &App, focused: bool) -> Line<'_> {
    let t = &app.theme;
    let prov_style = if app.middle_pane_tab == MiddlePaneTab::Providers {
        if focused { t.heading } else { t.text }
    } else {
        t.muted
    };
    let gs_style = if app.middle_pane_tab == MiddlePaneTab::GlobalSettings {
        if focused { t.heading } else { t.text }
    } else {
        t.muted
    };

    Line::from(vec![
        Span::styled(" Providers", prov_style),
        Span::styled(" | ", t.border),
        Span::styled("Global Settings ", gs_style),
    ])
}

fn draw_edit_overlay(
    frame: &mut Frame<'_>,
    app: &App,
    edit: &crate::app::SettingEditState,
    area: Rect,
) {
    let Some(entry) = app.global_settings.get(edit.index) else {
        return;
    };
    super::draw_setting_edit_overlay(frame, &entry.key, entry.kind, edit, area, &app.theme);
}

fn draw_confirm_set(frame: &mut Frame<'_>, app: &App, idx: usize, area: Rect) {
    let t = &app.theme;
    let Some(entry) = app.global_settings.get(idx) else {
        return;
    };
    let new_value = app.setting_edit.as_ref().map_or("-", |e| e.input.as_str());

    let lines = vec![
        Line::from(Span::styled(" Confirm Global Setting Change ", t.heading)),
        Line::from(""),
        Line::from(vec![
            Span::styled("Set ", t.text),
            Span::styled(&entry.key, t.accent),
            Span::styled(" = ", t.text),
            Span::styled(new_value, t.accent),
            Span::styled(" globally?", t.text),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "This will apply to all sandboxes on this gateway.",
            t.status_warn,
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("[y]", t.key_hint),
            Span::styled(" Confirm  ", t.muted),
            Span::styled("[n]", t.key_hint),
            Span::styled(" Cancel", t.muted),
        ]),
    ];

    super::draw_confirm_popup(frame, lines, t.border_focused, 60, area);
}

fn draw_confirm_delete(frame: &mut Frame<'_>, app: &App, idx: usize, area: Rect) {
    let t = &app.theme;
    let Some(entry) = app.global_settings.get(idx) else {
        return;
    };

    let lines = vec![
        Line::from(Span::styled(" Delete Global Setting ", t.status_err)),
        Line::from(""),
        Line::from(vec![
            Span::styled("Delete global setting ", t.text),
            Span::styled(&entry.key, t.accent),
            Span::styled("?", t.text),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "This will unset the value for all sandboxes on this gateway.",
            t.status_warn,
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("[y]", t.key_hint),
            Span::styled(" Delete  ", t.muted),
            Span::styled("[n]", t.key_hint),
            Span::styled(" Cancel", t.muted),
        ]),
    ];

    super::draw_confirm_popup(frame, lines, t.status_err, 60, area);
}
