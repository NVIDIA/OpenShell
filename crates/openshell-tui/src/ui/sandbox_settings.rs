// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Padding, Row, Table};

use super::draw_empty_message;
use crate::app::{App, SandboxPolicyTab, SettingScope};

pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let t = &app.theme;

    let header = Row::new(vec![
        Cell::from(Span::styled("  KEY", t.muted)),
        Cell::from(Span::styled("TYPE", t.muted)),
        Cell::from(Span::styled("VALUE", t.muted)),
        Cell::from(Span::styled("SCOPE", t.muted)),
    ])
    .bottom_margin(1);

    let rows: Vec<Row<'_>> = app
        .sandbox_settings
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let selected = i == app.sandbox_settings_selected;
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
                if entry.is_globally_managed() {
                    t.status_warn
                } else {
                    t.accent
                }
            } else {
                t.muted
            };

            let scope_style = match entry.scope {
                SettingScope::Global => t.status_warn,
                SettingScope::Sandbox => t.accent,
                SettingScope::Unset => t.muted,
            };

            Row::new(vec![
                key_cell,
                Cell::from(Span::styled(type_label, t.muted)),
                Cell::from(Span::styled(value_display, value_style)),
                Cell::from(Span::styled(entry.scope.label(), scope_style)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(30),
        Constraint::Percentage(10),
        Constraint::Percentage(40),
        Constraint::Percentage(20),
    ];

    let title = draw_policy_tab_title(app);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(t.border_focused)
        .padding(Padding::horizontal(1));

    let table = Table::new(rows, widths).header(header).block(block);
    frame.render_widget(table, area);

    if app.sandbox_settings.is_empty() {
        draw_empty_message(frame, area, " No settings available.", t.muted);
    }

    // Overlays.
    if let Some(ref edit) = app.sandbox_setting_edit
        && app.sandbox_confirm_setting_set.is_none()
    {
        draw_edit_overlay(frame, app, edit, area);
    }
    if let Some(idx) = app.sandbox_confirm_setting_set {
        draw_confirm_set(frame, app, idx, area);
    }
    if let Some(idx) = app.sandbox_confirm_setting_delete {
        draw_confirm_delete(frame, app, idx, area);
    }
}

/// Draw the tab title for the sandbox bottom pane: Policy | Settings.
pub fn draw_policy_tab_title(app: &App) -> Line<'_> {
    let t = &app.theme;
    let pol_style = if app.sandbox_policy_tab == SandboxPolicyTab::Policy {
        t.heading
    } else {
        t.muted
    };
    let set_style = if app.sandbox_policy_tab == SandboxPolicyTab::Settings {
        t.heading
    } else {
        t.muted
    };

    Line::from(vec![
        Span::styled(" Policy", pol_style),
        Span::styled(" | ", t.border),
        Span::styled("Settings ", set_style),
    ])
}

fn draw_edit_overlay(
    frame: &mut Frame<'_>,
    app: &App,
    edit: &crate::app::SettingEditState,
    area: Rect,
) {
    let Some(entry) = app.sandbox_settings.get(edit.index) else {
        return;
    };
    super::draw_setting_edit_overlay(frame, &entry.key, entry.kind, edit, area, &app.theme);
}

fn draw_confirm_set(frame: &mut Frame<'_>, app: &App, idx: usize, area: Rect) {
    let t = &app.theme;
    let Some(entry) = app.sandbox_settings.get(idx) else {
        return;
    };
    let new_value = app
        .sandbox_setting_edit
        .as_ref()
        .map_or("-", |e| e.input.as_str());
    let sandbox_name = app.selected_sandbox_name().unwrap_or("-");

    let lines = vec![
        Line::from(Span::styled(" Confirm Sandbox Setting Change ", t.heading)),
        Line::from(""),
        Line::from(vec![
            Span::styled("Set ", t.text),
            Span::styled(&entry.key, t.accent),
            Span::styled(" = ", t.text),
            Span::styled(new_value, t.accent),
            Span::styled(" for ", t.text),
            Span::styled(sandbox_name, t.accent),
            Span::styled("?", t.text),
        ]),
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
    let Some(entry) = app.sandbox_settings.get(idx) else {
        return;
    };
    let sandbox_name = app.selected_sandbox_name().unwrap_or("-");

    let lines = vec![
        Line::from(Span::styled(" Delete Sandbox Setting ", t.status_err)),
        Line::from(""),
        Line::from(vec![
            Span::styled("Delete setting ", t.text),
            Span::styled(&entry.key, t.accent),
            Span::styled(" for ", t.text),
            Span::styled(sandbox_name, t.accent),
            Span::styled("?", t.text),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("[y]", t.key_hint),
            Span::styled(" Delete  ", t.muted),
            Span::styled("[n]", t.key_hint),
            Span::styled(" Cancel", t.muted),
        ]),
    ];

    super::draw_confirm_popup(frame, lines, t.status_err, 55, area);
}
