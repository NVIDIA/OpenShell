// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};

use crate::app::App;
use crate::theme::styles;

/// Draw a compact metadata pane for the currently selected sandbox.
///
/// This is non-interactive (no focus state) — always rendered with the
/// unfocused border style in the top ~20% of the sandbox screen.
pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let idx = app.sandbox_selected;
    let name = app.sandbox_names.get(idx).map_or("-", String::as_str);
    let phase = app.sandbox_phases.get(idx).map_or("-", String::as_str);
    let image = app.sandbox_images.get(idx).map_or("-", String::as_str);
    let created = app.sandbox_created.get(idx).map_or("-", String::as_str);
    let age = app.sandbox_ages.get(idx).map_or("-", String::as_str);

    let phase_style = match phase {
        "Ready" => styles::STATUS_OK,
        "Provisioning" => styles::STATUS_WARN,
        "Error" => styles::STATUS_ERR,
        _ => styles::MUTED,
    };

    let status_indicator = match phase {
        "Ready" => "●",
        "Provisioning" => "◐",
        "Error" => "○",
        _ => "…",
    };

    // Row 1: Name + Status
    let row1 = Line::from(vec![
        Span::styled("  Name: ", styles::MUTED),
        Span::styled(name, styles::HEADING),
        Span::styled("              Status: ", styles::MUTED),
        Span::styled(format!("{status_indicator} "), phase_style),
        Span::styled(phase, phase_style),
    ]);

    // Row 2: Image + Created + Age
    let row2 = Line::from(vec![
        Span::styled("  Image: ", styles::MUTED),
        Span::styled(image, styles::TEXT),
        Span::styled("   Created: ", styles::MUTED),
        Span::styled(created, styles::TEXT),
        Span::styled("   Age: ", styles::MUTED),
        Span::styled(age, styles::TEXT),
    ]);

    // Row 3: Providers
    let providers_str = if app.sandbox_providers_list.is_empty() {
        "none".to_string()
    } else {
        app.sandbox_providers_list.join(", ")
    };
    let row3 = Line::from(vec![
        Span::styled("  Providers: ", styles::MUTED),
        Span::styled(providers_str, styles::TEXT),
    ]);

    let mut lines = vec![Line::from(""), row1, row2, row3];

    // Delete confirmation in title area (same pattern as provider delete).
    if app.confirm_delete {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  ", styles::TEXT),
            Span::styled("Delete sandbox '", styles::STATUS_ERR),
            Span::styled(name, styles::STATUS_ERR),
            Span::styled("'? ", styles::STATUS_ERR),
            Span::styled("[y]", styles::KEY_HINT),
            Span::styled(" Confirm  ", styles::TEXT),
            Span::styled("[Esc]", styles::KEY_HINT),
            Span::styled(" Cancel", styles::TEXT),
        ]));
    }

    let block = Block::default()
        .title(Span::styled(format!(" Sandbox: {name} "), styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::BORDER) // non-interactive — unfocused border
        .padding(Padding::horizontal(1));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}
