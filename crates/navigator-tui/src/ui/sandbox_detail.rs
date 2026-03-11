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

    // Count pending draft recommendations for this sandbox.
    let pending_count = app.sandbox_draft_counts.get(idx).copied().unwrap_or(0);
    // Also check the live draft_chunks when on the sandbox screen (more up-to-date).
    let pending_count = if pending_count > 0 {
        pending_count
    } else {
        app.draft_chunks
            .iter()
            .filter(|c| c.status == "pending")
            .count()
    };

    // Row 1: Name + Status + optional draft badge
    let mut row1_spans = vec![
        Span::styled("  Name: ", styles::MUTED),
        Span::styled(name, styles::HEADING),
    ];
    if pending_count > 0 {
        row1_spans.push(Span::raw(" "));
        row1_spans.push(Span::styled(
            format!(" {pending_count} pending "),
            styles::BADGE,
        ));
    }
    row1_spans.extend([
        Span::styled("              Status: ", styles::MUTED),
        Span::styled(format!("{status_indicator} "), phase_style),
        Span::styled(phase, phase_style),
    ]);
    let row1 = Line::from(row1_spans);

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

    // Row 4: Forwarded Ports
    let forwards_str = app
        .sandbox_notes
        .get(idx)
        .filter(|s| !s.is_empty())
        .map_or_else(|| "none".to_string(), Clone::clone);
    let row4 = Line::from(vec![
        Span::styled("  Forwards: ", styles::MUTED),
        Span::styled(forwards_str, styles::TEXT),
    ]);

    let mut lines = vec![Line::from(""), row1, row2, row3, row4];

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

    let mut title_spans: Vec<Span<'_>> =
        vec![Span::styled(format!(" Sandbox: {name} "), styles::HEADING)];
    if pending_count > 0 {
        title_spans.push(Span::styled(
            format!(" {pending_count} pending "),
            styles::BADGE,
        ));
        title_spans.push(Span::raw(" "));
    }
    let block = Block::default()
        .title(Line::from(title_spans))
        .borders(Borders::ALL)
        .border_style(styles::BORDER) // non-interactive — unfocused border
        .padding(Padding::horizontal(1));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}
