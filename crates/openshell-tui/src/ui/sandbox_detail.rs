// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};

use crate::app::App;

/// Draw a compact metadata pane for the currently selected sandbox.
///
/// This is non-interactive (no focus state) — always rendered with the
/// unfocused border style in the top ~20% of the sandbox screen.
pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let t = &app.theme;
    let idx = app.sandbox_selected;
    let name = app.sandbox_names.get(idx).map_or("-", String::as_str);
    let phase = app.sandbox_phases.get(idx).map_or("-", String::as_str);
    let image = app.sandbox_images.get(idx).map_or("-", String::as_str);
    let created = app.sandbox_created.get(idx).map_or("-", String::as_str);
    let age = app.sandbox_ages.get(idx).map_or("-", String::as_str);

    let phase_style = match phase {
        "Ready" => t.status_ok,
        "Provisioning" => t.status_warn,
        "Error" => t.status_err,
        _ => t.muted,
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
        Span::styled("  Name: ", t.muted),
        Span::styled(name, t.heading),
    ];
    if pending_count > 0 {
        row1_spans.push(Span::raw(" "));
        row1_spans.push(Span::styled(format!(" {pending_count} pending "), t.badge));
    }
    row1_spans.extend([
        Span::styled("              Status: ", t.muted),
        Span::styled(format!("{status_indicator} "), phase_style),
        Span::styled(phase, phase_style),
    ]);
    let row1 = Line::from(row1_spans);

    // Row 2: Image + Created + Age
    let row2 = Line::from(vec![
        Span::styled("  Image: ", t.muted),
        Span::styled(image, t.text),
        Span::styled("   Created: ", t.muted),
        Span::styled(created, t.text),
        Span::styled("   Age: ", t.muted),
        Span::styled(age, t.text),
    ]);

    // Row 3: Providers
    let providers_str = if app.sandbox_providers_list.is_empty() {
        "none".to_string()
    } else {
        app.sandbox_providers_list.join(", ")
    };
    let row3 = Line::from(vec![
        Span::styled("  Providers: ", t.muted),
        Span::styled(providers_str, t.text),
    ]);

    // Row 4: Forwarded Ports
    let forwards_str = app
        .sandbox_notes
        .get(idx)
        .filter(|s| !s.is_empty())
        .map_or_else(|| "none".to_string(), Clone::clone);
    let row4 = Line::from(vec![
        Span::styled("  Forwards: ", t.muted),
        Span::styled(forwards_str, t.text),
    ]);

    let mut lines = vec![Line::from(""), row1, row2, row3, row4];

    // Show global policy indicator when the sandbox's policy is managed at
    // gateway scope.
    if app.sandbox_policy_is_global {
        let version_label = if app.sandbox_global_policy_version > 0 {
            format!("managed globally (v{})", app.sandbox_global_policy_version)
        } else {
            "managed globally".to_string()
        };
        lines.push(Line::from(vec![
            Span::styled("  Policy: ", t.muted),
            Span::styled(version_label, t.status_warn),
        ]));
    }

    // Show pending network rules prompt — but not when delete confirmation is
    // active, since it would push the confirmation off the bottom of the pane.
    if pending_count > 0 && !app.confirm_delete {
        lines.push(Line::from(vec![
            Span::styled("  ", t.text),
            Span::styled(
                format!(
                    "{pending_count} pending network rule{}",
                    if pending_count == 1 { "" } else { "s" }
                ),
                t.accent,
            ),
            Span::styled(" — press ", t.muted),
            Span::styled("[r]", t.key_hint),
            Span::styled(" to review", t.muted),
        ]));
    }

    // Delete confirmation in title area (same pattern as provider delete).
    // Takes priority over the pending-policy prompt so it isn't pushed off-screen.
    if app.confirm_delete {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  ", t.text),
            Span::styled("Delete sandbox '", t.status_err),
            Span::styled(name, t.status_err),
            Span::styled("'? ", t.status_err),
            Span::styled("[y]", t.key_hint),
            Span::styled(" Confirm  ", t.text),
            Span::styled("[Esc]", t.key_hint),
            Span::styled(" Cancel", t.text),
        ]));
    }

    let mut title_spans: Vec<Span<'_>> =
        vec![Span::styled(format!(" Sandbox: {name} "), t.heading)];
    if pending_count > 0 {
        title_spans.push(Span::styled(format!(" {pending_count} pending "), t.badge));
        title_spans.push(Span::raw(" "));
    }
    let block = Block::default()
        .title(Line::from(title_spans))
        .borders(Borders::ALL)
        .border_style(t.border) // non-interactive — unfocused border
        .padding(Padding::horizontal(1));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}
