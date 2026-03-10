// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};

use crate::app::App;
use crate::theme::styles;

/// Draw the scrollable policy viewer pane (bottom ~80% of the sandbox screen).
///
/// Always focused when visible (the metadata pane above is non-interactive).
pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let version = app.sandbox_policy.as_ref().map_or(0, |p| p.version);

    let title = format!(" Policy (v{version}) ");

    // Calculate inner dimensions (borders + padding).
    let inner_height = area.height.saturating_sub(2) as usize;

    if app.policy_lines.is_empty() {
        let lines = vec![Line::from(Span::styled("Loading...", styles::MUTED))];
        let block = Block::default()
            .title(Span::styled(title, styles::HEADING))
            .borders(Borders::ALL)
            .border_style(styles::BORDER_FOCUSED)
            .padding(Padding::horizontal(1));
        frame.render_widget(Paragraph::new(lines).block(block), area);
        return;
    }

    let total = app.policy_lines.len();
    let scroll = app.policy_scroll.min(total.saturating_sub(1));

    let visible_lines: Vec<Line<'_>> = app
        .policy_lines
        .iter()
        .skip(scroll)
        .take(inner_height)
        .cloned()
        .collect();

    // Scroll position indicator.
    let pos = scroll + 1;
    let scroll_info = format!(" [{pos}/{total}] ");

    let block = Block::default()
        .title(Span::styled(title, styles::HEADING))
        .title_bottom(Line::from(Span::styled(scroll_info, styles::MUTED)).right_aligned())
        .borders(Borders::ALL)
        .border_style(styles::BORDER_FOCUSED)
        .padding(Padding::horizontal(1));

    frame.render_widget(Paragraph::new(visible_lines).block(block), area);
}
