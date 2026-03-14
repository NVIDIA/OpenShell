// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Splash screen shown on TUI startup — the "B2 Framed" design.
//!
//! Renders the ANSI Shadow block-letter logo (OPEN in white, SHELL in green)
//! inside a double-line border, with the tagline and a version/prompt footer.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph};

// ---------------------------------------------------------------------------
// ANSI Shadow figlet art — OPEN (6 lines, 35 display cols)
// ---------------------------------------------------------------------------

const OPEN_ART: [&str; 6] = [
    " ██████╗ ██████╗ ███████╗███╗   ██╗",
    "██╔═══██╗██╔══██╗██╔════╝████╗  ██║",
    "██║   ██║██████╔╝█████╗  ██╔██╗ ██║",
    "██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║",
    "╚██████╔╝██║     ███████╗██║ ╚████║",
    " ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝",
];

// ---------------------------------------------------------------------------
// ANSI Shadow figlet art — SHELL (6 lines, 40 display cols)
// ---------------------------------------------------------------------------

const SHELL_ART: [&str; 6] = [
    "███████╗██╗  ██╗███████╗██╗     ██╗",
    "██╔════╝██║  ██║██╔════╝██║     ██║",
    "███████╗███████║█████╗  ██║     ██║",
    "╚════██║██╔══██║██╔══╝  ██║     ██║",
    "███████║██║  ██║███████╗███████╗███████╗",
    "╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝",
];

const TAGLINE: &str = "Shells Wide Shut.";

/// Maximum display width of the art (SHELL line 5 is the widest at 40 cols).
const ART_WIDTH: u16 = 40;

/// Total content lines: 6 (OPEN) + 6 (SHELL) + 1 (blank) + 1 (tagline) = 14.
const CONTENT_LINES: u16 = 14;

// Border (2) + top/bottom inner padding (2) + content + blank before footer (1) + footer (2).
const MODAL_HEIGHT: u16 = CONTENT_LINES + 7;

// Art width + left/right padding (3+3) + borders (2).
const MODAL_WIDTH: u16 = ART_WIDTH + 8;

/// Draw the splash screen centered on the full terminal area.
pub fn draw(frame: &mut Frame<'_>, area: Rect, theme: &crate::theme::Theme) {
    let t = theme;
    let modal_w = MODAL_WIDTH.min(area.width.saturating_sub(2));
    let modal_h = MODAL_HEIGHT.min(area.height.saturating_sub(2));

    // Center the modal.
    let popup = centered_rect(modal_w, modal_h, area);

    // Clear the area behind the modal.
    frame.render_widget(Clear, popup);

    // Outer double-line border.
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(t.border)
        .padding(Padding::new(3, 3, 1, 1));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    // Split inner area: art content + spacer + footer (2 lines).
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(CONTENT_LINES), // OPEN + SHELL + blank + tagline
            Constraint::Min(0),                // spacer
            Constraint::Length(2),             // footer (version + prompt)
        ])
        .split(inner);

    // -- Art + tagline --
    let open_style = t.heading;
    let shell_style = t.accent_bold;

    let mut content_lines: Vec<Line<'_>> = Vec::with_capacity(CONTENT_LINES as usize);

    for line in &OPEN_ART {
        content_lines.push(Line::from(Span::styled(*line, open_style)));
    }
    for line in &SHELL_ART {
        content_lines.push(Line::from(Span::styled(*line, shell_style)));
    }

    // Blank + tagline.
    content_lines.push(Line::from(""));
    content_lines.push(Line::from(Span::styled(TAGLINE, t.muted)).alignment(Alignment::Center));

    frame.render_widget(Paragraph::new(content_lines), chunks[0]);

    // -- Footer: version + ALPHA badge on line 1, prompt on line 2 --
    let version = format!("v{}", openshell_core::VERSION);
    let alpha_badge = "ALPHA";

    let footer = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(version, t.accent),
            Span::styled(" ", t.muted),
            Span::styled(alpha_badge, t.title_bar),
        ]),
        Line::from(Span::styled("press any key ░", t.muted)),
    ]);

    frame.render_widget(footer, chunks[2]);
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length((area.height.saturating_sub(height)) / 2),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area);
    let horiz = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length((area.width.saturating_sub(width)) / 2),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(vert[1]);
    horiz[1]
}
