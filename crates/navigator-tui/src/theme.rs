// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod colors {
    use ratatui::style::Color;

    pub const NVIDIA_GREEN: Color = Color::Rgb(118, 185, 0);
    pub const EVERGLADE: Color = Color::Rgb(18, 49, 35);
    pub const MAROON: Color = Color::Rgb(128, 0, 0);
    pub const BG: Color = Color::Black;
    pub const FG: Color = Color::White;
}

pub mod styles {
    use ratatui::style::{Color, Modifier, Style};

    use super::colors;

    pub const TEXT: Style = Style::new().fg(colors::FG);
    pub const MUTED: Style = Style::new().fg(colors::FG).add_modifier(Modifier::DIM);
    pub const HEADING: Style = Style::new().fg(colors::FG).add_modifier(Modifier::BOLD);
    pub const ACCENT: Style = Style::new().fg(colors::NVIDIA_GREEN);
    pub const ACCENT_BOLD: Style = Style::new()
        .fg(colors::NVIDIA_GREEN)
        .add_modifier(Modifier::BOLD);
    pub const SELECTED: Style = Style::new().add_modifier(Modifier::BOLD);
    pub const BORDER: Style = Style::new().fg(colors::EVERGLADE);
    pub const BORDER_FOCUSED: Style = Style::new().fg(colors::NVIDIA_GREEN);
    pub const STATUS_OK: Style = Style::new().fg(colors::NVIDIA_GREEN);
    pub const STATUS_WARN: Style = Style::new().fg(Color::Yellow);
    pub const STATUS_ERR: Style = Style::new().fg(Color::Red);
    pub const KEY_HINT: Style = Style::new().fg(colors::NVIDIA_GREEN);
    /// Background highlight for the cursor line in log viewer.
    pub const LOG_CURSOR: Style = Style::new().bg(colors::EVERGLADE);
    /// Maroon style for the pacman chase claw.
    pub const CLAW: Style = Style::new().fg(colors::MAROON).add_modifier(Modifier::BOLD);
    pub const TITLE_BAR: Style = Style::new()
        .fg(colors::FG)
        .bg(colors::EVERGLADE)
        .add_modifier(Modifier::BOLD);
    /// Notification badge for pending recommendation counts.
    pub const BADGE: Style = Style::new()
        .fg(colors::BG)
        .bg(colors::NVIDIA_GREEN)
        .add_modifier(Modifier::BOLD);
}
