// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ratatui::style::{Color, Modifier, Style};

/// User-facing theme selection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeMode {
    /// Detect from terminal environment; fall back to dark.
    #[default]
    Auto,
    Dark,
    Light,
}

impl std::fmt::Display for ThemeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Dark => write!(f, "dark"),
            Self::Light => write!(f, "light"),
        }
    }
}

impl std::str::FromStr for ThemeMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "dark" => Ok(Self::Dark),
            "light" => Ok(Self::Light),
            other => Err(format!(
                "unknown theme mode: {other} (expected auto, dark, or light)"
            )),
        }
    }
}

/// Complete color theme for the TUI.
///
/// Obtain a theme via [`Theme::dark`], [`Theme::light`], or [`detect`].
/// All fields are public [`Style`] values matching the semantic roles used
/// throughout the UI.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    // Text
    pub text: Style,
    pub muted: Style,
    pub heading: Style,

    // Accent (brand color)
    pub accent: Style,
    pub accent_bold: Style,

    // Selection
    pub selected: Style,

    // Borders
    pub border: Style,
    pub border_focused: Style,

    // Status indicators
    pub status_ok: Style,
    pub status_warn: Style,
    pub status_err: Style,

    // Navigation
    pub key_hint: Style,

    // Log viewer
    pub log_cursor: Style,
    pub log_selection: Style,

    // Animation
    pub claw: Style,

    // Chrome
    pub title_bar: Style,
    pub badge: Style,
}

/// Brand colors shared between themes.
mod brand {
    use ratatui::style::Color;

    pub const NVIDIA_GREEN: Color = Color::Rgb(118, 185, 0);
    pub const NVIDIA_GREEN_DARK: Color = Color::Rgb(80, 140, 0);
    pub const EVERGLADE: Color = Color::Rgb(18, 49, 35);
    pub const MAROON: Color = Color::Rgb(128, 0, 0);
}

impl Theme {
    /// Dark theme — NVIDIA green on dark terminal background.
    ///
    /// This reproduces the original hardcoded palette exactly.
    #[must_use]
    pub fn dark() -> Self {
        let fg = Color::White;
        let bg = Color::Black;

        Self {
            text: Style::new().fg(fg),
            muted: Style::new().fg(fg).add_modifier(Modifier::DIM),
            heading: Style::new().fg(fg).add_modifier(Modifier::BOLD),

            accent: Style::new().fg(brand::NVIDIA_GREEN),
            accent_bold: Style::new()
                .fg(brand::NVIDIA_GREEN)
                .add_modifier(Modifier::BOLD),

            selected: Style::new().add_modifier(Modifier::BOLD),

            border: Style::new().fg(brand::EVERGLADE),
            border_focused: Style::new().fg(brand::NVIDIA_GREEN),

            status_ok: Style::new().fg(brand::NVIDIA_GREEN),
            status_warn: Style::new().fg(Color::Yellow),
            status_err: Style::new().fg(Color::Red),

            key_hint: Style::new().fg(brand::NVIDIA_GREEN),

            log_cursor: Style::new().bg(brand::EVERGLADE),
            log_selection: Style::new().bg(Color::Rgb(30, 60, 45)),

            claw: Style::new().fg(brand::MAROON).add_modifier(Modifier::BOLD),

            title_bar: Style::new()
                .fg(fg)
                .bg(brand::EVERGLADE)
                .add_modifier(Modifier::BOLD),
            badge: Style::new()
                .fg(bg)
                .bg(brand::NVIDIA_GREEN)
                .add_modifier(Modifier::BOLD),
        }
    }

    /// Light theme — darker accents on light terminal background.
    #[must_use]
    pub fn light() -> Self {
        let fg = Color::Rgb(30, 30, 30);
        let muted_fg = Color::Rgb(120, 120, 120);
        let border_color = Color::Rgb(180, 200, 170);
        let title_bg = Color::Rgb(220, 235, 210);
        let cursor_bg = Color::Rgb(230, 245, 220);
        let selection_bg = Color::Rgb(215, 235, 200);

        Self {
            text: Style::new().fg(fg),
            muted: Style::new().fg(muted_fg),
            heading: Style::new().fg(fg).add_modifier(Modifier::BOLD),

            accent: Style::new().fg(brand::NVIDIA_GREEN_DARK),
            accent_bold: Style::new()
                .fg(brand::NVIDIA_GREEN_DARK)
                .add_modifier(Modifier::BOLD),

            selected: Style::new().add_modifier(Modifier::BOLD),

            border: Style::new().fg(border_color),
            border_focused: Style::new().fg(brand::NVIDIA_GREEN_DARK),

            status_ok: Style::new().fg(brand::NVIDIA_GREEN_DARK),
            status_warn: Style::new().fg(Color::Rgb(180, 140, 0)),
            status_err: Style::new().fg(Color::Rgb(200, 40, 40)),

            key_hint: Style::new().fg(brand::NVIDIA_GREEN_DARK),

            log_cursor: Style::new().bg(cursor_bg),
            log_selection: Style::new().bg(selection_bg),

            claw: Style::new().fg(brand::MAROON).add_modifier(Modifier::BOLD),

            title_bar: Style::new()
                .fg(fg)
                .bg(title_bg)
                .add_modifier(Modifier::BOLD),
            badge: Style::new()
                .fg(Color::White)
                .bg(brand::NVIDIA_GREEN_DARK)
                .add_modifier(Modifier::BOLD),
        }
    }
}

/// Resolve a [`ThemeMode`] into a concrete [`Theme`].
///
/// - `Dark` / `Light` → returns the corresponding theme directly.
/// - `Auto` → queries the terminal background color via OSC 11
///   (supported by iTerm2, Terminal.app, most modern terminals),
///   then falls back to [`Theme::dark`] if the query fails.
///
/// **Must be called before `enable_raw_mode()`** — the OSC query
/// temporarily enters raw mode itself and restores it afterward.
#[must_use]
pub fn detect(mode: ThemeMode) -> Theme {
    match mode {
        ThemeMode::Dark => Theme::dark(),
        ThemeMode::Light => Theme::light(),
        ThemeMode::Auto => {
            if is_light_terminal() {
                Theme::light()
            } else {
                Theme::dark()
            }
        }
    }
}

/// Detect whether the terminal has a light background using OSC 11.
///
/// Uses `terminal-colorsaurus` to send an OSC 11 query to the terminal,
/// which returns the actual background RGB color. This works reliably on
/// iTerm2, Terminal.app, WezTerm, Alacritty, and most modern terminals.
///
/// Falls back to `false` (dark) if the terminal doesn't respond to the
/// query (e.g. `TERM=dumb`, piped output, very old terminals).
fn is_light_terminal() -> bool {
    use terminal_colorsaurus::{QueryOptions, ThemeMode as ColorsaurusMode};
    matches!(
        terminal_colorsaurus::theme_mode(QueryOptions::default()),
        Ok(ColorsaurusMode::Light)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dark_and_light_themes_differ() {
        let dark = Theme::dark();
        let light = Theme::light();

        // Core text styles must differ between themes.
        assert_ne!(dark.text, light.text, "text style should differ");
        assert_ne!(dark.muted, light.muted, "muted style should differ");
        assert_ne!(dark.accent, light.accent, "accent style should differ");
        assert_ne!(dark.border, light.border, "border style should differ");
        assert_ne!(
            dark.title_bar, light.title_bar,
            "title_bar style should differ"
        );
        assert_ne!(dark.badge, light.badge, "badge style should differ");
        assert_ne!(
            dark.log_cursor, light.log_cursor,
            "log_cursor style should differ"
        );
        assert_ne!(
            dark.log_selection, light.log_selection,
            "log_selection style should differ"
        );
    }

    #[test]
    fn dark_theme_matches_original_palette() {
        // Regression guard: `Theme::dark()` must reproduce the original
        // hardcoded values exactly so existing dark-terminal users see
        // zero visual change.
        let d = Theme::dark();

        assert_eq!(d.text, Style::new().fg(Color::White));
        assert_eq!(
            d.muted,
            Style::new().fg(Color::White).add_modifier(Modifier::DIM)
        );
        assert_eq!(
            d.heading,
            Style::new().fg(Color::White).add_modifier(Modifier::BOLD)
        );
        assert_eq!(d.accent, Style::new().fg(brand::NVIDIA_GREEN));
        assert_eq!(
            d.accent_bold,
            Style::new()
                .fg(brand::NVIDIA_GREEN)
                .add_modifier(Modifier::BOLD)
        );
        assert_eq!(d.selected, Style::new().add_modifier(Modifier::BOLD));
        assert_eq!(d.border, Style::new().fg(brand::EVERGLADE));
        assert_eq!(d.border_focused, Style::new().fg(brand::NVIDIA_GREEN));
        assert_eq!(d.status_ok, Style::new().fg(brand::NVIDIA_GREEN));
        assert_eq!(d.status_warn, Style::new().fg(Color::Yellow));
        assert_eq!(d.status_err, Style::new().fg(Color::Red));
        assert_eq!(d.key_hint, Style::new().fg(brand::NVIDIA_GREEN));
        assert_eq!(d.log_cursor, Style::new().bg(brand::EVERGLADE));
        assert_eq!(d.log_selection, Style::new().bg(Color::Rgb(30, 60, 45)));
        assert_eq!(
            d.claw,
            Style::new().fg(brand::MAROON).add_modifier(Modifier::BOLD)
        );
        assert_eq!(
            d.title_bar,
            Style::new()
                .fg(Color::White)
                .bg(brand::EVERGLADE)
                .add_modifier(Modifier::BOLD)
        );
        assert_eq!(
            d.badge,
            Style::new()
                .fg(Color::Black)
                .bg(brand::NVIDIA_GREEN)
                .add_modifier(Modifier::BOLD)
        );
    }

    #[test]
    fn detect_explicit_modes() {
        // Explicit modes bypass env detection.
        let dark = detect(ThemeMode::Dark);
        let light = detect(ThemeMode::Light);

        assert_eq!(dark.text, Theme::dark().text);
        assert_eq!(light.text, Theme::light().text);
    }

    #[test]
    fn theme_mode_display_and_parse() {
        for mode in [ThemeMode::Auto, ThemeMode::Dark, ThemeMode::Light] {
            let s = mode.to_string();
            let parsed: ThemeMode = s.parse().unwrap();
            assert_eq!(mode, parsed);
        }

        assert!("invalid".parse::<ThemeMode>().is_err());
    }
}
