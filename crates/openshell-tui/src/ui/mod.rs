// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod create_provider;
pub(crate) mod create_sandbox;
mod dashboard;
pub(crate) mod providers;
pub(crate) mod sandbox_detail;
mod sandbox_draft;
pub(crate) mod sandbox_logs;
mod sandbox_policy;
pub(crate) mod sandboxes;
mod splash;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::{self, App, Focus, InputMode, Screen};

pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
    // Splash screen is a full-screen takeover — no chrome.
    if app.screen == Screen::Splash {
        splash::draw(frame, frame.size(), &app.theme);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title bar
            Constraint::Min(0),    // main content
            Constraint::Length(1), // nav bar
            Constraint::Length(1), // command bar
        ])
        .split(frame.size());

    draw_title_bar(frame, app, chunks[0]);

    match app.screen {
        Screen::Splash => unreachable!(),
        Screen::Dashboard => dashboard::draw(frame, app, chunks[1]),
        Screen::Sandbox => draw_sandbox_screen(frame, app, chunks[1]),
    }

    draw_nav_bar(frame, app, chunks[2]);
    draw_command_bar(frame, app, chunks[3]);

    // Modal overlays (drawn last so they're on top).
    if app.create_form.is_some() {
        create_sandbox::draw(frame, app, frame.size());
    }
    if app.create_provider_form.is_some() {
        create_provider::draw(frame, app, frame.size());
    }
    if app.provider_detail.is_some() {
        create_provider::draw_detail(frame, app, frame.size());
    }
    if app.update_provider_form.is_some() {
        create_provider::draw_update(frame, app, frame.size());
    }
}

// ---------------------------------------------------------------------------
// Sandbox full-screen
// ---------------------------------------------------------------------------

fn draw_sandbox_screen(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(20), // metadata
            Constraint::Percentage(80), // policy or logs
        ])
        .split(area);

    sandbox_detail::draw(frame, app, chunks[0]);

    match app.focus {
        Focus::SandboxLogs => sandbox_logs::draw(frame, app, chunks[1]),
        Focus::SandboxDraft => sandbox_draft::draw(frame, app, chunks[1]),
        _ => sandbox_policy::draw(frame, app, chunks[1]),
    }

    // Log detail popup renders over the full frame (not constrained to pane).
    if app.focus == Focus::SandboxLogs {
        if let Some(detail_idx) = app.log_detail_index {
            let filtered: Vec<&app::LogLine> = app.filtered_log_lines();
            if let Some(log) = filtered.get(detail_idx) {
                sandbox_logs::draw_detail_popup(frame, log, frame.size(), &app.theme);
            }
        }
    }

    // Draft detail popup renders over the full frame.
    if app.focus == Focus::SandboxDraft && app.draft_detail_open {
        let abs = app.draft_scroll + app.draft_selected;
        if let Some(chunk) = app.draft_chunks.get(abs) {
            sandbox_draft::draw_detail_popup(frame, chunk, frame.size(), &app.theme);
        }
    }

    // Approve-all confirmation popup renders over everything.
    if app.approve_all_confirm_open && !app.approve_all_confirm_chunks.is_empty() {
        sandbox_draft::draw_approve_all_popup(
            frame,
            &app.approve_all_confirm_chunks,
            frame.size(),
            &app.theme,
        );
    }
}

// ---------------------------------------------------------------------------
// Chrome: title bar, nav bar, command bar
// ---------------------------------------------------------------------------

fn draw_title_bar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let t = &app.theme;
    let status_span = match app.status_text.as_str() {
        s if s.contains("Healthy") => Span::styled(&app.status_text, t.status_ok),
        s if s.contains("Degraded") => Span::styled(&app.status_text, t.status_warn),
        s if s.contains("Unhealthy") => Span::styled(&app.status_text, t.status_err),
        _ => Span::styled(&app.status_text, t.muted),
    };

    let mut parts: Vec<Span<'_>> = vec![
        Span::styled(" >_ OpenShell ", t.accent_bold),
        Span::styled(" ALPHA ", t.badge),
        Span::styled(" | ", t.muted),
        Span::styled("Current Gateway: ", t.text),
        Span::styled(&app.gateway_name, t.heading),
        Span::styled(" (", t.muted),
        status_span,
        Span::styled(")", t.muted),
        Span::styled(" | ", t.muted),
    ];

    match app.screen {
        Screen::Splash => unreachable!("splash handled before draw_title_bar"),
        Screen::Dashboard => {
            parts.push(Span::styled("Dashboard", t.text));
        }
        Screen::Sandbox => {
            let name = app
                .sandbox_names
                .get(app.sandbox_selected)
                .map_or("-", String::as_str);
            parts.push(Span::styled("Sandbox: ", t.text));
            parts.push(Span::styled(name, t.heading));
        }
    }

    let title = Line::from(parts);
    frame.render_widget(Paragraph::new(title).style(t.title_bar), area);
}

fn draw_nav_bar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let t = &app.theme;
    let spans = match app.screen {
        Screen::Splash => unreachable!("splash handled before draw_nav_bar"),
        Screen::Dashboard => match app.focus {
            Focus::Providers => vec![
                Span::styled(" ", t.text),
                Span::styled("[Tab]", t.key_hint),
                Span::styled(" Switch Panel", t.text),
                Span::styled("  ", t.text),
                Span::styled("[j/k]", t.key_hint),
                Span::styled(" Navigate", t.text),
                Span::styled("  ", t.text),
                Span::styled("[Enter]", t.key_hint),
                Span::styled(" Detail", t.text),
                Span::styled("  ", t.text),
                Span::styled("[c]", t.key_hint),
                Span::styled(" Create", t.text),
                Span::styled("  ", t.text),
                Span::styled("[u]", t.key_hint),
                Span::styled(" Update", t.text),
                Span::styled("  ", t.text),
                Span::styled("[d]", t.key_hint),
                Span::styled(" Delete", t.text),
                Span::styled("  |  ", t.border),
                Span::styled("[:]", t.muted),
                Span::styled(" Command  ", t.muted),
                Span::styled("[q]", t.muted),
                Span::styled(" Quit", t.muted),
            ],
            Focus::Sandboxes => vec![
                Span::styled(" ", t.text),
                Span::styled("[Tab]", t.key_hint),
                Span::styled(" Switch Panel", t.text),
                Span::styled("  ", t.text),
                Span::styled("[j/k]", t.key_hint),
                Span::styled(" Navigate", t.text),
                Span::styled("  ", t.text),
                Span::styled("[Enter]", t.key_hint),
                Span::styled(" Select", t.text),
                Span::styled("  ", t.text),
                Span::styled("[c]", t.key_hint),
                Span::styled(" Create Sandbox", t.text),
                Span::styled("  |  ", t.border),
                Span::styled("[:]", t.muted),
                Span::styled(" Command  ", t.muted),
                Span::styled("[q]", t.muted),
                Span::styled(" Quit", t.muted),
            ],
            _ => vec![
                Span::styled(" ", t.text),
                Span::styled("[Tab]", t.key_hint),
                Span::styled(" Switch Panel", t.text),
                Span::styled("  ", t.text),
                Span::styled("[j/k]", t.key_hint),
                Span::styled(" Navigate", t.text),
                Span::styled("  ", t.text),
                Span::styled("[Enter]", t.key_hint),
                Span::styled(" Select", t.text),
                Span::styled("  |  ", t.border),
                Span::styled("[:]", t.muted),
                Span::styled(" Command  ", t.muted),
                Span::styled("[q]", t.muted),
                Span::styled(" Quit", t.muted),
            ],
        },
        Screen::Sandbox => match app.focus {
            Focus::SandboxLogs => {
                if app.log_selection_anchor.is_some() {
                    // Visual selection mode — reduced hint set.
                    vec![
                        Span::styled(" ", t.text),
                        Span::styled("[j/k]", t.key_hint),
                        Span::styled(" Extend", t.text),
                        Span::styled("  ", t.text),
                        Span::styled("[y]", t.key_hint),
                        Span::styled(" Yank", t.text),
                        Span::styled("  ", t.text),
                        Span::styled("[g/G]", t.key_hint),
                        Span::styled(" Top/Bottom", t.text),
                        Span::styled("  |  ", t.border),
                        Span::styled("[Esc]", t.muted),
                        Span::styled(" Cancel", t.muted),
                        Span::styled("  ", t.text),
                        Span::styled("[q]", t.muted),
                        Span::styled(" Quit", t.muted),
                    ]
                } else {
                    // Normal log viewer mode.
                    let filter_label = app.log_source_filter.label();
                    let autoscroll_label = if app.log_autoscroll {
                        " Autoscroll"
                    } else {
                        " Follow"
                    };
                    let autoscroll_style = if app.log_autoscroll {
                        t.status_ok
                    } else {
                        t.text
                    };
                    vec![
                        Span::styled(" ", t.text),
                        Span::styled("[j/k]", t.key_hint),
                        Span::styled(" Navigate", t.text),
                        Span::styled("  ", t.text),
                        Span::styled("[Enter]", t.key_hint),
                        Span::styled(" Detail", t.text),
                        Span::styled("  ", t.text),
                        Span::styled("[g/G]", t.key_hint),
                        Span::styled(" Top/Bottom", t.text),
                        Span::styled("  ", t.text),
                        Span::styled("[f]", t.key_hint),
                        Span::styled(autoscroll_label, autoscroll_style),
                        Span::styled("  ", t.text),
                        Span::styled("[s]", t.key_hint),
                        Span::styled(format!(" Source: {filter_label}"), t.text),
                        Span::styled("  ", t.text),
                        Span::styled("[y]", t.key_hint),
                        Span::styled(" Copy", t.text),
                        Span::styled("  ", t.text),
                        Span::styled("[Y]", t.key_hint),
                        Span::styled(" Copy All", t.text),
                        Span::styled("  ", t.text),
                        Span::styled("[v]", t.key_hint),
                        Span::styled(" Select", t.text),
                        Span::styled("  ", t.text),
                        Span::styled("[r]", t.key_hint),
                        Span::styled(" Rules", t.text),
                        Span::styled("  |  ", t.border),
                        Span::styled("[Esc]", t.muted),
                        Span::styled(" Policy", t.muted),
                        Span::styled("  ", t.text),
                        Span::styled("[q]", t.muted),
                        Span::styled(" Quit", t.muted),
                    ]
                }
            }
            Focus::SandboxDraft => {
                // Build state-aware action hints based on selected chunk.
                let selected_status = app
                    .draft_chunks
                    .get(app.draft_scroll + app.draft_selected)
                    .map(|c| c.status.as_str())
                    .unwrap_or("");
                let mut spans = vec![
                    Span::styled(" ", t.text),
                    Span::styled("[j/k]", t.key_hint),
                    Span::styled(" Navigate", t.text),
                    Span::styled("  ", t.text),
                    Span::styled("[Enter]", t.key_hint),
                    Span::styled(" Detail", t.text),
                ];
                match selected_status {
                    "pending" => {
                        spans.extend([
                            Span::styled("  ", t.text),
                            Span::styled("[a]", t.key_hint),
                            Span::styled(" Approve", t.text),
                            Span::styled("  ", t.text),
                            Span::styled("[x]", t.key_hint),
                            Span::styled(" Reject", t.text),
                            Span::styled("  ", t.text),
                            Span::styled("[A]", t.key_hint),
                            Span::styled(" Approve All", t.text),
                        ]);
                    }
                    "approved" => {
                        spans.extend([
                            Span::styled("  ", t.text),
                            Span::styled("[x]", t.key_hint),
                            Span::styled(" Revoke", t.text),
                        ]);
                    }
                    "rejected" => {
                        spans.extend([
                            Span::styled("  ", t.text),
                            Span::styled("[a]", t.key_hint),
                            Span::styled(" Approve", t.text),
                        ]);
                    }
                    _ => {}
                }
                spans.extend([
                    Span::styled("  ", t.text),
                    Span::styled("[p]", t.key_hint),
                    Span::styled(" Policy", t.text),
                    Span::styled("  ", t.text),
                    Span::styled("[l]", t.key_hint),
                    Span::styled(" Logs", t.text),
                    Span::styled("  |  ", t.border),
                    Span::styled("[Esc]", t.muted),
                    Span::styled(" Back", t.muted),
                    Span::styled("  ", t.text),
                    Span::styled("[q]", t.muted),
                    Span::styled(" Quit", t.muted),
                ]);
                spans
            }
            _ => vec![
                Span::styled(" ", t.text),
                Span::styled("[j/k]", t.key_hint),
                Span::styled(" Scroll", t.text),
                Span::styled("  ", t.text),
                Span::styled("[g/G]", t.key_hint),
                Span::styled(" Top/Bottom", t.text),
                Span::styled("  ", t.text),
                Span::styled("[s]", t.key_hint),
                Span::styled(" Shell", t.text),
                Span::styled("  ", t.text),
                Span::styled("[l]", t.key_hint),
                Span::styled(" Logs", t.text),
                Span::styled("  ", t.text),
                Span::styled("[r]", t.key_hint),
                Span::styled(" Rules", t.text),
                Span::styled("  ", t.text),
                Span::styled("[d]", t.key_hint),
                Span::styled(" Delete", t.text),
                Span::styled("  |  ", t.border),
                Span::styled("[Esc]", t.muted),
                Span::styled(" Back", t.muted),
                Span::styled("  ", t.text),
                Span::styled("[q]", t.muted),
                Span::styled(" Quit", t.muted),
            ],
        },
    };

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_command_bar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let t = &app.theme;
    let line = match app.input_mode {
        InputMode::Command => Line::from(vec![
            Span::styled(" :", t.accent_bold),
            Span::styled(&app.command_input, t.text),
            Span::styled("_", t.accent),
        ]),
        InputMode::Normal => Line::from(vec![Span::styled("", t.muted)]),
    };

    let bar = Paragraph::new(line).block(Block::default().borders(Borders::NONE));
    frame.render_widget(bar, area);
}
