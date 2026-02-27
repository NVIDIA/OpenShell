mod dashboard;
pub(crate) mod sandbox_detail;
pub(crate) mod sandbox_logs;
pub(crate) mod sandboxes;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::{App, Focus, InputMode, Screen};
use crate::theme::styles;

pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
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
        Screen::Dashboard => dashboard::draw(frame, app, chunks[1]),
        Screen::Sandbox => draw_sandbox_screen(frame, app, chunks[1]),
    }

    draw_nav_bar(frame, app, chunks[2]);
    draw_command_bar(frame, app, chunks[3]);
}

// ---------------------------------------------------------------------------
// Sandbox full-screen
// ---------------------------------------------------------------------------

fn draw_sandbox_screen(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    match app.focus {
        Focus::SandboxLogs => sandbox_logs::draw(frame, app, area),
        _ => sandbox_detail::draw(frame, app, area),
    }
}

// ---------------------------------------------------------------------------
// Chrome: title bar, nav bar, command bar
// ---------------------------------------------------------------------------

fn draw_title_bar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let status_span = match app.status_text.as_str() {
        s if s.contains("Healthy") => Span::styled(&app.status_text, styles::STATUS_OK),
        s if s.contains("Degraded") => Span::styled(&app.status_text, styles::STATUS_WARN),
        s if s.contains("Unhealthy") => Span::styled(&app.status_text, styles::STATUS_ERR),
        _ => Span::styled(&app.status_text, styles::MUTED),
    };

    let mut parts: Vec<Span<'_>> = vec![
        Span::styled(" Gator", styles::ACCENT_BOLD),
        Span::styled(" │ ", styles::MUTED),
        Span::styled("Current Cluster: ", styles::TEXT),
        Span::styled(&app.cluster_name, styles::HEADING),
        Span::styled(" (", styles::MUTED),
        status_span,
        Span::styled(")", styles::MUTED),
        Span::styled(" │ ", styles::MUTED),
    ];

    match app.screen {
        Screen::Dashboard => {
            parts.push(Span::styled("Dashboard", styles::TEXT));
        }
        Screen::Sandbox => {
            let name = app
                .sandbox_names
                .get(app.sandbox_selected)
                .map_or("-", String::as_str);
            parts.push(Span::styled("Sandbox: ", styles::TEXT));
            parts.push(Span::styled(name, styles::HEADING));
        }
    }

    let title = Line::from(parts);
    frame.render_widget(Paragraph::new(title).style(styles::TITLE_BAR), area);
}

fn draw_nav_bar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let spans = match app.screen {
        Screen::Dashboard => vec![
            Span::styled(" ", styles::TEXT),
            Span::styled("[Tab]", styles::KEY_HINT),
            Span::styled(" Switch Panel", styles::TEXT),
            Span::styled("  ", styles::TEXT),
            Span::styled("[Enter]", styles::KEY_HINT),
            Span::styled(" Select", styles::TEXT),
            Span::styled("  ", styles::TEXT),
            Span::styled("[j/k]", styles::KEY_HINT),
            Span::styled(" Navigate", styles::TEXT),
            Span::styled("  │  ", styles::BORDER),
            Span::styled("[:]", styles::MUTED),
            Span::styled(" Command  ", styles::MUTED),
            Span::styled("[q]", styles::MUTED),
            Span::styled(" Quit", styles::MUTED),
        ],
        Screen::Sandbox => match app.focus {
            Focus::SandboxLogs => {
                let filter_label = app.log_source_filter.label();
                let autoscroll_label = if app.log_autoscroll {
                    " Autoscroll"
                } else {
                    " Follow"
                };
                let autoscroll_style = if app.log_autoscroll {
                    styles::STATUS_OK
                } else {
                    styles::TEXT
                };
                vec![
                    Span::styled(" ", styles::TEXT),
                    Span::styled("[j/k]", styles::KEY_HINT),
                    Span::styled(" Navigate", styles::TEXT),
                    Span::styled("  ", styles::TEXT),
                    Span::styled("[Enter]", styles::KEY_HINT),
                    Span::styled(" Detail", styles::TEXT),
                    Span::styled("  ", styles::TEXT),
                    Span::styled("[g/G]", styles::KEY_HINT),
                    Span::styled(" Top/Bottom", styles::TEXT),
                    Span::styled("  ", styles::TEXT),
                    Span::styled("[f]", styles::KEY_HINT),
                    Span::styled(autoscroll_label, autoscroll_style),
                    Span::styled("  ", styles::TEXT),
                    Span::styled("[s]", styles::KEY_HINT),
                    Span::styled(format!(" Source: {filter_label}"), styles::TEXT),
                    Span::styled("  │  ", styles::BORDER),
                    Span::styled("[Esc]", styles::MUTED),
                    Span::styled(" Back", styles::MUTED),
                    Span::styled("  ", styles::TEXT),
                    Span::styled("[q]", styles::MUTED),
                    Span::styled(" Quit", styles::MUTED),
                ]
            }
            _ => vec![
                Span::styled(" ", styles::TEXT),
                Span::styled("[l]", styles::KEY_HINT),
                Span::styled(" Logs", styles::TEXT),
                Span::styled("  ", styles::TEXT),
                Span::styled("[d]", styles::KEY_HINT),
                Span::styled(" Delete", styles::TEXT),
                Span::styled("  │  ", styles::BORDER),
                Span::styled("[Esc]", styles::MUTED),
                Span::styled(" Back to Dashboard", styles::MUTED),
                Span::styled("  ", styles::TEXT),
                Span::styled("[q]", styles::MUTED),
                Span::styled(" Quit", styles::MUTED),
            ],
        },
    };

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_command_bar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let line = match app.input_mode {
        InputMode::Command => Line::from(vec![
            Span::styled(" :", styles::ACCENT_BOLD),
            Span::styled(&app.command_input, styles::TEXT),
            Span::styled("█", styles::ACCENT),
        ]),
        InputMode::Normal => Line::from(vec![Span::styled("", styles::MUTED)]),
    };

    let bar = Paragraph::new(line).block(Block::default().borders(Borders::NONE));
    frame.render_widget(bar, area);
}
