mod dashboard;
pub(crate) mod sandbox_detail;
pub(crate) mod sandbox_logs;
pub(crate) mod sandboxes;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::{App, InputMode, View};
use crate::theme::styles;

pub fn draw(frame: &mut Frame<'_>, app: &App) {
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

    match app.view {
        View::Dashboard => dashboard::draw(frame, app, chunks[1]),
    }

    draw_nav_bar(frame, chunks[2]);
    draw_command_bar(frame, app, chunks[3]);
}

fn draw_title_bar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let status_span = match app.status_text.as_str() {
        s if s.contains("Healthy") => Span::styled(&app.status_text, styles::STATUS_OK),
        s if s.contains("Degraded") => Span::styled(&app.status_text, styles::STATUS_WARN),
        s if s.contains("Unhealthy") => Span::styled(&app.status_text, styles::STATUS_ERR),
        _ => Span::styled(&app.status_text, styles::MUTED),
    };

    let view_label = match app.view {
        View::Dashboard => "Dashboard",
    };

    let title = Line::from(vec![
        Span::styled(" Gator", styles::ACCENT_BOLD),
        Span::styled(" ─ ", styles::MUTED),
        Span::styled(view_label, styles::TEXT),
        Span::styled(" ─ ", styles::MUTED),
        Span::styled("Cluster Status: ", styles::TEXT),
        status_span,
    ]);

    frame.render_widget(Paragraph::new(title).style(styles::TITLE_BAR), area);
}

fn draw_nav_bar(frame: &mut Frame<'_>, area: Rect) {
    let spans = vec![
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
    ];

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
