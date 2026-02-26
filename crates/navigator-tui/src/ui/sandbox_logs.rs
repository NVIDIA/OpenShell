use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::theme::styles;

pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let name = app
        .sandbox_names
        .get(app.sandbox_selected)
        .map_or("-", String::as_str);

    let block = Block::default()
        .title(Span::styled(format!(" Logs: {name} "), styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::BORDER_FOCUSED)
        .padding(Padding::horizontal(1));

    // Calculate visible area inside the block (borders + padding).
    let inner_height = area.height.saturating_sub(2) as usize; // top + bottom border

    let lines: Vec<Line<'_>> = app
        .sandbox_log_lines
        .iter()
        .skip(app.sandbox_log_scroll)
        .take(inner_height)
        .map(|line| {
            // Color log lines by level.
            let style = if line.contains("ERROR") {
                styles::STATUS_ERR
            } else if line.contains("WARN") {
                styles::STATUS_WARN
            } else if line.contains("INFO") {
                styles::STATUS_OK
            } else {
                styles::MUTED
            };
            Line::from(Span::styled(line.as_str(), style))
        })
        .collect();

    // Show scroll position in the title area.
    let total = app.sandbox_log_lines.len();
    let pos = app.sandbox_log_scroll + 1;
    let scroll_info = if total > 0 {
        format!(" [{pos}/{total}] ")
    } else {
        String::new()
    };

    let block = block.title_bottom(Line::from(vec![
        Span::styled(scroll_info, styles::MUTED),
        Span::styled(
            " [j/k] Scroll  [g/G] Top/Bottom  [Esc] Back ",
            styles::MUTED,
        ),
    ]));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}
