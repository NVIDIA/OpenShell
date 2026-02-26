use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};

use crate::app::{App, LogLine};
use crate::theme::styles;

pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let name = app
        .sandbox_names
        .get(app.sandbox_selected)
        .map_or("-", String::as_str);

    let filter_label = app.log_source_filter.label();

    let block = Block::default()
        .title(Span::styled(format!(" Logs: {name} "), styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::BORDER_FOCUSED)
        .padding(Padding::horizontal(1));

    // Calculate visible area inside the block (borders + padding).
    let inner_height = area.height.saturating_sub(2) as usize;

    let filtered: Vec<&LogLine> = app.filtered_log_lines();

    if filtered.is_empty() && app.sandbox_log_lines.is_empty() {
        // Still loading.
        let lines = vec![Line::from(Span::styled("Loading...", styles::MUTED))];
        let block = block.title_bottom(Line::from(Span::styled(
            format!(" filter: {filter_label} "),
            styles::MUTED,
        )));
        frame.render_widget(Paragraph::new(lines).block(block), area);
        return;
    }

    let lines: Vec<Line<'_>> = filtered
        .iter()
        .skip(app.sandbox_log_scroll)
        .take(inner_height)
        .map(|log| render_log_line(log))
        .collect();

    // Scroll position.
    let total = filtered.len();
    let pos = app.sandbox_log_scroll + 1;
    let scroll_info = if total > 0 {
        format!(" [{pos}/{total}] ")
    } else {
        String::new()
    };

    let block = block.title_bottom(Line::from(vec![
        Span::styled(scroll_info, styles::MUTED),
        Span::styled(format!(" filter: {filter_label} "), styles::MUTED),
    ]));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Render a single structured log line with source, level, target, message, and fields.
fn render_log_line<'a>(log: &'a LogLine) -> Line<'a> {
    let level_style = match log.level.as_str() {
        "ERROR" => styles::STATUS_ERR,
        "WARN" => styles::STATUS_WARN,
        "INFO" => styles::STATUS_OK,
        _ => styles::MUTED,
    };

    let source_style = match log.source.as_str() {
        "sandbox" => styles::ACCENT,
        _ => styles::MUTED,
    };

    let ts = format_short_time(log.timestamp_ms);

    let mut spans = vec![
        Span::styled(ts, styles::MUTED),
        Span::raw(" "),
        Span::styled(format!("{:<7}", log.source), source_style),
        Span::raw(" "),
        Span::styled(format!("{:<5}", log.level), level_style),
        Span::raw(" "),
    ];

    // Target (module path) — show abbreviated.
    if !log.target.is_empty() {
        spans.push(Span::styled(format!("[{}] ", log.target), styles::MUTED));
    }

    // Message.
    spans.push(Span::styled(log.message.as_str(), styles::TEXT));

    // Structured fields — append key=value pairs.
    if !log.fields.is_empty() {
        let mut pairs: Vec<(&String, &String)> = log.fields.iter().collect();
        pairs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in pairs {
            spans.push(Span::raw(" "));
            spans.push(Span::styled(format!("{k}="), styles::MUTED));
            spans.push(Span::styled(v.as_str(), styles::TEXT));
        }
    }

    Line::from(spans)
}

fn format_short_time(epoch_ms: i64) -> String {
    if epoch_ms <= 0 {
        return String::from("--:--:--");
    }
    let secs = epoch_ms / 1000;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}
