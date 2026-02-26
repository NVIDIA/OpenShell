use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Padding, Paragraph, Row, Table};

use crate::app::{App, Focus};
use crate::theme::styles;

pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    // Dynamic height: cluster table gets just enough rows, rest goes to sandbox table.
    #[allow(clippy::cast_possible_truncation)]
    let cluster_height = (app.clusters.len() as u16 + 4).clamp(5, 12);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(cluster_height), Constraint::Min(0)])
        .split(area);

    draw_cluster_list(frame, app, chunks[0]);
    super::sandboxes::draw(frame, app, chunks[1], app.focus == Focus::Sandboxes);
}

fn draw_cluster_list(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let focused = app.focus == Focus::Clusters;

    let header = Row::new(vec![
        Cell::from(Span::styled("  NAME", styles::MUTED)),
        Cell::from(Span::styled("ENDPOINT", styles::MUTED)),
        Cell::from(Span::styled("TYPE", styles::MUTED)),
        Cell::from(Span::styled("STATUS", styles::MUTED)),
    ])
    .bottom_margin(1);

    let rows: Vec<Row<'_>> = app
        .clusters
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let is_active = entry.name == app.cluster_name;
            let is_cursor = focused && i == app.cluster_selected;

            // Name cell: cursor marker (▌) + active dot (●).
            let cursor = if is_cursor { "▌" } else { " " };
            let dot = if is_active { "● " } else { "  " };
            let dot_style = if is_active {
                styles::STATUS_OK
            } else {
                styles::MUTED
            };
            let name_style = if is_active {
                styles::HEADING
            } else {
                styles::TEXT
            };
            let name_cell = Cell::from(Line::from(vec![
                Span::styled(cursor, styles::ACCENT),
                Span::styled(dot, dot_style),
                Span::styled(&entry.name, name_style),
            ]));

            let type_label = if entry.is_remote { "remote" } else { "local" };

            let status_cell = if is_active {
                let status_style = if app.status_text.contains("Healthy") {
                    styles::STATUS_OK
                } else if app.status_text.contains("Degraded") {
                    styles::STATUS_WARN
                } else if app.status_text.contains("Unhealthy") {
                    styles::STATUS_ERR
                } else {
                    styles::MUTED
                };
                Cell::from(Line::from(vec![
                    Span::styled("● ", status_style),
                    Span::styled(&app.status_text, status_style),
                ]))
            } else {
                Cell::from(Span::styled("─", styles::MUTED))
            };

            Row::new(vec![
                name_cell,
                Cell::from(Span::styled(&entry.endpoint, styles::MUTED)),
                Cell::from(Span::styled(type_label, styles::MUTED)),
                status_cell,
            ])
        })
        .collect();

    let border_style = if focused {
        styles::BORDER_FOCUSED
    } else {
        styles::BORDER
    };

    let block = Block::default()
        .title(Span::styled(" Clusters ", styles::HEADING))
        .borders(Borders::ALL)
        .border_style(border_style)
        .padding(Padding::horizontal(1));

    let widths = [
        Constraint::Percentage(25),
        Constraint::Percentage(35),
        Constraint::Percentage(15),
        Constraint::Percentage(25),
    ];

    let table = Table::new(rows, widths).header(header).block(block);

    frame.render_widget(table, area);

    if app.clusters.is_empty() {
        let inner = Rect {
            x: area.x + 2,
            y: area.y + 2,
            width: area.width.saturating_sub(4),
            height: area.height.saturating_sub(3),
        };
        let msg = Paragraph::new(Span::styled(
            " No clusters found. Run `nav cluster admin deploy` to create one.",
            styles::MUTED,
        ));
        frame.render_widget(msg, inner);
    }
}
