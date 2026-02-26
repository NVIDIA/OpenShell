use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::theme::styles;

pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let idx = app.sandbox_selected;
    let name = app.sandbox_names.get(idx).map_or("-", String::as_str);
    let phase = app.sandbox_phases.get(idx).map_or("-", String::as_str);
    let image = app.sandbox_images.get(idx).map_or("-", String::as_str);
    let created = app.sandbox_created.get(idx).map_or("-", String::as_str);
    let age = app.sandbox_ages.get(idx).map_or("-", String::as_str);

    let phase_style = match phase {
        "Ready" => styles::STATUS_OK,
        "Provisioning" => styles::STATUS_WARN,
        "Error" => styles::STATUS_ERR,
        _ => styles::MUTED,
    };

    let status_indicator = match phase {
        "Ready" => "●",
        "Provisioning" => "◐",
        "Error" => "○",
        _ => "…",
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Name:     ", styles::MUTED),
            Span::styled(name, styles::HEADING),
        ]),
        Line::from(vec![
            Span::styled("  Status:   ", styles::MUTED),
            Span::styled(format!("{status_indicator} "), phase_style),
            Span::styled(phase, phase_style),
        ]),
        Line::from(vec![
            Span::styled("  Image:    ", styles::MUTED),
            Span::styled(image, styles::TEXT),
        ]),
        Line::from(vec![
            Span::styled("  Created:  ", styles::MUTED),
            Span::styled(created, styles::TEXT),
        ]),
        Line::from(vec![
            Span::styled("  Age:      ", styles::MUTED),
            Span::styled(age, styles::TEXT),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled("  Actions", styles::HEADING)]),
        Line::from(""),
    ];

    if app.confirm_delete {
        lines.push(Line::from(vec![
            Span::styled("  ", styles::TEXT),
            Span::styled("Delete sandbox '", styles::STATUS_ERR),
            Span::styled(name, styles::STATUS_ERR),
            Span::styled("'? ", styles::STATUS_ERR),
            Span::styled("[y]", styles::KEY_HINT),
            Span::styled(" Confirm  ", styles::TEXT),
            Span::styled("[Esc]", styles::KEY_HINT),
            Span::styled(" Cancel", styles::TEXT),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled("    ", styles::TEXT),
            Span::styled("[l]", styles::KEY_HINT),
            Span::styled(" View Logs", styles::TEXT),
        ]));
        lines.push(Line::from(vec![
            Span::styled("    ", styles::TEXT),
            Span::styled("[d]", styles::KEY_HINT),
            Span::styled(" Delete", styles::TEXT),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("    ", styles::TEXT),
            Span::styled("[Esc]", styles::MUTED),
            Span::styled(" Back", styles::MUTED),
        ]));
    }

    let block = Block::default()
        .title(Span::styled(format!(" Sandbox: {name} "), styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::BORDER_FOCUSED)
        .padding(Padding::horizontal(1));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}
