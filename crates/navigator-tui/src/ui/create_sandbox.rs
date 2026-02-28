use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};

use crate::app::{App, CreateFormField, CreatePhase};
use crate::theme::styles;

/// Draw the create sandbox modal overlay.
pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(form) = &app.create_form else {
        return;
    };

    match form.phase {
        CreatePhase::Form => draw_form(frame, app, area),
        CreatePhase::Creating => draw_creating(frame, app, area),
    }
}

// ---------------------------------------------------------------------------
// Form view
// ---------------------------------------------------------------------------

fn draw_form(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(form) = &app.create_form else {
        return;
    };

    let modal_width = 72u16.min(area.width.saturating_sub(4));

    #[allow(clippy::cast_possible_truncation)]
    let provider_rows = form.providers.len().clamp(1, 8) as u16;
    let content_height = 3 + 3 + 3 + 1 + 1 + provider_rows + 1 + 1 + 1 + 1 + 1;
    let modal_height = (content_height + 3).min(area.height.saturating_sub(2));
    let popup_area = centered_rect(modal_width, modal_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(" Create Sandbox ", styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::ACCENT)
        .padding(Padding::new(2, 2, 1, 1));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let constraints = [
        Constraint::Length(3),             // Name
        Constraint::Length(3),             // Image
        Constraint::Length(3),             // Command
        Constraint::Length(1),             // Spacer
        Constraint::Length(1),             // Providers label
        Constraint::Length(provider_rows), // Provider list
        Constraint::Length(1),             // Spacer
        Constraint::Length(1),             // Submit button
        Constraint::Length(1),             // Status message
        Constraint::Length(1),             // Spacer
        Constraint::Length(1),             // Nav hint
        Constraint::Min(0),
    ];

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    // --- Name ---
    draw_text_field(
        frame,
        "Name",
        &form.name,
        "optional — auto-generated if empty",
        form.focused_field == CreateFormField::Name,
        chunks[0],
    );

    // --- Image ---
    draw_text_field(
        frame,
        "Image",
        &form.image,
        "optional — server default if empty",
        form.focused_field == CreateFormField::Image,
        chunks[1],
    );

    // --- Command ---
    draw_text_field(
        frame,
        "Command",
        &form.command,
        "entrypoint to run in the sandbox",
        form.focused_field == CreateFormField::Command,
        chunks[2],
    );

    // --- Providers label ---
    let providers_focused = form.focused_field == CreateFormField::Providers;
    let prov_label_style = if providers_focused {
        styles::ACCENT_BOLD
    } else {
        styles::TEXT
    };
    let prov_hint = if providers_focused {
        Span::styled("  [Space] toggle  [j/k] navigate", styles::MUTED)
    } else {
        Span::styled("", styles::MUTED)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Providers:", prov_label_style),
            prov_hint,
        ])),
        chunks[4],
    );

    // --- Provider list (existing providers by name + type) ---
    if form.providers.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  (none — create providers first)",
                styles::MUTED,
            ))),
            chunks[5],
        );
    } else {
        let lines: Vec<Line<'_>> = form
            .providers
            .iter()
            .enumerate()
            .take(provider_rows as usize)
            .map(|(i, p)| {
                let checkbox = if p.selected { "[x]" } else { "[ ]" };
                let is_cursor = providers_focused && i == form.provider_cursor;
                let marker = if is_cursor { ">" } else { " " };
                let style = if is_cursor {
                    styles::ACCENT
                } else {
                    styles::TEXT
                };
                let type_display = if p.provider_type.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", p.provider_type)
                };
                Line::from(vec![
                    Span::styled(format!("  {marker} {checkbox} "), style),
                    Span::styled(&p.name, style),
                    Span::styled(type_display, styles::MUTED),
                ])
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), chunks[5]);
    }

    // --- Submit ---
    let submit_focused = form.focused_field == CreateFormField::Submit;
    let submit_style = if submit_focused {
        styles::ACCENT_BOLD
    } else {
        styles::MUTED
    };
    let submit_label = if submit_focused {
        "  ▶ Create Sandbox"
    } else {
        "  Create Sandbox"
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(submit_label, submit_style))),
        chunks[7],
    );

    // --- Status ---
    if let Some(ref status) = form.status {
        let style = if status.contains("failed") || status.contains("error") {
            styles::STATUS_ERR
        } else if status.contains("Created") {
            styles::STATUS_OK
        } else {
            styles::MUTED
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(format!("  {status}"), style))),
            chunks[8],
        );
    }

    // --- Nav hint ---
    let hint = Line::from(vec![
        Span::styled("[Tab]", styles::KEY_HINT),
        Span::styled(" Next ", styles::MUTED),
        Span::styled("[S-Tab]", styles::KEY_HINT),
        Span::styled(" Prev ", styles::MUTED),
        Span::styled("[Enter]", styles::KEY_HINT),
        Span::styled(" Submit ", styles::MUTED),
        Span::styled("[Esc]", styles::KEY_HINT),
        Span::styled(" Cancel", styles::MUTED),
    ]);
    frame.render_widget(Paragraph::new(hint), chunks[10]);
}

// ---------------------------------------------------------------------------
// Creating animation view
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Creating view — shown after user confirms, sandbox being created
// ---------------------------------------------------------------------------

fn draw_creating(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(form) = &app.create_form else {
        return;
    };

    // content: header(1) + spacer(1) + animation(1)
    // chrome:  border(2) + padding top/bottom(2)
    let content_height = 1 + 1 + 1;
    let modal_width = 60u16.min(area.width.saturating_sub(4));
    let modal_height = (content_height + 4).min(area.height.saturating_sub(2));
    let popup_area = centered_rect(modal_width, modal_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(" Creating Sandbox ", styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::ACCENT)
        .padding(Padding::new(2, 2, 1, 1));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Length(1), // spacer
            Constraint::Length(1), // animation
            Constraint::Min(0),
        ])
        .split(inner);

    // Header — changes once result arrives.
    let (header, header_style) = match &form.create_result {
        Some(Ok(name)) => (format!("Created sandbox: {name}"), styles::STATUS_OK),
        Some(Err(msg)) => (format!("Failed: {msg}"), styles::STATUS_ERR),
        None => ("Creating sandbox...".to_string(), styles::TEXT),
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(header, header_style))),
        chunks[0],
    );

    // Pacman chase animation.
    let elapsed_ms = form.anim_start.map_or(0, |s| s.elapsed().as_millis());
    let track_width = chunks[2].width.saturating_sub(1) as usize;
    let anim_line = render_chase(track_width, elapsed_ms);
    frame.render_widget(Paragraph::new(anim_line), chunks[2]);
}

/// Render the NVIDIA pacman chasing a maroon claw across a dot track.
///
/// The sprite scrolls right across `track_width`, wrapping around.
pub fn render_chase(track_width: usize, elapsed_ms: u128) -> Line<'static> {
    if track_width < 10 {
        return Line::from(Span::styled("...", styles::MUTED));
    }

    let frame = (elapsed_ms / 140) as usize;
    let mouth_open = frame % 2 == 0;

    // Characters.
    let pac = if mouth_open { "ᗧ" } else { "●" };
    let claw = ">('>"; // lobster claw facing right

    let dot_char = '·';
    let num_dots: usize = 6;
    let claw_len = claw.len();

    // Sprite total width: pac(1) + gaps with dots(num_dots * 2) + space + claw.
    let sprite_width = 1 + num_dots * 2 + 1 + claw_len;

    // Position: how far the left edge of the sprite is from the left wall.
    // Cycle length = track_width + sprite_width (fully off-screen before wrap).
    let cycle = track_width + sprite_width;
    let pos = frame % cycle;

    // Build character-by-character: a track_width buffer of (content, style) slots.
    // We'll collect spans by walking the sprite across the track.
    let mut buf: Vec<(char, ratatui::style::Style)> = vec![(' ', styles::MUTED); track_width];

    // Helper: place a character if it's within bounds.
    let mut place = |col: usize, ch: char, style: ratatui::style::Style| {
        // `col` is the absolute position (can be negative via wrapping, so use isize).
        if col < track_width {
            buf[col] = (ch, style);
        }
    };

    // Pacman position (left edge of sprite).
    let pac_col = pos;
    // Place pacman.
    for (i, ch) in pac.chars().enumerate() {
        place(pac_col.wrapping_add(i), ch, styles::ACCENT_BOLD);
    }

    // Dots after pacman.
    for d in 0..num_dots {
        let col = pac_col + 1 + d * 2;
        place(col, ' ', styles::MUTED);
        place(col + 1, dot_char, styles::MUTED);
    }

    // Claw after the dots.
    let claw_col = pac_col + 1 + num_dots * 2 + 1;
    for (i, ch) in claw.chars().enumerate() {
        place(claw_col + i, ch, styles::CLAW);
    }

    // Convert buffer to spans (group consecutive same-style chars).
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut current_str = String::new();
    let mut current_style = buf[0].1;

    for &(ch, style) in &buf {
        if style == current_style {
            current_str.push(ch);
        } else {
            if !current_str.is_empty() {
                spans.push(Span::styled(current_str.clone(), current_style));
                current_str.clear();
            }
            current_style = style;
            current_str.push(ch);
        }
    }
    if !current_str.is_empty() {
        spans.push(Span::styled(current_str, current_style));
    }

    Line::from(spans)
}

// ---------------------------------------------------------------------------
// Form helpers
// ---------------------------------------------------------------------------

fn draw_text_field(
    frame: &mut Frame<'_>,
    label: &str,
    value: &str,
    placeholder: &str,
    focused: bool,
    area: Rect,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // label
            Constraint::Length(1), // input
            Constraint::Length(1), // gap
        ])
        .split(area);

    let label_style = if focused {
        styles::ACCENT_BOLD
    } else {
        styles::TEXT
    };
    let mut label_spans = vec![Span::styled(format!("{label}:"), label_style)];
    if !placeholder.is_empty() {
        label_spans.push(Span::styled(format!("  {placeholder}"), styles::MUTED));
    }
    frame.render_widget(Paragraph::new(Line::from(label_spans)), chunks[0]);

    let display = if value.is_empty() && !focused {
        Line::from(Span::styled("  -", styles::MUTED))
    } else if focused {
        Line::from(vec![
            Span::styled(format!("  {value}"), styles::ACCENT),
            Span::styled("█", styles::ACCENT),
        ])
    } else {
        Line::from(Span::styled(format!("  {value}"), styles::TEXT))
    };
    frame.render_widget(Paragraph::new(display), chunks[1]);
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
