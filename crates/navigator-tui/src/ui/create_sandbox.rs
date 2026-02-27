use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};
use ratatui::Frame;

use crate::app::{App, CreateFormField, CreatePhase};
use crate::event::ProviderResolution;
use crate::theme::styles;

/// Draw the create sandbox modal overlay.
pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(form) = &app.create_form else {
        return;
    };

    match form.phase {
        CreatePhase::Form => draw_form(frame, app, area),
        CreatePhase::Resolving => draw_resolving(frame, app, area),
        CreatePhase::Confirm => draw_confirm(frame, app, area),
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

    // --- Provider list ---
    if form.providers.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  (none available)",
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
                Line::from(vec![
                    Span::styled(format!("  {marker} {checkbox} "), style),
                    Span::styled(&p.name, style),
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
// Resolving view — shown while discovering providers
// ---------------------------------------------------------------------------

fn draw_resolving(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(form) = &app.create_form else {
        return;
    };

    #[allow(clippy::cast_possible_truncation)]
    let provider_lines = form.provider_statuses.len().max(1) as u16;
    // content: header(1) + spacer(1) + providers + spacer(1) + animation(1)
    // chrome:  border(2) + padding top/bottom(2)
    let content_height = 1 + 1 + provider_lines + 1 + 1;
    let modal_width = 60u16.min(area.width.saturating_sub(4));
    let modal_height = (content_height + 4).min(area.height.saturating_sub(2));
    let popup_area = centered_rect(modal_width, modal_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(" Resolving Providers ", styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::ACCENT)
        .padding(Padding::new(2, 2, 1, 1));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),              // status text
            Constraint::Length(1),              // spacer
            Constraint::Length(provider_lines), // provider status lines
            Constraint::Length(1),              // spacer
            Constraint::Length(1),              // animation
            Constraint::Min(0),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "Checking providers...",
            styles::TEXT,
        ))),
        chunks[0],
    );

    if form.provider_statuses.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  Querying gateway...",
                styles::MUTED,
            ))),
            chunks[2],
        );
    } else {
        frame.render_widget(Paragraph::new(provider_status_lines(form)), chunks[2]);
    }

    let elapsed_ms = form.anim_start.map_or(0, |s| s.elapsed().as_millis());
    let track_width = chunks[4].width.saturating_sub(1) as usize;
    let anim_line = render_chase(track_width, elapsed_ms);
    frame.render_widget(Paragraph::new(anim_line), chunks[4]);
}

// ---------------------------------------------------------------------------
// Confirm view — show resolution results, wait for user to proceed
// ---------------------------------------------------------------------------

fn draw_confirm(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(form) = &app.create_form else {
        return;
    };

    #[allow(clippy::cast_possible_truncation)]
    let existing_count = form.existing_providers.len() as u16;
    #[allow(clippy::cast_possible_truncation)]
    let missing_count = form.missing_providers.len() as u16;
    let has_missing = missing_count > 0;

    // Missing providers: compact single-line format with inline checkbox.
    let provider_lines = existing_count + missing_count;

    // content: header(1) + spacer(1) + providers + spacer(1) + hints(1)
    // chrome:  border(2) + padding top/bottom(2)
    let content_height = 1 + 1 + provider_lines + 1 + 1;
    let modal_width = 60u16.min(area.width.saturating_sub(4));
    let modal_height = (content_height + 4).min(area.height.saturating_sub(2));
    let popup_area = centered_rect(modal_width, modal_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(" Provider Resolution ", styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::ACCENT)
        .padding(Padding::new(2, 2, 1, 1));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),              // header
            Constraint::Length(1),              // spacer
            Constraint::Length(provider_lines), // provider lines
            Constraint::Length(1),              // spacer
            Constraint::Length(1),              // nav hints
            Constraint::Min(0),
        ])
        .split(inner);

    // Header.
    let header = if has_missing {
        format!("{existing_count} on gateway, {missing_count} missing")
    } else {
        format!("All {existing_count} provider(s) found on gateway")
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(header, styles::TEXT))),
        chunks[0],
    );

    // Provider lines: existing (checkmark) + missing (compact inline toggle).
    let mut lines: Vec<Line<'_>> = Vec::new();

    for (ptype, pname) in &form.existing_providers {
        lines.push(Line::from(vec![
            Span::styled("  ✓ ", styles::STATUS_OK),
            Span::styled(format!("{ptype} -> {pname}"), styles::STATUS_OK),
        ]));
    }

    for (i, (ptype, should_create)) in form.missing_providers.iter().enumerate() {
        let is_cursor = i == form.confirm_cursor;
        let marker = if is_cursor { ">" } else { " " };
        let checkbox = if *should_create { "[x]" } else { "[ ]" };
        let style = if is_cursor {
            styles::ACCENT
        } else {
            styles::STATUS_ERR
        };
        let cb_style = if is_cursor {
            styles::ACCENT
        } else {
            styles::MUTED
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {marker}✗ "), style),
            Span::styled(format!("{ptype}"), style),
            Span::styled(format!("  {checkbox} create from local creds?"), cb_style),
        ]));
    }

    frame.render_widget(Paragraph::new(lines), chunks[2]);

    // Nav hints.
    let mut hint_spans = vec![
        Span::styled("[Enter]", styles::KEY_HINT),
        Span::styled(" Create ", styles::MUTED),
        Span::styled("[Esc]", styles::KEY_HINT),
        Span::styled(" Cancel", styles::MUTED),
    ];
    if has_missing {
        hint_spans.splice(
            0..0,
            [
                Span::styled("[j/k]", styles::KEY_HINT),
                Span::styled(" Nav ", styles::MUTED),
                Span::styled("[Space]", styles::KEY_HINT),
                Span::styled(" Toggle ", styles::MUTED),
            ],
        );
    }
    frame.render_widget(Paragraph::new(Line::from(hint_spans)), chunks[4]);
}

// ---------------------------------------------------------------------------
// Creating view — shown after user confirms, sandbox being created
// ---------------------------------------------------------------------------

fn draw_creating(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(form) = &app.create_form else {
        return;
    };

    let has_statuses = !form.provider_statuses.is_empty();

    #[allow(clippy::cast_possible_truncation)]
    let status_lines = if has_statuses {
        form.provider_statuses.len() as u16
    } else {
        0
    };
    // Spacer between statuses and animation only if there are statuses.
    let status_spacer = u16::from(has_statuses);

    // content: header(1) + spacer(1) + statuses + status_spacer + animation(1)
    // chrome:  border(2) + padding top/bottom(2)
    let content_height = 1 + 1 + status_lines + status_spacer + 1;
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
            Constraint::Length(1),             // header
            Constraint::Length(1),             // spacer
            Constraint::Length(status_lines),  // provider discovery progress
            Constraint::Length(status_spacer), // spacer (only if statuses)
            Constraint::Length(1),             // animation
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

    // Provider discovery progress.
    if has_statuses {
        frame.render_widget(Paragraph::new(provider_status_lines(form)), chunks[2]);
    }

    // Pacman chase animation.
    let elapsed_ms = form.anim_start.map_or(0, |s| s.elapsed().as_millis());
    let track_width = chunks[4].width.saturating_sub(1) as usize;
    let anim_line = render_chase(track_width, elapsed_ms);
    frame.render_widget(Paragraph::new(anim_line), chunks[4]);
}

// ---------------------------------------------------------------------------
// Shared provider status line rendering
// ---------------------------------------------------------------------------

fn provider_status_lines(form: &crate::app::CreateSandboxForm) -> Vec<Line<'static>> {
    form.provider_statuses
        .iter()
        .map(|(ptype, resolution)| {
            let (icon, desc, style) = match resolution {
                ProviderResolution::Exists(name) => (
                    "✓",
                    format!("{ptype} -> {name} (exists)"),
                    styles::STATUS_OK,
                ),
                ProviderResolution::Missing => {
                    ("✗", format!("{ptype}: not on gateway"), styles::STATUS_ERR)
                }
                ProviderResolution::Discovering => (
                    "…",
                    format!("{ptype}: discovering local credentials"),
                    styles::MUTED,
                ),
                ProviderResolution::Created(name) => (
                    "✓",
                    format!("{ptype} -> {name} (created from local creds)"),
                    styles::STATUS_OK,
                ),
                ProviderResolution::NotFound => (
                    "✗",
                    format!("{ptype}: no local credentials found"),
                    styles::STATUS_ERR,
                ),
                ProviderResolution::Failed(msg) => {
                    ("✗", format!("{ptype}: {msg}"), styles::STATUS_ERR)
                }
            };
            Line::from(vec![
                Span::styled(format!("  {icon} "), style),
                Span::styled(desc, style),
            ])
        })
        .collect()
}

/// Render the NVIDIA pacman chasing a maroon claw across a dot track.
///
/// The sprite scrolls right across `track_width`, wrapping around.
fn render_chase(track_width: usize, elapsed_ms: u128) -> Line<'static> {
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
