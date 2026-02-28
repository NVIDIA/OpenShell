use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};

use crate::app::{App, CreateProviderPhase, ProviderKeyField};
use crate::theme::styles;

/// Draw the create provider modal overlay.
pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(form) = &app.create_provider_form else {
        return;
    };

    match form.phase {
        CreateProviderPhase::SelectType => draw_select_type(frame, form, area),
        CreateProviderPhase::ChooseMethod => draw_choose_method(frame, form, area),
        CreateProviderPhase::EnterKey => draw_enter_key(frame, form, area),
        CreateProviderPhase::Creating => draw_creating(frame, form, area),
    }
}

// ---------------------------------------------------------------------------
// Phase 1: Select provider type
// ---------------------------------------------------------------------------

fn draw_select_type(frame: &mut Frame<'_>, form: &crate::app::CreateProviderForm, area: Rect) {
    let modal_width = 50u16.min(area.width.saturating_sub(4));
    #[allow(clippy::cast_possible_truncation)]
    let type_rows = form.types.len().clamp(1, 10) as u16;
    // header(1) + spacer(1) + types + spacer(1) + hint(1)
    let content_height = 1 + 1 + type_rows + 1 + 1;
    let modal_height = (content_height + 4).min(area.height.saturating_sub(2));
    let popup_area = centered_rect(modal_width, modal_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(" Create Provider ", styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::ACCENT)
        .padding(Padding::new(2, 2, 1, 1));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),         // header
            Constraint::Length(1),         // spacer
            Constraint::Length(type_rows), // type list
            Constraint::Length(1),         // spacer
            Constraint::Length(1),         // hint
            Constraint::Min(0),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "Select provider type:",
            styles::TEXT,
        ))),
        chunks[0],
    );

    let lines: Vec<Line<'_>> = form
        .types
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let is_cursor = i == form.type_cursor;
            let marker = if is_cursor { ">" } else { " " };
            let style = if is_cursor {
                styles::ACCENT
            } else {
                styles::TEXT
            };
            Line::from(vec![
                Span::styled(format!("  {marker} "), style),
                Span::styled(t.as_str(), style),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), chunks[2]);

    let hint = Line::from(vec![
        Span::styled("[j/k]", styles::KEY_HINT),
        Span::styled(" Navigate ", styles::MUTED),
        Span::styled("[Enter]", styles::KEY_HINT),
        Span::styled(" Select ", styles::MUTED),
        Span::styled("[Esc]", styles::KEY_HINT),
        Span::styled(" Cancel", styles::MUTED),
    ]);
    frame.render_widget(Paragraph::new(hint), chunks[4]);
}

// ---------------------------------------------------------------------------
// Phase 2: Choose method (autodetect vs manual)
// ---------------------------------------------------------------------------

fn draw_choose_method(frame: &mut Frame<'_>, form: &crate::app::CreateProviderForm, area: Rect) {
    let modal_width = 55u16.min(area.width.saturating_sub(4));
    // header(1) + spacer(1) + type_label(1) + spacer(1) + 2 options + spacer(1) + hint(1)
    let content_height = 1 + 1 + 1 + 1 + 2 + 1 + 1;
    let modal_height = (content_height + 4).min(area.height.saturating_sub(2));
    let popup_area = centered_rect(modal_width, modal_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(" Create Provider ", styles::HEADING))
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
            Constraint::Length(1), // type label
            Constraint::Length(1), // spacer
            Constraint::Length(2), // options
            Constraint::Length(1), // spacer
            Constraint::Length(1), // hint
            Constraint::Min(0),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "How would you like to provide credentials?",
            styles::TEXT,
        ))),
        chunks[0],
    );

    let selected_type = &form.types[form.type_cursor];
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Type: ", styles::MUTED),
            Span::styled(selected_type.as_str(), styles::HEADING),
        ])),
        chunks[2],
    );

    let options = ["Autodetect from environment", "Enter key manually"];
    let lines: Vec<Line<'_>> = options
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let is_cursor = i == form.method_cursor;
            let marker = if is_cursor { ">" } else { " " };
            let style = if is_cursor {
                styles::ACCENT
            } else {
                styles::TEXT
            };
            Line::from(vec![
                Span::styled(format!("  {marker} "), style),
                Span::styled(*label, style),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), chunks[4]);

    let hint = Line::from(vec![
        Span::styled("[j/k]", styles::KEY_HINT),
        Span::styled(" Navigate ", styles::MUTED),
        Span::styled("[Enter]", styles::KEY_HINT),
        Span::styled(" Select ", styles::MUTED),
        Span::styled("[Esc]", styles::KEY_HINT),
        Span::styled(" Back", styles::MUTED),
    ]);
    frame.render_widget(Paragraph::new(hint), chunks[6]);
}

// ---------------------------------------------------------------------------
// Phase 3: Enter key manually (BYO)
// ---------------------------------------------------------------------------

fn draw_enter_key(frame: &mut Frame<'_>, form: &crate::app::CreateProviderForm, area: Rect) {
    let modal_width = 64u16.min(area.width.saturating_sub(4));

    let has_warning = form.warning.is_some();
    let warning_rows: u16 = if has_warning { 2 } else { 0 }; // warning + spacer

    #[allow(clippy::cast_possible_truncation)]
    let content_height = if form.is_generic {
        // type(1) + name(2) + spacer(1) + env_name(2) + value(2) + spacer(1) + submit(1) + status(1) + hint(1)
        warning_rows + 12
    } else {
        let num_creds = form.credentials.len().clamp(1, 8) as u16;
        // type(1) + name(2) + spacer(1) + creds + spacer(1) + submit(1) + status(1) + hint(1)
        warning_rows + 1 + 2 + 1 + num_creds + 1 + 1 + 1 + 1
    };
    let modal_height = (content_height + 4).min(area.height.saturating_sub(2));
    let popup_area = centered_rect(modal_width, modal_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(" Create Provider ", styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::ACCENT)
        .padding(Padding::new(2, 2, 1, 1));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Build dynamic constraints.
    let mut constraints: Vec<Constraint> = Vec::new();
    if has_warning {
        constraints.push(Constraint::Length(1)); // warning text
        constraints.push(Constraint::Length(1)); // spacer
    }
    constraints.push(Constraint::Length(1)); // type label
    constraints.push(Constraint::Length(2)); // name field
    constraints.push(Constraint::Length(1)); // spacer
    if form.is_generic {
        constraints.push(Constraint::Length(2)); // env var name
        constraints.push(Constraint::Length(2)); // value
    } else {
        #[allow(clippy::cast_possible_truncation)]
        let num_creds = form.credentials.len().clamp(1, 8) as u16;
        constraints.push(Constraint::Length(num_creds)); // credential rows
    }
    constraints.push(Constraint::Length(1)); // spacer
    constraints.push(Constraint::Length(1)); // submit
    constraints.push(Constraint::Length(1)); // status
    constraints.push(Constraint::Length(1)); // hint
    constraints.push(Constraint::Min(0));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let mut idx = 0;

    // Warning banner.
    if let Some(ref warning) = form.warning {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("⚠ ", styles::STATUS_WARN),
                Span::styled(warning.as_str(), styles::STATUS_WARN),
            ])),
            chunks[idx],
        );
        idx += 2; // warning + spacer
    }

    // Type label.
    let selected_type = &form.types[form.type_cursor];
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Type: ", styles::MUTED),
            Span::styled(selected_type.as_str(), styles::HEADING),
        ])),
        chunks[idx],
    );
    idx += 1;

    // Name field.
    let name_placeholder = format!("optional (defaults to {selected_type})");
    draw_text_field(
        frame,
        "Name",
        &form.name,
        &name_placeholder,
        form.key_field == ProviderKeyField::Name,
        chunks[idx],
    );
    idx += 1;

    // Spacer.
    idx += 1;

    if form.is_generic {
        // Env var name field.
        draw_text_field(
            frame,
            "Env var name",
            &form.generic_env_name,
            "e.g. MY_API_KEY",
            form.key_field == ProviderKeyField::EnvVarName,
            chunks[idx],
        );
        idx += 1;

        // Value field (secret).
        draw_secret_field(
            frame,
            "Value",
            &form.generic_value,
            form.key_field == ProviderKeyField::GenericValue,
            chunks[idx],
        );
        idx += 1;
    } else {
        // Credential rows — env var name + masked value on the same line.
        let max_name_len = form
            .credentials
            .iter()
            .map(|(n, _)| n.len())
            .max()
            .unwrap_or(0);
        let lines: Vec<Line<'_>> = form
            .credentials
            .iter()
            .enumerate()
            .take(8)
            .map(|(i, (env_name, value))| {
                let is_focused =
                    form.key_field == ProviderKeyField::Credential && i == form.cred_cursor;
                let padded = format!("{:width$}", env_name, width = max_name_len);
                let name_style = if is_focused {
                    styles::ACCENT_BOLD
                } else {
                    styles::TEXT
                };
                let mut spans = vec![Span::styled(format!("  {padded}: "), name_style)];
                if value.is_empty() {
                    if is_focused {
                        spans.push(Span::styled("_", styles::ACCENT));
                    } else {
                        spans.push(Span::styled("-", styles::MUTED));
                    }
                } else {
                    let masked = mask_input_value(value);
                    spans.push(Span::styled(
                        masked,
                        if is_focused {
                            styles::ACCENT
                        } else {
                            styles::MUTED
                        },
                    ));
                    if is_focused {
                        spans.push(Span::styled("_", styles::ACCENT));
                    }
                }
                Line::from(spans)
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), chunks[idx]);
        idx += 1;
    }

    // Spacer.
    idx += 1;

    // Submit button.
    let submit_focused = form.key_field == ProviderKeyField::Submit;
    let submit_style = if submit_focused {
        styles::ACCENT_BOLD
    } else {
        styles::MUTED
    };
    let submit_label = if submit_focused {
        "  > Create Provider"
    } else {
        "  Create Provider"
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(submit_label, submit_style))),
        chunks[idx],
    );
    idx += 1;

    // Status.
    if let Some(ref status) = form.status {
        let style = if status.contains("required")
            || status.contains("failed")
            || status.contains("Failed")
        {
            styles::STATUS_ERR
        } else {
            styles::STATUS_OK
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(format!("  {status}"), style))),
            chunks[idx],
        );
    }
    idx += 1;

    // Hint.
    let hint = Line::from(vec![
        Span::styled("[Tab]", styles::KEY_HINT),
        Span::styled(" Next ", styles::MUTED),
        Span::styled("[S-Tab]", styles::KEY_HINT),
        Span::styled(" Prev ", styles::MUTED),
        Span::styled("[Enter]", styles::KEY_HINT),
        Span::styled(" Submit ", styles::MUTED),
        Span::styled("[Esc]", styles::KEY_HINT),
        Span::styled(" Back", styles::MUTED),
    ]);
    frame.render_widget(Paragraph::new(hint), chunks[idx]);
}

/// Mask a secret input value for display (truncate with `...` if long).
fn mask_input_value(value: &str) -> String {
    let len = value.len();
    if len <= 20 {
        "*".repeat(len)
    } else {
        format!("{}...", "*".repeat(17))
    }
}

// ---------------------------------------------------------------------------
// Phase 4: Creating (pacman animation + result)
// ---------------------------------------------------------------------------

fn draw_creating(frame: &mut Frame<'_>, form: &crate::app::CreateProviderForm, area: Rect) {
    let modal_width = 55u16.min(area.width.saturating_sub(4));
    // header(1) + spacer(1) + animation(1)
    let content_height = 1 + 1 + 1;
    let modal_height = (content_height + 4).min(area.height.saturating_sub(2));
    let popup_area = centered_rect(modal_width, modal_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(" Creating Provider ", styles::HEADING))
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

    let (header, header_style) = match &form.create_result {
        Some(Ok(name)) => (format!("Created provider: {name}"), styles::STATUS_OK),
        Some(Err(msg)) => (format!("Failed: {msg}"), styles::STATUS_ERR),
        None => ("Creating provider...".to_string(), styles::TEXT),
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(header, header_style))),
        chunks[0],
    );

    let elapsed_ms = form.anim_start.map_or(0, |s| s.elapsed().as_millis());
    let track_width = chunks[2].width.saturating_sub(1) as usize;
    let anim_line = super::create_sandbox::render_chase(track_width, elapsed_ms);
    frame.render_widget(Paragraph::new(anim_line), chunks[2]);
}

// ---------------------------------------------------------------------------
// Provider detail modal (Get)
// ---------------------------------------------------------------------------

pub fn draw_detail(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(detail) = &app.provider_detail else {
        return;
    };

    let modal_width = 55u16.min(area.width.saturating_sub(4));
    // name(1) + type(1) + spacer(1) + cred_key(1) + masked(1) + spacer(1) + hint(1)
    let content_height = 7;
    let modal_height = (content_height + 4).min(area.height.saturating_sub(2));
    let popup_area = centered_rect(modal_width, modal_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(" Provider Detail ", styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::ACCENT)
        .padding(Padding::new(2, 2, 1, 1));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // name
            Constraint::Length(1), // type
            Constraint::Length(1), // spacer
            Constraint::Length(1), // cred key
            Constraint::Length(1), // masked value
            Constraint::Length(1), // spacer
            Constraint::Length(1), // hint
            Constraint::Min(0),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Name: ", styles::MUTED),
            Span::styled(&detail.name, styles::HEADING),
        ])),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Type: ", styles::MUTED),
            Span::styled(&detail.provider_type, styles::TEXT),
        ])),
        chunks[1],
    );

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Credential: ", styles::MUTED),
            Span::styled(&detail.credential_key, styles::TEXT),
        ])),
        chunks[3],
    );

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Value: ", styles::MUTED),
            Span::styled(&detail.masked_value, styles::MUTED),
        ])),
        chunks[4],
    );

    let hint = Line::from(vec![
        Span::styled("[Esc]", styles::KEY_HINT),
        Span::styled(" Close", styles::MUTED),
    ]);
    frame.render_widget(Paragraph::new(hint), chunks[6]);
}

// ---------------------------------------------------------------------------
// Update provider modal
// ---------------------------------------------------------------------------

pub fn draw_update(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(form) = &app.update_provider_form else {
        return;
    };

    let modal_width = 60u16.min(area.width.saturating_sub(4));
    // name(1) + type(1) + spacer(1) + key_label(1) + value(1) + cursor_hint(1) + spacer(1) + status(1) + hint(1)
    let content_height = 9;
    let modal_height = (content_height + 4).min(area.height.saturating_sub(2));
    let popup_area = centered_rect(modal_width, modal_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(" Update Provider ", styles::HEADING))
        .borders(Borders::ALL)
        .border_style(styles::ACCENT)
        .padding(Padding::new(2, 2, 1, 1));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // name
            Constraint::Length(1), // type
            Constraint::Length(1), // spacer
            Constraint::Length(1), // key label
            Constraint::Length(1), // value input
            Constraint::Length(1), // cursor hint
            Constraint::Length(1), // spacer
            Constraint::Length(1), // status
            Constraint::Length(1), // hint
            Constraint::Min(0),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Name: ", styles::MUTED),
            Span::styled(&form.provider_name, styles::HEADING),
        ])),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Type: ", styles::MUTED),
            Span::styled(&form.provider_type, styles::TEXT),
        ])),
        chunks[1],
    );

    let key_label = if form.credential_key.is_empty() {
        "New value:"
    } else {
        &form.credential_key
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("{key_label}:"),
            styles::ACCENT_BOLD,
        ))),
        chunks[3],
    );

    // Mask the input value as dots.
    let masked: String = "*".repeat(form.new_value.len());
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!("  {masked}"), styles::ACCENT),
            Span::styled("_", styles::ACCENT),
        ])),
        chunks[4],
    );

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "  Type the new credential value",
            styles::MUTED,
        ))),
        chunks[5],
    );

    if let Some(ref status) = form.status {
        let style = if status.contains("required")
            || status.contains("failed")
            || status.contains("Failed")
        {
            styles::STATUS_ERR
        } else {
            styles::STATUS_OK
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(format!("  {status}"), style))),
            chunks[7],
        );
    }

    let hint = Line::from(vec![
        Span::styled("[Enter]", styles::KEY_HINT),
        Span::styled(" Update ", styles::MUTED),
        Span::styled("[Esc]", styles::KEY_HINT),
        Span::styled(" Cancel", styles::MUTED),
    ]);
    frame.render_widget(Paragraph::new(hint), chunks[8]);
}

// ---------------------------------------------------------------------------
// Helpers
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
            Span::styled("_", styles::ACCENT),
        ])
    } else {
        Line::from(Span::styled(format!("  {value}"), styles::TEXT))
    };
    frame.render_widget(Paragraph::new(display), chunks[1]);
}

fn draw_secret_field(frame: &mut Frame<'_>, label: &str, value: &str, focused: bool, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // label
            Constraint::Length(1), // input
        ])
        .split(area);

    let label_style = if focused {
        styles::ACCENT_BOLD
    } else {
        styles::TEXT
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(format!("{label}:"), label_style))),
        chunks[0],
    );

    let masked: String = "*".repeat(value.len());
    let display = if value.is_empty() && !focused {
        Line::from(Span::styled("  -", styles::MUTED))
    } else if focused {
        Line::from(vec![
            Span::styled(format!("  {masked}"), styles::ACCENT),
            Span::styled("_", styles::ACCENT),
        ])
    } else {
        Line::from(Span::styled(format!("  {masked}"), styles::MUTED))
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
