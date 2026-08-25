// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network rules panel for the sandbox screen.

use crate::app::App;
use openshell_core::proto::{L7Allow, L7DenyRule, L7QueryMatcher, NetworkEndpoint, PolicyChunk};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};

use super::centered_rect;

/// Draw the network rules panel (list view with highlight bar).
pub fn draw(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let t = &app.theme;
    let pending_count = app
        .draft_chunks
        .iter()
        .filter(|c| c.status == "pending")
        .count();

    let title = if pending_count > 0 {
        Line::from(vec![
            Span::styled(" Network Rules ", t.heading),
            Span::styled(format!(" {pending_count} pending "), t.badge),
            Span::raw(" "),
        ])
    } else {
        Line::from(Span::styled(" Network Rules ", t.heading))
    };

    let mut block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(t.border_focused)
        .padding(Padding::horizontal(1));

    if app.sandbox_policy_is_global {
        block = block.title_bottom(
            Line::from(Span::styled(
                " Cannot approve rules while global policy is active ",
                t.status_warn,
            ))
            .left_aligned(),
        );
    }

    if app.draft_chunks.is_empty() {
        let msg = Paragraph::new(
            "No network rules yet. Denied connections will \
             generate rules automatically.",
        )
        .block(block)
        .style(t.muted);
        frame.render_widget(msg, area);
        return;
    }

    // Calculate visible area inside the block (borders + padding).
    let inner_height = area.height.saturating_sub(2) as usize;
    app.draft_viewport_height = inner_height;

    // Clamp cursor to visible range.
    let total = app.draft_chunks.len();
    let visible_count = total.saturating_sub(app.draft_scroll).min(inner_height);
    if visible_count > 0 {
        app.draft_selected = app.draft_selected.min(visible_count - 1);
    }

    let cursor_pos = app.draft_selected;

    let lines: Vec<Line<'_>> = app
        .draft_chunks
        .iter()
        .skip(app.draft_scroll)
        .take(inner_height)
        .enumerate()
        .map(|(i, chunk)| {
            let is_selected = i == cursor_pos;

            let globally_locked = app.sandbox_policy_is_global;

            let status_style = if globally_locked {
                t.muted
            } else {
                match chunk.status.as_str() {
                    "pending" => t.status_warn,
                    "approved" => t.status_ok,
                    "rejected" => t.status_err,
                    _ => t.muted,
                }
            };

            let name_style = if globally_locked {
                t.muted
            } else if is_selected {
                t.selected
            } else if chunk.status == "rejected" {
                t.muted
            } else {
                t.text
            };

            let mut spans = Vec::new();

            // Highlight bar prefix (like logs).
            if is_selected {
                spans.push(Span::styled("▌ ", t.accent));
            } else {
                spans.push(Span::raw("  "));
            }

            // Endpoint summary with L4/L7 detail.
            let endpoint_str = chunk
                .proposed_rule
                .as_ref()
                .and_then(|r| r.endpoints.first())
                .map(format_endpoint_summary)
                .unwrap_or_default();

            spans.push(Span::styled(&chunk.rule_name, name_style));
            if !endpoint_str.is_empty() {
                spans.push(Span::styled("  ", t.muted));
                spans.push(Span::styled(endpoint_str, t.accent));
            }
            // Show binary name (just the filename, not full path) if present.
            if !chunk.binary.is_empty() {
                let bin_short = chunk.binary.rsplit('/').next().unwrap_or(&chunk.binary);
                spans.push(Span::styled("  ", t.muted));
                spans.push(Span::styled(format!("({bin_short})"), t.muted));
            }
            spans.push(Span::raw("  "));
            spans.push(Span::styled(format!("[{}]", chunk.status), status_style));
            spans.push(Span::styled(
                format!("  {:.0}%", chunk.confidence * 100.0),
                t.muted,
            ));
            if let Some(annotation) = approval_annotation(chunk) {
                let annotation_style = match annotation.kind {
                    ApprovalAnnotationKind::AutoApproved => t.status_ok,
                    ApprovalAnnotationKind::RequiresReview => t.status_warn,
                    ApprovalAnnotationKind::Reviewed => t.muted,
                };
                spans.push(Span::styled("  ", t.muted));
                spans.push(Span::styled(annotation.short_label, annotation_style));
            }
            if chunk.hit_count > 1 {
                spans.push(Span::styled(format!("  {}x", chunk.hit_count), t.accent));
            }
            if let Some(reason) = rejection_guidance(chunk) {
                spans.push(Span::styled(
                    format!("  \"{}\"", truncate_display(reason, 32)),
                    t.muted,
                ));
            }

            let mut line = Line::from(spans);
            if is_selected {
                line = line.style(t.log_cursor);
            }
            line
        })
        .collect();

    // Scroll position indicator.
    let pos = app.draft_scroll + cursor_pos + 1;
    let scroll_info = format!(" [{pos}/{total}] ");

    let block = block.title_bottom(Line::from(vec![Span::styled(scroll_info, t.muted)]));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

// ---------------------------------------------------------------------------
// Detail popup (Enter key)
// ---------------------------------------------------------------------------

/// What `draw_detail_popup` actually laid out, so the app can clamp its scroll
/// offset to content that exists.
pub struct DetailMetrics {
    /// Total rows of content, after wrapping.
    pub total_rows: usize,
    /// Rows visible in the scrollable body, excluding the pinned hint row.
    pub body_height: usize,
}

pub fn draw_detail_popup(
    frame: &mut Frame<'_>,
    chunk: &PolicyChunk,
    area: Rect,
    theme: &crate::theme::Theme,
    scroll: usize,
) -> DetailMetrics {
    let t = theme;
    let popup_width = (area.width * 4 / 5).min(area.width.saturating_sub(4));
    let popup_height = 22u16.min(area.height.saturating_sub(4));
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let status_style = match chunk.status.as_str() {
        "pending" => t.status_warn.add_modifier(Modifier::BOLD),
        "approved" => t.status_ok.add_modifier(Modifier::BOLD),
        "rejected" => t.status_err.add_modifier(Modifier::BOLD),
        _ => t.muted,
    };

    let block = Block::default()
        .title(Span::styled(format!(" {} ", chunk.rule_name), t.heading))
        .borders(Borders::ALL)
        .border_style(t.accent)
        .padding(Padding::new(1, 1, 0, 0));

    // Text columns inside the borders and the one-column padding on each side.
    // Content is wrapped to this width here rather than by `Wrap`, so the row
    // count below is exactly what renders and the scroll clamp stays honest.
    let text_width = usize::from(popup_width).saturating_sub(4).max(1);

    let mut lines: Vec<Line<'_>> = vec![
        Line::from(vec![
            Span::styled("Status:     ", t.muted),
            Span::styled(&chunk.status, status_style),
        ]),
        Line::from(vec![
            Span::styled("Confidence: ", t.muted),
            Span::styled(format!("{:.0}%", chunk.confidence * 100.0), t.text),
        ]),
    ];

    if let Some(annotation) = approval_annotation(chunk) {
        let annotation_style = match annotation.kind {
            ApprovalAnnotationKind::AutoApproved => t.status_ok.add_modifier(Modifier::BOLD),
            ApprovalAnnotationKind::RequiresReview => t.status_warn.add_modifier(Modifier::BOLD),
            ApprovalAnnotationKind::Reviewed => t.muted,
        };
        push_wrapped(
            &mut lines,
            "Review:     ",
            t.muted,
            &annotation.detail_label,
            annotation_style,
            text_width,
        );
    }

    // Reviewer's persisted rejection guidance. The reason is free-form and has
    // no server-side length cap, so it wraps and the popup scrolls instead of
    // clipping the tail.
    if let Some(reason) = rejection_guidance(chunk) {
        push_wrapped(
            &mut lines,
            "Guidance:   ",
            t.muted,
            reason,
            t.status_err,
            text_width,
        );
    }

    // Binary (denormalized from the denial).
    if !chunk.binary.is_empty() {
        push_wrapped(
            &mut lines,
            "Binary:     ",
            t.muted,
            &chunk.binary,
            t.text,
            text_width,
        );
    }

    // Hit count (accumulated real denial count) and first/last seen. Kept on one
    // row while it fits, so a narrow terminal wraps it instead of losing the tail.
    let denied_label = "Denied:     ";
    let denied_count = format!(
        "{} connection{}",
        chunk.hit_count,
        if chunk.hit_count == 1 { "" } else { "s" }
    );
    let denied_seen = format!(
        "(first {} / last {})",
        format_short_time(chunk.first_seen_ms),
        format_short_time(chunk.last_seen_ms),
    );
    let denied_width = display_width(denied_label)
        + display_width(&denied_count)
        + 2
        + display_width(&denied_seen);
    if denied_width <= text_width {
        lines.push(Line::from(vec![
            Span::styled(denied_label, t.muted),
            Span::styled(denied_count, t.accent),
            Span::styled(format!("  {denied_seen}"), t.muted),
        ]));
    } else {
        push_wrapped(
            &mut lines,
            denied_label,
            t.muted,
            &denied_count,
            t.accent,
            text_width,
        );
        push_wrapped(
            &mut lines,
            &" ".repeat(display_width(denied_label)),
            t.muted,
            &denied_seen,
            t.muted,
            text_width,
        );
    }

    // Endpoints.
    if let Some(ref rule) = chunk.proposed_rule {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Endpoints:", t.muted)));
        for ep in &rule.endpoints {
            push_wrapped(
                &mut lines,
                "  -> ",
                t.muted,
                &format_endpoint_summary(ep),
                t.accent,
                text_width,
            );

            for detail in format_endpoint_details(ep) {
                push_wrapped(&mut lines, "     ", t.text, &detail, t.text, text_width);
            }
        }

        // Binaries.
        if !rule.binaries.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Binaries:", t.muted)));
            for b in &rule.binaries {
                push_wrapped(&mut lines, "  ", t.text, &b.path, t.text, text_width);
            }
        }
    }

    // Rationale.
    if !chunk.rationale.is_empty() {
        lines.push(Line::from(""));
        push_wrapped(
            &mut lines,
            "Rationale:  ",
            t.muted,
            &chunk.rationale,
            t.text,
            text_width,
        );
    }

    // Security notes.
    if !chunk.security_notes.is_empty() {
        lines.push(Line::from(""));
        let warn = t.status_warn.add_modifier(Modifier::BOLD);
        push_wrapped(
            &mut lines,
            "! ",
            warn,
            &chunk.security_notes,
            warn,
            text_width,
        );
    }

    // Split the inner area into a scrollable body and pinned hint rows, so the
    // action and close controls stay on screen however long the content is. The
    // hints need a second row on a narrow terminal and that shrinks the body, so
    // settle the two together.
    let inner = block.inner(popup_area);
    let inner_height = usize::from(inner.height);
    let total_rows = lines.len();
    let max_footer = inner_height.saturating_sub(1).max(1);

    let mut footer_rows = 1usize;
    let mut hint_rows = Vec::new();
    for _ in 0..2 {
        let body = inner_height.saturating_sub(footer_rows);
        let scrollable = total_rows.saturating_sub(body) > 0;
        hint_rows = pack_hints(&hint_units(chunk, t, scrollable), text_width);
        let needed = hint_rows.len().clamp(1, max_footer);
        if needed == footer_rows {
            break;
        }
        footer_rows = needed;
    }

    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(u16::try_from(footer_rows).unwrap_or(1)),
        ])
        .split(inner);
    let body_height = usize::from(parts[0].height);
    let max_scroll = total_rows.saturating_sub(body_height);
    let scroll = scroll.min(max_scroll);

    let block = if max_scroll > 0 {
        block.title_bottom(
            Line::from(Span::styled(
                format!(" {}/{} ", scroll + 1, total_rows),
                t.muted,
            ))
            .right_aligned(),
        )
    } else {
        block
    };

    frame.render_widget(block, popup_area);
    frame.render_widget(
        Paragraph::new(lines).scroll((u16::try_from(scroll).unwrap_or(u16::MAX), 0)),
        parts[0],
    );
    frame.render_widget(Paragraph::new(hint_rows), parts[1]);

    DetailMetrics {
        total_rows,
        body_height,
    }
}

// ---------------------------------------------------------------------------
// Approve-all confirmation popup ([A] key)
// ---------------------------------------------------------------------------

pub fn draw_approve_all_popup(
    frame: &mut Frame<'_>,
    chunks: &[PolicyChunk],
    area: Rect,
    theme: &crate::theme::Theme,
) {
    let t = theme;
    let count = chunks.len();
    // Height: header(1) + blank(1) + chunks(count, capped at 12) + blank(1) + hints(1) + borders(2) + padding(1)
    let list_lines = count.min(12);
    let popup_height = u16::try_from(7 + list_lines).unwrap_or(u16::MAX);
    let popup_height = popup_height.min(area.height.saturating_sub(4));
    let popup_width = (area.width * 4 / 5).min(area.width.saturating_sub(4));
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(
            " Approve All ",
            t.status_warn.add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(t.accent)
        .padding(Padding::new(1, 1, 0, 0));

    // Usable width inside borders + padding.
    let inner_width = popup_width.saturating_sub(4) as usize;

    let mut lines: Vec<Line<'_>> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("Approve ", t.text),
        Span::styled(
            format!("{count}"),
            t.status_warn.add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                " pending policy request{}?",
                if count == 1 { "" } else { "s" }
            ),
            t.text,
        ),
    ]));
    lines.push(Line::from(""));

    for (i, chunk) in chunks.iter().enumerate() {
        if i >= 12 {
            lines.push(Line::from(Span::styled(
                format!("  ... and {} more", count - 12),
                t.muted,
            )));
            break;
        }
        let endpoint_str = chunk
            .proposed_rule
            .as_ref()
            .and_then(|r| r.endpoints.first())
            .map(format_endpoint_summary)
            .unwrap_or_default();

        // Truncate to fit within the popup width.
        // "  -> " (5) + rule_name + "  " (2) + endpoint
        let prefix_len = 5;
        let sep_len = 2;
        let budget = inner_width.saturating_sub(prefix_len + sep_len);
        let (name_str, ep_str) = if chunk.rule_name.len() + endpoint_str.len() > budget {
            let ep_budget = endpoint_str.len().min(budget / 2);
            let name_budget = budget.saturating_sub(ep_budget);
            (
                truncate_str(&chunk.rule_name, name_budget),
                truncate_str(&endpoint_str, ep_budget),
            )
        } else {
            (chunk.rule_name.clone(), endpoint_str)
        };

        let mut row_spans = vec![
            Span::styled("  -> ", t.muted),
            Span::styled(name_str, t.text),
            Span::styled("  ", t.muted),
            Span::styled(ep_str, t.accent),
        ];
        if !chunk.binary.is_empty() {
            let bin_short = chunk.binary.rsplit('/').next().unwrap_or(&chunk.binary);
            row_spans.push(Span::styled("  ", t.muted));
            row_spans.push(Span::styled(format!("({bin_short})"), t.muted));
        }
        lines.push(Line::from(row_spans));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("[y/Enter]", t.key_hint),
        Span::styled(" Approve all  ", t.text),
        Span::styled("[n/Esc]", t.key_hint),
        Span::styled(" Cancel", t.text),
    ]));

    frame.render_widget(Paragraph::new(lines).block(block), popup_area);
}

/// Truncate a string to `max_len` chars, appending "..." if truncated.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s.chars().take(max_len).collect()
    } else {
        let mut out: String = s.chars().take(max_len - 3).collect();
        out.push_str("...");
        out
    }
}

/// Terminal display width of `text` in columns.
///
/// Uses the same measurement ratatui applies when it lays cells out, so a
/// double-width glyph such as CJK counts as the two columns it will occupy.
/// Counting `chars` here instead would let CJK text render past the popup edge
/// with no way to scroll to the missing tail.
fn display_width(text: &str) -> usize {
    Span::raw(text).width()
}

/// Word-wrap `text` into rows of at most `width` display columns.
///
/// A word wider than `width` is hard-broken rather than allowed to overflow.
/// Always returns at least one row so callers can index the first row safely.
fn wrap_value(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
    let mut rows: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut cur_width = 0usize;
    let mut buf = [0u8; 4];
    for word in text.split_whitespace() {
        let word_width = display_width(word);
        if word_width > width {
            if cur_width > 0 {
                rows.push(std::mem::take(&mut cur));
                cur_width = 0;
            }
            for ch in word.chars() {
                let ch_width = display_width(ch.encode_utf8(&mut buf));
                if cur_width + ch_width > width && cur_width > 0 {
                    rows.push(std::mem::take(&mut cur));
                    cur_width = 0;
                }
                cur.push(ch);
                cur_width += ch_width;
            }
            continue;
        }
        let needed = if cur_width == 0 {
            word_width
        } else {
            cur_width + 1 + word_width
        };
        if needed > width {
            rows.push(std::mem::take(&mut cur));
            cur_width = 0;
        }
        if cur_width > 0 {
            cur.push(' ');
            cur_width += 1;
        }
        cur.push_str(word);
        cur_width += word_width;
    }
    if cur_width > 0 || rows.is_empty() {
        rows.push(cur);
    }
    rows
}

/// Truncate `text` to `max_columns` display columns, appending `...` when cut.
///
/// `truncate_str` counts chars, which is right for its existing callers but
/// would let a CJK value take twice its budget on the list row.
fn truncate_display(text: &str, max_columns: usize) -> String {
    if display_width(text) <= max_columns {
        return text.to_string();
    }
    if max_columns <= 3 {
        return ".".repeat(max_columns);
    }
    let budget = max_columns - 3;
    let mut out = String::new();
    let mut width = 0usize;
    let mut buf = [0u8; 4];
    for ch in text.chars() {
        let ch_width = display_width(ch.encode_utf8(&mut buf));
        if width + ch_width > budget {
            break;
        }
        out.push(ch);
        width += ch_width;
    }
    out.push_str("...");
    out
}

/// Push `text` wrapped to `width`, with `prefix` on the first row and a matching
/// indent on continuation rows so the label column stays aligned.
fn push_wrapped(
    lines: &mut Vec<Line<'_>>,
    prefix: &str,
    prefix_style: Style,
    text: &str,
    text_style: Style,
    width: usize,
) {
    let indent = display_width(prefix);
    let available = width.saturating_sub(indent).max(1);
    for (i, row) in wrap_value(text, available).into_iter().enumerate() {
        let head = if i == 0 {
            Span::styled(prefix.to_string(), prefix_style)
        } else {
            Span::raw(" ".repeat(indent))
        };
        lines.push(Line::from(vec![head, Span::styled(row, text_style)]));
    }
}

/// One footer hint: the spans that render it, and its display width.
type HintUnit = (Vec<Span<'static>>, usize);

/// State-aware hints for the detail popup footer.
fn hint_units(chunk: &PolicyChunk, t: &crate::theme::Theme, scrollable: bool) -> Vec<HintUnit> {
    let mut units: Vec<HintUnit> = Vec::new();
    {
        let mut add = |key: &str, label: &str, key_style: Style, label_style: Style| {
            units.push((
                vec![
                    Span::styled(key.to_string(), key_style),
                    Span::styled(label.to_string(), label_style),
                ],
                display_width(key) + display_width(label),
            ));
        };
        match chunk.status.as_str() {
            "pending" => {
                add("[a]", " Approve  ", t.key_hint, t.text);
                add("[x]", " Reject  ", t.key_hint, t.text);
            }
            "approved" => add("[x]", " Revoke  ", t.key_hint, t.text),
            "rejected" => add("[a]", " Approve  ", t.key_hint, t.text),
            _ => {}
        }
        if scrollable {
            add("[j/k]", " Scroll  ", t.key_hint, t.text);
        }
        add("[Esc]", " Close", t.muted, t.muted);
    }
    units
}

/// Pack hint units into rows no wider than `width`, never splitting a unit.
///
/// A narrow terminal would otherwise clip the trailing hints, and `[Esc] Close`
/// is the last one.
fn pack_hints(units: &[HintUnit], width: usize) -> Vec<Line<'static>> {
    let mut rows: Vec<Line<'static>> = Vec::new();
    let mut current: Vec<Span<'static>> = Vec::new();
    let mut current_width = 0usize;
    for (spans, unit_width) in units {
        if current_width + unit_width > width && !current.is_empty() {
            rows.push(Line::from(std::mem::take(&mut current)));
            current_width = 0;
        }
        current.extend(spans.iter().cloned());
        current_width += unit_width;
    }
    if !current.is_empty() {
        rows.push(Line::from(current));
    }
    if rows.is_empty() {
        rows.push(Line::from(String::new()));
    }
    rows
}

/// The reviewer's persisted note for a rejected chunk.
///
/// Gated on status rather than on the field alone: the gateway's
/// `update_draft_chunk_status` leaves `rejection_reason` untouched when a chunk
/// is later approved, so an approved chunk can still carry a stale note.
fn rejection_guidance(chunk: &PolicyChunk) -> Option<&str> {
    if chunk.status != "rejected" {
        return None;
    }
    let reason = chunk.rejection_reason.trim();
    (!reason.is_empty()).then_some(reason)
}

#[derive(Clone, Copy)]
enum ApprovalAnnotationKind {
    AutoApproved,
    RequiresReview,
    Reviewed,
}

struct ApprovalAnnotation {
    kind: ApprovalAnnotationKind,
    short_label: String,
    detail_label: String,
}

fn approval_annotation(chunk: &PolicyChunk) -> Option<ApprovalAnnotation> {
    let application_error = chunk.application_error.trim();
    if !application_error.is_empty() {
        return Some(ApprovalAnnotation {
            kind: ApprovalAnnotationKind::RequiresReview,
            short_label: "application blocked".to_string(),
            detail_label: format!("candidate cannot be applied: {application_error}"),
        });
    }
    let validation = chunk.validation_result.trim();
    if validation.is_empty() {
        return None;
    }

    if validation == "prover: no new findings" {
        if chunk.status == "approved" {
            return Some(ApprovalAnnotation {
                kind: ApprovalAnnotationKind::AutoApproved,
                short_label: "auto-approved".to_string(),
                detail_label: "proposal was auto-approved; no additional risk detected".to_string(),
            });
        }

        return Some(ApprovalAnnotation {
            kind: ApprovalAnnotationKind::RequiresReview,
            short_label: "review required".to_string(),
            detail_label: "rule requires review; no additional risk detected".to_string(),
        });
    }

    let issues = validation_issue_summary(validation);
    if chunk.status == "approved" {
        return Some(ApprovalAnnotation {
            kind: ApprovalAnnotationKind::Reviewed,
            short_label: "reviewed".to_string(),
            detail_label: format!("rule was approved after review; possible issues: {issues}"),
        });
    }

    Some(ApprovalAnnotation {
        kind: ApprovalAnnotationKind::RequiresReview,
        short_label: "review required".to_string(),
        detail_label: format!(
            "rule was not auto-approved and requires review; possible issues: {issues}"
        ),
    })
}

fn validation_issue_summary(validation: &str) -> String {
    let mut issues = Vec::new();
    for line in validation.lines().skip(1) {
        let Some((category, _)) = line.trim().split_once(':') else {
            continue;
        };
        let label = category.trim().replace('_', " ");
        if !label.is_empty() && !issues.contains(&label) {
            issues.push(label);
        }
    }

    if issues.is_empty() {
        validation.lines().next().unwrap_or(validation).to_string()
    } else {
        issues.join(", ")
    }
}

fn format_endpoint_summary(endpoint: &NetworkEndpoint) -> String {
    let host_port = if endpoint.port > 0 {
        format!("{}:{}", endpoint.host, endpoint.port)
    } else {
        endpoint.host.clone()
    };

    let mut tags = vec![endpoint_layer_label(endpoint).to_string()];
    if !endpoint.access.is_empty() {
        tags.push(format!("access={}", endpoint.access));
    }
    for rule in &endpoint.rules {
        if let Some(allow) = &rule.allow {
            tags.push(format!("allow {}", format_allow_rule(allow)));
        }
    }
    for deny in &endpoint.deny_rules {
        tags.push(format!("deny {}", format_deny_rule(deny)));
    }

    format!("{host_port} [{}]", tags.join(", "))
}

fn format_endpoint_details(endpoint: &NetworkEndpoint) -> Vec<String> {
    let mut details = Vec::new();

    if !endpoint.path.is_empty() {
        details.push(format!("Path scope: {}", endpoint.path));
    }
    if !endpoint.tls.is_empty() {
        details.push(format!("TLS: {}", endpoint.tls));
    }
    if !endpoint.enforcement.is_empty() {
        details.push(format!("Enforcement: {}", endpoint.enforcement));
    }
    if endpoint.request_body_credential_rewrite {
        details.push("Request body credential rewrite".to_string());
    }
    if endpoint.websocket_credential_rewrite {
        details.push("WebSocket credential rewrite".to_string());
    }
    for rule in &endpoint.rules {
        if let Some(allow) = &rule.allow {
            details.push(format!("Allow: {}", format_allow_rule(allow)));
        }
    }
    for deny in &endpoint.deny_rules {
        details.push(format!("Deny: {}", format_deny_rule(deny)));
    }

    details
}

fn endpoint_layer_label(endpoint: &NetworkEndpoint) -> &str {
    if endpoint.protocol.eq_ignore_ascii_case("rest") {
        "L7 rest"
    } else if endpoint.protocol.is_empty() {
        "L4"
    } else {
        endpoint.protocol.as_str()
    }
}

fn format_allow_rule(allow: &L7Allow) -> String {
    let mut parts = Vec::new();
    if !allow.method.is_empty() || !allow.path.is_empty() {
        parts.push(format!(
            "{} {}",
            non_empty_or(&allow.method, "*"),
            non_empty_or(&allow.path, "*")
        ));
    }
    if !allow.command.is_empty() {
        parts.push(format!("command {}", allow.command));
    }
    if !allow.operation_type.is_empty() || !allow.operation_name.is_empty() {
        parts.push(format!(
            "graphql {} {}",
            non_empty_or(&allow.operation_type, "*"),
            non_empty_or(&allow.operation_name, "*")
        ));
    }
    if !allow.fields.is_empty() {
        parts.push(format!("fields {}", allow.fields.join(",")));
    }
    append_query_matchers(&mut parts, &allow.query);
    if parts.is_empty() {
        "*".to_string()
    } else {
        parts.join("; ")
    }
}

fn format_deny_rule(deny: &L7DenyRule) -> String {
    let mut parts = Vec::new();
    if !deny.method.is_empty() || !deny.path.is_empty() {
        parts.push(format!(
            "{} {}",
            non_empty_or(&deny.method, "*"),
            non_empty_or(&deny.path, "*")
        ));
    }
    if !deny.command.is_empty() {
        parts.push(format!("command {}", deny.command));
    }
    if !deny.operation_type.is_empty() || !deny.operation_name.is_empty() {
        parts.push(format!(
            "graphql {} {}",
            non_empty_or(&deny.operation_type, "*"),
            non_empty_or(&deny.operation_name, "*")
        ));
    }
    if !deny.fields.is_empty() {
        parts.push(format!("fields {}", deny.fields.join(",")));
    }
    append_query_matchers(&mut parts, &deny.query);
    if parts.is_empty() {
        "*".to_string()
    } else {
        parts.join("; ")
    }
}

fn append_query_matchers(
    parts: &mut Vec<String>,
    query: &std::collections::HashMap<String, L7QueryMatcher>,
) {
    if query.is_empty() {
        return;
    }
    let mut entries: Vec<_> = query.iter().collect();
    entries.sort_by_key(|(key, _)| *key);
    let formatted = entries
        .into_iter()
        .map(|(key, matcher)| {
            if matcher.any.is_empty() {
                format!("{key}={}", non_empty_or(&matcher.glob, "*"))
            } else {
                format!("{key} in [{}]", matcher.any.join(","))
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    parts.push(format!("query {formatted}"));
}

fn non_empty_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::Theme;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// Column width computed independently of the production `display_width`.
    ///
    /// Asserting with the helper under test would be tautological: if it
    /// regressed to counting chars, the assertion would regress with it.
    fn expected_columns(text: &str) -> usize {
        text.chars()
            .map(|c| {
                let wide = ('\u{1100}'..='\u{115f}').contains(&c)
                    || ('\u{2e80}'..='\u{a4cf}').contains(&c)
                    || ('\u{ac00}'..='\u{d7a3}').contains(&c)
                    || ('\u{f900}'..='\u{faff}').contains(&c)
                    || ('\u{fe30}'..='\u{fe6f}').contains(&c)
                    || ('\u{ff00}'..='\u{ff60}').contains(&c)
                    || ('\u{ffe0}'..='\u{ffe6}').contains(&c);
                usize::from(wide) + 1
            })
            .sum()
    }

    fn make_chunk(status: &str, rejection_reason: &str) -> PolicyChunk {
        PolicyChunk {
            status: status.to_string(),
            rejection_reason: rejection_reason.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn rejected_chunk_exposes_its_reason() {
        let chunk = make_chunk("rejected", "too broad: allows any port");
        assert_eq!(
            rejection_guidance(&chunk),
            Some("too broad: allows any port")
        );
    }

    #[test]
    fn approved_chunk_hides_stale_reason() {
        // Approving passes None for the reason, which leaves the stored value in
        // place, so a chunk rejected and later approved still carries the note.
        let chunk = make_chunk("approved", "too broad: allows any port");
        assert_eq!(rejection_guidance(&chunk), None);
    }

    #[test]
    fn pending_chunk_has_no_guidance() {
        assert_eq!(rejection_guidance(&make_chunk("pending", "")), None);
    }

    #[test]
    fn blank_reason_is_dropped() {
        assert_eq!(rejection_guidance(&make_chunk("rejected", "")), None);
        assert_eq!(rejection_guidance(&make_chunk("rejected", "   \n")), None);
    }

    #[test]
    fn reason_is_trimmed() {
        let chunk = make_chunk("rejected", "  needs a narrower host  ");
        assert_eq!(rejection_guidance(&chunk), Some("needs a narrower host"));
    }

    #[test]
    fn long_reason_truncates_for_the_list_row() {
        let reason = "rejected because the endpoint list is far too permissive";
        let shown = truncate_display(reason, 32);
        assert_eq!(display_width(&shown), 32);
        assert!(shown.ends_with("..."));
        assert!(shown.starts_with("rejected because"));
    }

    #[test]
    fn short_reason_is_not_truncated() {
        assert_eq!(truncate_str("too broad", 32), "too broad");
    }

    // --- wrapping ---------------------------------------------------------

    #[test]
    fn wrap_value_breaks_on_word_boundaries() {
        assert_eq!(
            wrap_value("alpha beta gamma", 11),
            vec!["alpha beta", "gamma"]
        );
    }

    #[test]
    fn wrap_value_hard_breaks_a_word_longer_than_the_width() {
        assert_eq!(wrap_value("abcdefghij", 4), vec!["abcd", "efgh", "ij"]);
    }

    #[test]
    fn wrap_value_always_returns_at_least_one_row() {
        assert_eq!(wrap_value("", 10), vec![String::new()]);
    }

    #[test]
    fn wrap_value_never_exceeds_the_width() {
        let text = "reject this rule because the endpoint list is far too permissive";
        for row in wrap_value(text, 17) {
            assert!(display_width(&row) <= 17, "row too wide: {row:?}");
        }
    }

    #[test]
    fn wrap_value_measures_display_columns_not_chars() {
        // CJK glyphs occupy two columns each, and with no spaces the whole
        // string takes the hard-break path.
        let cjk = "这条规则的范围太广".repeat(20);
        for row in wrap_value(&cjk, 40) {
            assert!(
                expected_columns(&row) <= 40,
                "row is {} columns: {row:?}",
                expected_columns(&row)
            );
        }

        // Mixed script exercises the word-packing path instead.
        let mixed = "scope 这条规则 to docs 路径 only ".repeat(20);
        for row in wrap_value(&mixed, 33) {
            assert!(
                expected_columns(&row) <= 33,
                "row is {} columns: {row:?}",
                expected_columns(&row)
            );
        }
    }

    #[test]
    fn truncate_display_counts_columns_not_chars() {
        let cjk = "这条规则的范围太广".repeat(10);
        let shown = truncate_display(&cjk, 32);
        assert!(
            expected_columns(&shown) <= 32,
            "truncated value is {} columns",
            expected_columns(&shown)
        );
        assert!(shown.ends_with("..."));
        assert_eq!(truncate_display("too broad", 32), "too broad");
    }

    // --- rendering --------------------------------------------------------

    fn render(chunk: &PolicyChunk, width: u16, height: u16, scroll: usize) -> (String, usize) {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut max_scroll = 0usize;
        terminal
            .draw(|frame| {
                let metrics = draw_detail_popup(
                    frame,
                    chunk,
                    Rect::new(0, 0, width, height),
                    &Theme::dark(),
                    scroll,
                );
                max_scroll = metrics.total_rows.saturating_sub(metrics.body_height);
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text: String = buffer
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        (text, max_scroll)
    }

    /// A rejection reason has no server-side length cap, so the popup has to keep
    /// a paragraph-length one reachable rather than clipping its tail.
    fn long_reason() -> String {
        let mut reason = String::from("PREFIX_MARKER ");
        while reason.len() < 1980 {
            reason.push_str("this rule is far too broad and must be narrowed; ");
        }
        reason.push_str(" SUFFIX_MARKER");
        reason
    }

    #[test]
    fn long_guidance_head_and_tail_are_both_reachable() {
        let chunk = PolicyChunk {
            status: "rejected".to_string(),
            rejection_reason: long_reason(),
            rule_name: "allow-github".to_string(),
            ..Default::default()
        };

        let (top, max_scroll) = render(&chunk, 80, 24, 0);
        assert!(max_scroll > 0, "content should overflow an 80x24 popup");
        assert!(
            top.contains("PREFIX_MARKER"),
            "head not visible at scroll 0"
        );

        let (bottom, _) = render(&chunk, 80, 24, max_scroll);
        assert!(
            bottom.contains("SUFFIX_MARKER"),
            "tail not reachable at max scroll"
        );
    }

    #[test]
    fn action_hints_stay_visible_at_every_scroll_position() {
        let chunk = PolicyChunk {
            status: "rejected".to_string(),
            rejection_reason: long_reason(),
            rule_name: "allow-github".to_string(),
            ..Default::default()
        };

        let (top, max_scroll) = render(&chunk, 80, 24, 0);
        let (bottom, _) = render(&chunk, 80, 24, max_scroll);
        for (label, screen) in [("top", &top), ("bottom", &bottom)] {
            assert!(screen.contains("Close"), "close hint missing at {label}");
            assert!(
                screen.contains("Approve"),
                "approve hint missing at {label}"
            );
            assert!(screen.contains("Scroll"), "scroll hint missing at {label}");
        }
    }

    #[test]
    fn scrolling_past_the_end_is_clamped_to_the_last_page() {
        let chunk = PolicyChunk {
            status: "rejected".to_string(),
            rejection_reason: long_reason(),
            rule_name: "allow-github".to_string(),
            ..Default::default()
        };
        let (_, max_scroll) = render(&chunk, 80, 24, 0);
        let (clamped, _) = render(&chunk, 80, 24, max_scroll + 500);
        let (last, _) = render(&chunk, 80, 24, max_scroll);
        assert_eq!(
            clamped, last,
            "over-scrolling should clamp to the last page"
        );
    }

    /// The same overflow already affected `rationale` before this change, so the
    /// scrollable body has to fix that case too.
    #[test]
    fn long_rationale_tail_is_reachable_on_a_pending_chunk() {
        let mut rationale = String::from("PREFIX_MARKER ");
        while rationale.len() < 1980 {
            rationale.push_str("the agent needs broad network access; ");
        }
        rationale.push_str(" SUFFIX_MARKER");
        let chunk = PolicyChunk {
            status: "pending".to_string(),
            rule_name: "allow-github".to_string(),
            rationale,
            ..Default::default()
        };

        let (_, max_scroll) = render(&chunk, 80, 24, 0);
        let (bottom, _) = render(&chunk, 80, 24, max_scroll);
        assert!(bottom.contains("SUFFIX_MARKER"));
        assert!(bottom.contains("Close"));
    }

    /// Double-width guidance must stay reachable too. Counting chars rather than
    /// columns made every wrapped row about twice as wide as the popup, so the
    /// right half of each row was clipped with nowhere to scroll. Markers are
    /// interleaved through the text rather than appended, because a trailing
    /// marker lands on its own short row either way and would not detect this.
    #[test]
    fn cjk_guidance_is_fully_reachable_at_80x24() {
        use std::fmt::Write as _;

        const MARKERS: usize = 16;
        let mut reason = String::new();
        for i in 0..MARKERS {
            let _ = write!(reason, "M{i:02}");
            reason.push_str(&"这条规则范围太广".repeat(4));
        }
        let chunk = PolicyChunk {
            status: "rejected".to_string(),
            rejection_reason: reason,
            rule_name: "allow-github".to_string(),
            ..Default::default()
        };

        let (_, max_scroll) = render(&chunk, 80, 24, 0);
        assert!(max_scroll > 0, "content should overflow an 80x24 popup");

        let mut seen = String::new();
        for scroll in 0..=max_scroll {
            seen.push_str(&render(&chunk, 80, 24, scroll).0);
        }
        for i in 0..MARKERS {
            let marker = format!("M{i:02}");
            assert!(
                seen.contains(&marker),
                "guidance marker {marker} was clipped and is unreachable at every scroll offset"
            );
        }
    }

    #[test]
    fn short_content_does_not_scroll() {
        let chunk = PolicyChunk {
            status: "rejected".to_string(),
            rejection_reason: "too broad".to_string(),
            rule_name: "allow-github".to_string(),
            ..Default::default()
        };
        let (screen, max_scroll) = render(&chunk, 80, 24, 0);
        assert_eq!(max_scroll, 0, "short content should not be scrollable");
        assert!(screen.contains("too broad"));
        assert!(
            !screen.contains("Scroll"),
            "scroll hint should be hidden when everything fits"
        );
    }

    fn denied_chunk(status: &str, reason: &str) -> PolicyChunk {
        PolicyChunk {
            status: status.to_string(),
            rejection_reason: reason.to_string(),
            rule_name: "allow-github".to_string(),
            confidence: 0.82,
            hit_count: 3,
            first_seen_ms: 1_700_000_000_000,
            last_seen_ms: 1_700_000_100_000,
            ..Default::default()
        }
    }

    /// Dropping `Wrap` means anything not routed through `push_wrapped` clips
    /// horizontally, so the denial timestamps have to wrap on a narrow popup.
    #[test]
    fn denied_timestamps_survive_a_narrow_popup() {
        for width in [60u16, 70u16, 80u16] {
            let chunk = denied_chunk("rejected", "scope this to docs/ paths only");
            let (screen, _) = render(&chunk, width, 24, 0);
            assert!(
                screen.contains("22:13:20"),
                "first-seen lost at width {width}"
            );
            assert!(
                screen.contains("22:15:00"),
                "last-seen lost at width {width}"
            );
        }
    }

    /// The close hint is the last one, so a narrow footer would drop it first.
    #[test]
    fn close_hint_survives_a_narrow_popup_with_scrollable_content() {
        for width in [60u16, 70u16, 80u16] {
            let chunk = denied_chunk("pending", "");
            let chunk = PolicyChunk {
                rationale: long_reason(),
                ..chunk
            };
            let (screen, max_scroll) = render(&chunk, width, 24, 0);
            assert!(max_scroll > 0, "content should overflow at width {width}");
            assert!(screen.contains("Close"), "close hint lost at width {width}");
            assert!(
                screen.contains("Approve"),
                "approve hint lost at width {width}"
            );
            assert!(
                screen.contains("Reject"),
                "reject hint lost at width {width}"
            );
        }
    }

    #[test]
    fn hints_pack_onto_one_row_when_they_fit() {
        let theme = Theme::dark();
        let chunk = denied_chunk("pending", "");
        let rows = pack_hints(&hint_units(&chunk, &theme, true), 200);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn hints_spill_onto_a_second_row_when_they_do_not_fit() {
        let theme = Theme::dark();
        let chunk = denied_chunk("pending", "");
        let rows = pack_hints(&hint_units(&chunk, &theme, true), 30);
        assert!(rows.len() > 1, "hints should wrap at 30 columns");
    }
}
