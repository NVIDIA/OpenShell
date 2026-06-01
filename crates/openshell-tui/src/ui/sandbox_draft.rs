// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network rules panel for the sandbox screen.

use crate::app::App;
use openshell_core::proto::{L7Allow, L7DenyRule, L7QueryMatcher, NetworkEndpoint, PolicyChunk};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};

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

pub fn draw_detail_popup(
    frame: &mut Frame<'_>,
    chunk: &PolicyChunk,
    area: Rect,
    theme: &crate::theme::Theme,
) {
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
        lines.push(Line::from(vec![
            Span::styled("Review:     ", t.muted),
            Span::styled(annotation.detail_label, annotation_style),
        ]));
    }

    // Binary (denormalized from the denial).
    if !chunk.binary.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Binary:     ", t.muted),
            Span::styled(&chunk.binary, t.text),
        ]));
    }

    // Hit count (accumulated real denial count) and first/last seen.
    lines.push(Line::from(vec![
        Span::styled("Denied:     ", t.muted),
        Span::styled(
            format!(
                "{} connection{}",
                chunk.hit_count,
                if chunk.hit_count == 1 { "" } else { "s" }
            ),
            t.accent,
        ),
        Span::styled(
            format!(
                "  (first {} / last {})",
                format_short_time(chunk.first_seen_ms),
                format_short_time(chunk.last_seen_ms),
            ),
            t.muted,
        ),
    ]));

    // Endpoints.
    if let Some(ref rule) = chunk.proposed_rule {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Endpoints:", t.muted)));
        for ep in &rule.endpoints {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("-> ", t.muted),
                Span::styled(format_endpoint_summary(ep), t.accent),
            ]));

            for detail in format_endpoint_details(ep) {
                lines.push(Line::from(vec![
                    Span::raw("     "),
                    Span::styled(detail, t.text),
                ]));
            }
        }

        // Binaries.
        if !rule.binaries.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Binaries:", t.muted)));
            for b in &rule.binaries {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(&b.path, t.text),
                ]));
            }
        }
    }

    // Rationale.
    if !chunk.rationale.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Rationale:  ", t.muted),
            Span::styled(&chunk.rationale, t.text),
        ]));
    }

    // Security notes.
    if !chunk.security_notes.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            format!("! {}", chunk.security_notes),
            t.status_warn.add_modifier(Modifier::BOLD),
        )]));
    }

    // Action hints — state-aware toggle keys.
    lines.push(Line::from(""));
    let mut hint_spans: Vec<Span<'_>> = Vec::new();
    match chunk.status.as_str() {
        "pending" => {
            hint_spans.extend([
                Span::styled("[a]", t.key_hint),
                Span::styled(" Approve  ", t.text),
                Span::styled("[x]", t.key_hint),
                Span::styled(" Reject  ", t.text),
            ]);
        }
        "approved" => {
            hint_spans.extend([
                Span::styled("[x]", t.key_hint),
                Span::styled(" Revoke  ", t.text),
            ]);
        }
        "rejected" => {
            hint_spans.extend([
                Span::styled("[a]", t.key_hint),
                Span::styled(" Approve  ", t.text),
            ]);
        }
        _ => {}
    }
    hint_spans.extend([
        Span::styled("[Esc]", t.muted),
        Span::styled(" Close", t.muted),
    ]);
    lines.push(Line::from(hint_spans));

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup_area,
    );
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
