// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workload program status from OSC 7501 terminal reports.
//!
//! Agents such as Claude Code declare whether they are working, blocked on the
//! user, or done by writing OSC 7501 reports to their terminal. The supervisor
//! observes workload PTY output, keeps the per-terminal records the protocol
//! defines, and answers the support query itself so reporting does not depend
//! on the terminal of whichever client happens to be attached.
//!
//! Report bytes pass through unchanged. Only the support query is removed from
//! the forwarded stream, because the supervisor answers it and a second answer
//! from a supporting client terminal would reach the program as input.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use base64::Engine as _;
use tokio::sync::watch;

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;

/// Largest legal sequence, OSC through ST.
const MAX_SEQUENCE: usize = 4096;
/// Records one terminal keeps before evicting the least recently updated.
const MAX_RECORDS: usize = 256;
const MAX_KEY: usize = 16;
const MAX_MSG_ENCODED: usize = 2732;
const MAX_TITLE_ENCODED: usize = 256;
const MAX_ID: usize = 128;
const MAX_ID_SEGMENT: usize = 32;
const MAX_ID_DEPTH: usize = 8;
const MAX_APP: usize = 32;

const REPORT_PREFIX: &[u8] = b"7501;";
const PROMPT_PREFIX: &[u8] = b"133;A";
/// Both prefixes are this long, so one bounded buffer decides the sequence.
const PREFIX_LEN: usize = 5;
const QUERY_BODY: &[u8] = b"7501;?";
const QUERY_ST: &[u8] = b"\x1b]7501;?\x1b\\";
const QUERY_BEL: &[u8] = b"\x1b]7501;?\x07";
// The reply lists the supported states and kinds so it never equals the query:
// a program that probes with terminal echo on reads its own echo, and a reply
// identical to the query would be answered again without end.
const REPLY_ST: &[u8] =
    b"\x1b]7501;?:states=idle,working,done,blocked,error:kinds=permission,question,auth\x1b\\";
const REPLY_BEL: &[u8] =
    b"\x1b]7501;?:states=idle,working,done,blocked,error:kinds=permission,question,auth\x07";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ProgramState {
    Idle,
    Done,
    Error,
    Blocked,
    Working,
}

impl ProgramState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Done => "done",
            Self::Error => "error",
            Self::Blocked => "blocked",
            Self::Working => "working",
        }
    }

    /// Whether the program is waiting on the user rather than running.
    #[must_use]
    pub fn awaits_user(self) -> bool {
        !matches!(self, Self::Working)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum BlockedKind {
    Permission,
    Question,
    Auth,
}

impl BlockedKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Permission => "permission",
            Self::Question => "question",
            Self::Auth => "auth",
        }
    }
}

/// One record as the protocol defines it. Free text (`msg`, `title`) is
/// validated but never retained: it is untrusted program output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramRecord {
    pub state: ProgramState,
    pub kind: Option<BlockedKind>,
    pub app: Option<String>,
    pub progress: Option<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Report {
    /// Replace the record at `id`; the empty id is the root record.
    Set { id: String, record: ProgramRecord },
    /// Remove the record at `id` and its descendants, or every record.
    Clear { id: Option<String> },
}

/// Terminator a query used, so the reply can match it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminator {
    St,
    Bel,
}

/// Something in the output stream that changes a terminal's records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalEvent {
    Report(Report),
    /// The shell started a new prompt (OSC 133 `A`), ending the program that
    /// ran before it.
    Prompt,
    /// A full terminal reset (RIS, `ESC c`) removes every record.
    Reset,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Scan {
    /// Output to forward to attached clients.
    pub forward: Vec<u8>,
    /// Record changes in the order they appeared in the output.
    pub events: Vec<TerminalEvent>,
    /// Support queries removed from `forward`, in order.
    pub queries: Vec<Terminator>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanState {
    Ground,
    Escape,
    Osc,
    OscEscape,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Tracking {
    Undecided,
    Report,
    Prompt,
    Ignore,
}

/// Streaming OSC scanner. Sequences may span reads; only the support query is
/// held back, and at most one query's worth of bytes at a time.
#[derive(Debug)]
pub struct Scanner {
    state: ScanState,
    tracking: Tracking,
    body: Vec<u8>,
    sequence_len: usize,
    held: Vec<u8>,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: ScanState::Ground,
            tracking: Tracking::Ignore,
            body: Vec::new(),
            sequence_len: 0,
            held: Vec::new(),
        }
    }

    pub fn scan(&mut self, input: &[u8]) -> Scan {
        let mut scan = Scan {
            forward: Vec::with_capacity(input.len()),
            ..Scan::default()
        };
        for &byte in input {
            self.hold(byte, &mut scan);
            self.parse(byte, &mut scan);
        }
        scan
    }

    /// Whether bytes are held back waiting to see if they form a query.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.held.is_empty()
    }

    /// Release held bytes when the program stops writing mid-sequence, so a
    /// lone ESC is never delayed indefinitely.
    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }

    fn hold(&mut self, byte: u8, scan: &mut Scan) {
        if self.held.is_empty() {
            if byte == ESC {
                self.held.push(byte);
            } else {
                scan.forward.push(byte);
            }
            return;
        }
        self.held.push(byte);
        if self.held == QUERY_ST || self.held == QUERY_BEL {
            scan.queries.push(if byte == BEL {
                Terminator::Bel
            } else {
                Terminator::St
            });
            self.held.clear();
        } else if !QUERY_ST.starts_with(&self.held) && !QUERY_BEL.starts_with(&self.held) {
            // An ESC that broke the match may begin the next query.
            let restart = byte == ESC;
            if restart {
                self.held.pop();
            }
            scan.forward.append(&mut self.held);
            if restart {
                self.held.push(ESC);
            }
        }
    }

    fn parse(&mut self, byte: u8, scan: &mut Scan) {
        match self.state {
            ScanState::Ground => {
                if byte == ESC {
                    self.state = ScanState::Escape;
                }
            }
            ScanState::Escape => self.after_escape(byte, scan),
            ScanState::Osc => match byte {
                BEL => self.finish(scan),
                ESC => self.state = ScanState::OscEscape,
                CAN | SUB => self.state = ScanState::Ground,
                _ => self.accumulate(byte),
            },
            ScanState::OscEscape => {
                if byte == b'\\' {
                    self.finish(scan);
                } else {
                    // ESC interrupted the string; it introduces what follows.
                    self.after_escape(byte, scan);
                }
            }
        }
    }

    fn after_escape(&mut self, byte: u8, scan: &mut Scan) {
        if byte == b'c' {
            scan.events.push(TerminalEvent::Reset);
        }
        self.state = match byte {
            b']' => {
                self.tracking = Tracking::Undecided;
                self.body.clear();
                // OSC plus the ST that ends it count toward the limit.
                self.sequence_len = 4;
                ScanState::Osc
            }
            ESC => ScanState::Escape,
            _ => ScanState::Ground,
        };
    }

    fn accumulate(&mut self, byte: u8) {
        self.sequence_len += 1;
        if self.sequence_len > MAX_SEQUENCE {
            self.tracking = Tracking::Ignore;
            self.body = Vec::new();
            return;
        }
        match self.tracking {
            Tracking::Undecided => {
                self.body.push(byte);
                if !REPORT_PREFIX.starts_with(&self.body) && !PROMPT_PREFIX.starts_with(&self.body)
                {
                    self.tracking = Tracking::Ignore;
                } else if self.body.len() == PREFIX_LEN {
                    self.tracking = if self.body == REPORT_PREFIX {
                        Tracking::Report
                    } else {
                        Tracking::Prompt
                    };
                }
            }
            Tracking::Report => self.body.push(byte),
            Tracking::Prompt | Tracking::Ignore => {}
        }
    }

    fn finish(&mut self, scan: &mut Scan) {
        self.state = ScanState::Ground;
        match self.tracking {
            Tracking::Prompt => scan.events.push(TerminalEvent::Prompt),
            Tracking::Report if self.body != QUERY_BODY => {
                if let Some(report) = parse_report(&self.body[REPORT_PREFIX.len()..]) {
                    scan.events.push(TerminalEvent::Report(report));
                }
            }
            _ => {}
        }
        self.tracking = Tracking::Ignore;
        self.body.clear();
    }
}

fn is_value_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"_.,+/=-".contains(&byte)
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"_.+-".contains(&byte)
}

fn valid_id(id: &str) -> bool {
    let segments: Vec<&str> = id.split('/').collect();
    id.len() <= MAX_ID
        && segments.len() <= MAX_ID_DEPTH
        && segments.iter().all(|segment| {
            (1..=MAX_ID_SEGMENT).contains(&segment.len()) && segment.bytes().all(is_name_byte)
        })
}

/// Validate base64 free text without keeping it.
fn valid_text(value: &str, max_encoded: usize) -> bool {
    if value.len() > max_encoded {
        return false;
    }
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    let Ok(decoded) = engine.decode(value) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&decoded) else {
        return false;
    };
    !text.chars().any(char::is_control)
}

/// Parse the pairs after `7501;`. `None` means the whole report is discarded.
fn parse_report(pairs: &[u8]) -> Option<Report> {
    let pairs = std::str::from_utf8(pairs).ok()?;
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for pair in pairs.split(':') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if key.is_empty()
            || key.len() > MAX_KEY
            || !key.bytes().all(|byte| byte.is_ascii_lowercase())
            || !value.bytes().all(is_value_byte)
        {
            continue;
        }
        fields.insert(key, value);
    }

    let id = match fields.get("id") {
        Some(id) if valid_id(id) => Some((*id).to_string()),
        Some(_) => return None,
        None => None,
    };
    if fields
        .get("msg")
        .is_some_and(|msg| !valid_text(msg, MAX_MSG_ENCODED))
        || fields
            .get("title")
            .is_some_and(|title| !valid_text(title, MAX_TITLE_ENCODED))
    {
        return None;
    }
    let state = match *fields.get("state")? {
        "clear" => return Some(Report::Clear { id }),
        "idle" => ProgramState::Idle,
        "working" => ProgramState::Working,
        "done" => ProgramState::Done,
        "blocked" => ProgramState::Blocked,
        "error" => ProgramState::Error,
        // A state added later must never read as an older one.
        _ => return None,
    };
    let kind = (state == ProgramState::Blocked)
        .then(|| match *fields.get("kind")? {
            "permission" => Some(BlockedKind::Permission),
            "question" => Some(BlockedKind::Question),
            "auth" => Some(BlockedKind::Auth),
            _ => None,
        })
        .flatten();
    let app = fields
        .get("app")
        .filter(|app| (1..=MAX_APP).contains(&app.len()) && app.bytes().all(is_name_byte))
        .map(|app| (*app).to_string());
    let progress = matches!(state, ProgramState::Working | ProgramState::Blocked)
        .then(|| {
            fields
                .get("progress")?
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= 100)
        })
        .flatten();
    Some(Report::Set {
        id: id.unwrap_or_default(),
        record: ProgramRecord {
            state,
            kind,
            app,
            progress,
        },
    })
}

/// The records one terminal holds.
#[derive(Debug, Default)]
struct Records {
    records: BTreeMap<String, (ProgramRecord, u64)>,
    next_update: u64,
}

impl Records {
    fn apply(&mut self, report: Report) {
        match report {
            Report::Set { id, record } => {
                let update = self.next_update;
                self.next_update += 1;
                self.records.insert(id, (record, update));
                while self.records.len() > MAX_RECORDS {
                    let oldest = self
                        .records
                        .iter()
                        .min_by_key(|(_, (_, update))| *update)
                        .map(|(id, _)| id.clone());
                    if let Some(oldest) = oldest {
                        self.records.remove(&oldest);
                    }
                }
            }
            Report::Clear { id: None } => self.records.clear(),
            Report::Clear { id: Some(id) } => {
                let prefix = format!("{id}/");
                self.records
                    .retain(|record_id, _| record_id != &id && !record_id.starts_with(&prefix));
            }
        }
    }

    /// A new prompt or a process exit ends the records that describe a
    /// running program.
    fn drop_running(&mut self) {
        self.records.retain(|_, (record, _)| {
            !matches!(record.state, ProgramState::Working | ProgramState::Blocked)
        });
    }

    fn app_for(&self, id: &str) -> Option<String> {
        let mut current = id;
        loop {
            if let Some((record, _)) = self.records.get(current)
                && let Some(app) = &record.app
            {
                return Some(app.clone());
            }
            if current.is_empty() {
                return None;
            }
            current = current.rsplit_once('/').map_or("", |(parent, _)| parent);
        }
    }

    /// The most active record: working, then blocked, error, done, idle.
    fn dominant(&self) -> Option<(ProgramState, Option<BlockedKind>, Option<String>)> {
        self.records
            .iter()
            .max_by_key(|(_, (record, update))| (record.state, *update))
            .map(|(id, (record, _))| (record.state, record.kind, self.app_for(id)))
    }
}

#[derive(Debug)]
struct TerminalStatus {
    records: Records,
    last_output: Instant,
}

/// Sandbox-wide status that changes only on program state transitions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ActivitySummary {
    /// Most active state across terminals; `None` until a program reports.
    pub state: Option<ProgramState>,
    pub kind: Option<BlockedKind>,
    pub app: Option<String>,
    /// Open workload terminals.
    pub terminals: usize,
    /// Terminals with a current program report.
    pub reporting_terminals: usize,
    /// Increments on every state transition, including one that is undone
    /// within the same read, so each transition is a distinct value.
    pub revision: u64,
}

/// Point-in-time activity including timestamps that change on every byte.
#[derive(Clone, Debug)]
pub struct ActivitySnapshot {
    pub summary: ActivitySummary,
    pub last_output: Option<Instant>,
    pub last_input: Option<Instant>,
    /// When `summary.state` last changed.
    pub state_since: Instant,
}

#[derive(Debug)]
struct Inner {
    next_terminal: u64,
    terminals: BTreeMap<u64, TerminalStatus>,
    state_since: Instant,
    /// Latest client input to any workload terminal, kept after the terminal
    /// closes so a short session still counts as recent input.
    last_input: Option<Instant>,
    revision: u64,
}

impl Inner {
    fn dominant_state(&self) -> Option<ProgramState> {
        self.terminals
            .values()
            .filter_map(|terminal| terminal.records.dominant())
            .map(|(state, _, _)| state)
            .max()
    }

    /// Record a transition when `before` differs from the current state.
    fn note_transition(&mut self, before: Option<ProgramState>) -> Option<ProgramState> {
        let after = self.dominant_state();
        if after != before {
            self.state_since = Instant::now();
            self.revision += 1;
        }
        after
    }
}

/// Program status across every workload terminal in one sandbox.
#[derive(Debug)]
pub struct ProgramActivity {
    inner: Mutex<Inner>,
    changes: watch::Sender<ActivitySummary>,
    /// Held from snapshot to enqueue, so pushes and request replies leave in
    /// snapshot order and carry increasing sequence numbers.
    report_order: tokio::sync::Mutex<u64>,
}

impl ProgramActivity {
    #[must_use]
    pub fn new() -> Arc<Self> {
        let (changes, _) = watch::channel(ActivitySummary::default());
        Arc::new(Self {
            inner: Mutex::new(Inner {
                next_terminal: 0,
                terminals: BTreeMap::new(),
                state_since: Instant::now(),
                last_input: None,
                revision: 0,
            }),
            changes,
            report_order: tokio::sync::Mutex::new(0),
        })
    }

    /// Notified only when the summary changes.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<ActivitySummary> {
        self.changes.subscribe()
    }

    #[must_use]
    pub fn snapshot(&self) -> ActivitySnapshot {
        let inner = self.inner.lock().expect("program activity lock poisoned");
        ActivitySnapshot {
            summary: summarize(&inner),
            last_output: inner.terminals.values().map(|t| t.last_output).max(),
            last_input: inner.last_input,
            state_since: inner.state_since,
        }
    }

    /// Track a new workload terminal. `reply` writes to the program's input.
    pub fn register(
        self: &Arc<Self>,
        reply: impl Fn(&[u8]) + Send + Sync + 'static,
    ) -> TerminalTap {
        let id = self.update(|inner| {
            let id = inner.next_terminal;
            inner.next_terminal += 1;
            inner.terminals.insert(
                id,
                TerminalStatus {
                    records: Records::default(),
                    last_output: Instant::now(),
                },
            );
            id
        });
        TerminalTap {
            activity: Arc::clone(self),
            id,
            scanner: Scanner::new(),
            reply: Box::new(reply),
        }
    }

    fn update<T>(&self, change: impl FnOnce(&mut Inner) -> T) -> T {
        let mut inner = self.inner.lock().expect("program activity lock poisoned");
        let before = inner.dominant_state();
        let result = change(&mut inner);
        inner.note_transition(before);
        self.publish(&inner);
        result
    }

    /// Publish while holding the lock, so summaries leave in mutation order
    /// and an older one never overwrites a newer one.
    fn publish(&self, inner: &Inner) {
        let after = summarize(inner);
        self.changes.send_if_modified(|current| {
            if *current == after {
                false
            } else {
                *current = after;
                true
            }
        });
    }

    /// Apply a terminal's output events in order, noting every transition so
    /// the timer does not depend on how reads split the output.
    fn apply_events(&self, id: u64, events: Vec<TerminalEvent>) {
        let mut inner = self.inner.lock().expect("program activity lock poisoned");
        let mut state = inner.dominant_state();
        let Some(terminal) = inner.terminals.get_mut(&id) else {
            return;
        };
        terminal.last_output = Instant::now();
        for event in events {
            let Some(terminal) = inner.terminals.get_mut(&id) else {
                break;
            };
            match event {
                TerminalEvent::Report(report) => terminal.records.apply(report),
                TerminalEvent::Prompt => terminal.records.drop_running(),
                TerminalEvent::Reset => terminal.records.apply(Report::Clear { id: None }),
            }
            state = inner.note_transition(state);
        }
        self.publish(&inner);
    }

    fn touch_input(&self, id: u64) {
        // Input never changes the summary; skip the change notification.
        let mut inner = self.inner.lock().expect("program activity lock poisoned");
        if inner.terminals.contains_key(&id) {
            inner.last_input = Some(Instant::now());
        }
    }
}

fn summarize(inner: &Inner) -> ActivitySummary {
    let dominant = inner
        .terminals
        .values()
        .filter_map(|terminal| terminal.records.dominant())
        .max_by_key(|(state, _, _)| *state);
    ActivitySummary {
        state: dominant.as_ref().map(|(state, _, _)| *state),
        kind: dominant.as_ref().and_then(|(_, kind, _)| *kind),
        app: dominant.and_then(|(_, _, app)| app),
        terminals: inner.terminals.len(),
        reporting_terminals: inner
            .terminals
            .values()
            .filter(|terminal| !terminal.records.records.is_empty())
            .count(),
        revision: inner.revision,
    }
}

/// Per-terminal view of the workload output stream. Dropping it ends the
/// terminal, which removes its records as a process exit would.
pub struct TerminalTap {
    activity: Arc<ProgramActivity>,
    id: u64,
    scanner: Scanner,
    reply: ReplyFn,
}

/// Writes supervisor-generated replies to the program's input.
type ReplyFn = Box<dyn Fn(&[u8]) + Send + Sync>;

impl TerminalTap {
    /// Observe program output and return the bytes to forward.
    pub fn output(&mut self, data: &[u8]) -> Vec<u8> {
        let scan = self.scanner.scan(data);
        for terminator in &scan.queries {
            (self.reply)(match terminator {
                Terminator::St => REPLY_ST,
                Terminator::Bel => REPLY_BEL,
            });
        }
        // Wire order matters: a prompt ends only the reports before it.
        self.activity.apply_events(self.id, scan.events);
        scan.forward
    }

    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.scanner.has_pending()
    }

    pub fn flush(&mut self) -> Vec<u8> {
        self.scanner.flush()
    }

    /// A handle that records client input for this terminal.
    #[must_use]
    pub fn input_marker(&self) -> InputMarker {
        InputMarker {
            activity: Arc::clone(&self.activity),
            id: self.id,
        }
    }
}

impl Drop for TerminalTap {
    fn drop(&mut self) {
        let id = self.id;
        self.activity.update(|inner| {
            inner.terminals.remove(&id);
        });
    }
}

#[derive(Clone)]
pub struct InputMarker {
    activity: Arc<ProgramActivity>,
    id: u64,
}

impl InputMarker {
    pub fn mark(&self) {
        self.activity.touch_input(self.id);
    }
}

/// How long held query bytes wait for the rest of the sequence.
pub const PENDING_FLUSH: std::time::Duration = std::time::Duration::from_millis(20);

/// Read the next chunk to forward, observing it through `tap`. Returns `None`
/// at end of stream after releasing any held bytes.
pub async fn read_observed<R>(
    reader: &mut R,
    buffer: &mut [u8],
    tap: &mut TerminalTap,
) -> Option<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    loop {
        let read = if tap.has_pending() {
            match tokio::time::timeout(PENDING_FLUSH, reader.read(buffer)).await {
                Ok(read) => read,
                Err(_) => return Some(tap.flush()),
            }
        } else {
            reader.read(buffer).await
        };
        match read {
            Ok(0) | Err(_) => {
                let rest = tap.flush();
                return (!rest.is_empty()).then_some(rest);
            }
            Ok(size) => {
                let forward = tap.output(&buffer[..size]);
                if !forward.is_empty() {
                    return Some(forward);
                }
            }
        }
    }
}

/// Log sandbox-wide program state transitions until the activity is dropped.
pub fn spawn_transition_log(activity: &Arc<ProgramActivity>) -> tokio::task::JoinHandle<()> {
    let mut changes = activity.subscribe();
    let activity = Arc::downgrade(activity);
    tokio::spawn(async move {
        let mut last_state = None;
        while changes.changed().await.is_ok() {
            if activity.upgrade().is_none() {
                break;
            }
            let summary = changes.borrow_and_update().clone();
            if summary.state == last_state {
                continue;
            }
            last_state = summary.state;
            tracing::debug!(
                state = summary.state.map_or("unknown", ProgramState::as_str),
                kind = summary.kind.map(BlockedKind::as_str),
                app = summary.app.as_deref(),
                terminals = summary.terminals,
                reporting_terminals = summary.reporting_terminals,
                "workload program status changed"
            );
        }
    })
}

/// How often the reporter checks for input that changed nothing else.
const INPUT_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
/// Minimum spacing of input-only reports while a client keeps typing. New
/// input is always reported within this interval plus one check, including
/// the last keystroke before the client stops.
const INPUT_REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

fn proto_state(state: Option<ProgramState>) -> openshell_core::proto::WorkloadProgramState {
    use openshell_core::proto::WorkloadProgramState as Proto;
    match state {
        None => Proto::Unspecified,
        Some(ProgramState::Idle) => Proto::Idle,
        Some(ProgramState::Working) => Proto::Working,
        Some(ProgramState::Done) => Proto::Done,
        Some(ProgramState::Blocked) => Proto::Blocked,
        Some(ProgramState::Error) => Proto::Error,
    }
}

fn proto_kind(kind: Option<BlockedKind>) -> openshell_core::proto::WorkloadBlockedKind {
    use openshell_core::proto::WorkloadBlockedKind as Proto;
    match kind {
        None => Proto::Unspecified,
        Some(BlockedKind::Permission) => Proto::Permission,
        Some(BlockedKind::Question) => Proto::Question,
        Some(BlockedKind::Auth) => Proto::Auth,
    }
}

fn proto_age(since: Instant) -> Option<prost_types::Duration> {
    openshell_core::time::duration_from_std(since.elapsed()).ok()
}

/// The gateway-bound report for a snapshot. Ages are measured now.
#[must_use]
pub fn activity_report(
    snapshot: &ActivitySnapshot,
) -> openshell_core::proto::SupervisorWorkloadActivity {
    openshell_core::proto::SupervisorWorkloadActivity {
        state: proto_state(snapshot.summary.state).into(),
        blocked_kind: proto_kind(snapshot.summary.kind).into(),
        app: snapshot.summary.app.clone().unwrap_or_default(),
        state_age: proto_age(snapshot.state_since),
        input_age: snapshot.last_input.and_then(proto_age),
        reporting_terminals: u32::try_from(snapshot.summary.reporting_terminals)
            .unwrap_or(u32::MAX),
        request_id: String::new(),
        sequence: 0,
    }
}

impl ProgramActivity {
    /// Snapshot the summary and enqueue it on `tx` as one ordered step.
    /// `request_id` is set when the summary answers a gateway request.
    /// Returns the snapshot that was sent.
    ///
    /// # Errors
    ///
    /// Returns an error when the session's outbound channel has closed.
    pub async fn send_report(
        &self,
        tx: &tokio::sync::mpsc::Sender<openshell_core::proto::SupervisorMessage>,
        request_id: &str,
    ) -> Result<ActivitySnapshot, ()> {
        let mut sequence = self.report_order.lock().await;
        *sequence += 1;
        let snapshot = self.snapshot();
        let mut report = activity_report(&snapshot);
        report.request_id = request_id.to_string();
        report.sequence = *sequence;
        let message = openshell_core::proto::SupervisorMessage {
            payload: Some(
                openshell_core::proto::supervisor_message::Payload::WorkloadActivity(report),
            ),
        };
        tx.send(message).await.map_err(|_| ())?;
        Ok(snapshot)
    }
}

/// Aborts the reporter when the session that owns it ends.
pub struct ReporterGuard(tokio::task::JoinHandle<()>);

impl Drop for ReporterGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Whether new input alone warrants a report. Input only matters while the
/// program waits on the user: a working program is never idle, and the next
/// state change reports the input it missed.
fn input_report_due(
    snapshot: &ActivitySnapshot,
    reported_input: Option<Instant>,
    last_send: Option<Instant>,
) -> bool {
    snapshot.last_input != reported_input
        && snapshot
            .summary
            .state
            .is_some_and(ProgramState::awaits_user)
        && last_send.is_none_or(|sent| sent.elapsed() >= INPUT_REPORT_INTERVAL)
}

/// Report activity on one gateway session: once at start, on every summary
/// change, and within seconds of new client input while the program waits
/// on the user.
pub fn spawn_activity_reporter(
    activity: &Arc<ProgramActivity>,
    tx: tokio::sync::mpsc::Sender<openshell_core::proto::SupervisorMessage>,
) -> ReporterGuard {
    let activity = Arc::clone(activity);
    let mut changes = activity.subscribe();
    ReporterGuard(tokio::spawn(async move {
        let mut input_check = tokio::time::interval(INPUT_CHECK_INTERVAL);
        input_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut reported_input: Option<Instant> = None;
        let mut last_send: Option<Instant> = None;
        let mut send_now = true;
        loop {
            let snapshot = activity.snapshot();
            if send_now || input_report_due(&snapshot, reported_input, last_send) {
                let Ok(sent) = activity.send_report(&tx, "").await else {
                    return;
                };
                reported_input = sent.last_input;
                last_send = Some(Instant::now());
            }
            tokio::select! {
                result = changes.changed() => {
                    if result.is_err() {
                        return;
                    }
                    changes.borrow_and_update();
                    send_now = true;
                }
                _ = input_check.tick() => send_now = false,
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use tokio::io::AsyncWriteExt as _;

    fn set(state: ProgramState) -> Report {
        Report::Set {
            id: String::new(),
            record: ProgramRecord {
                state,
                kind: None,
                app: None,
                progress: None,
            },
        }
    }

    fn report(body: &str) -> Option<Report> {
        parse_report(body.as_bytes())
    }

    #[test]
    fn parses_blocked_report_with_kind_app_and_message() {
        let parsed =
            report("state=blocked:kind=permission:app=claude-code:msg=QWxsb3cgcm0/").unwrap();
        assert_eq!(
            parsed,
            Report::Set {
                id: String::new(),
                record: ProgramRecord {
                    state: ProgramState::Blocked,
                    kind: Some(BlockedKind::Permission),
                    app: Some("claude-code".into()),
                    progress: None,
                },
            }
        );
    }

    #[test]
    fn discards_unknown_state_missing_state_and_bad_ids() {
        assert_eq!(report("state=sleeping"), None);
        assert_eq!(report("app=cargo"), None);
        assert_eq!(report("state=idle:id=a//b"), None);
        assert_eq!(report("state=idle:id=a/b/c/d/e/f/g/h/i"), None);
    }

    #[test]
    fn discards_message_with_control_characters_or_bad_base64() {
        // "a\nb"
        assert_eq!(report("state=done:msg=YQpi"), None);
        assert_eq!(report("state=done:msg=A"), None);
        // Bytes outside the value alphabet make the pair malformed, not the report.
        assert!(report("state=done:msg=@@@").is_some());
        assert!(report("state=done:msg=b2s").is_some());
    }

    #[test]
    fn skips_malformed_pairs_and_ignores_irrelevant_fields() {
        let parsed = report("bogus: state = working :progress=101:kind=auth:Key=x").unwrap();
        let Report::Set { record, .. } = parsed else {
            panic!("expected set");
        };
        assert_eq!(record.state, ProgramState::Working);
        assert_eq!(record.progress, None);
        assert_eq!(record.kind, None);
        let Report::Set { record, .. } = report("state=working:progress=42").unwrap() else {
            panic!("expected set");
        };
        assert_eq!(record.progress, Some(42));
    }

    #[test]
    fn clear_without_id_clears_everything() {
        assert_eq!(report("state=clear"), Some(Report::Clear { id: None }));
        assert_eq!(
            report("state=clear:id=build"),
            Some(Report::Clear {
                id: Some("build".into())
            })
        );
    }

    #[test]
    fn scanner_passes_reports_through_and_strips_queries() {
        let mut scanner = Scanner::new();
        let input = b"hi\x1b]7501;?\x1b\\\x1b[c\x1b]7501;state=working\x07there";
        let scan = scanner.scan(input);
        assert_eq!(scan.queries, vec![Terminator::St]);
        assert_eq!(
            scan.events,
            vec![TerminalEvent::Report(set(ProgramState::Working))]
        );
        assert_eq!(
            scan.forward,
            b"hi\x1b[c\x1b]7501;state=working\x07there".to_vec()
        );
        assert!(!scanner.has_pending());
    }

    #[test]
    fn scanner_handles_sequences_split_across_reads() {
        let input = b"\x1b]7501;?\x07\x1b]7501;state=done\x1b\\ok";
        for split in 0..input.len() {
            let mut scanner = Scanner::new();
            let first = scanner.scan(&input[..split]);
            let second = scanner.scan(&input[split..]);
            let mut forward = first.forward;
            forward.extend(second.forward);
            assert_eq!(
                forward,
                b"\x1b]7501;state=done\x1b\\ok".to_vec(),
                "split {split}"
            );
            assert_eq!(
                [first.queries, second.queries].concat(),
                vec![Terminator::Bel]
            );
            assert_eq!(
                [first.events, second.events].concat(),
                vec![TerminalEvent::Report(set(ProgramState::Done))]
            );
        }
    }

    #[test]
    fn scanner_flushes_lone_escape_and_restarts_on_new_escape() {
        let mut scanner = Scanner::new();
        let scan = scanner.scan(b"a\x1b");
        assert_eq!(scan.forward, b"a".to_vec());
        assert!(scanner.has_pending());
        assert_eq!(scanner.flush(), b"\x1b".to_vec());

        let mut scanner = Scanner::new();
        let scan = scanner.scan(b"\x1b]75\x1b]7501;?\x07");
        assert_eq!(scan.forward, b"\x1b]75".to_vec());
        assert_eq!(scan.queries, vec![Terminator::Bel]);
    }

    #[test]
    fn scanner_ignores_oversized_and_other_sequences() {
        let mut scanner = Scanner::new();
        let mut input = b"\x1b]7501;state=working:msg=".to_vec();
        input.extend(std::iter::repeat_n(b'A', MAX_SEQUENCE));
        input.extend(b"\x1b\\\x1b]0;title\x07\x1b]133;A\x07");
        let scan = scanner.scan(&input);
        assert_eq!(scan.events, vec![TerminalEvent::Prompt]);
        assert_eq!(scan.forward, input);
    }

    #[test]
    fn records_clear_descendants_and_inherit_app() {
        let mut records = Records::default();
        records.apply(report("state=working:app=cargo:id=build").unwrap());
        records.apply(report("state=done:id=build/test").unwrap());
        records.apply(report("state=idle:id=other").unwrap());
        assert_eq!(
            records.dominant(),
            Some((ProgramState::Working, None, Some("cargo".into())))
        );
        assert_eq!(records.app_for("build/test"), Some("cargo".into()));
        records.apply(Report::Clear {
            id: Some("build".into()),
        });
        assert_eq!(records.dominant(), Some((ProgramState::Idle, None, None)));
        records.drop_running();
        assert_eq!(records.records.len(), 1);
    }

    #[test]
    fn records_evict_least_recently_updated_over_cap() {
        let mut records = Records::default();
        for index in 0..=MAX_RECORDS {
            records.apply(report(&format!("state=idle:id=r{index}")).unwrap());
        }
        assert_eq!(records.records.len(), MAX_RECORDS);
        assert!(!records.records.contains_key("r0"));
    }

    #[tokio::test]
    async fn activity_answers_queries_and_aggregates_terminals() {
        let activity = ProgramActivity::new();
        let mut changes = activity.subscribe();
        let replies = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let sink = Arc::clone(&replies);
        let mut main = activity.register(move |bytes| {
            sink.lock().unwrap().push(bytes.to_vec());
        });
        let mut shell = activity.register(|_| {});

        let forward = main.output(b"\x1b]7501;?\x1b\\\x1b]7501;state=done:app=claude-code\x1b\\");
        assert_eq!(replies.lock().unwrap().as_slice(), &[REPLY_ST.to_vec()]);
        assert_eq!(
            forward,
            b"\x1b]7501;state=done:app=claude-code\x1b\\".to_vec()
        );
        assert!(changes.has_changed().unwrap());
        let summary = changes.borrow_and_update().clone();
        assert_eq!(summary.state, Some(ProgramState::Done));
        assert_eq!(summary.app.as_deref(), Some("claude-code"));
        assert_eq!(summary.terminals, 2);
        assert_eq!(summary.reporting_terminals, 1);

        shell.output(b"\x1b]7501;state=working\x07");
        assert_eq!(
            activity.snapshot().summary.state,
            Some(ProgramState::Working)
        );

        shell.input_marker().mark();
        assert!(activity.snapshot().last_input.is_some());

        // A new prompt ends the shell's running program.
        shell.output(b"\x1b]133;A\x07");
        assert_eq!(activity.snapshot().summary.state, Some(ProgramState::Done));

        drop(main);
        drop(shell);
        let summary = activity.snapshot().summary;
        assert_eq!(summary.state, None);
        assert_eq!(summary.terminals, 0);
    }

    #[test]
    fn prompts_and_reports_apply_in_wire_order_for_every_chunking() {
        let input: &[u8] = b"\x1b]7501;state=working\x07\x1b]133;A\x07";
        let finals: Vec<Option<ProgramState>> = (0..=input.len())
            .map(|split| {
                let activity = ProgramActivity::new();
                let mut tap = activity.register(|_| {});
                tap.output(&input[..split]);
                tap.output(&input[split..]);
                activity.snapshot().summary.state
            })
            .collect();
        assert!(
            finals.iter().all(Option::is_none),
            "a prompt after a report ends it however the bytes arrive: {finals:?}"
        );

        // A report after the prompt belongs to the next program.
        let activity = ProgramActivity::new();
        let mut tap = activity.register(|_| {});
        tap.output(b"\x1b]133;A\x07\x1b]7501;state=blocked\x07");
        assert_eq!(
            activity.snapshot().summary.state,
            Some(ProgramState::Blocked)
        );
    }

    #[tokio::test]
    async fn a_turn_within_one_read_restarts_the_timer_and_notifies() {
        let activity = ProgramActivity::new();
        let mut tap = activity.register(|_| {});
        tap.output(b"\x1b]7501;state=done\x07");
        let mut changes = activity.subscribe();
        changes.borrow_and_update();
        let before = activity.snapshot();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        tap.output(b"\x1b]7501;state=working\x07\x1b]7501;state=done\x07");
        let after = activity.snapshot();
        assert_eq!(after.summary.state, Some(ProgramState::Done));
        assert!(
            after.state_since > before.state_since,
            "the new turn restarts the wait"
        );
        assert_eq!(after.summary.revision, before.summary.revision + 2);
        assert!(changes.has_changed().unwrap(), "the reporter is told");
    }

    #[test]
    fn concurrent_terminals_publish_every_transition_in_order() {
        let activity = ProgramActivity::new();
        let mut changes = activity.subscribe();
        let mut threads = Vec::new();
        for _ in 0..4 {
            let activity = Arc::clone(&activity);
            threads.push(std::thread::spawn(move || {
                let mut tap = activity.register(|_| {});
                for _ in 0..200 {
                    tap.output(b"\x1b]7501;state=working\x07");
                    tap.output(b"\x1b]7501;state=done\x07");
                }
                std::mem::forget(tap);
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        // The last published summary is the final state, never an older one.
        assert_eq!(*changes.borrow_and_update(), activity.snapshot().summary);
    }

    fn received(
        message: openshell_core::proto::SupervisorMessage,
    ) -> openshell_core::proto::SupervisorWorkloadActivity {
        let Some(openshell_core::proto::supervisor_message::Payload::WorkloadActivity(report)) =
            message.payload
        else {
            panic!("expected workload activity");
        };
        report
    }

    #[tokio::test]
    async fn replies_carry_the_request_id_and_every_summary_a_new_sequence() {
        let activity = ProgramActivity::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        activity.send_report(&tx, "req-1").await.unwrap();
        activity.send_report(&tx, "").await.unwrap();
        let reply = received(rx.recv().await.unwrap());
        let push = received(rx.recv().await.unwrap());
        assert_eq!(reply.request_id, "req-1");
        assert!(push.request_id.is_empty());
        assert!(push.sequence > reply.sequence);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn replies_and_pushes_leave_in_snapshot_order() {
        let activity = ProgramActivity::new();
        let mut tap = activity.register(|_| {});
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mut senders = Vec::new();
        for index in 0..32 {
            let activity = Arc::clone(&activity);
            let tx = tx.clone();
            senders.push(tokio::spawn(async move {
                let request = if index % 2 == 0 { "req" } else { "" };
                activity.send_report(&tx, request).await.unwrap();
            }));
            let report: &[u8] = if index % 2 == 0 {
                b"\x1b]7501;state=working\x07"
            } else {
                b"\x1b]7501;state=done\x07"
            };
            tap.output(report);
        }
        for sender in senders {
            sender.await.unwrap();
        }
        activity.send_report(&tx, "").await.unwrap();
        drop(tx);
        let mut last = 0;
        let mut final_state = 0;
        while let Some(message) = rx.recv().await {
            let report = received(message);
            assert!(
                report.sequence > last,
                "sequence {} after {last}",
                report.sequence
            );
            last = report.sequence;
            final_state = report.state;
        }
        assert_eq!(
            final_state,
            i32::from(openshell_core::proto::WorkloadProgramState::Done),
            "the newest summary is the last one sent"
        );
    }

    #[test]
    fn full_terminal_reset_clears_records() {
        let activity = ProgramActivity::new();
        let mut tap = activity.register(|_| {});
        let forward = tap.output(b"\x1b]7501;state=done\x07\x1bc");
        assert_eq!(forward, b"\x1b]7501;state=done\x07\x1bc".to_vec());
        assert_eq!(activity.snapshot().summary.state, None);
        // ESC c interrupting an unterminated OSC also resets.
        tap.output(b"\x1b]7501;state=done\x07\x1b]7501;state=wor\x1bc");
        assert_eq!(activity.snapshot().summary.state, None);
    }

    #[test]
    fn reports_without_a_probe_count_and_input_outlives_its_terminal() {
        let activity = ProgramActivity::new();
        let mut probing = activity.register(|_| {});
        probing.output(b"\x1b]7501;?\x07");
        let mut codex = activity.register(|_| {});
        codex.output(b"\x1b]7501;state=working:app=codex\x07");
        assert_eq!(activity.snapshot().summary.reporting_terminals, 1);

        let marker = probing.input_marker();
        marker.mark();
        let typed = activity.snapshot().last_input;
        drop(probing);
        assert!(typed.is_some());
        assert_eq!(activity.snapshot().last_input, typed);
    }

    #[test]
    fn echoed_replies_are_not_queries() {
        for reply in [REPLY_ST, REPLY_BEL] {
            let scan = Scanner::new().scan(reply);
            assert!(scan.queries.is_empty());
            assert!(scan.events.is_empty());
            assert_eq!(scan.forward, reply.to_vec());
        }
    }

    #[tokio::test]
    async fn reporter_sends_on_start_and_on_every_state_change() {
        use openshell_core::proto::{WorkloadProgramState, supervisor_message::Payload};
        let activity = ProgramActivity::new();
        let mut tap = activity.register(|_| {});
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let guard = spawn_activity_reporter(&activity, tx);
        let next_state = async |rx: &mut tokio::sync::mpsc::Receiver<_>| {
            let message: openshell_core::proto::SupervisorMessage = rx.recv().await.unwrap();
            let Some(Payload::WorkloadActivity(report)) = message.payload else {
                panic!("expected workload activity");
            };
            report.state
        };
        assert_eq!(
            next_state(&mut rx).await,
            i32::from(WorkloadProgramState::Unspecified)
        );
        tap.output(b"\x1b]7501;state=working:app=claude-code\x07");
        assert_eq!(
            next_state(&mut rx).await,
            i32::from(WorkloadProgramState::Working)
        );
        tap.output(b"\x1b]7501;state=done:app=claude-code\x07");
        assert_eq!(
            next_state(&mut rx).await,
            i32::from(WorkloadProgramState::Done)
        );
        drop(guard);
        tokio::task::yield_now().await;
        tap.output(b"\x1b]7501;state=working\x07");
        assert!(rx.recv().await.is_none(), "the guard ends the reporter");
    }

    #[test]
    fn input_alone_is_reported_only_while_the_program_waits() {
        let activity = ProgramActivity::new();
        let mut tap = activity.register(|_| {});
        let long_ago = Instant::now().checked_sub(INPUT_REPORT_INTERVAL * 2);
        let marker = tap.input_marker();
        tap.output(b"\x1b]7501;state=working:app=codex\x07");
        marker.mark();
        assert!(
            !input_report_due(&activity.snapshot(), None, long_ago),
            "input to a working program waits for its next state change"
        );
        tap.output(b"\x1b]7501;state=done:app=codex\x07");
        marker.mark();
        let snapshot = activity.snapshot();
        assert!(input_report_due(&snapshot, None, long_ago));
        assert!(
            !input_report_due(&snapshot, snapshot.last_input, long_ago),
            "input already reported is not reported again"
        );
        assert!(
            !input_report_due(&snapshot, None, Some(Instant::now())),
            "input reports are spaced"
        );
    }

    #[tokio::test]
    async fn read_observed_releases_held_bytes_after_a_pause() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let activity = ProgramActivity::new();
        let mut tap = activity.register(|_| {});
        let mut buffer = [0_u8; 16];
        writer.write_all(b"x\x1b").await.unwrap();
        assert_eq!(
            read_observed(&mut reader, &mut buffer, &mut tap).await,
            Some(b"x".to_vec())
        );
        assert_eq!(
            read_observed(&mut reader, &mut buffer, &mut tap).await,
            Some(b"\x1b".to_vec())
        );
        drop(writer);
        assert_eq!(
            read_observed(&mut reader, &mut buffer, &mut tap).await,
            None
        );
    }
}
