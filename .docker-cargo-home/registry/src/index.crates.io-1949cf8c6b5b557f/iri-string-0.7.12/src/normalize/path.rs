//! Path normalization.

use core::fmt;
use core::ops::{ControlFlow, Range};

use crate::parser::str::{find_split_hole, rfind};
use crate::spec::{Spec, UriSpec};

use super::pct_case::PctCaseNormalized;
use super::{Error, NormalizationMode, NormalizationOp};

/// Path that is (possibly) not yet processed or being processed.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Path<'a> {
    /// The result. No more processing is needed.
    Done(&'a str),
    /// Not yet completely processed path.
    NeedsProcessing(PathToNormalize<'a>),
}

/// Path that needs merge and/or dot segment removal.
///
/// This works like a queue with `pop_front` functionality.
///
/// # Invariants
///
/// * `back` should be `None` if `front` is empty.
/// * `back` should be a non-empty string if `Some`.
/// * `front` should ends with a slash if `back` is `Some`.
///     + In other words, any path segments can exist in `front` or `back`
///       but not both at a time.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PathToNormalize<'a> {
    /// Front half of the buffer.
    front: &'a str,
    /// Back half of the buffer.
    back: Option<&'a str>,
}

impl<'a> PathToNormalize<'a> {
    /// Creates a `PathToNormalize` from the given single path.
    #[inline]
    #[must_use]
    pub(crate) fn from_single_path(path: &'a str) -> Self {
        Self {
            front: path,
            back: None,
        }
    }

    /// Creates a `PathToNormalize` from the given base and reference paths to be resolved.
    #[must_use]
    pub(crate) fn from_paths_to_be_resolved(base: &'a str, reference: &'a str) -> Self {
        if reference.starts_with('/') {
            return Self {
                front: reference,
                back: None,
            };
        }

        match rfind(base.as_bytes(), b'/') {
            Some(last_slash_pos) => {
                let front = &base[..=last_slash_pos];
                debug_assert!(front.ends_with('/'));
                Self {
                    front,
                    back: Some(reference).filter(|s| !s.is_empty()),
                }
            }
            None => Self {
                front: reference,
                back: None,
            },
        }
    }

    /// Returns true if the path is empty string.
    #[inline]
    #[must_use]
    fn is_empty(&self) -> bool {
        debug_assert!(
            !(self.front.is_empty() && self.back.is_some()),
            "the front buffer must have been refilled"
        );
        self.front.is_empty()
    }

    /// Returns the length of the path.
    #[inline]
    #[must_use]
    pub(super) fn len(&self) -> usize {
        self.front.len() + self.back.map_or(0, |s| s.len())
    }

    /// Returns `true` if the path starts with a slash.
    #[must_use]
    fn starts_with_slash(&self) -> bool {
        self.front.starts_with('/')
    }

    /// Returns a byte at the position.
    ///
    /// Returns `None` if the index is out of range.
    // This characteristic is necessary since `i` can be the index after the
    // last byte (i.e., the "end" index of the range).
    #[must_use]
    fn byte_at(&self, i: usize) -> Option<u8> {
        match i.checked_sub(self.front.len()) {
            None => Some(self.front.as_bytes()[i]),
            Some(back_i) => self
                .back
                .and_then(|back| back.as_bytes().get(back_i).copied()),
        }
    }

    /// Returns the position of the next slash after (including) `start`.
    #[inline]
    #[must_use]
    fn find_next_slash_from(&self, start: usize) -> Option<usize> {
        if let Some(back_i) = start.checked_sub(self.front.len()) {
            // Search the back buffer.
            return self.back?[back_i..].find('/').map(|pos| start + pos);
        }
        match self.front[start..].find('/') {
            Some(pos) => Some(start + pos),
            None => {
                debug_assert!(
                    self.back.is_none(),
                    "front must ends with a slash if back is `Some`"
                );
                None
            }
        }
    }

    /// Removes the `len` characters from the beginning of `self`.
    fn remove_start(&mut self, len: usize) {
        if let Some(back_len) = len.checked_sub(self.front.len()) {
            self.front = self
                .back
                .take()
                .and_then(|s| s.get(back_len..))
                .unwrap_or_default();
            return;
        }
        self.front = &self.front[len..];
    }

    /// Removes the prefix that are ignorable on normalization.
    //
    // Skips the prefix dot segments without leading slashes (such as `./`,
    // `../`, and `../.././`). This is necessary because such segments should be
    // removed along with the FOLLOWING slashes, not leading slashes.
    fn remove_ignorable_prefix(&mut self) {
        while let Some(seg) = PathSegmentsIter::new(self).next() {
            if seg.has_leading_slash {
                // The first segment starting with a slash is not target.
                break;
            }
            match seg.kind(self) {
                SegmentKind::Dot | SegmentKind::DotDot => {
                    // Attempt to skip the following slash by `+ 1`.
                    let skip = self.front.len().min(seg.name_range.end + 1);
                    self.remove_start(skip);
                }
                SegmentKind::Normal => break,
            }
        }
    }
}

impl PathToNormalize<'_> {
    /// Writes the normalized path.
    pub(crate) fn fmt_write_normalize<S: Spec, W: fmt::Write>(
        mut self,
        f: &mut W,
        op: NormalizationOp,
        authority_is_present: bool,
    ) -> fmt::Result {
        if self.is_empty() {
            return Ok(());
        }

        if (op.mode == NormalizationMode::PreserveAuthoritylessRelativePath)
            && !authority_is_present
            && !self.starts_with_slash()
        {
            // Treat the path as "opaque", i.e. do not apply dot segments removal.
            // See <https://github.com/lo48576/iri-string/issues/29>.
            debug_assert!(
                op.mode.case_pct_normalization(),
                "case/pct normalization should still be applied"
            );
            write!(f, "{}", PctCaseNormalized::<S>::new(self.front))?;
            if let Some(back) = self.back {
                write!(f, "{}", PctCaseNormalized::<S>::new(back))?;
            }
            return Ok(());
        }

        // Skip the prefix dot segments without leading slashes (such as `./`,
        // `../`, and `../.././`). This is necessary because such segments should
        // be removed along with the FOLLOWING slashes, not leading slashes.
        self.remove_ignorable_prefix();
        if self.is_empty() {
            // The path consists of only `/.`s and `/..`s.
            // In this case, if the authority component is present, the result
            // should be `/`, not empty.
            if authority_is_present {
                f.write_char('/')?;
            }
            return Ok(());
        }

        // None: No segments are written yet.
        // Some(false): Something other than `/` is already written as the path.
        // Some(true): Only a `/` is written as the path.
        let mut only_a_slash_is_written = None;
        // `true` if the path may have not yet handled dot segments.
        let mut may_have_not_yet_resolved_dot_segments = true;
        // Scan for the dot segments and resolve them.
        while !self.is_empty() && may_have_not_yet_resolved_dot_segments {
            /// The size of the queue to track the path segments.
            ///
            /// This should be nonzero.
            const QUEUE_SIZE: usize = 8;

            let ret = self.resolve_and_write_path_prefixes::<S, _, QUEUE_SIZE>(
                &mut only_a_slash_is_written,
                &mut may_have_not_yet_resolved_dot_segments,
                authority_is_present,
                f,
                op,
            )?;
            if matches!(ret, ControlFlow::Break(_)) {
                return Ok(());
            }
        }

        if !self.is_empty() {
            if !authority_is_present {
                // Note that `self` has no dot segments anymore. In order to handle
                // authority-less relative path correctly, it would be enough to
                // check if the path to be written starts with `//` or not.
                match only_a_slash_is_written {
                    None => {
                        // TODO: `Option::is_some_and()` is stabilized since Rust 1.70.0.
                        if ((self.front == "/")
                            && self.back.map_or(false, |back| back.starts_with('/')))
                            || self.front.starts_with("//")
                        {
                            f.write_str("/.//")?;
                            self.remove_start("//".len());
                        }
                    }
                    Some(true) => {
                        if self.starts_with_slash() {
                            f.write_str(".//")?;
                            self.remove_start("/".len());
                        }
                    }
                    Some(false) => {}
                }
            }

            // Emit the path at once. No need to split into segments since it
            // has no dot segments.
            if op.mode.case_pct_normalization() {
                write!(f, "{}", PctCaseNormalized::<S>::new(self.front))?;
                if let Some(back) = &self.back {
                    write!(f, "{}", PctCaseNormalized::<S>::new(back))?;
                }
            } else {
                f.write_str(self.front)?;
                if let Some(back) = &self.back {
                    f.write_str(back)?;
                }
            }
        }

        Ok(())
    }

    /// Resolves the path and writes the prefixes as much as confirmed.
    fn resolve_and_write_path_prefixes<S, W, const QUEUE_SIZE: usize>(
        &mut self,
        only_a_slash_is_written: &mut Option<bool>,
        may_have_not_yet_resolved_dot_segments: &mut bool,
        authority_is_present: bool,
        f: &mut W,
        op: NormalizationOp,
    ) -> Result<ControlFlow<()>, fmt::Error>
    where
        S: Spec,
        W: fmt::Write,
    {
        assert!(!self.is_empty());
        assert!(*may_have_not_yet_resolved_dot_segments);

        // Skip the dot segments at the head.
        {
            let skipped_len = PathSegmentsIter::new(self)
                .map_while(|seg| match seg.kind(self) {
                    SegmentKind::Dot | SegmentKind::DotDot => {
                        debug_assert!(
                            seg.has_leading_slash,
                            "dot segments without a leading slash have already been skipped"
                        );
                        Some(seg.name_range.end)
                    }
                    SegmentKind::Normal => None,
                })
                .last()
                .unwrap_or(0);
            self.remove_start(skipped_len);
            if self.is_empty() {
                // Finished with a dot segment.
                // The last `/.` or `/..` should be replaced to `/`.
                if !authority_is_present && (*only_a_slash_is_written == Some(true)) {
                    // Insert a dot segment to break the prefix `//`.
                    // Without this, the path starts with `//` and it may
                    // be confused with the prefix of an authority.
                    f.write_str(".//")?;
                } else {
                    f.write_char('/')?;
                }
                return Ok(ControlFlow::Break(()));
            }
        }

        // Find decisive path segments from higher to lower.
        let (segname_queue, first_segment_has_leading_slash, resolved_end): (
            [Option<&'_ str>; QUEUE_SIZE],
            bool,
            usize,
        ) = {
            let mut segname_queue: [Option<&'_ str>; QUEUE_SIZE] = [Default::default(); QUEUE_SIZE];
            let mut first_segment_has_leading_slash = false;
            // The end byte position of the prefix that is being written in this
            // function call. The part before this position is ignorable after
            // the next iteration.
            let mut resolved_end = 0;

            let mut level: usize = 0;
            for seg in PathSegmentsIter::new(self) {
                let kind = seg.kind(self);
                match kind {
                    SegmentKind::Dot => {
                        *may_have_not_yet_resolved_dot_segments = true;
                    }
                    SegmentKind::DotDot => {
                        level = level.saturating_sub(1);
                        *may_have_not_yet_resolved_dot_segments = true;
                        if let Some(dest) = segname_queue.get_mut(level) {
                            *dest = None;
                        }
                    }
                    SegmentKind::Normal => {
                        if let Some(dest) = segname_queue.get_mut(level) {
                            *dest = Some(seg.segment(self));
                            *may_have_not_yet_resolved_dot_segments = false;
                            resolved_end = seg.name_range.end;
                            if level == 0 {
                                first_segment_has_leading_slash = seg.has_leading_slash;
                            }
                        }
                        level += 1;
                    }
                }
            }

            (segname_queue, first_segment_has_leading_slash, resolved_end)
        };

        // At this point, `segname_queue` has the prefix of the resolved path.
        for segname in segname_queue.iter().flatten() {
            PathToNormalize::emit_segment::<S, _>(
                f,
                only_a_slash_is_written,
                first_segment_has_leading_slash,
                segname,
                authority_is_present,
                op,
            )?;
        }

        // Trim the processed prefix.
        self.remove_start(resolved_end);

        Ok(ControlFlow::Continue(()))
    }

    /// Emits a non-dot segment and update the current state.
    //
    // `first_segment_has_leading_slash` can be any value if the segment is not the first one.
    fn emit_segment<S: Spec, W: fmt::Write>(
        f: &mut W,
        only_a_slash_is_written: &mut Option<bool>,
        first_segment_has_leading_slash: bool,
        segname: &str,
        authority_is_present: bool,
        op: NormalizationOp,
    ) -> fmt::Result {
        // Omit the leading slash of the segment only if the segment is
        // the first one and marked as not having a leading slash.
        match *only_a_slash_is_written {
            None => {
                // First segment.
                if first_segment_has_leading_slash {
                    f.write_char('/')?;
                }
                *only_a_slash_is_written =
                    Some(first_segment_has_leading_slash && segname.is_empty());
            }
            Some(only_a_slash) => {
                if only_a_slash && !authority_is_present {
                    // Apply serialization like WHATWG URL Standard.
                    // This prevents `<scheme=foo>:<path=//bar>` from written as `foo://bar`,
                    // which is interpreted as `<scheme=foo>://<authority=bar>`, which is
                    // semantically different from the original IRI. Prepending `./`, the
                    // serialization result would be `foo:/.//bar`, which is semantically
                    // equivalent to the original.
                    f.write_str("./")?;
                    *only_a_slash_is_written = Some(false);
                }
                f.write_char('/')?;
            }
        }

        // Write the segment name.
        if op.mode.case_pct_normalization() {
            write!(f, "{}", PctCaseNormalized::<S>::new(segname))
        } else {
            f.write_str(segname)
        }
    }

    /// Checks if the path is normalizable by RFC 3986 algorithm when the authority is absent.
    ///
    /// Returns `Ok(())` when normalizable, returns `Err(_)` if not.
    pub(crate) fn ensure_rfc3986_normalizable_with_authority_absent(&self) -> Result<(), Error> {
        /// A sink to get the prefix of the input.
        #[derive(Default)]
        struct PrefixRetriever {
            /// The buffer to remember the prefix of the input.
            buf: [u8; 3],
            /// The next write position in the buffer.
            cursor: usize,
        }
        impl PrefixRetriever {
            /// Returns the read prefix data.
            #[inline]
            #[must_use]
            fn as_bytes(&self) -> &[u8] {
                &self.buf[..self.cursor]
            }
        }
        impl fmt::Write for PrefixRetriever {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                if !s.is_empty() && (self.cursor >= self.buf.len()) {
                    // Enough bytes are read.
                    return Err(fmt::Error);
                }
                self.buf[self.cursor..]
                    .iter_mut()
                    .zip(s.bytes())
                    .for_each(|(dest, src)| *dest = src);
                self.cursor = self.cursor.saturating_add(s.len()).min(self.buf.len());
                Ok(())
            }
        }

        let mut prefix = PrefixRetriever::default();
        // The failure of this write indicates more than 3 characters are read.
        // This is safe to ignore since the check needs only 3 characters.
        let _ = self.fmt_write_normalize::<UriSpec, _>(
            &mut prefix,
            NormalizationOp {
                mode: NormalizationMode::None,
            },
            // Assume the authority is absent.
            false,
        );

        if prefix.as_bytes() == b"/./" {
            Err(Error::new())
        } else {
            Ok(())
        }
    }
}

/// Characteristic of a path.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PathCharacteristic {
    /// Absolute path, not special.
    CommonAbsolute,
    /// Absolute path, not special.
    CommonRelative,
    /// The first path segment of the relative path has one or more colon characters.
    RelativeFirstSegmentHasColon,
    /// The path starts with the double slash.
    StartsWithDoubleSlash,
}

impl PathCharacteristic {
    /// Returns true if the path is absolute.
    #[inline]
    #[must_use]
    pub(crate) fn is_absolute(self) -> bool {
        matches!(self, Self::CommonAbsolute | Self::StartsWithDoubleSlash)
    }

    /// Returns the characteristic of the path.
    pub(crate) fn from_path_to_display<S: Spec>(
        path: &PathToNormalize<'_>,
        op: NormalizationOp,
        authority_is_present: bool,
    ) -> Self {
        /// Dummy writer to get necessary values.
        #[derive(Default, Clone, Copy)]
        struct Writer {
            /// Result.
            result: Option<PathCharacteristic>,
            /// Whether the normalized path is absolute.
            is_absolute: Option<bool>,
        }
        impl fmt::Write for Writer {
            fn write_str(&mut self, mut s: &str) -> fmt::Result {
                if self.result.is_some() {
                    // Nothing more to do.
                    return Err(fmt::Error);
                }
                while !s.is_empty() {
                    if self.is_absolute.is_none() {
                        // The first input.
                        match s.strip_prefix('/') {
                            Some(rest) => {
                                self.is_absolute = Some(true);
                                s = rest;
                            }
                            None => {
                                self.is_absolute = Some(false);
                            }
                        }
                        continue;
                    }
                    if self.is_absolute == Some(true) {
                        let result = if s.starts_with('/') {
                            PathCharacteristic::StartsWithDoubleSlash
                        } else {
                            PathCharacteristic::CommonAbsolute
                        };
                        self.result = Some(result);
                        return Err(fmt::Error);
                    }
                    // Processing the first segment of the relative path.
                    match find_split_hole(s, b'/') {
                        Some((first_seg, _rest)) => {
                            let result = if first_seg.contains(':') {
                                PathCharacteristic::RelativeFirstSegmentHasColon
                            } else {
                                PathCharacteristic::CommonRelative
                            };
                            self.result = Some(result);
                            return Err(fmt::Error);
                        }
                        None => {
                            // `s` might not be the complete first segment.
                            if s.contains(':') {
                                self.result =
                                    Some(PathCharacteristic::RelativeFirstSegmentHasColon);
                                return Err(fmt::Error);
                            }
                            break;
                        }
                    }
                }
                Ok(())
            }
        }

        let mut writer = Writer::default();
        match path.fmt_write_normalize::<S, _>(&mut writer, op, authority_is_present) {
            // Empty path.
            Ok(_) => PathCharacteristic::CommonRelative,
            Err(_) => writer
                .result
                .expect("the formatting quits early by `Err` when the check is done"),
        }
    }
}

/// Path segment kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentKind {
    /// `.` or the equivalents.
    Dot,
    /// `..` or the equivalents.
    DotDot,
    /// Other normal (not special) segments.
    Normal,
}

impl SegmentKind {
    /// Creates a new `SegmentKind` from the given segment name.
    #[must_use]
    fn from_segment(s: &str) -> Self {
        if !(1..=6).contains(&s.len()) {
            // The length of a dot segment can only be 1, 2, 3, 4, or 6.
            return SegmentKind::Normal;
        }
        if !(s.starts_with('.') || s.starts_with('%')) {
            return SegmentKind::Normal;
        }
        match s {
            "." | "%2E" | "%2e" => SegmentKind::Dot,
            ".." | ".%2E" | ".%2e" | "%2E." | "%2E%2E" | "%2E%2e" | "%2e." | "%2e%2E"
            | "%2e%2e" => SegmentKind::DotDot,
            _ => SegmentKind::Normal,
        }
    }
}

/// A segment with optional leading slash.
#[derive(Debug, Clone)]
struct PathSegment {
    /// Presence of a leading slash.
    has_leading_slash: bool,
    /// Range of the segment name (without any slashes).
    name_range: Range<usize>,
}

impl PathSegment {
    /// Returns the segment without any slashes.
    #[inline]
    #[must_use]
    fn segment<'a>(&self, path: &PathToNormalize<'a>) -> &'a str {
        if let Some(seg_name) = path.front.get(self.name_range.clone()) {
            return seg_name;
        }
        let front_len = path.front.len();
        let back = path
            .back
            .expect("the segname range implies that the back buffer is filled");
        let back_range = (self.name_range.start - front_len)..(self.name_range.end - front_len);
        &back[back_range]
    }

    /// Returns the segment kind.
    #[inline]
    #[must_use]
    fn kind(&self, path: &PathToNormalize<'_>) -> SegmentKind {
        SegmentKind::from_segment(self.segment(path))
    }
}

/// Iterator of path segments.
struct PathSegmentsIter<'a> {
    /// Path.
    path: &'a PathToNormalize<'a>,
    /// Current cursor position.
    ///
    /// This is the next scan start position. If the previous segment has a
    /// trailing slash, the value will be the next byte position of the slash.
    cursor: usize,
}

impl<'a> PathSegmentsIter<'a> {
    /// Creates a new iterator of path segments.
    #[inline]
    #[must_use]
    fn new(path: &'a PathToNormalize<'a>) -> Self {
        Self { path, cursor: 0 }
    }
}

impl Iterator for PathSegmentsIter<'_> {
    type Item = PathSegment;

    fn next(&mut self) -> Option<Self::Item> {
        let cursor_byte = self.path.byte_at(self.cursor)?;
        let has_leading_slash = cursor_byte == b'/';
        let segname_start = if has_leading_slash {
            // Skip the leading slash.
            self.cursor + 1
        } else {
            self.cursor
        };

        // Find the trailing slash of the next segment.
        let segname_end = self
            .path
            .find_next_slash_from(segname_start)
            .unwrap_or_else(|| self.path.len());
        self.cursor = segname_end;
        Some(PathSegment {
            has_leading_slash,
            name_range: segname_start..segname_end,
        })
    }
}
