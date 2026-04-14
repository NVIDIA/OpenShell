//! Minor conveniences on top of the backtrace crate
//!
//! See [`short_frames_strict`][] for details.
use backtrace::*;
use std::ops::Range;

#[cfg(test)]
mod test;

/// Gets an iterator over the frames that are part of Rust's "short backtrace" range.
/// If no such range is found, the full stack is yielded.
///
/// Rust generally tries to include special frames on the stack called `rust_end_short_backtrace`
/// and `rust_begin_short_backtrace` which delimit the "real" stackframes from "gunk" stackframes
/// like setting up main and invoking the panic runtime. This yields all the "real" frames between
/// those two (which theoretically can be nothing with enough optimization, although that's unlikely
/// for any non-trivial program).
///
/// If only one of the special frames is present we will only clamp one side of the stack
/// (similar to `a..` or `..a`). If the special frames are in the wrong order we will discard
/// them and produce the full stack. If multiple versions of a special frame are found
/// (I've seen it in the wild), we will pick the "innermost" ones, producing the smallest
/// possible backtrace (and excluding all special frames from the output).
///
/// Each element of the iterator includes a Range which you should use to slice
/// the frame's `symbols()` array. This handles the theoretical situation where "real" frames
/// got inlined together with the special marker frames. I want to believe this can't happen
/// but you can never trust backtraces to be reasonable! We will never yield a Frame to you
/// with an empty Range.
///
/// Note that some "gunk" frames may still be found within the short backtrace, as there is still some
/// platform-specific and optimization-specific glue around the edges because compilers are
/// complicated and nothing's perfect. This can include:
///
/// * `core::ops::function::FnOnce::call_once`
/// * `std::panicking::begin_panic_handler`
/// * `core::panicking::panic_fmt`
/// * `rust_begin_unwind`
///
/// In the future we may introduce a non-strict short_frames which heuristically filters
/// those frames out too. Until then, the strict approach is safe.
///
/// # Example
///
/// Here's an example simple "short backtrace" implementation.
/// Note the use of `sub_frames` for the inner loop to restrict `symbols`!
///
/// This example is based off of code found in `miette` (Apache-2.0), which itself
/// copied the logic from `human-panic` (MIT/Apache-2.0).
///
/// FIXME: it would be nice if this example consulted `RUST_BACKTRACE=full`,
/// and maybe other vars used by rust's builtin panic handler..?
///
/// ```
/// fn backtrace() -> String {
///     use std::fmt::Write;
///     if let Ok(var) = std::env::var("RUST_BACKTRACE") {
///         if !var.is_empty() && var != "0" {
///             const HEX_WIDTH: usize = std::mem::size_of::<usize>() + 2;
///             // Padding for next lines after frame's address
///             const NEXT_SYMBOL_PADDING: usize = HEX_WIDTH + 6;
///             let mut backtrace = String::new();
///             let trace = backtrace::Backtrace::new();
///             let frames = backtrace_ext::short_frames_strict(&trace).enumerate();
///             for (idx, (frame, subframes)) in frames {
///                 let ip = frame.ip();
///                 let _ = write!(backtrace, "\n{:4}: {:2$?}", idx, ip, HEX_WIDTH);
///     
///                 let symbols = frame.symbols();
///                 if symbols.is_empty() {
///                     let _ = write!(backtrace, " - <unresolved>");
///                     continue;
///                 }
///     
///                 for (idx, symbol) in symbols[subframes].iter().enumerate() {
///                     // Print symbols from this address,
///                     // if there are several addresses
///                     // we need to put it on next line
///                     if idx != 0 {
///                         let _ = write!(backtrace, "\n{:1$}", "", NEXT_SYMBOL_PADDING);
///                     }
///     
///                     if let Some(name) = symbol.name() {
///                         let _ = write!(backtrace, " - {}", name);
///                     } else {
///                         let _ = write!(backtrace, " - <unknown>");
///                     }
///     
///                     // See if there is debug information with file name and line
///                     if let (Some(file), Some(line)) = (symbol.filename(), symbol.lineno()) {
///                         let _ = write!(
///                             backtrace,
///                             "\n{:3$}at {}:{}",
///                             "",
///                             file.display(),
///                             line,
///                             NEXT_SYMBOL_PADDING
///                         );
///                     }
///                 }
///             }
///             return backtrace;
///         }
///     }
///     "".into()
/// }
/// ```
pub fn short_frames_strict(
    backtrace: &Backtrace,
) -> impl Iterator<Item = (&BacktraceFrame, Range<usize>)> {
    short_frames_strict_impl(backtrace)
}

pub(crate) fn short_frames_strict_impl<B: Backtraceish>(
    backtrace: &B,
) -> impl Iterator<Item = (&B::Frame, Range<usize>)> {
    // Search for the special frames
    let mut short_start = None;
    let mut short_end = None;
    let frames = backtrace.frames();
    for (frame_idx, frame) in frames.iter().enumerate() {
        let symbols = frame.symbols();
        for (subframe_idx, frame) in symbols.iter().enumerate() {
            if let Some(name) = frame.name_str() {
                // Yes these ARE backwards, and that's intentional! We want to print the frames from
                // "newest to oldest" (show what panicked first), and that's the order that Backtrace
                // gives us, but these magic labels view the stack in the opposite order. So we just
                // swap it once here and forget about that weirdness.
                //
                // Note that due to platform/optimization wobblyness you can end up with multiple frames
                // that contain these names in sequence. If that happens we just want to pick the two
                // that are closest together. For the start that means just using the last one we found,
                // and for the end that means taking the first one we find.
                if name.contains("rust_end_short_backtrace") {
                    short_start = Some((frame_idx, subframe_idx));
                }
                if name.contains("rust_begin_short_backtrace") && short_end.is_none() {
                    short_end = Some((frame_idx, subframe_idx));
                }
            }
        }
    }

    // Check if these are in the right order, if they aren't, discard them
    // This also handles the mega-cursed case of "someone made a symbol with both names
    // so actually they're the exact same subframe".
    if let (Some(start), Some(end)) = (short_start, short_end) {
        if start >= end {
            short_start = None;
            short_end = None;
        }
    }

    // By default we want to produce a full stack trace and now we'll try to clamp it.
    let mut first_frame = 0usize;
    let mut first_subframe = 0usize;
    // NOTE: this is INCLUSIVE
    let mut last_frame = frames.len().saturating_sub(1);
    // NOTE: this is EXCLUSIVE
    let mut last_subframe_excl = backtrace
        .frames()
        .last()
        .map(|frame| frame.symbols().len())
        .unwrap_or(0);

    // This code tries to be really paranoid about boundary conditions although in practice
    // most of them are impossible because there's always going to be gunk on either side
    // of the short backtrace to smooth out the boundaries, and panic_fmt is basically
    // impossible to optimize out. Still, don't trust backtracers!!!
    //
    // This library has a fuckton of tests to try to catch all the little corner cases here.

    // If we found the start bound...
    if let Some((idx, sub_idx)) = short_start {
        if frames[idx].symbols().len() == sub_idx + 1 {
            // If it was the last subframe of this frame, we want to just
            // use the whole next frame! It's ok if this takes us to `first_frame = len`,
            // that will be properly handled as an empty output
            first_frame = idx + 1;
            first_subframe = 0;
        } else {
            // Otherwise use this frame, and all the subframes after it
            first_frame = idx;
            first_subframe = sub_idx + 1;
        }
    }

    // If we found the end bound...
    if let Some((idx, sub_idx)) = short_end {
        if sub_idx == 0 {
            // If it was the first subframe of this frame, we want to just
            // use the whole previous frame!
            if idx == 0 {
                // If we were *also* on the first frame, set subframe_excl
                // to 0, indicating an empty output
                last_frame = 0;
                last_subframe_excl = 0;
            } else {
                last_frame = idx - 1;
                last_subframe_excl = frames[last_frame].symbols().len();
            }
        } else {
            // Otherwise use this frame (no need subframe math, exclusive bound!)
            last_frame = idx;
            last_subframe_excl = sub_idx;
        }
    }

    // If the two subframes managed to perfectly line up with eachother, just
    // throw everything out and yield an empty range. We don't need to fix any
    // other values at this point as they won't be used for anything with an
    // empty iterator
    let final_frames = {
        let start = (first_frame, first_subframe);
        let end = (last_frame, last_subframe_excl);
        if start == end {
            &frames[0..0]
        } else {
            &frames[first_frame..=last_frame]
        }
    };

    // Get the index of the last frame when starting from the first frame
    let adjusted_last_frame = last_frame.saturating_sub(first_frame);

    // finally do the iteration
    final_frames.iter().enumerate().map(move |(idx, frame)| {
        // Default to all subframes being yielded
        let mut sub_start = 0;
        let mut sub_end_excl = frame.symbols().len();
        // If we're on first frame, apply its subframe clamp
        if idx == 0 {
            sub_start = first_subframe;
        }
        // If we're on the last frame, apply its subframe clamp
        if idx == adjusted_last_frame {
            sub_end_excl = last_subframe_excl;
        }
        (frame, sub_start..sub_end_excl)
    })
}

pub(crate) trait Backtraceish {
    type Frame: Frameish;
    fn frames(&self) -> &[Self::Frame];
}

pub(crate) trait Frameish {
    type Symbol: Symbolish;
    fn symbols(&self) -> &[Self::Symbol];
}

pub(crate) trait Symbolish {
    fn name_str(&self) -> Option<&str>;
}

impl Backtraceish for Backtrace {
    type Frame = BacktraceFrame;
    fn frames(&self) -> &[Self::Frame] {
        self.frames()
    }
}

impl Frameish for BacktraceFrame {
    type Symbol = BacktraceSymbol;
    fn symbols(&self) -> &[Self::Symbol] {
        self.symbols()
    }
}

impl Symbolish for BacktraceSymbol {
    // We need to shortcut SymbolName here because
    // HRTB isn't in our msrv
    fn name_str(&self) -> Option<&str> {
        self.name().and_then(|n| n.as_str())
    }
}
