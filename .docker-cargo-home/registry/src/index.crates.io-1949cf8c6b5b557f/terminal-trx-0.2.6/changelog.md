# Changelog
## 0.2.6
* Add `Terminal::has_connected_stdio_stream` to test if at least
  one standard I/O stream is connected to a given terminal.

## 0.2.5
* Update `windows-sys` to 0.61
* Raise the MSRV to 1.74 (this matches `terminal-colorsaurus`' MSRV)

## 0.2.4
* Fix "permission denied" errors on windows
  when enabling raw mode and stdin is redirected.

## 0.2.3
* Ensure that virtual terminal sequences are processed on Windows
  when raw mode is enabled. This is needed for <https://github.com/tautropfli/terminal-colorsaurus/issues/19>.

## 0.2.2
* Update `windows-sys` dependency to 0.59.

## 0.2.1
* Tests can now be run directly from the packaged sources instead
  of relying on in-tree sources.
* Remove private `__test_unsupported` feature.

## 0.2.0
* Breaking: `lock()` now ignores poisoning errors, removing the need for `PoisonError`.

## 0.1.0
Initial release
