The following terminals have known support or non-support for
querying for the background/foreground colors and have been tested
with `terminal-colorsaurus`:

## Supported
* Alacritty
* Contour
* foot
* [Ghostty]
* GNOME Terminal, (GNOME) Console, MATE Terminal, XFCE Terminal, (elementary) Terminal, LXTerminal
* Hyper
* The builtin terminal of JetBrains IDEs (i.e. IntelliJ IDEA, …)
* iTerm2
* kitty
* Konsole
* macOS Terminal
* neovim's built-in [terminal][nvim-terminal]
* Rio
* Terminology
* Termux
* tmux (next-3.4)
* urxvt (rxvt-unicode)
* VSCode (xterm.js)
* Warp
* WezTerm
* Windows Terminal (>= v1.22)
* xterm
* [Zed](https://zed.dev)

## Unsupported
* linux
* Jetbrains Fleet
* iSH
* GNU Screen

## Details

A list of terminals that were tested for support of `OSC 10` / `OSC 11` and `DA1` (= `CSI c`).

| Terminal                   | `OSC 10` and `OSC 11` | `DA1` | Version Tested                     |
|----------------------------|-----------------------|-------|------------------------------------|
| [Alacritty]                | yes                   | yes   | Version 0.13.1 (1) (macOS)         |
| [Contour]                  | yes                   | yes   | 0.4.1.6292 (macOS)                 |
| [foot]                     | yes                   | yes   | 1.16.1                             |
| [Ghostty]                  | yes                   | yes   | 1.0.0 (macOS)                      |
| [Hyper]                    | yes                   | yes   | 3.4.1 (macOS)                      |
| [iTerm2]                   | yes                   | yes   | Build 3.5.0beta18                  |
| [kitty]                    | yes                   | yes   | 0.31.0                             |
| (GNOME) [Console] [^1]     | yes                   | yes   | 3.50.1                             |
| [Konsole]                  | yes                   | yes   | 23.08.4                            |
| [mintty]                   | yes                   | yes   | 3.6.1                              |
| macOS Terminal             | yes [^3]              | yes   | Version 2.13 (447)                 |
| [neovim][nvim-terminal]    | yes                   | yes   | v0.10.2                            |
| [mlterm]                   | yes                   | yes   | [`f3474e1`][mlterm-commit]         |
| [Rio]                      | yes                   | yes   | 0.0.36 (wayland)                   |
| [rxvt-unicode]             | yes [^2]              | yes   | 9.31                               |
| [Terminology]              | yes [^4]              | yes   | 1.13.0                             |
| [Termux]                   | yes                   | yes   | 0.118.0                            |
| [Therm]                    | yes                   | yes   | 0.6.4                              |
| Warp                       | yes                   | yes   | v0.2024.12.18.08.02.stable\_04     |
| [wayst]                    | yes                   | yes   | [`51773da`][wayst-commit]          |
| [WezTerm]                  | yes                   | yes   | 20240203-110809-5046fc22 (flatpak) |
| [xterm]                    | yes                   | yes   | 385                                |
| [Yakuake]                  | yes                   | yes   | 24.12.0                            |
| [zed]                      | yes                   | yes   | 0.167.1 (flatpak)                  |
| [zutty]                    | yes                   | yes   | `050bf2b`                          |
| IntelliJ IDEA ([JediTerm]) | yes                   | yes   | PyCharm 2023.3.2 (macOS)           |
| VSCode ([xterm.js])        | yes                   | yes   | 1.85.1 (macOS)                     |
| Windows Terminal (conhost) | yes                   | yes   | [`b3f4162`][conhost-commit]        |
| anyterm                    | no                    | *no*  | 1.2.3                              |
| ConEmu / Cmder             | no                    | yes   | 230724 stable                      |
| cool-retro-term            | no                    | yes   | 1.2.0                              |
| Eterm                      | no                    | *no*  | 0.9.6                              |
| [Extraterm]                | no                    | yes   | 0.80.0                             |
| [iSH] (hterm)              | no                    | yes   | 1.3.2 (Build 494) (iOS)            |
| Jetbrains Fleet            | no                    | yes   | build 1.40.87 (macOS)              |
| [Lapce]                    | no                    | yes   | 0.4.2 (macOS)                      |
| [La Terminal]              | no                    | yes   | 1.9.1                              |
| Linux console              | no                    | yes   | -                                  |
| MobaXterm                  | no                    | yes   | v24.2                              |
| mrxvt                      | no                    | yes   | 0.5.3                              |
| [PuTTY]                    | no                    | yes   | 0.80                               |
| shellinabox                | no                    | *no*  | 2.20                               |
| QMLKonsole                 | no                    | yes   | 23.08.5                            |
| [QTerminal]                | no                    | yes   | 1.3.0                              |
| [mosh]                     | no                    | yes   | 1.4.0                              |
| [pangoterm]                | no                    | yes   | [revision 634][pangoterm-rev]      |

<br>

[^1]: Some Linux terminals are omitted since they all use the `vte` library behind the scenes. \
      Here's a non-exhaustive list: GNOME Terminal, (GNOME) Console, MATE Terminal, XFCE Terminal, (GNOME) Builder, (elementary) Terminal, LXTerminal, and Guake.
[^2]: The currently released version has a bug where it terminates the response with `ESC` instead of `ST`. Fixed by revision [1.600](http://cvs.schmorp.de/rxvt-unicode/src/command.C?revision=1.600&view=markup)
[^3]: Response is always terminated with `BEL` even when the query is terminated by `ST`.
[^4]: Response to `OSC 10` is always terminated with `BEL` even when the query is terminated by `ST`.

The following shell commands can be used to test a terminal:
```shell
printf '\e[c' && cat -v # Tests for DA1. Example output: ^[[?65;1;9c
printf '\e]10;?\e\\' && cat -v # Tests for foreground color support. Example output: ^[]10;rgb:0000/0000/0000^[\
printf '\e]11;?\e\\' && cat -v # Tests for background color support. Example output: ^[]11;rgb:ffff/ffff/ffff^[\
```

[Alacritty]: https://alacritty.org/
[anyterm]: https://anyterm.org/
[conhost-commit]: https://github.com/microsoft/terminal/commit/b3f41626b4d212da8ca7c08077b12c289f918c86
[Console]: https://apps.gnome.org/en-GB/Console/
[Contour]: https://contour-terminal.org/
[cool-retro-term]: https://github.com/Swordfish90/cool-retro-term
[Ghostty]: https://ghostty.org
[Extraterm]: https://extraterm.org
[foot]: https://codeberg.org/dnkl/foot
[Hyper]: https://hyper.is/
[iSH]: https://ish.app/
[iTerm2]: https://iterm2.com/
[JediTerm]: https://github.com/JetBrains/jediterm
[kitty]: https://sw.kovidgoyal.net/kitty/
[Konsole]: https://konsole.kde.org/
[Lapce]: https://lapce.dev/
[La Terminal]: https://la-terminal.net/
[mintty]: https://mintty.github.io/
[nvim-terminal]: http://neovim.io/doc/user/terminal.html
[mlterm-commit]: https://github.com/arakiken/mlterm/commit/f3474e1eb6a97239b38869f0fba78ce3e6a8ad87
[mlterm]: https://mlterm.sourceforge.net/
[mosh]: https://mosh.org
[pangoterm-rev]: https://bazaar.launchpad.net/~leonerd/pangoterm/trunk/revision/634
[pangoterm]: http://www.leonerd.org.uk/code/pangoterm/
[PuTTY]: https://www.chiark.greenend.org.uk/~sgtatham/putty/
[QTerminal]: https://github.com/lxqt/qterminal
[Rio Terminal]: https://raphamorim.io/rio/
[Rio]: https://raphamorim.io/rio/
[rxvt-unicode]: http://software.schmorp.de/pkg/rxvt-unicode.html
[shellinabox]: https://github.com/shellinabox/shellinabox
[Terminology]: http://www.enlightenment.org/
[Termux]: https://termux.dev/en/
[Therm]: https://github.com/trufae/Therm
[wayst]: https://github.com/91861/wayst
[wayst-commit]: https://github.com/91861/wayst/commit/51773da1817abb14f2b90635daf30aac0f1536b6
[WezTerm]: https://wezfurlong.org/wezterm/
[xterm.js]: https://xtermjs.org/
[xterm]: https://invisible-island.net/xterm/
[Yakuake]: https://apps.kde.org/en-gb/yakuake/
[zed]: https://zed.dev/
[zutty]: https://tomscii.sig7.se/zutty/
