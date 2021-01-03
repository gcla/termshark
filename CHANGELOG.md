# Changelog

## [Unreleased]
### Added 

- Termshark is now available for linux/arm64, NetBSD and OpenBSD.
- Vim keys h, j, k and l can now be used in widgets that accept left, down, up and right user input.
- Termshark's tables support vim-style navigation - use G to go to the bottom, gg to go to the top, or
  add a numeric prefix.
- Other vim-style navigation keypresses are now implemented :r/:e to load a pcap, :q! to quit, ZZ to quit,
  C-w C-w to cycle through views and C-w = to reset spacing.
- You can now set packet marks with the m key (e.g. ma, mb). Jump to packet marks with the ' key (e.g. 'a,
  'b). Set cross-file packet marks with capital letters (e.g. mA, mB). Jump to last location with ''.
- Display termshark's log file via the new menu option "Show Log"
- Termshark now provides last-line mode/a minibuffer for issuing commands. Access it with the ":" key.
- Termshark provides the following minibuffer commands:
  - `recents` - pick a pcap from recently loaded files.
  - `filter` - pick a display filter from the recently used list.
  - `set` - set various config properties.
  - `marks` - display currently set local and cross-file packet marks.
- Map keys to other key sequences using a vim-style map command e.g. `map <f1> ZZ`. Use vim-syntax to express
  keystrokes - alphanumeric characters, and angle brackets for compound keys (`<C-s>`, `<A-\>`, `<esc>`,
  `<space>`, `<enter>`)
- Added support for themes. See this
  [example](https://raw.githubusercontent.com/gcla/termshark/master/assets/themes/dracula-256.toml). Themes
  are loaded from `~/.config/termshark/themes/` or from a small cache built-in
  to termshark. A new minibuffer command `theme` can be used to change theme;
  `no-theme` turns off theming.

### Changed

- Fixed a race condition that allowed an invalid Wireshark display filter to be applied.
- Fixed race conditions that resulted in spurious warnings about a failure to kill tshark processes
- If auto-scroll is enabled, and you navigate to a different packet in the packet list view during a live
  capture, auto-scroll is resumed if you hit 'G' or the `end` key.
- Fixed a problem preventing the correct operation of piped input to termshark on freebsd.
- The Escape key no longer opens the main menu. Instead it puts focus on the menu button. Hit Enter to open.
  This is more intuitive with the presence of ":" to open the minibuffer.

## [2.1.1] - 2020-02-02
### Added

- Termshark now provides a conversations view for the most common conversation types.
- Termshark now supports multiple live captures/interfaces on the command-line e.g. `termshark -i eth0 -i eth1`
- Termshark's packet hex view displays a scrollbar if the data doesn't fit in the space available.
- Termshark can show a capture file's properties using the capinfos binary (bundled with tshark).
- Termshark now supports [extcap interfaces](https://tshark.dev/capture/sources/extcap_interfaces/) by default. 

## [2.0.3] - 2019-12-23

### Added

- Termshark now colorizes its packet list view by default, using the current Wireshark `colorfilter` rules.
- Termshark now supports tshark's `-t` option to specify the timestamp format in the packet list view.

### Changed

- Fixed a potential deadlock when reassembling very long streams.

## [2.0.2] - 2019-11-11

### Changed

- Internal Go API name changes that I didn't understand when I released termshark V2.

## [2.0.1] - 2019-11-10

### Changed

- Fix a mistake that caused a build break on homebrew.

## [2.0.0] - 2019-11-10
### Added

- Termshark supports TCP and UDP stream reassembly. See termshark's "Analysis" menu.
- By popular demand, termshark now has a dark mode! To turn on, run termshark and open the menu.
- Termshark can be configured to "auto-scroll" when reading live data (interface, fifo or stdin).
- Termshark uses less CPU, is less laggy under mouse input, and will use less than half as much RAM on larger pcaps.
- Termshark now supports piped input e.g.
```
$ tshark -i eth0 -w - | termshark
```
- Termshark now supports input from a fifo e.g.
```
1$ mkfifo myfifo
1$ tshark -i eth0 -w myfifo
2$ termshark -r myfifo
```
- Termshark supports running its UI on a different tty (make sure the tty doesn't have another process competing for reads and writes). This is useful
  if you are feeding termshark with data from a process that writes to stderr, or if you want to see information displayed in the terminal that would
  be covered up by termshark's UI e.g.
```
termshark -i eth0 --tty=/dev/pts/5
```
- Like Wireshark, termshark will now preserve the opened and closed structure of a packet as you move from one packet to the next. This lets the user
  see differences between packets more easily.
- Termshark can now be installed for MacOS from [Homebrew](docs/FAQ.md#homebrew). 
- Termshark now respects job control signals sent via the shell i.e. SIGTSTP and SIGCONT.
- Termshark on Windows no longer depends on the Cywgin tail command (and thus a Cygwin installation).
- The current packet capture source (file, interface, pipe, etc) is displayed in the termshark title bar.
- Termshark can be configured to eagerly load all pcap PDML data, rather than 1000 packets at a time.

### Changed

- You can now simply hit enter in the display filter widget to make its value take effect.


## [1.0.0] - 2019-04-17

- Initial release.

[Unreleased]: https://github.com/gcla/termshark/commpare/v2.1.1...HEAD
[1.0.0]: https://github.com/gcla/termshark/releases/tag/v1.0.0
[2.0.0]: https://github.com/gcla/termshark/releases/tag/v2.0.0
[2.0.3]: https://github.com/gcla/termshark/releases/tag/v2.0.3
[2.1.1]: https://github.com/gcla/termshark/releases/tag/v2.1.1
