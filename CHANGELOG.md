# Changelog

## [Unreleased]

### Added

- Better navigation defaults for the hex view, and some vim key integration (thanks @uzxmx).

## [2.4.0] - 2022-07-11
### Added

- You can now search for information in packets, in similar fashion to Wireshark's packet search. Hit `ctrl-f`
  to open the search bar.
- Termshark now supports Wireshark-like profiles. Access via the new minibuffer profile commands: create to
  make a new profile; use to switch profile. A profile can be "linked" to a Wireshark profile to make use
  of Wireshark color profiles in termshark.

### Changed

- Now you can build and install termshark with one command: `go install github.com/gcla/termshark/v2/cmd/termshark`
- Fixed a bug that resulted in stream reassembly sporadically failing and displaying a blank screen.
- Termshark will now, by default, suppress errors from tshark. You can change this via the minibuffer
  `set suppress-tshark-errors` command.
- Added a summary of standard error to the error dialogs displayed when a tshark process fails to run
  correctly (has a non-zero exit code).
- Fixed a race condition that caused extcap captures (e.g. randpkt) to sporadically fail.
- Dark-mode is now the default in the absence of a specific user-setting.
- Fixed a bug that caused mouse-clicks within the hex view to not function correctly if the viewport was not
  at the top of the data to be displayed.
- When focus is in the packet hex view, the mouse wheel will no longer move the cursor - instead it will move
  the scroll position.
- If the display filter is empty, it is now displayed in cyan to indicate it is not yet either valid or
  invalid. This can be changed via the `filter-empty` theme element.
- In the conversations view, a column of IP addresses is now sorted numerically rather than lexicographically.
- Various text input widgets now support "bracketed-paste" meaning they understand when content is pasted into
  the terminal. The result is a smoother interface with fewer updates.
- Fixed a bug that caused the "client pkts" and "server pkts" counts in the stream reassembly view not to be
  updated.

## [2.3.0] - 2021-09-04
### Added

- Termshark's columns can now be changed via the minibuffer `columns` command. Columns can be added, removed
  or hidden from view. If your Wireshark config is available, termshark can
  import your Wireshark column configuration. Custom columns can be chosen via a display filter expression.
- The packet structure view now provides a contextual menu with options to
  - apply the structure filter as a custom column
  - prepare or apply the same filter as a display filter
- A new console-command, "wormhole", allows you to send termshark's current pcap with magic wormhole. Pair
  with the tmux plugin tmux-wormhole to open the pcap quickly in Wireshark.
- Added a -w flag - if supplied for a live capture, termshark will write the packets to this capture file.
- Added a config option, main.disk-cache-size-mb, that can be set to have termshark limit the size
  of its pcap cache directory.  When the directory size exceeds its limit, termshark deletes oldest
  pcap files first.
- Added a workflow that helps a user to upgrade from a low-color TERM setting if termshark detects that
  there is a 256-color version available in the terminfo database.
- Added 8-color light and dark themes for TERMs such as xterm and screen.
- Termshark is now available for M1 on Mac.

### Changed

- Fixed a bug that caused "And" and "Or" conversation filters to be incorrect if the current display filter is
  empty.
- Fixed a bug that caused multi-token capture filters to fail.
- Fixed a bug that slowed down the user's interaction with the display filter widget.

## [2.2.0] - 2021-01-03
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
- Termshark on Windows no longer depends on the Cygwin tail command (and thus a Cygwin installation).
- The current packet capture source (file, interface, pipe, etc) is displayed in the termshark title bar.
- Termshark can be configured to eagerly load all pcap PDML data, rather than 1000 packets at a time.

### Changed

- You can now simply hit enter in the display filter widget to make its value take effect.


## [1.0.0] - 2019-04-17

- Initial release.

[Unreleased]: https://github.com/gcla/termshark/compare/v2.1.1...HEAD
[1.0.0]: https://github.com/gcla/termshark/releases/tag/v1.0.0
[2.0.0]: https://github.com/gcla/termshark/releases/tag/v2.0.0
[2.0.3]: https://github.com/gcla/termshark/releases/tag/v2.0.3
[2.1.1]: https://github.com/gcla/termshark/releases/tag/v2.1.1
