# Changelog

## [2.1.0] - 2020-02-02
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

[Unreleased]: https://github.com/gcla/termshark/commpare/v2.1.0...HEAD
[1.0.0]: https://github.com/gcla/termshark/releases/tag/v1.0.0
[2.0.0]: https://github.com/gcla/termshark/releases/tag/v2.0.0
[2.0.3]: https://github.com/gcla/termshark/releases/tag/v2.0.3
[2.1.0]: https://github.com/gcla/termshark/releases/tag/v2.1.0
