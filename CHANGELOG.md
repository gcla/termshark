# Changelog

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

[Unreleased]: https://github.com/gcla/termshark/commpare/v1.0.0...HEAD
[1.0.0]: https://github.com/gcla/termshark/releases/tag/v1.0.0
