# Termshark 
A terminal user-interface for tshark, inspired by Wireshark. 

![demo1](https://drive.google.com/uc?export=view&id=1vDecxjqwJrtMGJjOObL-LLvi-1pBVByt)

If you're debugging on a remote machine with a large pcap and no desire to scp it back to your desktop, termshark can help!

## Features

- Read pcap files or sniff live interfaces (where tshark is permitted).
- Inspect each packet using familiar Wireshark-inspired views
- Filter pcaps or live captures using Wireshark's display filters
- Copy ranges of packets to the clipboard from the terminal
- Written in Golang, compiles to a single executable on each platform - downloads available for Linux (+termux), macOS, FreeBSD, and Windows

## Building

Termshark uses Go modules, so it's best to compile with Go 1.11 or higher. Set `GO111MODULE=on` then run:

```bash
go get github.com/gcla/termshark/cmd/termshark
```
Then add ```~/go/bin/``` to your ```PATH```.

For all packet analysis, termshark depends on tshark from the Wireshark project. Make sure ```tshark``` is in your ```PATH```.

## Quick Start

Inspect a local pcap:

```bash
termshark -r test.pcap
```

Capture ping packets on interface ```eth0```:

```bash
termshark -i eth0 icmp
```

Run ```termshark -h``` for options.

## Downloads

Pre-compiled executables are available via [Github releases](https://github.com/gcla/termshark/releases)

## User Guide

See the [termshark user guide](docs/UserGuide.md) (and my best guess at some [FAQs](docs/FAQ.md))

## Dependencies

Termshark depends on these open-source packages:

- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) - command-line network protocol analyzer, part of [Wireshark](https://wireshark.org)
- [tcell](https://github.com/gdamore/tcell) - a cell based terminal handling package, inspired by termbox
- [gowid](https://github.com/gcla/gowid) - compositional terminal UI widgets, inspired by [urwid](http://urwid.org), built on [tcell](https://github.com/gdamore/tcell)

Note that tshark is a run-time dependency, and must be in your ```PATH``` for termshark to function.  Version 1.10.2 or higher is required (approx 2013).

## Contact

- The author - Graham Clark (grclark@gmail.com)

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

