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

tshark has many more features that termshark doesn't expose yet! See [What's Next](docs/FAQ.md#whats-next).

## Install Packages

Termshark is pre-packaged for the following platforms: [Arch Linux](docs/Packages.md#arch-linux), [Debian (unstable)](docs/Packages.md#debian), [FreeBSD](docs/Packages.md#freebsd), [Homebrew](docs/Packages.md#homebrew), [SnapCraft](docs/Packages.md#snapcraft), [Termux (Android)](docs/Packages.md#termux-android) and [Ubuntu](docs/Packages.md#ubuntu).

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

## Contributors

Thanks to everyone that's contributed ports, patches and effort!

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore -->
<table><tr><td align="center"><a href="https://swit.sh"><img src="https://avatars0.githubusercontent.com/u/10995145?v=4" width="100px;" alt="Ross Jacobs"/><br /><sub><b>Ross Jacobs</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=pocc" title="Code">💻</a></td><td align="center"><a href="https://github.com/Hongarc"><img src="https://avatars1.githubusercontent.com/u/19208123?v=4" width="100px;" alt="Hongarc"/><br /><sub><b>Hongarc</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=Hongarc" title="Documentation">📖</a></td><td align="center"><a href="https://github.com/zi0r"><img src="https://avatars0.githubusercontent.com/u/1676702?v=4" width="100px;" alt="Ryan Steinmetz"/><br /><sub><b>Ryan Steinmetz</b></sub></a><br /><a href="#platform-zi0r" title="Packaging/porting to new platform">📦</a></td><td align="center"><a href="https://søb.org/"><img src="https://avatars2.githubusercontent.com/u/8722223?v=4" width="100px;" alt="Nicolai Søborg"/><br /><sub><b>Nicolai Søborg</b></sub></a><br /><a href="#platform-NicolaiSoeborg" title="Packaging/porting to new platform">📦</a></td><td align="center"><a href="https://qulogic.gitlab.io/"><img src="https://avatars2.githubusercontent.com/u/302469?v=4" width="100px;" alt="Elliott Sales de Andrade"/><br /><sub><b>Elliott Sales de Andrade</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=QuLogic" title="Code">💻</a></td><td align="center"><a href="http://rski.github.io"><img src="https://avatars2.githubusercontent.com/u/2960312?v=4" width="100px;" alt="Romanos"/><br /><sub><b>Romanos</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=rski" title="Code">💻</a></td><td align="center"><a href="https://github.com/denyspozniak"><img src="https://avatars0.githubusercontent.com/u/22612345?v=4" width="100px;" alt="Denys"/><br /><sub><b>Denys</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Adenyspozniak" title="Bug reports">🐛</a></td></tr><tr><td align="center"><a href="https://github.com/jerry73204"><img src="https://avatars1.githubusercontent.com/u/7629150?v=4" width="100px;" alt="jerry73204"/><br /><sub><b>jerry73204</b></sub></a><br /><a href="#platform-jerry73204" title="Packaging/porting to new platform">📦</a></td><td align="center"><a href="http://thann.github.com"><img src="https://avatars1.githubusercontent.com/u/578515?v=4" width="100px;" alt="Jon Knapp"/><br /><sub><b>Jon Knapp</b></sub></a><br /><a href="#platform-Thann" title="Packaging/porting to new platform">📦</a></td><td align="center"><a href="https://github.com/mharjac"><img src="https://avatars2.githubusercontent.com/u/2997453?v=4" width="100px;" alt="Mario Harjac"/><br /><sub><b>Mario Harjac</b></sub></a><br /><a href="#platform-mharjac" title="Packaging/porting to new platform">📦</a></td></tr></table>

<!-- ALL-CONTRIBUTORS-LIST:END -->

## Contact

- The author - Graham Clark (grclark@gmail.com)

## License

[![License: MIT](https://img.shields.io/github/license/gcla/termshark.svg?color=yellow)](LICENSE)
