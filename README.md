[twitter-follow-url]: https://twitter.com/intent/follow?screen_name=termshark
[twitter-follow-img]: https://img.shields.io/twitter/follow/termshark.svg?style=social&label=Follow

# Termshark
A terminal user-interface for tshark, inspired by Wireshark.

**V2 is out now with stream reassembly, dark-mode and more! Here's the [ChangeLog](CHANGELOG.md#changelog).**

![demo2](https://drive.google.com/uc?export=view&id=1EmqYrOPwLXanoi7o74PQMOX1KSgOqhNr)

If you're debugging on a remote machine with a large pcap and no desire to scp it back to your desktop, termshark can help!

## Features

- Read pcap files or sniff live interfaces (where tshark is permitted).
- Inspect each packet using familiar Wireshark-inspired views
- Filter pcaps or live captures using Wireshark's display filters
- Reassemble and inspect TCP and UDP flows
- Copy ranges of packets to the clipboard from the terminal
- Written in Golang, compiles to a single executable on each platform - downloads available for Linux, macOS, FreeBSD, Android (termux) and Windows

tshark has many more features that termshark doesn't expose yet! See [What's Next](docs/FAQ.md#whats-next).

## Install Packages

Termshark is pre-packaged for the following platforms: [Arch Linux](docs/Packages.md#arch-linux), [Debian (unstable)](docs/Packages.md#debian), [FreeBSD](docs/Packages.md#freebsd), [Homebrew](docs/Packages.md#homebrew), [Kali Linux](docs/Packages.md#kali-linux), [NixOS](docs/Packages.md#nixos), [SnapCraft](docs/Packages.md#snapcraft), [Termux (Android)](docs/Packages.md#termux-android) and [Ubuntu](docs/Packages.md#ubuntu).

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

Pre-compiled executables are available via [Github releases](https://github.com/gcla/termshark/releases). Or download the latest build from the master branch - [![Build Status](https://travis-ci.org/gcla/termshark.svg?branch=master)](https://travis-ci.org/gcla/termshark).

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
<table><tr><td align="center"><a href="https://swit.sh"><img src="https://avatars0.githubusercontent.com/u/10995145?v=4" width="100px;" alt="Ross Jacobs"/><br /><sub><b>Ross Jacobs</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=pocc" title="Code">💻</a> <a href="https://github.com/gcla/termshark/issues?q=author%3Apocc" title="Bug reports">🐛</a> <a href="#userTesting-pocc" title="User Testing">📓</a></td><td align="center"><a href="https://github.com/Hongarc"><img src="https://avatars1.githubusercontent.com/u/19208123?v=4" width="100px;" alt="Hongarc"/><br /><sub><b>Hongarc</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=Hongarc" title="Documentation">📖</a></td><td align="center"><a href="https://github.com/zi0r"><img src="https://avatars0.githubusercontent.com/u/1676702?v=4" width="100px;" alt="Ryan Steinmetz"/><br /><sub><b>Ryan Steinmetz</b></sub></a><br /><a href="#platform-zi0r" title="Packaging/porting to new platform">📦</a></td><td align="center"><a href="https://søb.org/"><img src="https://avatars2.githubusercontent.com/u/8722223?v=4" width="100px;" alt="Nicolai Søborg"/><br /><sub><b>Nicolai Søborg</b></sub></a><br /><a href="#platform-NicolaiSoeborg" title="Packaging/porting to new platform">📦</a></td><td align="center"><a href="https://qulogic.gitlab.io/"><img src="https://avatars2.githubusercontent.com/u/302469?v=4" width="100px;" alt="Elliott Sales de Andrade"/><br /><sub><b>Elliott Sales de Andrade</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=QuLogic" title="Code">💻</a></td><td align="center"><a href="http://rski.github.io"><img src="https://avatars2.githubusercontent.com/u/2960312?v=4" width="100px;" alt="Romanos"/><br /><sub><b>Romanos</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=rski" title="Code">💻</a></td><td align="center"><a href="https://github.com/denyspozniak"><img src="https://avatars0.githubusercontent.com/u/22612345?v=4" width="100px;" alt="Denys"/><br /><sub><b>Denys</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Adenyspozniak" title="Bug reports">🐛</a></td></tr><tr><td align="center"><a href="https://github.com/jerry73204"><img src="https://avatars1.githubusercontent.com/u/7629150?v=4" width="100px;" alt="jerry73204"/><br /><sub><b>jerry73204</b></sub></a><br /><a href="#platform-jerry73204" title="Packaging/porting to new platform">📦</a></td><td align="center"><a href="http://thann.github.com"><img src="https://avatars1.githubusercontent.com/u/578515?v=4" width="100px;" alt="Jon Knapp"/><br /><sub><b>Jon Knapp</b></sub></a><br /><a href="#platform-Thann" title="Packaging/porting to new platform">📦</a></td><td align="center"><a href="https://github.com/mharjac"><img src="https://avatars2.githubusercontent.com/u/2997453?v=4" width="100px;" alt="Mario Harjac"/><br /><sub><b>Mario Harjac</b></sub></a><br /><a href="#platform-mharjac" title="Packaging/porting to new platform">📦</a></td><td align="center"><a href="https://github.com/abenson"><img src="https://avatars1.githubusercontent.com/u/227317?v=4" width="100px;" alt="Andrew Benson"/><br /><sub><b>Andrew Benson</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Aabenson" title="Bug reports">🐛</a></td><td align="center"><a href="https://github.com/sagis-tikal"><img src="https://avatars2.githubusercontent.com/u/46102019?v=4" width="100px;" alt="sagis-tikal"/><br /><sub><b>sagis-tikal</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Asagis-tikal" title="Bug reports">🐛</a></td><td align="center"><a href="https://github.com/punkymaniac"><img src="https://avatars2.githubusercontent.com/u/9916797?v=4" width="100px;" alt="punkymaniac"/><br /><sub><b>punkymaniac</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Apunkymaniac" title="Bug reports">🐛</a></td><td align="center"><a href="https://github.com/msenturk"><img src="https://avatars3.githubusercontent.com/u/9482568?v=4" width="100px;" alt="msenturk"/><br /><sub><b>msenturk</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Amsenturk" title="Bug reports">🐛</a></td></tr><tr><td align="center"><a href="https://github.com/szuecs"><img src="https://avatars3.githubusercontent.com/u/50872?v=4" width="100px;" alt="Sandor Szücs"/><br /><sub><b>Sandor Szücs</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Aszuecs" title="Bug reports">🐛</a></td><td align="center"><a href="https://github.com/dawidd6"><img src="https://avatars1.githubusercontent.com/u/9713907?v=4" width="100px;" alt="Dawid Dziurla"/><br /><sub><b>Dawid Dziurla</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Adawidd6" title="Bug reports">🐛</a></td><td align="center"><a href="https://github.com/jJit0"><img src="https://avatars1.githubusercontent.com/u/23521148?v=4" width="100px;" alt="jJit0"/><br /><sub><b>jJit0</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3AjJit0" title="Bug reports">🐛</a></td><td align="center"><a href="http://colinrogers001.com"><img src="https://avatars3.githubusercontent.com/u/20195547?v=4" width="100px;" alt="inzel"/><br /><sub><b>inzel</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Ainzel" title="Bug reports">🐛</a></td><td align="center"><a href="https://github.com/thejerrod"><img src="https://avatars1.githubusercontent.com/u/25254103?v=4" width="100px;" alt="thejerrod"/><br /><sub><b>thejerrod</b></sub></a><br /><a href="#ideas-thejerrod" title="Ideas, Planning, & Feedback">🤔</a></td><td align="center"><a href="https://github.com/gdluca"><img src="https://avatars3.githubusercontent.com/u/12004506?v=4" width="100px;" alt="gdluca"/><br /><sub><b>gdluca</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Agdluca" title="Bug reports">🐛</a></td><td align="center"><a href="https://github.com/winpat"><img src="https://avatars2.githubusercontent.com/u/6016963?v=4" width="100px;" alt="Patrick Winter"/><br /><sub><b>Patrick Winter</b></sub></a><br /><a href="#platform-winpat" title="Packaging/porting to new platform">📦</a></td></tr><tr><td align="center"><a href="https://github.com/RobertLarsen"><img src="https://avatars0.githubusercontent.com/u/795303?v=4" width="100px;" alt="Robert Larsen"/><br /><sub><b>Robert Larsen</b></sub></a><br /><a href="#ideas-RobertLarsen" title="Ideas, Planning, & Feedback">🤔</a> <a href="#userTesting-RobertLarsen" title="User Testing">📓</a></td><td align="center"><a href="https://mingrammer.com"><img src="https://avatars0.githubusercontent.com/u/6178510?v=4" width="100px;" alt="MinJae Kwon"/><br /><sub><b>MinJae Kwon</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Amingrammer" title="Bug reports">🐛</a></td><td align="center"><a href="https://github.com/the-c0d3r"><img src="https://avatars2.githubusercontent.com/u/4526565?v=4" width="100px;" alt="the-c0d3r"/><br /><sub><b>the-c0d3r</b></sub></a><br /><a href="#ideas-the-c0d3r" title="Ideas, Planning, & Feedback">🤔</a></td><td align="center"><a href="https://github.com/gvanem"><img src="https://avatars0.githubusercontent.com/u/945271?v=4" width="100px;" alt="Gisle Vanem"/><br /><sub><b>Gisle Vanem</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Agvanem" title="Bug reports">🐛</a></td><td align="center"><a href="https://github.com/hook-s3c"><img src="https://avatars1.githubusercontent.com/u/31825993?v=4" width="100px;" alt="hook"/><br /><sub><b>hook</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Ahook-s3c" title="Bug reports">🐛</a></td><td align="center"><a href="https://twitter.com/_lennart"><img src="https://avatars0.githubusercontent.com/u/35022?v=4" width="100px;" alt="Lennart Koopmann"/><br /><sub><b>Lennart Koopmann</b></sub></a><br /><a href="#ideas-lennartkoopmann" title="Ideas, Planning, & Feedback">🤔</a></td><td align="center"><a href="https://keybase.io/cfernandez"><img src="https://avatars1.githubusercontent.com/u/5316229?v=4" width="100px;" alt="Fernandez, ReK2"/><br /><sub><b>Fernandez, ReK2</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3AReK2Fernandez" title="Bug reports">🐛</a></td></tr><tr><td align="center"><a href="https://github.com/mazball"><img src="https://avatars2.githubusercontent.com/u/22456251?v=4" width="100px;" alt="mazball"/><br /><sub><b>mazball</b></sub></a><br /><a href="#ideas-mazball" title="Ideas, Planning, & Feedback">🤔</a></td><td align="center"><a href="https://github.com/wfailla"><img src="https://avatars1.githubusercontent.com/u/5494665?v=4" width="100px;" alt="wfailla"/><br /><sub><b>wfailla</b></sub></a><br /><a href="#ideas-wfailla" title="Ideas, Planning, & Feedback">🤔</a></td><td align="center"><a href="https://github.com/rongyi"><img src="https://avatars3.githubusercontent.com/u/1034762?v=4" width="100px;" alt="荣怡"/><br /><sub><b>荣怡</b></sub></a><br /><a href="#ideas-rongyi" title="Ideas, Planning, & Feedback">🤔</a></td><td align="center"><a href="https://github.com/thebyrdman-git"><img src="https://avatars1.githubusercontent.com/u/55452713?v=4" width="100px;" alt="thebyrdman-git"/><br /><sub><b>thebyrdman-git</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Athebyrdman-git" title="Bug reports">🐛</a></td><td align="center"><a href="http://www.mi.fu-berlin.de/en/inf/groups/ilab/members/mosig.html"><img src="https://avatars2.githubusercontent.com/u/32590522?v=4" width="100px;" alt="Clemens Mosig"/><br /><sub><b>Clemens Mosig</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Acmosig" title="Bug reports">🐛</a></td><td align="center"><a href="http://www.cipherdyne.org/"><img src="https://avatars3.githubusercontent.com/u/380228?v=4" width="100px;" alt="Michael Rash"/><br /><sub><b>Michael Rash</b></sub></a><br /><a href="#userTesting-mrash" title="User Testing">📓</a></td></tr></table>

<!-- ALL-CONTRIBUTORS-LIST:END -->

## Contact

- The author - Graham Clark (grclark@gmail.com) [![Follow on Twitter][twitter-follow-img]][twitter-follow-url]

## License

[![License: MIT](https://img.shields.io/github/license/gcla/termshark.svg?color=yellow)](LICENSE)
