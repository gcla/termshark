[twitter-follow-url]: https://twitter.com/intent/follow?screen_name=termshark
[twitter-follow-img]: https://img.shields.io/twitter/follow/termshark.svg?style=social&label=Follow

# Termshark
A terminal user-interface for tshark, inspired by Wireshark.

**V2.4 is out now with packet search and profiles for colors and columns! See the [ChangeLog](CHANGELOG.md#changelog).**

![demo24](/../gh-pages/images/demo4.gif?raw=true)

If you're debugging on a remote machine with a large pcap and no desire to scp it back to your desktop, termshark can help!

## Features

- Read pcap files or sniff live interfaces (where tshark is permitted)
- Filter pcaps or live captures using Wireshark's display filters
- Reassemble and inspect TCP and UDP flows
- View network conversations by protocol
- Copy ranges of packets to the clipboard from the terminal
- Written in Golang, compiles to a single executable on each platform - downloads available for Linux, macOS, BSD variants, Android (termux) and Windows

tshark has many more features that termshark doesn't expose yet! See [What's Next](docs/FAQ.md#whats-next).

## Install Packages

Termshark is pre-packaged for the following platforms: [Arch Linux](docs/Packages.md#arch-linux), [Debian (unstable)](docs/Packages.md#debian), [FreeBSD](docs/Packages.md#freebsd), [Homebrew](docs/Packages.md#homebrew), [MacPorts](docs/Packages.md#macports), [Kali Linux](docs/Packages.md#kali-linux), [NixOS](docs/Packages.md#nixos), [SnapCraft](docs/Packages.md#snapcraft), [Termux (Android)](docs/Packages.md#termux-android) and [Ubuntu](docs/Packages.md#ubuntu).

## Building

Termshark uses Go modules. Set `GO111MODULE=on` then run:

```bash
go install github.com/gcla/termshark/v2/cmd/termshark@v2.4.0
```

For versions of Go between 1.14 and 1.17, use

```bash
go get github.com/gcla/termshark/v2/cmd/termshark
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

Pre-compiled executables are available via [Github releases](https://github.com/gcla/termshark/releases). Or download the latest build from the master branch - [![Build Status](https://travis-ci.com/gcla/termshark.svg?branch=master)](https://travis-ci.com/gcla/termshark).

## Documentation

See the [termshark user guide](docs/UserGuide.md), and my best guess at some [FAQs](docs/FAQ.md). For a summary of updates, see the [ChangeLog](CHANGELOG.md#changelog).

## Dependencies

Termshark depends on these open-source packages:

- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) - command-line network protocol analyzer, part of [Wireshark](https://wireshark.org)
- [tcell](https://github.com/gdamore/tcell) - a cell based terminal handling package, inspired by termbox
- [gowid](https://github.com/gcla/gowid) - compositional terminal UI widgets, inspired by [urwid](http://urwid.org), built on [tcell](https://github.com/gdamore/tcell)

Note that tshark is a run-time dependency, and must be in your ```PATH``` for termshark to function.  Version 1.10.2 or higher is required (approx 2013).

## Contributors

Thanks to everyone that's contributed ports, patches and effort!

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://swit.sh"><img src="https://avatars0.githubusercontent.com/u/10995145?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Ross Jacobs</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=pocc" title="Code">💻</a> <a href="https://github.com/gcla/termshark/issues?q=author%3Apocc" title="Bug reports">🐛</a> <a href="#userTesting-pocc" title="User Testing">📓</a></td>
    <td align="center"><a href="https://github.com/Hongarc"><img src="https://avatars1.githubusercontent.com/u/19208123?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Hongarc</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=Hongarc" title="Documentation">📖</a></td>
    <td align="center"><a href="https://github.com/zi0r"><img src="https://avatars0.githubusercontent.com/u/1676702?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Ryan Steinmetz</b></sub></a><br /><a href="#platform-zi0r" title="Packaging/porting to new platform">📦</a></td>
    <td align="center"><a href="https://søb.org/"><img src="https://avatars2.githubusercontent.com/u/8722223?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Nicolai Søborg</b></sub></a><br /><a href="#platform-NicolaiSoeborg" title="Packaging/porting to new platform">📦</a></td>
    <td align="center"><a href="https://qulogic.gitlab.io/"><img src="https://avatars2.githubusercontent.com/u/302469?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Elliott Sales de Andrade</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=QuLogic" title="Code">💻</a></td>
    <td align="center"><a href="http://rski.github.io"><img src="https://avatars2.githubusercontent.com/u/2960312?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Romanos</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=rski" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/denyspozniak"><img src="https://avatars0.githubusercontent.com/u/22612345?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Denys</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Adenyspozniak" title="Bug reports">🐛</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/jerry73204"><img src="https://avatars1.githubusercontent.com/u/7629150?v=4?s=100" width="100px;" alt=""/><br /><sub><b>jerry73204</b></sub></a><br /><a href="#platform-jerry73204" title="Packaging/porting to new platform">📦</a></td>
    <td align="center"><a href="http://thann.github.com"><img src="https://avatars1.githubusercontent.com/u/578515?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Jon Knapp</b></sub></a><br /><a href="#platform-Thann" title="Packaging/porting to new platform">📦</a></td>
    <td align="center"><a href="https://github.com/mharjac"><img src="https://avatars2.githubusercontent.com/u/2997453?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Mario Harjac</b></sub></a><br /><a href="#platform-mharjac" title="Packaging/porting to new platform">📦</a></td>
    <td align="center"><a href="https://github.com/abenson"><img src="https://avatars1.githubusercontent.com/u/227317?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Andrew Benson</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Aabenson" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/sagis-tikal"><img src="https://avatars2.githubusercontent.com/u/46102019?v=4?s=100" width="100px;" alt=""/><br /><sub><b>sagis-tikal</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Asagis-tikal" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/punkymaniac"><img src="https://avatars2.githubusercontent.com/u/9916797?v=4?s=100" width="100px;" alt=""/><br /><sub><b>punkymaniac</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Apunkymaniac" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/msenturk"><img src="https://avatars3.githubusercontent.com/u/9482568?v=4?s=100" width="100px;" alt=""/><br /><sub><b>msenturk</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Amsenturk" title="Bug reports">🐛</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/szuecs"><img src="https://avatars3.githubusercontent.com/u/50872?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Sandor Szücs</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Aszuecs" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/dawidd6"><img src="https://avatars1.githubusercontent.com/u/9713907?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Dawid Dziurla</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Adawidd6" title="Bug reports">🐛</a> <a href="#platform-dawidd6" title="Packaging/porting to new platform">📦</a></td>
    <td align="center"><a href="https://github.com/jJit0"><img src="https://avatars1.githubusercontent.com/u/23521148?v=4?s=100" width="100px;" alt=""/><br /><sub><b>jJit0</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3AjJit0" title="Bug reports">🐛</a></td>
    <td align="center"><a href="http://colinrogers001.com"><img src="https://avatars3.githubusercontent.com/u/20195547?v=4?s=100" width="100px;" alt=""/><br /><sub><b>inzel</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Ainzel" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/thejerrod"><img src="https://avatars1.githubusercontent.com/u/25254103?v=4?s=100" width="100px;" alt=""/><br /><sub><b>thejerrod</b></sub></a><br /><a href="#ideas-thejerrod" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/gdluca"><img src="https://avatars3.githubusercontent.com/u/12004506?v=4?s=100" width="100px;" alt=""/><br /><sub><b>gdluca</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Agdluca" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/winpat"><img src="https://avatars2.githubusercontent.com/u/6016963?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Patrick Winter</b></sub></a><br /><a href="#platform-winpat" title="Packaging/porting to new platform">📦</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/RobertLarsen"><img src="https://avatars0.githubusercontent.com/u/795303?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Robert Larsen</b></sub></a><br /><a href="#ideas-RobertLarsen" title="Ideas, Planning, & Feedback">🤔</a> <a href="#userTesting-RobertLarsen" title="User Testing">📓</a></td>
    <td align="center"><a href="https://mingrammer.com"><img src="https://avatars0.githubusercontent.com/u/6178510?v=4?s=100" width="100px;" alt=""/><br /><sub><b>MinJae Kwon</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Amingrammer" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/the-c0d3r"><img src="https://avatars2.githubusercontent.com/u/4526565?v=4?s=100" width="100px;" alt=""/><br /><sub><b>the-c0d3r</b></sub></a><br /><a href="#ideas-the-c0d3r" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/gvanem"><img src="https://avatars0.githubusercontent.com/u/945271?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Gisle Vanem</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Agvanem" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/hook-s3c"><img src="https://avatars1.githubusercontent.com/u/31825993?v=4?s=100" width="100px;" alt=""/><br /><sub><b>hook</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Ahook-s3c" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://twitter.com/_lennart"><img src="https://avatars0.githubusercontent.com/u/35022?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Lennart Koopmann</b></sub></a><br /><a href="#ideas-lennartkoopmann" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://keybase.io/cfernandez"><img src="https://avatars1.githubusercontent.com/u/5316229?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Fernandez, ReK2</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3AReK2Fernandez" title="Bug reports">🐛</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/mazball"><img src="https://avatars2.githubusercontent.com/u/22456251?v=4?s=100" width="100px;" alt=""/><br /><sub><b>mazball</b></sub></a><br /><a href="#ideas-mazball" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/wfailla"><img src="https://avatars1.githubusercontent.com/u/5494665?v=4?s=100" width="100px;" alt=""/><br /><sub><b>wfailla</b></sub></a><br /><a href="#ideas-wfailla" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/rongyi"><img src="https://avatars3.githubusercontent.com/u/1034762?v=4?s=100" width="100px;" alt=""/><br /><sub><b>荣怡</b></sub></a><br /><a href="#ideas-rongyi" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/thebyrdman-git"><img src="https://avatars1.githubusercontent.com/u/55452713?v=4?s=100" width="100px;" alt=""/><br /><sub><b>thebyrdman-git</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Athebyrdman-git" title="Bug reports">🐛</a></td>
    <td align="center"><a href="http://www.mi.fu-berlin.de/en/inf/groups/ilab/members/mosig.html"><img src="https://avatars2.githubusercontent.com/u/32590522?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Clemens Mosig</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Acmosig" title="Bug reports">🐛</a></td>
    <td align="center"><a href="http://www.cipherdyne.org/"><img src="https://avatars3.githubusercontent.com/u/380228?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Michael Rash</b></sub></a><br /><a href="#userTesting-mrash" title="User Testing">📓</a></td>
    <td align="center"><a href="https://github.com/joelparker"><img src="https://avatars3.githubusercontent.com/u/136451?v=4?s=100" width="100px;" alt=""/><br /><sub><b>joelparker</b></sub></a><br /><a href="#userTesting-joelparker" title="User Testing">📓</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/dragosmaftei"><img src="https://avatars1.githubusercontent.com/u/15351028?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Dragos Maftei</b></sub></a><br /><a href="#ideas-dragosmaftei" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="http://www.giassa.net"><img src="https://avatars1.githubusercontent.com/u/8325672?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Matthew Giassa</b></sub></a><br /><a href="#ideas-IAXES" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/sean-abbott"><img src="https://avatars0.githubusercontent.com/u/1402071?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Sean Abbott</b></sub></a><br /><a href="#platform-sean-abbott" title="Packaging/porting to new platform">📦</a></td>
    <td align="center"><a href="http://www.linsong.org"><img src="https://avatars1.githubusercontent.com/u/36017?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Vincent Wang</b></sub></a><br /><a href="#ideas-linsong" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/Piping"><img src="https://avatars3.githubusercontent.com/u/12042284?v=4?s=100" width="100px;" alt=""/><br /><sub><b>piping</b></sub></a><br /><a href="#ideas-Piping" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/kevinhwang91"><img src="https://avatars0.githubusercontent.com/u/17562139?v=4?s=100" width="100px;" alt=""/><br /><sub><b>kevinhwang91</b></sub></a><br /><a href="#ideas-kevinhwang91" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/gcla/termshark/issues?q=author%3Akevinhwang91" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://jbo.io"><img src="https://avatars0.githubusercontent.com/u/936126?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Justin Overfelt</b></sub></a><br /><a href="#ideas-jboverfelt" title="Ideas, Planning, & Feedback">🤔</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/loudsong"><img src="https://avatars3.githubusercontent.com/u/1447613?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Anthony</b></sub></a><br /><a href="#ideas-loudsong" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/basondole"><img src="https://avatars2.githubusercontent.com/u/50369643?v=4?s=100" width="100px;" alt=""/><br /><sub><b>basondole</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Abasondole" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/zoulja"><img src="https://avatars1.githubusercontent.com/u/10187203?v=4?s=100" width="100px;" alt=""/><br /><sub><b>zoulja</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Azoulja" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/freddii"><img src="https://avatars.githubusercontent.com/u/7213207?v=4?s=100" width="100px;" alt=""/><br /><sub><b>freddii</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Afreddii" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/thordy"><img src="https://avatars.githubusercontent.com/u/1622278?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Thord Setsaas</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=thordy" title="Documentation">📖</a></td>
    <td align="center"><a href="https://github.com/deliciouslytyped"><img src="https://avatars.githubusercontent.com/u/47436522?v=4?s=100" width="100px;" alt=""/><br /><sub><b>deliciouslytyped</b></sub></a><br /><a href="https://github.com/gcla/termshark/issues?q=author%3Adeliciouslytyped" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/factorion"><img src="https://avatars.githubusercontent.com/u/40322086?v=4?s=100" width="100px;" alt=""/><br /><sub><b>factorion</b></sub></a><br /><a href="#platform-factorion" title="Packaging/porting to new platform">📦</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/herbygillot"><img src="https://avatars.githubusercontent.com/u/618376?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Herby Gillot</b></sub></a><br /><a href="#platform-herbygillot" title="Packaging/porting to new platform">📦</a></td>
    <td align="center"><a href="https://github.com/nmeum"><img src="https://avatars.githubusercontent.com/u/2326560?v=4?s=100" width="100px;" alt=""/><br /><sub><b>nmeum</b></sub></a><br /><a href="#ideas-nmeum" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://deftly.net"><img src="https://avatars.githubusercontent.com/u/68368?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Aaron Bieber</b></sub></a><br /><a href="#ideas-qbit" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/elig0n"><img src="https://avatars.githubusercontent.com/u/31196036?v=4?s=100" width="100px;" alt=""/><br /><sub><b>elig0n</b></sub></a><br /><a href="#ideas-elig0n" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/luzpaz"><img src="https://avatars.githubusercontent.com/u/4140247?v=4?s=100" width="100px;" alt=""/><br /><sub><b>luzpaz</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=luzpaz" title="Documentation">📖</a></td>
    <td align="center"><a href="https://github.com/uzxmx"><img src="https://avatars.githubusercontent.com/u/2149136?v=4?s=100" width="100px;" alt=""/><br /><sub><b>uzxmx</b></sub></a><br /><a href="https://github.com/gcla/termshark/commits?author=uzxmx" title="Code">💻</a></td>
  </tr>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

## Contact

- The author - Graham Clark (grclark@gmail.com) [![Follow on Twitter][twitter-follow-img]][twitter-follow-url]

## License

[![License: MIT](https://img.shields.io/github/license/gcla/termshark.svg?color=yellow)](LICENSE)
