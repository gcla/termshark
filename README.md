[twitter-follow-url]: https://twitter.com/intent/follow?screen_name=termshark
[twitter-follow-img]: https://img.shields.io/twitter/follow/termshark.svg?style=social&label=Follow

# Termshark
A terminal user-interface for tshark, inspired by Wireshark.

**V2.2 is out now with vim keys, packet marks, a command-line and themes! See the [ChangeLog](CHANGELOG.md#changelog).**

![demo21](/../gh-pages/images/demo21.png?raw=true)

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

Termshark uses Go modules, so it's best to compile with Go 1.12 or higher. Set `GO111MODULE=on` then run:

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

Pre-compiled executables are available via [Github releases](https://github.com/gcla/termshark/releases). Or download the latest build from the master branch - [![Build Status](https://travis-ci.org/gcla/termshark.svg?branch=master)](https://travis-ci.org/gcla/termshark).

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
<!-- prettier-ignore -->
| [<img src="https://avatars0.githubusercontent.com/u/10995145?v=4" width="72px;"/><br /><sub><b>Ross Jacobs</b></sub>](https://swit.sh)<br />[💻](https://github.com/gcla/termshark/commits?author=pocc "Code") [🐛](https://github.com/gcla/termshark/issues?q=author%3Apocc "Bug reports") [📓](#userTesting-pocc "User Testing") | [<img src="https://avatars1.githubusercontent.com/u/19208123?v=4" width="72px;"/><br /><sub><b>Hongarc</b></sub>](https://github.com/Hongarc)<br />[📖](https://github.com/gcla/termshark/commits?author=Hongarc "Documentation") | [<img src="https://avatars0.githubusercontent.com/u/1676702?v=4" width="72px;"/><br /><sub><b>Ryan Steinmetz</b></sub>](https://github.com/zi0r)<br />[📦](#platform-zi0r "Packaging/porting to new platform") | [<img src="https://avatars2.githubusercontent.com/u/8722223?v=4" width="72px;"/><br /><sub><b>Nicolai Søborg</b></sub>](https://søb.org/)<br />[📦](#platform-NicolaiSoeborg "Packaging/porting to new platform") | [<img src="https://avatars2.githubusercontent.com/u/302469?v=4" width="72px;"/><br /><sub><b>Elliott Sales de Andrade</b></sub>](https://qulogic.gitlab.io/)<br />[💻](https://github.com/gcla/termshark/commits?author=QuLogic "Code") | [<img src="https://avatars2.githubusercontent.com/u/2960312?v=4" width="72px;"/><br /><sub><b>Romanos</b></sub>](http://rski.github.io)<br />[💻](https://github.com/gcla/termshark/commits?author=rski "Code") | [<img src="https://avatars0.githubusercontent.com/u/22612345?v=4" width="72px;"/><br /><sub><b>Denys</b></sub>](https://github.com/denyspozniak)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Adenyspozniak "Bug reports") | [<img src="https://avatars1.githubusercontent.com/u/7629150?v=4" width="72px;"/><br /><sub><b>jerry73204</b></sub>](https://github.com/jerry73204)<br />[📦](#platform-jerry73204 "Packaging/porting to new platform") |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| [<img src="https://avatars1.githubusercontent.com/u/578515?v=4" width="72px;"/><br /><sub><b>Jon Knapp</b></sub>](http://thann.github.com)<br />[📦](#platform-Thann "Packaging/porting to new platform") | [<img src="https://avatars2.githubusercontent.com/u/2997453?v=4" width="72px;"/><br /><sub><b>Mario Harjac</b></sub>](https://github.com/mharjac)<br />[📦](#platform-mharjac "Packaging/porting to new platform") | [<img src="https://avatars1.githubusercontent.com/u/227317?v=4" width="72px;"/><br /><sub><b>Andrew Benson</b></sub>](https://github.com/abenson)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Aabenson "Bug reports") | [<img src="https://avatars2.githubusercontent.com/u/46102019?v=4" width="72px;"/><br /><sub><b>sagis-tikal</b></sub>](https://github.com/sagis-tikal)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Asagis-tikal "Bug reports") | [<img src="https://avatars2.githubusercontent.com/u/9916797?v=4" width="72px;"/><br /><sub><b>punkymaniac</b></sub>](https://github.com/punkymaniac)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Apunkymaniac "Bug reports") | [<img src="https://avatars3.githubusercontent.com/u/9482568?v=4" width="72px;"/><br /><sub><b>msenturk</b></sub>](https://github.com/msenturk)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Amsenturk "Bug reports") | [<img src="https://avatars3.githubusercontent.com/u/50872?v=4" width="72px;"/><br /><sub><b>Sandor Szücs</b></sub>](https://github.com/szuecs)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Aszuecs "Bug reports") | [<img src="https://avatars1.githubusercontent.com/u/9713907?v=4" width="72px;"/><br /><sub><b>Dawid Dziurla</b></sub>](https://github.com/dawidd6)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Adawidd6 "Bug reports") [📦](#platform-dawidd6 "Packaging/porting to new platform") |
| [<img src="https://avatars1.githubusercontent.com/u/23521148?v=4" width="72px;"/><br /><sub><b>jJit0</b></sub>](https://github.com/jJit0)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3AjJit0 "Bug reports") | [<img src="https://avatars3.githubusercontent.com/u/20195547?v=4" width="72px;"/><br /><sub><b>inzel</b></sub>](http://colinrogers001.com)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Ainzel "Bug reports") | [<img src="https://avatars1.githubusercontent.com/u/25254103?v=4" width="72px;"/><br /><sub><b>thejerrod</b></sub>](https://github.com/thejerrod)<br />[🤔](#ideas-thejerrod "Ideas, Planning, & Feedback") | [<img src="https://avatars3.githubusercontent.com/u/12004506?v=4" width="72px;"/><br /><sub><b>gdluca</b></sub>](https://github.com/gdluca)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Agdluca "Bug reports") | [<img src="https://avatars2.githubusercontent.com/u/6016963?v=4" width="72px;"/><br /><sub><b>Patrick Winter</b></sub>](https://github.com/winpat)<br />[📦](#platform-winpat "Packaging/porting to new platform") | [<img src="https://avatars0.githubusercontent.com/u/795303?v=4" width="72px;"/><br /><sub><b>Robert Larsen</b></sub>](https://github.com/RobertLarsen)<br />[🤔](#ideas-RobertLarsen "Ideas, Planning, & Feedback") [📓](#userTesting-RobertLarsen "User Testing") | [<img src="https://avatars0.githubusercontent.com/u/6178510?v=4" width="72px;"/><br /><sub><b>MinJae Kwon</b></sub>](https://mingrammer.com)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Amingrammer "Bug reports") | [<img src="https://avatars2.githubusercontent.com/u/4526565?v=4" width="72px;"/><br /><sub><b>the-c0d3r</b></sub>](https://github.com/the-c0d3r)<br />[🤔](#ideas-the-c0d3r "Ideas, Planning, & Feedback") |
| [<img src="https://avatars0.githubusercontent.com/u/945271?v=4" width="72px;"/><br /><sub><b>Gisle Vanem</b></sub>](https://github.com/gvanem)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Agvanem "Bug reports") | [<img src="https://avatars1.githubusercontent.com/u/31825993?v=4" width="72px;"/><br /><sub><b>hook</b></sub>](https://github.com/hook-s3c)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Ahook-s3c "Bug reports") | [<img src="https://avatars0.githubusercontent.com/u/35022?v=4" width="72px;"/><br /><sub><b>Lennart Koopmann</b></sub>](https://twitter.com/_lennart)<br />[🤔](#ideas-lennartkoopmann "Ideas, Planning, & Feedback") | [<img src="https://avatars1.githubusercontent.com/u/5316229?v=4" width="72px;"/><br /><sub><b>Fernandez, ReK2</b></sub>](https://keybase.io/cfernandez)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3AReK2Fernandez "Bug reports") | [<img src="https://avatars2.githubusercontent.com/u/22456251?v=4" width="72px;"/><br /><sub><b>mazball</b></sub>](https://github.com/mazball)<br />[🤔](#ideas-mazball "Ideas, Planning, & Feedback") | [<img src="https://avatars1.githubusercontent.com/u/5494665?v=4" width="72px;"/><br /><sub><b>wfailla</b></sub>](https://github.com/wfailla)<br />[🤔](#ideas-wfailla "Ideas, Planning, & Feedback") | [<img src="https://avatars3.githubusercontent.com/u/1034762?v=4" width="72px;"/><br /><sub><b>荣怡</b></sub>](https://github.com/rongyi)<br />[🤔](#ideas-rongyi "Ideas, Planning, & Feedback") | [<img src="https://avatars1.githubusercontent.com/u/55452713?v=4" width="72px;"/><br /><sub><b>thebyrdman-git</b></sub>](https://github.com/thebyrdman-git)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Athebyrdman-git "Bug reports") |
| [<img src="https://avatars2.githubusercontent.com/u/32590522?v=4" width="72px;"/><br /><sub><b>Clemens Mosig</b></sub>](http://www.mi.fu-berlin.de/en/inf/groups/ilab/members/mosig.html)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Acmosig "Bug reports") | [<img src="https://avatars3.githubusercontent.com/u/380228?v=4" width="72px;"/><br /><sub><b>Michael Rash</b></sub>](http://www.cipherdyne.org/)<br />[📓](#userTesting-mrash "User Testing") | [<img src="https://avatars3.githubusercontent.com/u/136451?v=4" width="72px;"/><br /><sub><b>joelparker</b></sub>](https://github.com/joelparker)<br />[📓](#userTesting-joelparker "User Testing") | [<img src="https://avatars1.githubusercontent.com/u/15351028?v=4" width="72px;"/><br /><sub><b>Dragos Maftei</b></sub>](https://github.com/dragosmaftei)<br />[🤔](#ideas-dragosmaftei "Ideas, Planning, & Feedback") | [<img src="https://avatars1.githubusercontent.com/u/8325672?v=4" width="72px;"/><br /><sub><b>Matthew Giassa</b></sub>](http://www.giassa.net)<br />[🤔](#ideas-IAXES "Ideas, Planning, & Feedback") | [<img src="https://avatars0.githubusercontent.com/u/1402071?v=4" width="72px;"/><br /><sub><b>Sean Abbott</b></sub>](https://github.com/sean-abbott)<br />[📦](#platform-sean-abbott "Packaging/porting to new platform") | [<img src="https://avatars1.githubusercontent.com/u/36017?v=4" width="72px;"/><br /><sub><b>Vincent Wang</b></sub>](http://www.linsong.org)<br />[🤔](#ideas-linsong "Ideas, Planning, & Feedback") | [<img src="https://avatars3.githubusercontent.com/u/12042284?v=4" width="72px;"/><br /><sub><b>piping</b></sub>](https://github.com/Piping)<br />[🤔](#ideas-Piping "Ideas, Planning, & Feedback") |
| [<img src="https://avatars0.githubusercontent.com/u/17562139?v=4" width="72px;"/><br /><sub><b>kevinhwang91</b></sub>](https://github.com/kevinhwang91)<br />[🤔](#ideas-kevinhwang91 "Ideas, Planning, & Feedback") [🐛](https://github.com/gcla/termshark/issues?q=author%3Akevinhwang91 "Bug reports") | [<img src="https://avatars0.githubusercontent.com/u/936126?v=4" width="72px;"/><br /><sub><b>Justin Overfelt</b></sub>](https://jbo.io)<br />[🤔](#ideas-jboverfelt "Ideas, Planning, & Feedback") | [<img src="https://avatars3.githubusercontent.com/u/1447613?v=4" width="72px;"/><br /><sub><b>Anthony</b></sub>](https://github.com/loudsong)<br />[🤔](#ideas-loudsong "Ideas, Planning, & Feedback") | [<img src="https://avatars2.githubusercontent.com/u/50369643?v=4" width="72px;"/><br /><sub><b>basondole</b></sub>](https://github.com/basondole)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Abasondole "Bug reports") | [<img src="https://avatars1.githubusercontent.com/u/10187203?v=4" width="72px;"/><br /><sub><b>zoulja</b></sub>](https://github.com/zoulja)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Azoulja "Bug reports") | [<img src="https://avatars.githubusercontent.com/u/7213207?v=4" width="72px;"/><br /><sub><b>freddii</b></sub>](https://github.com/freddii)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Afreddii "Bug reports") | [<img src="https://avatars.githubusercontent.com/u/1622278?v=4" width="72px;"/><br /><sub><b>Thord Setsaas</b></sub>](https://github.com/thordy)<br />[📖](https://github.com/gcla/termshark/commits?author=thordy "Documentation") | [<img src="https://avatars.githubusercontent.com/u/47436522?v=4" width="72px;"/><br /><sub><b>deliciouslytyped</b></sub>](https://github.com/deliciouslytyped)<br />[🐛](https://github.com/gcla/termshark/issues?q=author%3Adeliciouslytyped "Bug reports") |
| [<img src="https://avatars.githubusercontent.com/u/40322086?v=4" width="72px;"/><br /><sub><b>factorion</b></sub>](https://github.com/factorion)<br />[📦](#platform-factorion "Packaging/porting to new platform") | [<img src="https://avatars.githubusercontent.com/u/618376?v=4" width="72px;"/><br /><sub><b>Herby Gillot</b></sub>](https://github.com/herbygillot)<br />[📦](#platform-herbygillot "Packaging/porting to new platform") |
<!-- ALL-CONTRIBUTORS-LIST:END -->

## Contact

- The author - Graham Clark (grclark@gmail.com) [![Follow on Twitter][twitter-follow-img]][twitter-follow-url]

## License

[![License: MIT](https://img.shields.io/github/license/gcla/termshark.svg?color=yellow)](LICENSE)
