# Install Packages

Here's how to install termshark on various OSes and with various package managers.

## Arch Linux

- [termshark](https://archlinux.org/packages/community/x86_64/termshark/): The
   official package.
- [termshark-git](https://aur.archlinux.org/packages/termshark-git): Compiles
  from source, made by [Thann](https://github.com/Thann)

## Debian

Termshark is only available in unstable/sid at the moment.

```bash
apt update
apt install termshark
```

## FreeBSD

Thanks to [Ryan Steinmetz](https://github.com/zi0r)

Termshark is in the FreeBSD ports tree! To install the package, run:

`pkg install termshark`

To build/install the port, run:

`cd /usr/ports/net/termshark/ && make install clean`

## Homebrew

```bash
brew update
brew install termshark
```

## MacPorts

```bash
sudo port selfupdate
sudo port install termshark
```

## Kali Linux

```bash
apt update
apt install termshark
```

## NixOS

Thanks to [Patrick Winter](https://github.com/winpat)

```bash
nix-channel --add https://nixos.org/channels/nixpkgs-unstable
nix-channel --update
nix-env -iA nixpkgs.termshark
```

## SnapCraft

Thanks to [mharjac](https://github.com/mharjac)

Termshark can be easily installed on almost all major distros just by issuing:

```bash
snap install termshark
```

Note there is a big caveat with Snap and the architecture of Wireshark that prevents termshark being able to read network interfaces. If installed via Snap, termshark will only be able to work with pcap files. See [this explanation](https://forum.snapcraft.io/t/wireshark-and-setcap/9629/6).

## Termux (Android)

```bash
pkg install root-repo
pkg install termshark
```

Note that termshark does not require a rooted phone to inspect a pcap, but it does depend on tshark which is itself in Termux's root-repo for programs that do work best on a rooted phone.

If you would like to use termshark's copy-mode to copy sections of packets to your Android clipboard, you will also need [Termux:API](https://play.google.com/store/apps/details?id=com.termux.api&hl=en_US). Install from the Play Store, then from termux, type:

```bash
pkg install termux-api
```

![device art](/../gh-pages/images/device art.png?raw=true)

## Ubuntu

If you are running Ubuntu 19.10 (eoan) or higher, termshark can be installed like this:

```bash
sudo apt install termshark
```

For Ubuntu < 19.10, you can use the PPA _nicolais/termshark_ to install termshark:

```bash
sudo add-apt-repository --update ppa:nicolais/termshark
sudo apt install termshark
```

Thanks to [Nicolai Søberg](https://github.com/NicolaiSoeborg)
