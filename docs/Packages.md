# Install Packages

Here's how to install termshark on various OSes and with various package managers.

## Arch Linux

- [termshark-bin](https://aur.archlinux.org/packages/termshark-bin): binary
  package which simply copies the released binary to install directory. Made by
  [jerry73204](https://github.com/jerry73204)
- [termshark-git](https://aur.archlinux.org/packages/termshark-git): Compiles
  from source, made by [Thann](https://github.com/Thann) 

## Debian (unstable)

Coming soon!

## FreeBSD

Thanks to [Ryan Steinmetz](https://github.com/zi0r)

Termshark is in the FreeBSD ports tree!  To install the package, run:

```pkg install termshark```

To build/install the port, run:

```cd /usr/ports/net/termshark/ && make install clean```

## Homebrew (macOS)

Recipe submitted for inclusion - coming soon! See the [PR](https://github.com/Homebrew/homebrew-core/pull/40233)

## SnapCraft

Thanks to [mharjac](https://github.com/mharjac)

Termshark can be easily installed on almost all major distros just by issuing: 

```bash
snap install termshark
```

After installation, it requires some additional permissions:

```bash
snap connect termshark:network-control
snap connect termshark:bluetooth-control
snap connect termshark:firewall-control
snap connect termshark:ppp
snap connect termshark:raw-usb
snap connect termshark:removable-media
```

## Ubuntu

Thanks to [Nicolai Søberg](https://github.com/NicolaiSoeborg)

You can use the PPA *nicolais/termshark* to install termshark:

```bash
sudo add-apt-repository --update ppa:nicolais/termshark
sudo apt install termshark
```


