# User Guide

Termshark provides a terminal-based user interface for analyzing packet captures. It's inspired by Wireshark, and depends on tshark for all its intelligence. Termshark is run from the command-line. You can see its options with

```bash
$ termshark -h
```
```console
termshark v1.0.0

A wireshark-inspired terminal user interface for tshark. Analyze network traffic interactively from your terminal.
See https://github.com/gcla/termshark for more information.

Usage:
  termshark [FilterOrFile]

Application Options:
  -i=<interface>                                          Interface to read.
  -r=<file>                                               Pcap file to read.
  -d=<layer type>==<selector>,<decode-as protocol>        Specify dissection of layer type.
  -Y=<displaY filter>                                     Apply display filter.
  -f=<capture filter>                                     Apply capture filter.
      --pass-thru=[yes|no|auto|true|false]                Run tshark instead (auto => if stdout is not a tty). (default: auto)
      --log-tty=[yes|no|true|false]                       Log to the terminal.. (default: false)
  -h, --help                                              Show this help message.
  -v, --version                                           Show version information.

Arguments:
  FilterOrFile:                                           Filter (capture for iface, display for pcap), or pcap file to read.

If --pass-thru is true (or auto, and stdout is not a tty), tshark will be
executed with the supplied command- line flags. You can provide
tshark-specific flags and they will be passed through to tshark (-n, -d, -T,
etc). For example:

$ termshark -r file.pcap -T psml -n | less
```

By default, termshark will launch an ncurses-like application in your terminal window, but if your standard output is not a tty, termshark will simply defer to tshark and pass its options through:

```console
$ termshark -r test.pcap | cat
    1   0.000000 192.168.44.123 → 192.168.44.213 TFTP 77 Read Request, File: C:\IBMTCPIP\lccm.1, Transfer type: octet
    2   0.000000 192.168.44.123 → 192.168.44.213 TFTP 77 Read Request, File: C:\IBMTCPIP\lccm.1, Transfer type: octet
```

## Read a pcap file

Launch termshark like this to inspect a file:

```bash
termshark -r test.pcap
```

You can also apply a display filter directly from the command-line:

```bash
termshark -r test.pcap icmp
```

Note that when reading a file, the filter will be interpreted as a display filter. When reading from an interface, the filter is interpreted as a capture filter. This follows tshark's behavior.

Termshark will launch in your terminal. From here, you can press `?` for help:

![tshelp](https://drive.google.com/uc?export=view&id=1DOZEAlP5xiNAoCKrZoIhWJ9Zz3gX0gJf)

## Filtering

Press `/` to focus on the display filter. Now you can type in a Wireshark display filter expression. The UI will update in real-time to display the validity of the current expression. If the expression is invalid, the filter widget will change color to red. As you type, termshark presents a drop-down menu with possible completions for the current term:

![filterbad](https://drive.google.com/uc?export=view&id=1KobuhX7KfA_i2VU-lCllPc3FkLUBEmQi)

When the filter widget is green, you can hit the "Apply" button to make its value take effect. Termshark will then reload the packets with the new display filter applied. 

![filterbad](https://drive.google.com/uc?export=view&id=10AVIaRtLWgqJ_fi0kWS_PI-vOogZTVv-)

## Changing Files

Termshark provides a "Recent" button which will open a menu with your most recently-loaded pcap files. Each invocation of termshark with the ```-r``` flag will add a pcap to the start of this list:

![recent](https://drive.google.com/uc?export=view&id=1jnENk7ANqo2TZeqA-4hujHDWfDko_isT)

## Changing Views

Press `tab` to move between the three packet views. You can also use the mouse to move views by clicking with the left mouse button. When focus is in any of these three views, hit the `\` key to maximize that view:

![max](https://drive.google.com/uc?export=view&id=143PHT2YDEuDig2QqFIGcZTjNg9TA7awB)

Press `\` to restore the original layout. Press `|` to move the hex view to the right-hand side:

![altview](https://drive.google.com/uc?export=view&id=1RinO3imTgboVYKLWblaLOqwjhu7OcUt4)

You can also press `<`,`>`,`+` and `-` to change the relative size of each view.

## Packet List View

Termshark's top-most view is a list of packets read from the capture (or interface). Termshark generates the data by running `tshark` on the input with the `-T psml` options, and parsing the resulting XML. Currently the columns displayed cannot be configured, and are the same as Wireshark's defaults. When the source is a pcap file, the list can be sorted by column by clicking the button next to each column header:

![sortcol](https://drive.google.com/uc?export=view&id=1UaXNRUp8UtR728j_CPTRTb0hpVy6EUte)

You can hit `home` to jump to the top of the list or `end` to jump to the bottom. Sometimes, especially if running on a small terminal, the values in a column will be truncated (e.g. long IPv6 addresses). To see the full value, move the purple cursor over the value:

![ipv6](https://drive.google.com/uc?export=view&id=1LXLz0gFieOf3mZEiP9QzwKSzSJL1FLT6)

## Packet Structure View

Termshark's middle view shows the structure of the packet selected in the list view. You can expand and contract the structure using the `[+]` and `[-]` buttons:

![structure](https://drive.google.com/uc?export=view&id=1Tv7kvLxXe5a2tbsvkWR6U8K6nhEBqk8D)

As you navigate the packet structure, different sections of the bottom view - a hex representation of the packet - will be highlighted.

## Packet Hex View

Termshark's bottom view shows the bytes that the packet comprises. Like Wireshark, they are displayed in a hexdump-like format. Hit the `t` key to switch from the hex bytes to the printable bytes and vice versa. As you move around the bytes, the middle (structure) view will update to show you where you are in the packet's structure. 

## Reading from an Interface

Launch termshark like this to read from an interface:

```bash
termshark -i eth0
```

You can also apply a capture filter directly from the command-line:

```bash
termshark -i eth0 tcp
```

Termshark will apply the capture filter as it reads, but the UI currently does not provide any indication of the capture filter that is in effect.

Termshark's UI will launch and the packet views will update as packets are read:

![readiface](https://drive.google.com/uc?export=view&id=1UPD6KaNGsFrQ9lW-_dx_0SXhTbWBX4vn)

You can apply a display filter while the packet capture process is ongoing - termshark will dynamically apply the filter without restarting the capture. Press `ctrl-c` to stop the capture process.

When you exit termshark, it will print a message with the location of the pcap file that was captured:

```console
$ termshark -i eth0
Packets read from interface eth0 have been saved in /home/gcla/.cache/termshark/eth0-657695279.pcap
```

## Copy Mode

Both the structure and hex view support "copy mode" a feature which lets you copy ranges of data from the currently selected packet. First, move focus to the part of the packet you wish to copy. Now hit the `c` key - a section of the packet will be highlighted in yellow:

![copymode1](https://drive.google.com/uc?export=view&id=1EE9zNYyzi3vLz6FBEgFfU0gRkkWsX1Dz)

You can hit the `left` and `right` arrow keys to expand or contract the selected region. Now hit `ctrl-c` to copy. Termshark will display a dialog showing you the format in which you can copy the data:

![copymode2](https://drive.google.com/uc?export=view&id=1EJW7DE1ycm9MbQkBFGOdDryoo5wlBgnZ)

Select the format you want and hit `enter` (or click). Copy mode is available in the packet structure and packet hex views.

This feature comes with a caveat! If you are connected to a remote machine e.g. via ssh, then you should use the `-X` flag to forward X11. On Linux, the default copy command is `xsel`. If you forward X11 with ssh, then the packet data will be copied to your desktop machine's clipboard. You can customize the copy command using termshark's config file e.g. 
```toml
[main]
  copy-command = ["xsel", "-i", "-p"]
```
to instead set the primary selection. If forwarding X11 is not an option, you could instead upload the data (received via stdin) to a service like pastebin, and print the URL on stdout - termshark will display the copy command's output in a dialog when the command completes. See the [FAQ](FAQ.md). 

If you are running on OSX, termux (Android) or Windows, termshark assumes you are running locally and uses a platform-specific copy command.


## Config File

Termshark reads options from a TOML configuration file saved in ```$XDG_CONFIG_HOME/termshark.toml``` (e.g. ```~/.config/termshark/termshark.toml``` on Linux). All options are saved under the ```[main]``` section. The available options are:

- ```copy-command``` (string) - the command termshark executes when the user hits ctrl-c in copy-mode. The default commands on each platform will copy the selected area to the clipboard. 
- ```copy-command-timeout``` (int) - how long termshark will wait (in seconds) for the copy command to complete before reporting an error.
- ```recent-files``` (string list) - the pcap files shown when the user clicks the "recent" button in termshark. Newly viewed files are added to the beginning.
- ```recent-filters``` (string list) - recently used Wireshark display filters.
- ```tshark``` (string) - make termshark use this specific ```tshark```.
- ```dumpcap``` (string) - make termshark use this specific ```dumpcap``` (used when reading from an interface).
- ```tail-command``` (string) - make termshark use this specific ```tail``` command. This is used when reading from an interface in order to feed ```dumpcap```-saved data to ```tshark```. The default is ```tail -f -c +0 <file>```. If you are running on Windows, the default is set to the cygwin tail command. But probably better to use Wireshark on Windows :-)
- ```tshark-args``` (string list) - these are added to each invocation of ```tshark``` made by termshark. For example, you could add decoder parameters like ```["-d","udp.port==2075,cflow]"```
- ```pdml-args``` (string list) - any extra parameters to pass to ```tshark``` when it is invoked to generate PDML.
- ```psml-args``` (string list) - any extra parameters to pass to ```tshark``` when it is invoked to generate PSML.
- ```validated-tsharks``` - (string list) - termshark saves the path of each ``tshark`` binary it invokes (in case the user upgrades the system ```tshark```). If the selected (e.g. ```PATH```) tshark binary has not been validated, termshark will check to ensure its version is compatible. tshark must be newer than v1.10.2 (from approximately 2013).
- ```ui-cache-size``` - (int) - termshark will remember the state of widgets representing packets e.g. which parts are expanded in the structure view, and which byte is in focus in the hex view. This setting allows the user to override the number of widgets that are cached. The default is 1000. 
- ```pcap-cache-size``` - (int) - termshark loads packet PDML (structure) and pcap (bytes) data in bundles of 1000. This setting determines how many such bundles termshark will keep cached. The default is 32.

