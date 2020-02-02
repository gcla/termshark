# Termshark User Guide

Termshark provides a terminal-based user interface for analyzing packet captures.

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Basic Usage](#basic-usage)
- [Choose a Source](#choose-a-source)
  - [Reading from an Interface](#reading-from-an-interface)
  - [Read a pcap file](#read-a-pcap-file)
    - [Changing Files](#changing-files)
  - [Reading from a fifo or stdin](#reading-from-a-fifo-or-stdin)
- [Using the TUI](#using-the-tui)
  - [Filtering](#filtering)
  - [Changing Views](#changing-views)
  - [Packet List View](#packet-list-view)
  - [Packet Structure View](#packet-structure-view)
  - [Packet Hex View](#packet-hex-view)
  - [Copy Mode](#copy-mode)
  - [Packet Capture Information](#packet-capture-information)
  - [Stream Reassembly](#stream-reassembly)
  - [Conversations](#conversations)
- [Configuration](#configuration)
  - [Dark Mode](#dark-mode)
  - [Packet Colors](#packet-colors)
  - [Config File](#config-file)
- [Troubleshooting](#troubleshooting)

## Basic Usage

Termshark is inspired by Wireshark, and depends on tshark for all its intelligence. Termshark is run from the command-line. You can see its options with

```bash
$ termshark -h
termshark v2.1.0

A wireshark-inspired terminal user interface for tshark. Analyze network traffic interactively from your terminal.
See https://termshark.io for more information.

Usage:
  termshark [FilterOrFile]

Application Options:
  -i=<interfaces>                                            Interface(s) to read.
  -r=<file>                                                  Pcap file to read.
  -d=<layer type>==<selector>,<decode-as protocol>           Specify dissection of layer type.
  -D                                                         Print a list of the interfaces on which termshark can capture.
  -Y=<displaY filter>                                        Apply display filter.
  -f=<capture filter>                                        Apply capture filter.
  -t=<timestamp format>[a|ad|adoy|d|dd|e|r|u|ud|udoy]        Set the format of the packet timestamp printed in summary lines.
      --tty=<tty>                                            Display the UI on this terminal.
      --pass-thru=[auto|true|false]                          Run tshark instead (auto => if stdout is not a tty). (default: auto)
      --log-tty                                              Log to the terminal.
  -h, --help                                                 Show this help message.
  -v, --version                                              Show version information.

Arguments:
  FilterOrFile:                                              Filter (capture for iface, display for pcap), or pcap file to read.

If --pass-thru is true (or auto, and stdout is not a tty), tshark will be
executed with the supplied command-line flags. You can provide
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

## Choose a Source

### Reading from an Interface

Launch termshark like this to read from an interface:

```bash
termshark -i eth0
```

You can also apply a capture filter directly from the command-line:

```bash
termshark -i eth0 tcp
```

Termshark will apply the capture filter as it reads, but the UI currently does not provide any indication of the capture filter that is in effect.

Termshark supports reading from more than one interface at a time:

```bash
termshark -i eth0 -i eth1
```

Once packets are detected, termshark's UI will launch and the packet views will update as packets are read:

![readiface](/../gh-pages/images/readiface.png?raw=true)

You can apply a display filter while the packet capture process is ongoing - termshark will dynamically apply the filter without restarting the capture. Press `ctrl-c` to stop the capture process.

When you exit termshark, it will print a message with the location of the pcap file that was captured:

```console
$ termshark -i eth0
Packets read from interface eth0 have been saved in /home/gcla/.cache/termshark/eth0-657695279.pcap
```

### Read a pcap file

Launch termshark like this to inspect a file:

```bash
termshark -r test.pcap
```

You can also apply a display filter directly from the command-line:

```bash
termshark -r test.pcap icmp
```

Note that when reading a file, the filter will be interpreted as a [display filter](https://wiki.wireshark.org/DisplayFilters). When reading from an interface, the filter is interpreted as a [capture filter](https://wiki.wireshark.org/CaptureFilters). This follows tshark's behavior.

Termshark will launch in your terminal. From here, you can press `?` for help:

![tshelp](/../gh-pages/images/tshelp.png?raw=true)

#### Changing Files

Termshark provides a "Recent" button which will open a menu with your most recently-loaded pcap files. Each invocation of termshark with the `-r` flag will add a pcap to the start of this list:

![recent](/../gh-pages/images/recent.png?raw=true)

### Reading from a fifo or stdin

Termshark supports reading packets from a Unix fifo or from standard input - for example

```bash
tcpdump -i eth0 -w - icmp | termshark
```

On some machines, packet capture commands might require sudo or root access. To facilitate this, termshark's UI will not launch until it detects that it has received some packet data on its input. This makes it easier for the user to type in his or her root password on the tty before termshark takes over:

```bash
$ sudo tcpdump -i eth0 -w - icmp | termshark
(The termshark UI will start when packets are detected...)
[sudo] password for gcla:
```

If the termshark UI is active in the terminal but you want to see something displayed there before termshark started, you can now issue a SIGTSTP signal (on Unix) and termshark will suspend itself and give up control of the terminal. In bash, this operation is usually bound to ctrl-z.

```bash
$ termshark -r foo.pcap

[1]+  Stopped                 termshark -r foo.pcap
$
```

Type `fg` to resume termshark. Another option is to launch termshark in its own tty. You could do this using a split screen in tmux. In one pane, type

```bash
tty && sleep infinity
```

If the output is e.g. `/dev/pts/10`, then you can launch termshark in the other tmux pane like this:

```bash
termshark -r foo.pcap --tty=/dev/pts/10
```

Issue a sleep in the pane for `/dev/pts/10` so that no other process reads from the terminal while it is dedicated to termshark.

## Using the TUI

### Filtering

Press `/` to focus on the display filter. Now you can type in a Wireshark display filter expression. The UI will update in real-time to display the validity of the current expression. If the expression is invalid, the filter widget will change color to red. As you type, termshark presents a drop-down menu with possible completions for the current term:

![filterbad](/../gh-pages/images/filterbad.png?raw=true)

When the filter widget is green, you can hit the "Apply" button to make its value take effect. Termshark will then reload the packets with the new display filter applied.

![filterbad](/../gh-pages/images/filterbad.png?raw=true)

### Changing Views

Press `tab` to move between the three packet views. You can also use the mouse to move views by clicking with the left mouse button. When focus is in any of these three views, hit the `\` key to maximize that view:

![max](/../gh-pages/images/max.png?raw=true)

Press `\` to restore the original layout. Press `|` to move the hex view to the right-hand side:

![altview](/../gh-pages/images/altview.png?raw=true)

You can also press `<`,`>`,`+` and `-` to change the relative size of each view.

### Packet List View

Termshark's top-most view is a list of packets read from the capture (or interface). Termshark generates the data by running `tshark` on the input with the `-T psml` options, and parsing the resulting XML. Currently the columns displayed cannot be configured, and are the same as Wireshark's defaults. When the source is a pcap file, the list can be sorted by column by clicking the button next to each column header:

![sortcol](/../gh-pages/images/sortcol.png?raw=true)

You can hit `home` to jump to the top of the list or `end` to jump to the bottom. Sometimes, especially if running on a small terminal, the values in a column will be truncated (e.g. long IPv6 addresses). To see the full value, move the purple cursor over the value:

![ipv6](/../gh-pages/images/ipv6.png?raw=true)

### Packet Structure View

Termshark's middle view shows the structure of the packet selected in the list view. You can expand and contract the structure using the `[+]` and `[-]` buttons, the 'enter' key, or the right and left cursor keys:

![structure](/../gh-pages/images/structure.png?raw=true)

As you navigate the packet structure, different sections of the bottom view - a hex representation of the packet - will be highlighted.

### Packet Hex View

Termshark's bottom view shows the bytes that the packet comprises. Like Wireshark, they are displayed in a hexdump-like format. As you move around the bytes, the middle (structure) view will update to show you where you are in the packet's structure.

### Copy Mode

Both the structure and hex view support "copy mode" a feature which lets you copy ranges of data from the currently selected packet. First, move focus to the part of the packet you wish to copy. Now hit the `c` key - a section of the packet will be highlighted in yellow:

![copymode1](/../gh-pages/images/copymode1.png?raw=true)

You can hit the `left` and `right` arrow keys to expand or contract the selected region. Now hit `ctrl-c` to copy. Termshark will display a dialog showing you the format in which you can copy the data:

![copymode2](/../gh-pages/images/copymode2.png?raw=true)

Select the format you want and hit `enter` (or click). Copy mode is available in the packet structure and packet hex views.

This feature comes with a caveat! If you are connected to a remote machine e.g. via ssh, then you should use the `-X` flag to forward X11. On Linux, the default copy command is `xsel`. If you forward X11 with ssh, then the packet data will be copied to your desktop machine's clipboard. You can customize the copy command using termshark's [config file](UserGuide.md#config-file) e.g.

```toml
[main]
  copy-command = ["xsel", "-i", "-p"]
```

to instead set the primary selection. If forwarding X11 is not an option, you could instead upload the data (received via stdin) to a service like pastebin, and print the URL on stdout - termshark will display the copy command's output in a dialog when the command completes. See the [FAQ](FAQ.md).

If you are running on OSX, termux (Android) or Windows, termshark assumes you are running locally and uses a platform-specific copy command.

### Packet Capture Information

To show a summary of the information represented in the current pcap file, go to the "Analysis" menu and choose "Capture file properties". Termshark generates this information using the `capinfos` binary which is distributed with `tshark`.

![capinfos1](/../gh-pages/images/capinfos1.png?raw=true)

### Stream Reassembly

Termshark is able to present reassembled TCP and UDP streams in a similar manner to Wireshark. In the packet list view, select a TCP or UDP packet then go to the "Analysis" menu and choose "Reassemble stream":

![streams1](/../gh-pages/images/streams1.png?raw=true)

Termshark shows you:

- A list of each client and server payload, in order, colored accordingly.
- The number of client and server packets, and times the conversation switched sides.
- A search box.
- A button to display the entire conversation, only the client side, or only the server side.

You can type a string in the search box and hit enter - or the Next button - to move through the matches.

![streams2](/../gh-pages/images/streams2.png?raw=true)

Select Regex to instead have termshark interpret your search string as a regular expression. Because termshark is written in Golang, the regular expression uses Golang's regex dialect. [regex101](https://regex101.com/) provides a nice online way to experiment with matches. A quick tip - if you want your match to [cross line endings](https://stackoverflow.com/a/58318036/784226), prefix your search with `(?s)`.

You can choose how to view the reassembled data by using the buttons at the bottom of the screen - ASCII, hex or Wireshark's raw format. Termshark will remember your preferred format.

![streams3](/../gh-pages/images/streams3.png?raw=true)

Like Wireshark, you can filter the displayed data to show only the client-side or only the server-side of the conversation:

![streams4](/../gh-pages/images/streams4.png?raw=true)

You can use Copy Mode in stream reassembly too. Hit the `c` key to enter Copy Mode. The currently selected "chunk" will be highlighted. Hit `ctrl-c` to copy that data. By default, termshark will copy the data to your clipboard. Hit the left arrow key to widen the data copied to the entire conversation (or filtered by client or server if that is selected).

![streams5](/../gh-pages/images/streams5.png?raw=true)

Finally, clicking on a reassembled piece of the stream (enter or left mouse click) will cause termshark to select the underlying packet that contributed that payload. If you hit `q` to exit stream reassembly, termshark will set focus on the selected packet.

### Conversations

To display a table of conversations represented in the current pcap, go to the "Analysis" menu  and choose "Conversations". Termshark uses `tshark` to generate a list of conversations by protocol. Currently, termshark supports displaying Ethernet, IPv4, IPv6, UDP and TCP. 

![convs1](/../gh-pages/images/convs1.png?raw=true)

You have have termshark filter the packets displayed according to the current conversation selected. The "Prepare..." button will set termshark's display filter field, but *not* apply it, letting you futher edit it first. The "Apply..." button will set the display filter and apply it immediately. Navigate to the interesting conversation, then click either "Prepare..." or "Apply..."

![convs2](/../gh-pages/images/convs2.png?raw=true)

In the first pop-up menu, you can choose how to extend the current display filter, if there is in. In the second pop-up menu, you can choose whether to filter by the conversation bidirectionally, unidirectionally, or just using the source or destination. These menus mirror those used in Wireshark. When you hit enter, the filter will be adjusted. Hit 'q' to quit the conversations screen.

![convs3](/../gh-pages/images/convs3.png?raw=true)

## Configuration

### Dark Mode

If termshark is too bright for your taste, try dark-mode. To enable, hit Esc to open the main menu and select "Toggle Dark Mode".

![darkmode](/../gh-pages/images/darkmode.png?raw=true)

Your choice is stored in the termshark [config file](UserGuide.md#config-file). Dark-mode is supported throughout the termshark user-interface.

### Packet Colors

By default, termshark will now display packets in the packet list view colored according to Wireshark's color rules. With recent installations of Wireshark, you can find this file at `$XDG_CONFIG_HOME/wireshark/colorfilters`. Termshark doesn't provide a way to edit the colors - the colors are provided by `tshark`. You can read about Wireshark's support [here](https://www.wireshark.org/docs/wsug_html_chunked/ChCustColorizationSection.html). If you don't like the way this looks in termshark, you can turn it off using termshark's main menu.

### Config File

Termshark reads options from a TOML configuration file saved in `$XDG_CONFIG_HOME/termshark/termshark.toml` (e.g. `~/.config/termshark/termshark.toml` on Linux). All options are saved under the `[main]` section. The available options are:

- `browse-command` (string list) - termshark will run this command with a URL e.g. when the user selects "FAQ" from the main menu. Any argument in the list that equals `$1` will be replaced by the URL prior to the command being run e.g.

```toml
[main]
  browse-command = ["firefox", "$1"]
```

- `capinfos` (string) - make termshark use this specific `capinfos` binary (for pcap properties).
- `capture-command` (string) - use this binary to capture packets, passing `-i`, `-w` and `-f` flags. 
- `color-tsharks` (string list) - a list of the paths of tshark binaries that termshark has confirmed support the `--color` flag. If you run termshark and the selected tshark binary is not in this list, termshark will check to see if it supports the `--color` flag.
- `colors` (bool) - if true, and tshark supports the feature, termshark will colorize packets in its list view.
- `conv-absolute-time` (bool) - if true, have tshark provide conversation data with a relative start time field.
- `conv-resolve-names` (bool) - if true, have tshark provide conversation data with ethernet names resolved.
- `conv-use-filter` (bool) - if true, have tshark provide conversation data limited to match the active display filter.
- `conv-types` (string list) - a list of the conversation types termshark will query for and display in the conversations view. Currently limited to `eth`, `ip`, `ipv6`, `udp`, `tcp`.
- `copy-command` (string) - the command termshark executes when the user hits ctrl-c in copy-mode. The default commands on each platform will copy the selected area to the clipboard.

```toml
[main]
  copy-command = ["xsel", "-i", "-b"]
```

- `copy-command-timeout` (int) - how long termshark will wait (in seconds) for the copy command to complete before reporting an error.
- `dark-mode` (bool) - if true, termshark will run in dark-mode.
- `dumpcap` (string) - make termshark use this specific `dumpcap` (used when reading from an interface).
- `packet-colors` (bool) - if true (or missing), termshark will colorize packets according to Wireshark's rules.
- `pcap-bundle-size` - (int) - load tshark PDML this many packets at a time. Termshark will lazily load PDML because it's a slow process and uses a lot of RAM. For example, if `pcap-bundle-size`=1000, then on first loading a pcap, termshark will load PDML for packets 1-1000. If you scroll past packet 500, termshark will optimistically load PDML for packets 1001-2000. A higher value will make termshark load more packets at a time; a value of 0 means load the entire pcap's worth of PDML. Termshark stores the data compressed in RAM, but expect approximately 10MB per 1000 packets loaded. If you have the memory, can wait a minute or two for the entire pcap to load, and e.g. plan to use the packet list header to sort the packets in various ways, setting `pcap-bundle-size` to 0 will provide the best experience.
- `pcap-cache-size` - (int) - termshark loads packet PDML (structure) and pcap (bytes) data in bundles of `pcap-bundle-size`. This setting determines how many such bundles termshark will keep cached. The default is 32.
- `pdml-args` (string list) - any extra parameters to pass to `tshark` when it is invoked to generate PDML.
- `psml-args` (string list) - any extra parameters to pass to `tshark` when it is invoked to generate PSML.
- `recent-files` (string list) - the pcap files shown when the user clicks the "recent" button in termshark. Newly viewed files are added to the beginning.
- `recent-filters` (string list) - recently used Wireshark display filters.
- `stream-cache-size` (int) - termshark caches the structures and UI used to display reassembled TCP and UDP streams. This allows for quickly redisplaying a stream that's been loaded before. This setting determines how many streams are cached. The default is 100.
- `stream-view` (string - the default view when displaying a reassembled stream. Choose from "hex"/"ascii"/"raw".
- `tail-command` (string) - make termshark use this specific `tail` command. This is used when reading from an interface in order to feed `dumpcap`-saved data to `tshark`. The default is `tail -f -c +0 <file>`. If you are running on Windows, the default is to use `termshark` itself with a special hidden `--tail` flag. But probably better to use Wireshark on Windows :-)
- `term` (string) - termshark will use this as a replacement for the TERM environment variable.

```toml
[main]
  term = "screen-256color"
```

- `tshark` (string) - make termshark use this specific `tshark`.
- `tshark-args` (string list) - these are added to each invocation of `tshark` made by termshark e.g.

```toml
[main]
  tshark-args = ["-d","udp.port==2075,cflow]"
```

- `ui-cache-size` - (int) - termshark will remember the state of widgets representing packets e.g. which parts are expanded in the structure view, and which byte is in focus in the hex view. This setting allows the user to override the number of widgets that are cached. The default is 1000.
- `validated-tsharks` - (string list) - termshark saves the path of each `tshark` binary it invokes (in case the user upgrades the system `tshark`). If the selected (e.g. `PATH`) tshark binary has not been validated, termshark will check to ensure its version is compatible. tshark must be newer than v1.10.2 (from approximately 2013).

## Troubleshooting

If termshark is running slowly or otherwise misbehaving, you might be able to narrow the issue down by using the `--debug` flag. When you start termshark with `--debug`, three things happen:

1. A web server runs with content available at [http://127.0.0.1:6060/debug/pprof](http://127.0.0.1:6060/debug/pprof) (or the remote IP). This is a Golang feature and provides a view of some low-level internals of the process such as running goroutines.
2. On receipt of SIGUSR1, termshark will start a Golang CPU profile that runs for 20 seconds.
3. On receipt of SIGUSR2, termshark will create a Golang memory/heap profile.

Profiles are stored under `$XDG_CONFIG_CACHE/termshark` (e.g. `~/.cache/termshark/`). If you open a termshark issue on github, these profiles will be useful for debugging.

For commonly asked questions, check out the [FAQ](/docs/FAQ.md).
