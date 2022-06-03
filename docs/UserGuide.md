# Termshark User Guide

Termshark provides a terminal-based user interface for analyzing packet captures.

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Basic Usage](#basic-usage)
- [Choose a Source](#choose-a-source)
  - [Reading from an Interface](#reading-from-an-interface)
  - [Read a pcap File](#read-a-pcap-file)
    - [Changing Files](#changing-files)
  - [Reading from a fifo or stdin](#reading-from-a-fifo-or-stdin)
- [Using the TUI](#using-the-tui)
  - [Filtering](#filtering)
  - [Changing Views](#changing-views)
  - [Packet List View](#packet-list-view)
  - [Packet Structure View](#packet-structure-view)
  - [Packet Hex View](#packet-hex-view)
  - [Marking Packets](#marking-packets)
  - [Searching Packets](#searching-packets)
  - [Copy Mode](#copy-mode)
  - [Packet Capture Information](#packet-capture-information)
  - [Stream Reassembly](#stream-reassembly)
  - [Conversations](#conversations)
  - [Columns](#columns)
  - [Command-Line](#command-line)
  - [Macros](#macros)
  - [Transfer a pcap File](#transfer-a-pcap-file)
- [Configuration](#configuration)
  - [Dark Mode](#dark-mode)
  - [Packet Colors](#packet-colors)
  - [Themes](#themes)
  - [Config File](#config-file)
- [Troubleshooting](#troubleshooting)

## Basic Usage

Termshark is inspired by Wireshark, and depends on tshark for all its intelligence. Termshark is run from the command-line. You can see its options with

```console
$ termshark -h
termshark v2.3.0

A wireshark-inspired terminal user interface for tshark. Analyze network traffic interactively from your terminal.
See https://termshark.io for more information.

Usage:
  termshark [FilterOrPcap]

Application Options:
  -i=<interfaces>                                            Interface(s) to read.
  -r=<infile/fifo>                                           Pcap file/fifo to read. Use - for stdin.
  -w=<outfile>                                               Write raw packet data to outfile.
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
  FilterOrPcap:                                              Filter (capture for iface, display for pcap), or pcap to read.

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

By default, termshark will save the packets - e.g. to `~/.cache/termshark/pcaps/` on Linux. If you use the `-w` flag, you can save them to your own file:

```bash
termshark -i eth0 -w save.pcap
```

You can also apply a capture filter directly from the command-line:

```bash
termshark -i eth0 tcp
```

Termshark will apply the capture filter as it reads. The UI will show the capture filter in parentheses at the top, after the name of the packet source.

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
Packets read from interface eth0 have been saved in /home/gcla/.cache/termshark/pcaps/eth0--2021-09-03--11-20-58.pcap
```

### Read a pcap File

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

```console
$ sudo tcpdump -i eth0 -w - icmp | termshark
(The termshark UI will start when packets are detected...)
[sudo] password for gcla:
```

If the termshark UI is active in the terminal but you want to see something displayed there before termshark started, you can now issue a SIGTSTP signal (on Unix) and termshark will suspend itself and give up control of the terminal. In bash, this operation is usually bound to `ctrl-z`.

```console
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

Press `tab` or `ctrl-w ctrl-w` to move between the three packet views. You can also use the mouse to move views by clicking with the left mouse button. When focus is in any of these three views, hit the `\` key to maximize that view:

![max](/../gh-pages/images/max.png?raw=true)

Press `\` to restore the original layout. Press `|` to move the hex view to the right-hand side:

![altview](/../gh-pages/images/altview.png?raw=true)

You can also press `<`,`>`,`+` and `-` to change the relative size of each view. To reset termshark to use its original relative sizes, hit `ctrl-w
=`. All termshark views support vim-style navigation with `h`, `j`, `k` and `l` along with regular cursor keys.

### Packet List View

Termshark's top-most view is a list of packets read from the capture (or interface). Termshark generates the data by running `tshark` on the input
with the `-T psml` options, and parsing the resulting XML. Currently the columns displayed cannot be configured, and are the same as Wireshark's
defaults. When the source is a pcap file, the list can be sorted by column by clicking the button next to each column header:

![sortcol](/../gh-pages/images/sortcol.png?raw=true)

You can hit `home` or `gg` to jump to the top of the list and `end` or `G` to jump to the bottom. You can jump to a specific packet by entering its
number - as a prefix - before hitting `gg` or `G` Sometimes, especially if running on a small terminal, the values in a column will be truncated
(e.g. long IPv6 addresses). To see the full value, move the purple cursor over the value:

![ipv6](/../gh-pages/images/ipv6.png?raw=true)

### Packet Structure View

Termshark's middle view shows the structure of the packet selected in the list view. You can expand and contract the structure using the `[+]` and `[-]` buttons, the 'enter' key, or the right and left cursor keys:

![structure](/../gh-pages/images/structure.png?raw=true)

As you navigate the packet structure, different sections of the bottom view - a hex representation of the packet - will be highlighted. The currently selected line in this view will display a small button at the right hand-side. This button opens a contextual menu from which you can add a custom column or apply a filter based on the current level of the packet structure.

![pdmlmenu](/../gh-pages/images/termshark-pdml-menu.png?raw=true)

### Packet Hex View

Termshark's bottom view shows the bytes that the packet comprises. Like Wireshark, they are displayed in a hexdump-like format. As you move around the bytes, the middle (structure) view will update to show you where you are in the packet's structure.

### Marking Packets

To make it easier to compare packets, you can mark a packet in the packet list view and then jump back to it later. Termshark's marks are modeled on vim's. Set a mark by navigating to the packet and then hit `m` followed by a letter - `a` through `z`. 

![marks1](/../gh-pages/images/marks1.png?raw=true)

To jump back to that mark, hit `'` followed by the letter you selected. To jump back to the packet that was selected prior to your jump, hit `''`. When you exit termshark or load a new pcap, these marks are deleted; but termshark also supports cross-pcap marks which are saved in termshark's config file. To make a cross-pcap mark, hit `m` followed by a capital letter - `A` through `Z`. If you jump to a cross-pcap mark made in another pcap, termshark will load that pcap back up. To display your current marks, use the [command-line](#command-line) `marks` command:

![marks2](/../gh-pages/images/marks2.png?raw=true)

### Searching Packets

To search within packets, hit `ctrl-f` to open termshark's search bar. The options provided closely mirror those available with Wireshark. The first button displays a menu that lets you choose the type of data searched:

- Packet List - the info shown in the packet list view (by default the top data pane)
- Packet Struct - the info shown in the packet struct view (by default the middle data pane)
- Packet Bytes - the info shown in the packet hex view (by default the bottom data pane)

The second button lets you choose what to search for:

- String (with or without case sensitivity)
- Regex (with or without case sensitivity)
- Hex
- Display Filter

The Hex syntax follows Wireshark and requires a sequence of 2 hex-digits, concatenated. For example, entering "AF054c" would mean to search for the following 3 bytes, consecutively - 175, 5, 76. 

Display Filter search is a special case and does not search the packet data directly. Instead, termshark launches a tshark process on the current pcap source with flags to apply the user's search filter. Termshark parses the output and every packet that appears in the PSML data is a match for the search.

If a match is found, termshark will navigate to the match location in the UI. For a Packet List search, the matching row and column are selected. For a Packet Struct search, the matching element in the packet structure view is expanded and the UI centered around it. For a Packet Bytes search, the cursor is moved to the start of the match in the packet hex view. 

To terminate the search early, hit `ctrl-c`.  To set focus on the search bar's input, hit `ctrl-f` again. To close the search bar, hit `ctrl-f` one more time.

![search1](/../gh-pages/images/search1.png?raw=true)


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

You can make termshark filter the packets displayed according to the current conversation selected. The "Prepare..." button will set termshark's display filter field, but *not* apply it, letting you futher edit it first. The "Apply..." button will set the display filter and apply it immediately. Navigate to the interesting conversation, then click either "Prepare..." or "Apply..."

![convs2](/../gh-pages/images/convs2.png?raw=true)

In the first pop-up menu, you can choose how to extend the current display filter, if there is one. In the second pop-up menu, you can choose whether to filter by the conversation bidirectionally, unidirectionally, or just using the source or destination. These menus mirror those used in Wireshark. When you hit enter, the filter will be adjusted. Hit 'q' to quit the conversations screen.

![convs3](/../gh-pages/images/convs3.png?raw=true)

### Columns

Like Wireshark, you can configure the columns that termshark displays. To do this, choose "Edit Columns" from the main menu, or type `columns` from the command-line.

![configcolumns](/../gh-pages/images/custom-columns.png?raw=true)

From this dialog, you can:

- Rearrange your current column set
- Hide columns or make them visible
- Delete and add columns
- Give each of your columns a custom name

If termshark can find your Wireshark config, it also offers the option of importing your Wireshark column set.

Use the drop-down menus to choose the column type. If you select a custom column, termshark will require you to provide a valid display filter
expression. Like Wireshark, the syntax of valid column expressions is a subset of those for display filters - essentially the disjunction (or) of
filter fields. Note that termshark follows Wireshark and currently allows you to enter *any* valid display filter expression.

Like Wireshark, the packet structure view allows you to quickly create custom columns. Navigate to the end of your chosen line of packet structure 
and select the `[=]` hamburger button. Based on the display filter expression that maps to this structure, you can create a custom column, 
or either prepare or directly set termshark's display filter.

![colfromstruct](/../gh-pages/images/vrrpcol1.png?raw=true)

### Command-Line

For fast navigation around the UI, termshark offers a vim-style command-line. To activate the command-line, hit the ':' key:

![cmdline1](/../gh-pages/images/cmdline1.png?raw=true)

Many of termshark's operations can be initiated from the command-line. After opening the command-line, hit tab to show all the commands available:

- **capinfo** - Show the current capture file properties (using the `capinfos` command)
- **clear-filter** - Clear the current display filter
- **clear-packets** - Clear the current pcap
- **columns** - Configure termshark's columns
- **convs** - Open the conversations view
- **filter** - Choose a display filter from those recently-used
- **help** - Show one of several help dialogs
- **load** - Load a pcap from the filesystem
- **logs** - Show termshark's log file (Unix-only)
- **map** - Map a keypress to a key sequence (see `help map`)
- **marks** - Show file-local and global packet marks
- **menu** - Open the UI menubar
- **no-theme** - Clear theme for the current terminal color mode
- **quit** - Quit termshark
- **recents** - Load a pcap from those recently-used
- **set** - Set various config properties (see `help set`)
- **streams** - Open the stream reassemably view
- **theme** - Set a new termshark theme
- **unmap** - Remove a keypress mapping made with the `map` command
- **wormhole** - Transfer the current pcap using magic wormhole
 
Some commands require a parameter or more. Candidate completions will be shown when possible; you can then scroll up or down through them and hit tab
or enter to complete the candidate. Candidates are filtered as you type. Hit enter to run a valid command or hit `ctrl-c` to close the command-line.

### Vim Navigation

Termshark lets you navigate the UI using familiar Vim key bindings and tries to apply other Vim concepts where it makes sense. All tabular views
support Vim's `hjkl` navigation keys. Here is a list of other Vim-style bindings:

- **gg**      - Go to the top of the current table
- **G**       - Go to the bottom of the current table
- **5gg**     - Go to the 5th row of the table
- **C-w C-w** - Switch panes (same as tab)
- **C-w =**   - Equalize pane spacing
- **ma**      - Mark current packet (use a through z)
- **'a**      - Jump to packet marked 'a'
- **mA**      - Mark current packet + pcap (use A through Z)
- **'A**      - Jump to packet + pcap marked 'A'
- **''**      - After a jump; jump back to prior packet
- **ZZ**      - Quit without confirmation

The command-line supports some Vim shortcuts too e.g. `:q!` to quit immediately.

### Macros

To support navigational shortcuts that are not directly built-in to the termshark UI, you can now create simple keyboard macros. These are modeled on
vim's key mappings. To create a macro, open the [command-line](#command-line) and use the `map` command. The first argument is the key to map and the
second argument is a sequence of keypresses that your first key should now map to. Termshark uses vim-syntax for keys. To express a keypress for a
printable character, simply use the printable character. Here is the syntax for the other keys that termshark understands:

- `<space>`
- `<esc>`
- `<enter>`
- `<f1>-<f12>`
- modifiers - `<C-s>`, `<A-/>`
- `<up>`, `<down>`, `<left>`, `<right>`
- `<pgup>`, `<pgdn>`
- `<home>`, `<end>`

Here are some example macros:

- `map <C-s> /` - hit ctrl-s to activate the display filter widget
- `map <f1> :quit<enter><enter>` - hit f1 to quit termshark without asking for confirmation
- `map <f1> ZZ` - another way to quit quickly!
- `map <f2> <esc>d` - toggle dark-mode

A termshark user requested the ability to move up and down the packet list but to keep focus on the packet structure view. This can be accomplished by setting these macros:

- `map <f5> <tab><tab><down><tab>`
- `map <f6> <tab><tab><up><tab>`

Then with focus on the packet structure view, hit `f5` to go down a packet and `f6` to go up a packet.

Macros are saved in the termshark config file. To display the current list of macros, simply type `map` from the command-line with no arguments.

![macros](/../gh-pages/images/macros.png?raw=true)

### Transfer a pcap File

Termshark can be convenient, but sometimes you need to get your current capture into Wireshark! Termshark integrates
[wormhole-william](https://github.com/psanford/wormhole-william) to help you quickly transfer your current capture to your Wireshark machine using
[magic wormhole](https://github.com/magic-wormhole/magic-wormhole). To start this process, choose "Send Pcap" from the "Misc" menu, or run "wormhole"
from the termshark command-line:

![wormhole1](/../gh-pages/images/wormhole1.png?raw=true)

Termshark will display the magic-wormhole code. On your Wireshark machine, use any magic-wormhole client to download using the code. For example:

```
$ wormhole receive 9-mosquito-athens
Receiving file (2.8 MB) into: vrrp.pcap
ok? (y/N): y
Receiving (->tcp:10.6.14.67:45483)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 2.83M/2.83M [00:00<00:00, 161MB/s]
Received file written to vrrp.pcap
```

If you use tmux on your Wireshark machine and run termshark - locally or over ssh - from that tmux session, then you can download and open the pcap
with a single keypress using [tmux-wormhole](https://github.com/gcla/tmux-wormhole), a tmux tpm plugin. Here's a demo:

https://user-images.githubusercontent.com/45680/122692277-0de7e180-d202-11eb-964c-fbc4a2534255.mp4

## Configuration

### Dark Mode

If termshark is too bright for your taste, try dark-mode. To enable, hit Esc to open the main menu and select "Toggle Dark Mode".

![darkmode](/../gh-pages/images/darkmode.png?raw=true)

Your choice is stored in the termshark [config file](UserGuide.md#config-file). Dark-mode is supported throughout the termshark user-interface.

### Packet Colors

By default, termshark will now display packets in the packet list view colored according to Wireshark's color rules. With recent installations of Wireshark, you can find this file at `$XDG_CONFIG_HOME/wireshark/colorfilters`. Termshark doesn't provide a way to edit the colors - the colors are provided by `tshark`. You can read about Wireshark's support [here](https://www.wireshark.org/docs/wsug_html_chunked/ChCustColorizationSection.html). If you don't like the way this looks in termshark, you can turn it off using termshark's main menu.

### Themes

Termshark can be themed to better line up with other terminal applications that you use. Most of termshark's UI elements have names and you can tie colors to these names. Here is an example theme:

```toml
[dracula]
  gray1 = "#464752"
  ...
  orange = "#ffb86c"
  purple = "#bd93f9"
  red = "#ff5555"
  white = "#f8f8f2"
  yellow = "#f1fa8c"

[dark]
  button = ["dracula.black","dracula.gray3"]
  button-focus = ["dracula.white","dracula.magenta"]
  button-selected = ["dracula.white","dracula.gray3"]
  ...
  
[light]
  button = ["dracula.black","dracula.white"]
  button-focus = ["dracula.black","dracula.purple"]
  button-selected = ["dracula.black","dracula.gray3"]
  ...  
```

Termshark finds themes in two ways - from:

- `$XDG_CONFIG_HOME/termshark/themes/*.toml` (e.g. `~/.config/termshark/themes/dracula.toml`)
- from a small database compiled-in to the termshark binary. 

The termshark command-line provides two commands to interact with themes:

- `theme` - choose a new theme from those provided and apply it.
- `no-theme` - use no theme.

Termshark saves your selected theme against the terminal color mode, which can be one of

- 16-color
- 256-color
- truecolor i.e. 24-bit color

The theme is saved in `termshark.toml` under, respectively, the keys:

- `main.theme-16`
- `main.theme-256`
- `main.theme-truecolor`

This means that if you run termshark on the same machine but with a different terminal emulator, you might need to re-apply the theme if the color
mode has changed (e.g. `xterm` v `gnome terminal`)

If you are running in truecolor/24-bit color, termshark will make the 256-color themes available too. Terminal emulators that support 24-bit color
will support 256-color mode as well.

If you have enabled termshark's packet colors - shown in the packet list view - then these colors will be reproduced faithfully according to
Wireshark's rules. These colors don't adhere to termshark's themes.

#### Built-in Themes and Base16

Termshark has four themes built-in:

- `default` - termshark's original color scheme (16-color, 256-color, truecolor)
- `dracula` - colors based on [Dracula theme](https://draculatheme.com/) project (256-color, truecolor)
- `solarized` - based on [Ethan Schoonover's](https://ethanschoonover.com/solarized/) work (256-color, truecolor)
- `base16` - (256-color, truecolor)

If you make another, please submit it! :-)

[Base16](https://github.com/chriskempson/base16) is a set of guidelines for building themes using a limited range of 8 colors and 8 grays. The
[base16-shell](https://github.com/chriskempson/base16-shell) project is a set of scripts that remap colors 0-21 in the 256-color space of a terminal
emulator. If you're in 256-color mode, this lets you have consistent coloring of your work in a terminal emulator, whether it's typing at the shell,
or running a TUI. If you use base16-shell, choose termshark's `base16` theme to make use of your shell theme's colors. 

#### Make a Theme

The layout of a theme is:

- the color definitions - `[mytheme]`
- set the foreground and background color of UI elements for
  - dark mode - `[dark]`
  - regular/light mode - `[light]`
  
Here's an [example theme](https://raw.githubusercontent.com/gcla/termshark/master/assets/themes/dracula-256.toml) to follow. This [tcell source
file](https://github.com/gdamore/tcell/blob/fcaa20f283682d6bbe19ceae067b37df3dc699d7/color.go#L821) shows some sample color names you can use.

The UI elements are listed in the `[dark]` and `[light]` sections. Each element is assigned a pair of colors - foreground and background. The colors
can be:

- a reference to another field in the theme toml e.g. `dracula.black`
- a color that termshark understands natively e.g. `#ffcc43`, `dark green`, `g50` (medium gray).

Save your theme toml file under `~/.config/termshark/themes/` with a suffix indicating the color-mode e.g. `mytheme-256.toml`. 

If your theme is a truecolor theme (suffix `-truecolor.toml`), then RGB colors will be reproduced precisely by termshark and so by the terminal
emulator. If your theme is a 256-color theme (suffix `-256.toml`), you can still use RGB colors in your toml, and termshark will then try to pick the
closest matching color in the 256-color space. If termshark detects you are using base16-shell, then it will ignore colors 0-21 when choosing the
closest match, since these will likely be remapped by the base16-shell theme.

Hopefully the meaning of the UI-element names is guessable, but one detail to know is the difference between focus, selected and unselected. In a
gowid application, one widget at a time will have "focus". For example, if you are navigating the packet's tree structure (the middle pane), one level
of that protocol structure will be shown in blue, and will be the focus widget. If you hit tab to move to the hex view of the packet's bytes (the
lower pane), then focus will move to the hex byte under the cursor; but the previously blue protocol structure in the middle pane will still be
obvious, shown in grey. That protocol level is now "selected", but not in "focus". So selected is a way to highlight a widget in a container of
widgets that will have focus when control returns to the container. Unselected means neither focus nor selected.

### Config File

Termshark reads options from a TOML configuration file saved in `$XDG_CONFIG_HOME/termshark/termshark.toml` (e.g. `~/.config/termshark/termshark.toml` on Linux). All options are saved under the `[main]` section. The available options are:

- `always-keep-pcap` (bool) - if true, and if termshark is run on a live packet source (`-i`), when termshark is asked to exit, it will not prompt the user to choose whether to keep or delete the capture.
- `auto-scroll` (bool) - if true, termshark will automatically scroll down when packets are read in a live-capture mode (e.g. `-i eth0`)
- `browse-command` (string list) - termshark will run this command with a URL e.g. when the user selects "FAQ" from the main menu. Any argument in the list that equals `$1` will be replaced by the URL prior to the command being run e.g.

```toml
[main]
  browse-command = ["firefox", "$1"]
```

- `capinfos` (string) - make termshark use this specific `capinfos` binary (for pcap properties).
- `capture-command` (string) - use this binary to capture packets, passing `-i`, `-w` and `-f` flags. 
- `color-tsharks` (string list) - a list of the paths of tshark binaries that termshark has confirmed support the `--color` flag. If you run termshark and the selected tshark binary is not in this list, termshark will check to see if it supports the `--color` flag.
- `colors` (bool) - if true, and tshark supports the feature, termshark will colorize packets in its list view.
- `column-format` (string list) - a list of columns, each a group of three strings: field name, display name, and visibility.
- `column-format-bak` (string list) - the value of `column-format` prior to its last change; for restoring previous settings.
- `conv-absolute-time` (bool) - if true, have tshark provide conversation data with a relative start time field.
- `conv-resolve-names` (bool) - if true, have tshark provide conversation data with ethernet names resolved.
- `conv-use-filter` (bool) - if true, have tshark provide conversation data limited to match the active display filter.
- `conv-types` (string list) - a list of the conversation types termshark will query for and display in the conversations view. Currently limited to `eth`, `ip`, `ipv6`, `udp`, `tcp`.
- `copy-command` (string) - the command termshark executes when the user hits `ctrl-c` in copy-mode. The default commands on each platform will copy the selected area to the clipboard.

```toml
[main]
  copy-command = ["xsel", "-i", "-b"]
```

- `copy-command-timeout` (int) - how long termshark will wait (in seconds) for the copy command to complete before reporting an error.
- `dark-mode` (bool) - if true, termshark will run in dark-mode.
- `debug` (bool) - if true, run a debug web-server on http://localhost:6060. Shows termshark/golang internals - in case of a problem.
- `disable-shark-fin` (bool) - if true then turn off the shark-fin screen-saver permanently.
- `disable-term-helper` (bool) - if true then don't try to nudge the user towards a 256-color TERM; run as-is.
- `disk-cache-size-mb` (int) - how large termshark will allow `$XDG_CACHE_HOME/termshark/pcaps/` to grow; if the limit is exceeded, termshark will delete pcaps, oldest first. Set to -1 to disable (grow indefinitely).
- `dumpcap` (string) - make termshark use this specific `dumpcap` (used when reading from an interface).
- `ignore-base16-colors` (bool) - if true, when running in a terminal with 256-colors, ignore colors 0-21 in the 256-color-space when choosing the best match for a theme's RGB (24-bit) color. This avoids choosing colors that are
   remapped using e.g. [base16-shell](https://github.com/chriskempson/base16-shell).
- `key-mappings` (string list) - a list of macros, where each string contains a vim-style keypress, a space, and then a sequence of keypresses.
- `marks` (string json) - a serialized json structure representing the cross-pcap marks - for each, the keypress (`A` through `Z`); the pcap filename; the packet number; and a short summary of the packet.
- `packet-colors` (bool) - if true (or missing), termshark will colorize packets according to Wireshark's rules.
- `pager` (string) - the pager program to use when displaying termshark's log file - run like this: `sh -c "<pager> termshark.log"`
- `pcap-bundle-size` - (int) - load tshark PDML this many packets at a time. Termshark will lazily load PDML because it's a slow process and uses a lot of RAM. For example, if `pcap-bundle-size`=1000, then on first loading a pcap, termshark will load PDML for packets 1-1000. If you scroll past packet 500, termshark will optimistically load PDML for packets 1001-2000. A higher value will make termshark load more packets at a time; a value of 0 means load the entire pcap's worth of PDML. Termshark stores the data compressed in RAM, but expect approximately 10MB per 1000 packets loaded. If you have the memory, can wait a minute or two for the entire pcap to load, and e.g. plan to use the packet list header to sort the packets in various ways, setting `pcap-bundle-size` to 0 will provide the best experience.
- `pcap-cache-dir` - (string) - if `use-tshark-temp-for-pcap-cache` is false, when termshark is run on a live packet source (`-i`), the captured packets will be saved here.
- `pcap-cache-size` - (int) - termshark loads packet PDML (structure) and pcap (bytes) data in bundles of `pcap-bundle-size`. This setting determines how many such bundles termshark will keep cached. The default is 32.
- `pdml-args` (string list) - any extra parameters to pass to `tshark` when it is invoked to generate PDML.
- `psml-args` (string list) - any extra parameters to pass to `tshark` when it is invoked to generate PSML.
- `recent-files` (string list) - the pcap files shown when the user clicks the "recent" button in termshark. Newly viewed files are added to the beginning.
- `recent-filters` (string list) - recently used Wireshark display filters.
- `respect-colorterm` (bool) - if termshark detects you are using base16-shell, it won't map any theme RGB color names (like #90FF32) to 0-21 in the 256-color space to avoid clashes with the active base16 theme. This shouldn't affect color reproduction if the terminal is 24-bit capable, but some terminal emulators (e.g. gnome-terminal) seem to use the 256-color space anyway. Termshark works around this by falling back to 256-color mode, interpolating RGB colors into the 256-color space and avoiding 0-21. If you really want termshark to run in 24-bit color mode anyway, set this to true.
- `search-type` - (string) - how to interpret the user's packet search term; one of `filter`, `hex`, `string` or `regex`.
- `search-target` - (string) - the type of packet data to search (unless `search-type` is `filter`); one of `list`, `details` or `bytes`.
- `search-case-sensitive` - (bool) - true if the user's packet search should be sensitive to the case of the search term.
- `stream-cache-size` (int) - termshark caches the structures and UI used to display reassembled TCP and UDP streams. This allows for quickly redisplaying a stream that's been loaded before. This setting determines how many streams are cached. The default is 100.
- `stream-view` (string - the default view when displaying a reassembled stream. Choose from "hex"/"ascii"/"raw".
- `suppress-tshark-errors` (bool) - if `true`, hide from the UI any errors generated during parsing of tshark-generated XML.
- `tail-command` (string) - make termshark use this specific `tail` command. This is used when reading from an interface in order to feed `dumpcap`-saved data to `tshark`. The default is `tail -f -c +0 <file>`. If you are running on Windows, the default is to use `termshark` itself with a special hidden `--tail` flag. But probably better to use Wireshark on Windows :-)
- `term` (string) - termshark will use this as a replacement for the TERM environment variable.

```toml
[main]
  term = "screen-256color"
```

- `theme-8` (string) - the theme applied when termshark runs in a 8-color terminal. If absent, no theme is used.
- `theme-16` (string) - the theme applied when termshark runs in a 16-color terminal. If absent, no theme is used.
- `theme-256` (string) - the theme applied when termshark runs in a 256-color terminal. If absent, no theme is used.
- `theme-truecolor` (string) - the theme applied when termshark runs in a terminal that supports 24-bit color. If absent, no theme is used.
- `tshark` (string) - make termshark use this specific `tshark`.
- `tshark-args` (string list) - these are added to each invocation of `tshark` made by termshark e.g.

```toml
[main]
  tshark-args = ["-d","udp.port==2075,cflow]"
```

- `ui-cache-size` - (int) - termshark will remember the state of widgets representing packets e.g. which parts are expanded in the structure view, and which byte is in focus in the hex view. This setting allows the user to override the number of widgets that are cached. The default is 1000.
- `use-tshark-temp-for-pcap-cache` - (bool) - if true, when termshark is run on a live packet source (`-i`), the captured packets will be saved in tshark's `Temp` folder (`tshark -G folders`).
- `validated-tsharks` - (string list) - termshark saves the path of each `tshark` binary it invokes (in case the user upgrades the system `tshark`). If the selected (e.g. `PATH`) tshark binary has not been validated, termshark will check to ensure its version is compatible. tshark must be newer than v1.10.2 (from approximately 2013).
- `wormhole-length` - (int) - the number of words in the magic-wormhole code.
- `wormhole-rendezvous-url` - (string) - the magic-wormhole rendezvous server to use. "The server performs store-and-forward delivery for small key-exchange and control messages." (https://github.com/magic-wormhole/magic-wormhole-mailbox-server). Omit to use the default.
- `wormhole-transit-relay` - (string) - the magic-wormhole transit relay to use. "helps clients establish bulk-data transit connections even when both are behind NAT boxes" (https://github.com/magic-wormhole/magic-wormhole-transit-relay). Omit to use the default.

## Troubleshooting

If termshark is running slowly or otherwise misbehaving, you might be able to narrow the issue down by using the `--debug` flag. When you start termshark with `--debug`, three things happen:

1. A web server runs with content available at [http://127.0.0.1:6060/debug/pprof](http://127.0.0.1:6060/debug/pprof) (or the remote IP). This is a Golang feature and provides a view of some low-level internals of the process such as running goroutines.
2. On receipt of SIGUSR1, termshark will start a Golang CPU profile that runs for 20 seconds.
3. On receipt of SIGUSR2, termshark will create a Golang memory/heap profile.

Profiles are stored under `$XDG_CACHE_HOME/termshark` (e.g. `~/.cache/termshark/`). If you open a termshark issue on github, these profiles will be useful for debugging.

For commonly asked questions, check out the [FAQ](/docs/FAQ.md).
