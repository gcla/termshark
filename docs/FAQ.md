
# FAQ

## How can I copy a section of a packet from a remote machine when I can't forward X11?

You can set up a custom termshark copy command that sends the copied data to a pastebin service, for example. If your remote machine is Ubuntu, try making an executable script called e.g. `/usr/local/bin/ts-copy.sh`

```bash
#!/bin/bash
echo -n "See " && pastebinit
```
Then edit ```~/.config/termshark/termshark.toml``` and set

```toml
[main]
  copy-command = "/usr/local/bin/ts-copy.sh"
  ```
  When you copy a section of a packet, you should see something like this:

![othercopy](https://drive.google.com/uc?export=view&id=11kLyrEhBQL3e50Nrzk_BhhZgCzt1cqDn)

## Can I run termshark on MacOS/OSX?

Yes, you can install it from [Homebrew](Packages.md#homebrew).

```bash
brew update
brew install termshark
```

You can see the formula [here](https://formulae.brew.sh/formula/termshark).

## Can I run termshark on Android?

Yes, termshark is now packaged for Termux in the `root-repo` repository. Here's how to get it running:

- Install [Termux](https://play.google.com/store/apps/details?id=com.termux&hl=en_US) and [Termux:API](https://play.google.com/store/apps/details?id=com.termux.api&hl=en_US) through the Google Play Store. Termux:API is needed for access to Android's clipboard, in case you want to use termshark to copy sections of packets.
- Run termux and type

```bash
pkg install root-repo
pkg install termux-api
pkg install termshark
```

## If I load a big pcap, termshark doesn't load all the packets at once - why?

Termshark cheats. When you give it a pcap, it generates PSML XML for every packet, but not the complete PDML (packet structure) XML. If you run ```time tshark -T pdml -r huge.pcap > /dev/null```  you'll see it can take many minutes to complete. So rather than generating PDML for the entire pcap file, termshark generates PDML in 1000 packet chunks (by default). It will always prioritize packets that are in view or could soon be in view, so that the user isn't kept waiting. Now, if you open a large pcap, and - once the packet list is complete - hit `end`, you would want to be able to see the structure of packets at the end of the pcap. If termshark generated the PDML in one shot, the user could be kept waiting many minutes to see the end, while tshark chugs through the file emitting data. So to display the data more quickly, termshark runs something like
```bash
tshark -T pdml -r huge.pcap -Y 'frame.number >= 12340000 and frame.number < 12341000'
```
tshark is able to seek through the pcap much more quickly when it doesn't have to generate PDML - so this results in termshark getting data back to the user much more rapidly.

If you start to page up quickly, you will likely approach a range of packets that termshark hasn't loaded, and it will have to issue another tshark command to fetch the data. Termshark launches the tshark command before those unloaded packets come into view but there's room here for more sophistication. One problem with this approach is that if you sort the packet list by a field like source IP, then moving up or down one packet may result in needing to display the structure and bytes for a packet many thousands of packets away from the current one ordered by time - so termshark might kick off a new  ```-T pdml``` command for each up or down movement, meaning termshark will continually display "Loading..."

## Termshark is too bright!

Termshark v2 supports dark-mode! Hit Esc to bring up the main menu then "Toggle Dark Mode". See the [User Guide](UserGuide.md#dark-mode).

## Termshark's colors are limited...

By default, termshark respects the ```TERM``` environment variable and chooses a color scheme based on what it thinks the terminal is capable of, via the excellent [tcell](https://github.com/gdamore/tcell) package. You might be running on a terminal that can display more colors than ```TERM``` reports - so you can try adjusting your ```TERM``` variable e.g. if ```TERM``` is ```xterm```, try

```bash
export TERM=xterm-256color
```

or even

```bash
export TERM=xterm-truecolor
```
then re-run termshark.

tcell makes use of the environment variable ```COLORTERM``` when determining how to emit color codes. If ```COLORTERM``` is set to ```truecolor```, then tcell will emit truecolor color codes when the application changes the foreground or background color. If you connect to a remote machine with ssh to run termshark, the ```COLORTERM``` variable will not be forwarded. If that leaves you with ```TERM=xterm``` for example, then termshark, via tcell, will fall back to 8-color support. Here again you can change ```TERM``` or add a setting for ```COLORTERM``` to your remote ```.bashrc``` file.

If you run termshark under tmux or screen and always have ```TERM``` set in a way that doesn't make full use of your terminal emulator, you can configure termshark to always override it. Add the following to your `termshark.toml` file:

```toml
[main]
  term = "screen-256color"
```

## The console is too narrow on Windows

Unfortunately, the standard console window won't let you increase its size beyond its initial bounds using the mouse. To work around this, after termshark starts, right-click on the window title and select "Properties". Click "Layout" and then adjust the "Window Size" settings. When you quit termshark, your console window will be restored to its original size.

![winconsole](https://drive.google.com/uc?export=view&id=1tYTiSdcQtsSRFmw0nw7awmL9MOZiUinM)

## How does termshark use tshark?

Termshark uses tshark to provide all the data it displays, and to validate display filter expressions. When you give termshark a pcap file, it will run

```bash
tshark -T psml -r my.pcap -Y '<expression from ui>' -o gui.column.format:\"...\"```
```

to generate the packet list data. Note that the columns are currently unconfigurable (future work...) Let's say the user is focused on packet number 1234. Then termshark will load packet structure and hex/byte data using commands like:

```bash
tshark -T pdml -r my.pcap -Y '<expression from ui> and frame.number >= 1000 and frame.number < 2000'
tshark -F pcap -r my.pcap -Y '<expression from ui> and frame.number >= 1000 and frame.number < 2000' -w -
```
If the user is reading from an interface, some extra processes are needed. To capture the data, termshark runs

```bash
dumpcap -P -i eth0 -f <capture filter> -w <tmpfile>
```
This process runs until the user hits `ctrl-c` or clicks the "Stop" button in the UI. The path to ```tmpfile``` is printed out to the user when termshark exits. Then to feed data continually to termshark, another process is started:

```bash
tail -f -c +0 tmpfile
```
The stdout of the ```tail``` command is connected to the stdin of the PSML reading command, which is adjusted to:

```bash
tshark -T psml -i - -l -Y '<expression from ui>' -o gui.column.format:\"...\"```
```
The ```-l``` switch might push the data to the UI more quickly... The PDML and byte/hex generating commands read directly from `tmpfile`, since they don't need to provide continual updates (they load data in batches as the user moves around).

When the user types in termshark's display filter widget, termshark issues the following command for each change:

```bash
tshark -Y '<expression from ui>' -r empty.pcap
```
and checks the return code of the process. If it's zero, termshark assumes the filter expression is valid, and turns the widget green. If the return code is non-zero, termshark assumes the expression is invalid and turns the widget red. The file `empty.pcap` is generated once on startup and cached in ```$XDG_CONFIG_CACHE/empty.pcap``` (on Linux, ```~/.cache/termshark/empty.pcap```) On slower systems like the Raspberry Pi, you might see this widget go orange for a couple of seconds while termshark waits for tshark to finish.

If the user selects the "Analysis -> Reassemble stream" menu option, termshark starts two more tshark processes to gather the data to display. First, tshark is invoked with the '-z' option to generate the reassembled stream information. Termshark knows the protocol and stream index to supply to tshark because it saves this information when processing the PDML to populate the packet structure view:

```console
tshark -r my.pcap -q -z follow,tcp,raw,15
```

This means "follow TCP stream number 15". The output will look something like:

```console
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 15
Node 0: 192.168.0.114:1137
Node 1: 192.168.0.193:21
        3232302043687269732053616e6465727320465450205365727665720d0a
55534552206373616e646572730d0a
        3333312050617373776f726420726571756972656420666f72206373616e646572732e0d0a
...
```

A second tshark process is started concurrently:

```console
tshark -T pdml -r my.pcap -Y "tcp.stream eq 15"
```

The output of that is parsed to build an array mapping the index of each "chunk" of the stream (e.g. above, 0 is "3232", 1 is "5553", 2 is "3333") to the index of the corresponding packet. This is not always x->x because the stream payloads for some packets are of zero length and are not represented in the output from the first tshark '-z' process. The mapping is used when the user clicks on a chunk of the reassembled stream in the UI - termshark will then change focus behind the scenes to the corresponding packet in the packet list view. If you exit the stream reassembly UI, you can see the newly selected packet. 

When termshark starts these stream reassembly processes, it also sets a display filter in the main UI e.g. "tcp.stream eq 15". This causes termshark to invoke the PSML and PDML processes again - in addition to the two stream-reassembly-specific processes that I've just described.

Finally, termshark uses tshark in one more way - to generate the possible completions for prefixes of display filter terms. If you type ```tcp.``` in the filter widget, termshark will show a drop-down menu of possible completions. This is generated once at startup by running

```bash
termshark -G fields
```
then parsing the output into a nested collection of Go maps, and serializing it to ```$XDG_CONFIG_CACHE/tsharkfieldsv2.gob.gz```.

## Termshark is laggy or using a lot of RAM

I hope this is much-improved with v2. If you still experience problems, try running termshark with the ```--debug``` flag e.g.

```bash
termshark --debug -r foo.pcap
```

You can then generate a CPU profile with

```bash
pkill -SIGUSR1 termshark
```

or a heap/memory profile with 

```bash
pkill -SIGUSR2 termshark
```

The profiles are stored under `$XDG_CONFIG_CACHE` (e.g. ~/.cache/termshark/). You can investigate with `go tool pprof` like this:

```bash
go tool pprof -http=:6061 $(which termshark) ~/.cache/termshark/mem-20190929122218.prof
```

and then navigate to http://127.0.0.1:6061/ui/ (or remote IP) - or open a termshark issue and upload the profile for us to check :-)

There will also be a debug web server running at http://127.0.0.1:6060/debug/pprof (or rmote IP) from where you can see running goroutines and other information.

## How much memory does termshark use?

It's hard to be precise, but I can provide some rough numbers. Termshark uses memory for two things:

- for each packet in the whole pcap, a subsection of the PSML (XML) for that packet
- in groups of 1000 (by default), loaded on demand, a subsection of the PDML (XML) for each packet in the group.

See [this question](FAQ.md#if-i-load-a-big-pcap-termshark-doesnt-load-all-the-packets-at-once---why) for more information on the on-demand loading.

Using a sequence of pcaps with respectively 100000, 200000, 300000 and 400000 packets, I can see termshark v2 (on linux) adds about 100 MB of VM space and about 50MB of RSS (resident set size) per 100000 packets - with only PSML loaded. As you scroll through the pcap, each 1000 packet boundary causes a load of 1000 PDML elements from tshark. Each extra 1000 packets increases RSS by about 30MB. This is about an 80% improvement over termshark v1 - accomplished by simply compressing the serialized representation in RAM.

## What is the oldest supported version of tshark?

As much as possible, I want termshark to work "right out of the box", and to me that meant not requiring the user to have to update tshark. On Linux I have successfully tested termshark with tshark versions back to git tag v1.11.0; but v1.10.0 failed to display the hex view. I didn't debug further. So v1.11.0 is the oldest supported version of tshark. Wireshark v1.11.0 was released in October 2013.

## What's next?

Termshark v2 implemented stream reassembly, a "What's next" feature from v1. For Termshark v3, some possibilities are:

- Show pcap statistics, conversation statics, etc - expose all tshark's ```-z``` options
- Colorize the packets in the packet list view using Wireshark's coloring rules
- Better navigation of the UI with the keyboard e.g. VIM-style commands!
- Allow the user to start reading from available interfaces once the UI has started
- And since tshark can be customized via the TOML config file, don't be so trusting of its output - there are surely bugs lurking here


