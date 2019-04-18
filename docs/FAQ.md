
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

## Can I run termshark on Android?

Yes, through the amazing termux package. Here are the steps:

- Install [Termux](https://play.google.com/store/apps/details?id=com.termux&hl=en_US) and [Termux:API](https://play.google.com/store/apps/details?id=com.termux.api&hl=en_US) through the Google Play Store
- Run termux and type
```bash
pkg update
pkg install termux-api
```
- Now you need to install tshark. Get the termux X11 packages first:
```bash
pkg install x11-repo
pkg install tshark
```
- Finally, copy the termshark Android binary to somewhere in your termux ```PATH```. 

## If I load a big pcap, termshark doesn't load all the packets at once - why?

Termshark cheats. When you give it a pcap, it generates PSML XML for every packet, but not the complete PDML (packet structure) XML. If you run ```time tshark -T pdml -r huge.pcap > /dev/null```  you'll see it can take many minutes to complete. So rather than generating PDML for the entire pcap file, termshark generates PDML in 1000 packet chunks (by default). It will always prioritize packets that are in view or could soon be in view, so that the user isn't kept waiting. Now, if you open a large pcap, and - once the packet list is complete - hit `end`, you would want to be able to see the structure of packets at the end of the pcap. If termshark generated the PDML in one shot, the user could be kept waiting many minutes to see the end, while tshark chugs through the file emitting data. So to display the data more quickly, termshark runs something like
```bash
tshark -T pdml -r huge.pcap -Y 'frame.number >= 12340000 and frame.number < 12341000'
```
tshark is able to seek through the pcap much more quickly when it doesn't have to generate PDML - so this results in termshark getting data back to the user much more rapidly. 

If you start to page up quickly, you will likely approach a range of packets that termshark hasn't loaded, and it will have to issue another tshark command to fetch the data. Termshark launches the tshark command before those unloaded packets come into view but there's room here for more sophistication. One problem with this approach is that if you sort the packet list by a field like source IP, then moving up or down one packet may result in needing to display the structure and bytes for a packet many thousands of packets away from the current one ordered by time - so termshark might kick off a new  ```-T pdml``` command for each up or down movement, meaning termshark will continually display "Loading..."

## Termshark's colors are limited...

Termshark respects the ```TERM``` environment variable and chooses a color scheme based on what it thinks the terminal is capable of, via the excellent [tcell](https://github.com/gdamore/tcell) package. You might be running on a terminal that can display more colors than ```TERM``` reports - so you can try adjusting your ```TERM``` variable e.g. if ```TERM``` is ```xterm```, try

```bash
export TERM=xterm-256color
```

or even

```bash
export TERM=xterm-truecolor
```
then re-run termshark.

tcell makes use of the environment variable ```COLORTERM``` when determining how to emit color codes. If ```COLORTERM``` is set to ```truecolor```, then tcell will emit truecolor color codes when the application changes the foreground or background color. If you connect to a remote machine with ssh to run termshark, the ```COLORTERM``` variable will not be forwarded. If that leaves you with ```TERM=xterm``` for example, then termshark, via tcell, will fall back to 8-color support. Here again you can change ```TERM``` or add a setting for ```COLORTERM``` to your remote ```.bashrc``` file.

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

Finally, termshark uses tshark in one more way - to generate the possible completions for prefixes of display filter terms. If you type ```tcp.``` in the filter widget, termshark will show a drop-down menu of possible completions. This is generated once at startup by running

```bash
termshark -G fields
```
then parsing the output into a nested collection of Go maps, and serializing it to ```$XDG_CONFIG_CACHE/tsharkfields.gob.gz```. 

## What's next?

There are many obvious ways to extend termshark, just based on the long list of tshark capabilities. I'd like to be able to:

- Select a packet and display the reassembled stream
- Show pcap statistics, conversation statics, etc - expose all tshark's ```-z``` options
- Colorize the packets in the packet list view using Wireshark's coloring rules
- Allow the user to start reading from available interfaces once the UI has started
- And since tshark can be customized via the TOML config file, don't be so trusting of its output - there are surely bugs lurking here

But I drew the line here for v1.0 in order to ship something!

