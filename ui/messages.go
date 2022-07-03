// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"
	"io"
	"log"
	"sync"
	"text/template"

	"github.com/blang/semver"
	"github.com/gcla/termshark/v2"
	"github.com/jessevdk/go-flags"
)

//======================================================================

// For fixing off-by-one errors in packet marks - NOT NEEDED now
var funcMap = template.FuncMap{
	"inc": func(i int) int {
		return i + 1
	},
}

var TemplateData map[string]interface{}

var Templates = template.Must(template.New("Help").Funcs(funcMap).Parse(`
{{define "NameVer"}}termshark {{.Version}}{{end}}
{{define "TsharkVer"}}using tshark {{.TsharkVersion}} (from {{.TsharkAbsolutePath}}){{end}}

{{define "OneLine"}}A wireshark-inspired terminal user interface for tshark. Analyze network traffic interactively from your terminal.{{end}}

{{define "Header"}}{{template "NameVer" .}}

{{template "OneLine"}}
See https://termshark.io for more information.{{end}}

{{define "Footer"}}
If --pass-thru is true (or auto, and stdout is not a tty), tshark will be
executed with the supplied command-line flags. You can provide
tshark-specific flags and they will be passed through to tshark (-n, -d, -T,
etc). For example:

$ termshark -r file.pcap -T psml -n | less{{end}}

{{define "UIUserGuide"}}{{.UserGuideURL}}

{{.CopyCommandMessage}}{{end}}

{{define "UIFAQ"}}{{.FAQURL}}

{{.CopyCommandMessage}}{{end}}

{{define "UIBug"}}{{.BugURL}}

{{.CopyCommandMessage}}{{end}}

{{define "UIFeature"}}{{.FeatureURL}}

{{.CopyCommandMessage}}{{end}}

{{define "UIHelp"}}{{template "NameVer" .}}

A wireshark-inspired tui for tshark. Analyze network traffic interactively from your terminal.

/__ - Go to display filter/stream search
q__ - Quit
tab - Switch panes
c__ - Switch to copy-mode
|__ - Cycle through pane layouts
\__ - Toggle pane zoom
esc - Activate menu
+/- - Adjust horizontal split
</> - Adjust vertical split
:__ - Activate cmdline mode (see help cmdline)
z__ - Maximize/restore any modal dialog
?__ - Display help

In the filter, type a wireshark display filter expression.

Most terminals will support using the mouse! Try clicking the Close button.

Use shift-left-mouse to copy and shift-right-mouse to paste.{{end}}

{{define "VimHelp"}}{{template "NameVer" .}}

Navigate the UI using vim-style keys.

hjkl___ - Move left/down/up/right in various views
gg_____ - Go to the top of the current table
G______ - Go to the bottom of the current table
5gg____ - Go to the 5th row of the table
C-w C-w - Switch panes (same as tab)
C-w_=__ - Equalize pane spacing
ma_____ - Mark current packet (use a through z)
'a_____ - Jump to packet marked 'a'
mA_____ - Mark current packet + pcap (use A through Z)
'A_____ - Jump to packet + pcap marked 'A'
''_____ - After a jump; jump back to prior packet
ZZ_____ - Quit without confirmation

See also help cmdline.{{end}}

{{define "CmdLineHelp"}}{{template "NameVer" .}}

Activate cmdline mode with the : key.

Hit tab to see and choose possible completions.

capinfo______ - Capture file properties
clear-filter_ - Clear the display filter and apply
clear-packets - Clear the current pcap
columns______ - Choose the columns to display
config_______ - Show termshark's config file (Unix-only)
convs________ - Open conversations view
filter_______ - Choose a display filter from recently-used
help_________ - Various help dialogs
load_________ - Load a pcap from the filesystem
logs_________ - Show termshark's log file (Unix-only)
map__________ - Map a keypress to a key sequence (see help map)
marks________ - Show file-local and global packet marks
menu_________ - Open the UI Misc menu
no-theme_____ - Clear theme for the current terminal color mode
profile______ - Profile actions - create, use, delete, etc
quit_________ - Quit termshark
recents______ - Load a pcap from those recently-used
set__________ - Set various config properties (see help set)
streams______ - Open stream reassembly view
theme________ - Choose a theme for the current terminal color mode
unmap________ - Remove a keypress mapping
wormhole_____ - Prepare to transfer the current pcap{{end}}

{{define "SetHelp"}}{{template "NameVer" .}}

Use the cmdline set command to change configuration.

Type :set and hit tab for options.

auto-scroll___________ - scroll during live captures
copy-timeout__________ - wait this long before failing a copy
dark-mode_____________ - enable or disable dark-mode
disable-shark-fin_____ - switch off the secret shark fin
packet-colors_________ - use colors in the packet list view
pager_________________ - pager (used for termshark's log file)
nopager_______________ - disable the pager (use PAGER instead)
suppress-tshark-errors - don't show tshark errors in the UI
term__________________ - make termshark assume this terminal type
noterm________________ - disable the terminal type (use TERM){{end}}

{{define "MapHelp"}}{{template "NameVer" .}}

Use the cmdline map command to set key macros e.g.

map <f1> ZZ       - hit f1 key to quit

Use vim-style syntax for key-presses. Printable characters
represent themselves. Compound keys can be:

<space>
<esc>
<enter>
<f1>-<f12>
<C-s>, <A-/>
<up>, <down>, <left>, <right>
<pgup>, <pgdn>
<home>, <end>

Use the unmap command to remove a mapping.{{end}}

{{define "CopyModeHelp"}}{{template "NameVer" .}}

termshark is in copy-mode. You can press:

'q', 'c' - Exit copy-mode
ctrl-c__ - Copy from selected widget
left____ - Widen selection
right___ - Narrow selection
'?'_____ - Display copy-mode help
{{end}}

{{define "Marks"}}{{if not .Marks}}No local marks are set{{else}}Mark Packet Summary{{range $key, $value := .Marks }}
{{printf " %c" $key}}{{printf "%6d" $value.Pos}}    {{printf "%s" $value.Summary}}{{end}}{{end}}

{{if not .GlobalMarks}}No cross-file marks are set{{else}}Mark Packet  File              Summary{{range $key, $value := .GlobalMarks }}
{{printf " %-4c" $key}} {{printf "%-7d" $value.Pos}}{{printf "%-18s" $value.Base}}{{printf "%s" $value.Summary}}{{end}}{{end}}{{end}}

{{define "Key Mappings"}}{{if .Maps.None}}No key mappings are set{{else}}  From          To   {{range $mapping := .Maps.Get }}
{{printf "  %-14v" $mapping.From}}{{printf "%v" $mapping.To}}   {{end}}{{end}}

{{end}}
`))

//======================================================================

var DoOnce sync.Once

func EnsureTemplateData() {
	DoOnce.Do(func() {
		TemplateData = make(map[string]interface{})
	})
}

func init() {
	EnsureTemplateData()
	TemplateData["Version"] = termshark.Version
	TemplateData["FAQURL"] = termshark.FAQURL
	TemplateData["UserGuideURL"] = termshark.UserGuideURL
	TemplateData["BugURL"] = termshark.BugURL
	TemplateData["FeatureURL"] = termshark.FeatureURL
}

func WriteHelp(p *flags.Parser, w io.Writer) {
	if err := Templates.ExecuteTemplate(w, "Header", TemplateData); err != nil {
		log.Fatal(err)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w)
	p.WriteHelp(w)

	if err := Templates.ExecuteTemplate(w, "Footer", TemplateData); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)
}

func WriteVersion(p *flags.Parser, w io.Writer) {
	if err := Templates.ExecuteTemplate(w, "NameVer", TemplateData); err != nil {
		log.Fatal(err)
	}

	fmt.Fprintln(w)
}

func WriteTsharkVersion(p *flags.Parser, bin string, ver semver.Version, w io.Writer) {
	TemplateData["TsharkVersion"] = ver.String()
	TemplateData["TsharkAbsolutePath"] = bin
	if err := Templates.ExecuteTemplate(w, "TsharkVer", TemplateData); err != nil {
		log.Fatal(err)
	}

	fmt.Fprintln(w)
}

func WriteMarks(p *flags.Parser, marks map[rune]int, w io.Writer) {
	if err := Templates.ExecuteTemplate(w, "Marks", TemplateData); err != nil {
		log.Fatal(err)
	}

	fmt.Fprintln(w)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
