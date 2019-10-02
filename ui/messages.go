// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import "text/template"

//======================================================================

var Templates = template.Must(template.New("Help").Parse(`
{{define "NameVer"}}termshark {{.Version}}{{end}}
{{define "TsharkVer"}}using tshark {{.TsharkVersion}} (from {{.TsharkAbsolutePath}}){{end}}

{{define "OneLine"}}A wireshark-inspired terminal user interface for tshark. Analyze network traffic interactively from your terminal.{{end}}

{{define "Header"}}{{template "NameVer" .}}

{{template "OneLine"}}
See https://termshark.io for more information.{{end}}

{{define "Footer"}}
If --pass-thru is true (or auto, and stdout is not a tty), tshark will be
executed with the supplied command- line flags. You can provide
tshark-specific flags and they will be passed through to tshark (-n, -d, -T,
etc). For example:

$ termshark -r file.pcap -T psml -n | less{{end}}

{{define "UIUserGuide"}}{{.UserGuideURL}}

{{.CopyCommandMessage}}{{end}}

{{define "UIFAQ"}}{{.FAQURL}}

{{.CopyCommandMessage}}{{end}}

{{define "UIHelp"}}{{template "NameVer" .}}

A wireshark-inspired tui for tshark. Analyze network traffic interactively from your terminal.

'/'   - Go to display filter
'q'   - Quit
'tab' - Switch panes
'c'   - Switch to copy-mode
'|'   - Cycle through pane layouts
'\'   - Toggle pane zoom
'esc' - Activate menu
't'   - In bytes view, switch hex ⟷ ascii
'+/-' - Adjust horizontal split
'</>' - Adjust vertical split
'?'   - Display help

In the filter, type a wireshark display filter expression.

Most terminals will support using the mouse! Try clicking the Close button.

Use shift-left-mouse to copy and shift-right-mouse to paste.{{end}}

{{define "CopyModeHelp"}}{{template "NameVer" .}}

termshark is in copy-mode. You can press:

'q', 'c' - Exit copy-mode
ctrl-c   - Copy from selected widget
left     - Widen selection
right    - Narrow selection{{end}}
'?'      - Display copy-mode help
`))

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
