// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package wiresharkcfg

import (
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgConv(t *testing.T) {
	inp1 := `
# Configuration file for Wireshark 3.2.3.
#
# This file is regenerated each time preferences are saved within
# Wireshark. Making manual changes should be safe, however.
# Preferences that have been commented out have not been
# changed from their default value.

####### User Interface ########

# Open a console window (Windows only)
# One of: NEVER, AUTOMATIC, ALWAYS
# (case-insensitive).
#gui.console_open: NEVER

# Restore current display filter after following a stream?
# TRUE or FALSE (case-insensitive)
#gui.restore_filter_after_following_stream: FALSE

# Where to start the File Open dialog box
# One of: LAST_OPENED, SPECIFIED
# (case-insensitive).
#gui.fileopen.style: LAST_OPENED

# The max. number of items in the open recent files list
# A decimal number
#gui.recent_files_count.max: 10

# The max. number of entries in the display filter list
# A decimal number
#gui.recent_display_filter_entries.max: 10

# Directory to start in when opening File Open dialog.
# A path to a directory
#gui.fileopen.dir: 

# The preview timeout in the File Open dialog
# A decimal number
#gui.fileopen.preview: 3

# Ask to save unsaved capture files?
# TRUE or FALSE (case-insensitive)
#gui.ask_unsaved: TRUE

# Display an autocomplete suggestion for display and capture filter controls
# TRUE or FALSE (case-insensitive)
#gui.autocomplete_filter: TRUE

# Wrap to beginning/end of file during search?
# TRUE or FALSE (case-insensitive)
#gui.find_wrap: TRUE

# Save window position at exit?
# TRUE or FALSE (case-insensitive)
#gui.geometry.save.position: TRUE

# Save window size at exit?
# TRUE or FALSE (case-insensitive)
#gui.geometry.save.size: TRUE

# Save window maximized state at exit?
# TRUE or FALSE (case-insensitive)
#gui.geometry.save.maximized: TRUE

# Main Toolbar style
# One of: ICONS, TEXT, BOTH
# (case-insensitive).
#gui.toolbar_main_style: ICONS

# Check for updates (Windows and macOS only)
# TRUE or FALSE (case-insensitive)
#gui.update.enabled: TRUE

# The type of update to fetch. You should probably leave this set to STABLE.
# One of: DEVELOPMENT, STABLE
# (case-insensitive).
#gui.update.channel: STABLE

# How often to check for software updates in seconds
# A decimal number
#gui.update.interval: 86400

# Custom window title to be appended to the existing title
# %F = file path of the capture file
# %P = profile name
# %S = a conditional separator (" - ") that only shows when surrounded by variables with values or static text
# %V = version info
# A string
#gui.window_title: 

# Custom window title to be prepended to the existing title
# %F = file path of the capture file
# %P = profile name
# %S = a conditional separator (" - ") that only shows when surrounded by variables with values or static text
# %V = version info
# A string
#gui.prepend_window_title: 

# Custom start page title
# A string
#gui.start_title: The World's Most Popular Network Protocol Analyzer

# Show version in the start page and/or main screen's title bar
# One of: WELCOME, TITLE, BOTH, NEITHER
# (case-insensitive).
#gui.version_placement: BOTH

# The maximum number of objects that can be exported
# A decimal number
#gui.max_export_objects: 1000

# Enable Packet Editor (Experimental)
# TRUE or FALSE (case-insensitive)
#gui.packet_editor.enabled: FALSE

# The position of "..." in packet list text.
# One of: LEFT, RIGHT, MIDDLE, NONE
# (case-insensitive).
#gui.packet_list_elide_mode: RIGHT

# Show all interfaces, including interfaces marked as hidden
# TRUE or FALSE (case-insensitive)
#gui.interfaces_show_hidden: FALSE

# Show remote interfaces in the interface selection
# TRUE or FALSE (case-insensitive)
#gui.interfaces_remote_display: TRUE

# Hide the given interface types in the startup list.
# A comma-separated string of interface type values (e.g. 5,9).
# 0 = Wired,
# 1 = AirPCAP,
# 2 = Pipe,
# 3 = STDIN,
# 4 = Bluetooth,
# 5 = Wireless,
# 6 = Dial-Up,
# 7 = USB,
# 8 = External Capture,
# 9 = Virtual
# A string
#gui.interfaces_hidden_types: 

####### User Interface: Colors ########

# Foregound color for an active selected item
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.active_frame.fg: 000000

# Background color for an active selected item
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.active_frame.bg: cbe8ff

# Color style for an active selected item
# One of: DEFAULT, FLAT, GRADIENT
# (case-insensitive).
#gui.active_frame.style: DEFAULT

# Foregound color for an inactive selected item
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.inactive_frame.fg: 000000

# Background color for an inactive selected item
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.inactive_frame.bg: efefef

# Color style for an inactive selected item
# One of: DEFAULT, FLAT, GRADIENT
# (case-insensitive).
#gui.inactive_frame.style: DEFAULT

# Color preferences for a marked frame
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.marked_frame.fg: ffffff

# Color preferences for a marked frame
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.marked_frame.bg: 00202a

# Color preferences for a ignored frame
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.ignored_frame.fg: 7f7f7f

# Color preferences for a ignored frame
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.ignored_frame.bg: ffffff

# TCP stream window color preference
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.stream.client.fg: 7f0000

# TCP stream window color preference
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.stream.client.bg: fbeded

# TCP stream window color preference
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.stream.server.fg: 00007f

# TCP stream window color preference
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.stream.server.bg: ededfb

# Valid color filter background
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.color_filter_bg.valid: afffaf

# Invalid color filter background
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.color_filter_bg.invalid: ffafaf

# Deprecated color filter background
# A six-digit hexadecimal RGB color triplet (e.g. fce94f)
#gui.color_filter_bg.deprecated: ffffaf

####### User Interface: Columns ########

# Packet list hidden columns
# List all columns to hide in the packet list.
gui.column.hidden: %Yut,%Cus:ip.flags:0:R

# Packet list column format
# Each pair of strings consists of a column title and its format
gui.column.format: 
	"No.", "%m",
	"Time", "%t",
	"Source", "%s",
	"Destination", "%d",
	"Protocol", "%p",
	"Length", "%L",
	"Info", "%i",
	"gcla1", "%Yut",
	"Flags", "%Cus:ip.flags:0:R",
	"Authority RRs", "%Cus:nbns.count.auth_rr:0:R"

####### User Interface: Font ########

# Font name for packet list, protocol tree, and hex dump panes. (Qt)
# A string
gui.qt.font_name: Liberation Mono,11,-1,5,50,0,0,0,0,0

####### User Interface: Layout ########

# Layout type (1-6)
# A decimal number
#gui.layout_type: 1

# Layout content of the pane 1
# One of: NONE, PLIST, PDETAILS, PBYTES
# (case-insensitive).
#gui.layout_content_1: PLIST

# Layout content of the pane 2
# One of: NONE, PLIST, PDETAILS, PBYTES
# (case-insensitive).
#gui.layout_content_2: PDETAILS

# Layout content of the pane 3
# One of: NONE, PLIST, PDETAILS, PBYTES
# (case-insensitive).
#gui.layout_content_3: PBYTES

# Enable Packet List Separator
# TRUE or FALSE (case-insensitive)
#gui.packet_list_separator.enabled: FALSE

# Show column definition in packet list header
# TRUE or FALSE (case-insensitive)
#gui.packet_header_column_definition.enabled: TRUE

# Show selected packet in the Status Bar
# TRUE or FALSE (case-insensitive)
#gui.show_selected_packet.enabled: FALSE

# Show file load time in the Status Bar
# TRUE or FALSE (case-insensitive)
#gui.show_file_load_time.enabled: FALSE

# Show related packet indicators in the first column
# TRUE or FALSE (case-insensitive)
#gui.packet_list_show_related: TRUE

# Show the intelligent scroll bar (a minimap of packet list colors in the scrollbar)
# TRUE or FALSE (case-insensitive)
#gui.packet_list_show_minimap: TRUE

####### Capture ########

# Default capture device
# A string
#capture.device: 

# Interface link-layer header types (Ex: en0(1),en1(143),...)
# A string
#capture.devices_linktypes: 

# Interface descriptions (Ex: eth0(eth0 descr),eth1(eth1 descr),...)
# A string
#capture.devices_descr: 

# Hide interface? (Ex: eth0,eth3,...)
# A string
#capture.devices_hide: 

# By default, capture in monitor mode on interface? (Ex: eth0,eth3,...)
# A string
#capture.devices_monitor_mode: 

# Interface buffer size (Ex: en0(1),en1(143),...)
# A string
#capture.devices_buffersize: 

# Interface snap length (Ex: en0(65535),en1(1430),...)
# A string
#capture.devices_snaplen: 

# Interface promiscuous mode (Ex: en0(0),en1(1),...)
# A string
#capture.devices_pmode: 

# Capture in promiscuous mode?
# TRUE or FALSE (case-insensitive)
#capture.prom_mode: TRUE

# Interface capture filter (Ex: en0(tcp),en1(udp),...)
# A string
#capture.devices_filter: 

# Capture in pcapng format?
# TRUE or FALSE (case-insensitive)
#capture.pcap_ng: TRUE

# Update packet list in real time during capture?
# TRUE or FALSE (case-insensitive)
#capture.real_time_update: TRUE

# Don't automatically load capture interfaces on startup
# TRUE or FALSE (case-insensitive)
#capture.no_interface_load: FALSE

# Disable external capture modules (extcap)
# TRUE or FALSE (case-insensitive)
#capture.no_extcap: FALSE

# Scroll packet list during capture?
# TRUE or FALSE (case-insensitive)
#capture.auto_scroll: TRUE

# Show capture information dialog while capturing?
# TRUE or FALSE (case-insensitive)
#capture.show_info: FALSE

# Column list
# List of columns to be displayed in the capture options dialog.
# Possible values: INTERFACE, LINK, PMODE, SNAPLEN, MONITOR, BUFFER, FILTER
# 
#capture.columns: 
#	"INTERFACE", "LINK",
#	"PMODE", "SNAPLEN",
#	"MONITOR", "BUFFER",
#	"FILTER"

####### Console ########

# Log level
# Console log level (for debugging)
# A bitmask of log levels:
# ERROR    = 4
# CRITICAL = 8
# WARNING  = 16
# MESSAGE  = 32
# INFO     = 64
# DEBUG    = 128
#console.log.level: 28

# Look for dissectors that left some bytes undecoded (debug)
# TRUE or FALSE (case-insensitive)
#console.incomplete_dissectors_check_debug: FALSE

####### Extcap Utilities ########

# Save arguments on start of capture
# TRUE or FALSE (case-insensitive)
#extcap.gui_save_on_start: TRUE

# Remote SSH server address
# A string
#extcap.sshdump.remotehost: 

# Remote SSH server port
# A string
#extcap.sshdump.remoteport: 

# Remote SSH server username
# A string
#extcap.sshdump.remoteusername: 

# Path to SSH private key
# A string
#extcap.sshdump.sshkey: 

# ProxyCommand
# A string
#extcap.sshdump.proxycommand: 

# Remote interface
# A string
#extcap.sshdump.remoteinterface: 

# Remote capture command
# A string
#extcap.sshdump.remotecapturecommand: 

# Use sudo on the remote machine
# A string
#extcap.sshdump.remotesudo: 

# No promiscuous mode
# A string
#extcap.sshdump.remotenoprom: 

# Remote capture filter
# A string
#extcap.sshdump.remotefilter: not ((host fe80::159e:3034:7984:2edc or host fe80::222d:65ae:e2c3:1120 or host fe80::42:6bff:fe9e:b8df or host 172.16.0.1 or host 10.6.14.98 or host 192.168.86.28 or host 10.225.13.1 or host 172.18.0.1 or host 172.17.0.1 or host 172.19.0.1) and port 22)

# Packets to capture
# A string
#extcap.sshdump.remotecount: 0

# Run in debug mode
# A string
#extcap.sshdump.debug: false

# Use a file for debug
# A string
#extcap.sshdump.debugfile: 

# Remote SSH server address
# A string
#extcap.ciscodump.remotehost: 

# Remote SSH server port
# A string
#extcap.ciscodump.remoteport: 22

# Remote SSH server username
# A string
#extcap.ciscodump.remoteusername: gcla

# Path to SSH private key
# A string
#extcap.ciscodump.sshkey: 

# ProxyCommand
# A string
#extcap.ciscodump.proxycommand: 

# Remote interface
# A string
#extcap.ciscodump.remoteinterface: 

# Remote capture filter
# A string
#extcap.ciscodump.remotefilter: deny tcp host fe80::159e:3034:7984:2edc any eq 0, deny tcp any eq 0 host fe80::159e:3034:7984:2edc, deny tcp host fe80::222d:65ae:e2c3:1120 any eq 0, deny tcp any eq 0 host fe80::222d:65ae:e2c3:1120, deny tcp host fe80::42:6bff:fe9e:b8df any eq 0, deny tcp any eq 0 host fe80::42:6bff:fe9e:b8df, deny tcp host 172.16.0.1 any eq 0, deny tcp any eq 0 host 172.16.0.1, deny tcp host 10.6.14.98 any eq 0, deny tcp any eq 0 host 10.6.14.98, deny tcp host 192.168.86.28 any eq 0, deny tcp any eq 0 host 192.168.86.28, deny tcp host 10.225.13.1 any eq 0, deny tcp any eq 0 host 10.225.13.1, deny tcp host 172.18.0.1 any eq 0, deny tcp any eq 0 host 172.18.0.1, deny tcp host 172.17.0.1 any eq 0, deny tcp any eq 0 host 172.17.0.1, deny tcp host 172.19.0.1 any eq 0, deny tcp any eq 0 host 172.19.0.1, permit ip any any

# Packets to capture
# A string
#extcap.ciscodump.remotecount: 

# Run in debug mode
# A string
#extcap.ciscodump.debug: false

# Use a file for debug
# A string
#extcap.ciscodump.debugfile: 

# Interface index
# A string
#extcap.dpauxmon.interface_id: 0

# Run in debug mode
# A string
#extcap.dpauxmon.debug: false

# Use a file for debug
# A string
#extcap.dpauxmon.debugfile: 

# Max bytes in a packet
# A string
#extcap.randpkt.maxbytes: 5000

# Number of packets
# A string
#extcap.randpkt.count: 1000

# Packet delay (ms)
# A string
#extcap.randpkt.delay: 0

# Random type
# A string
#extcap.randpkt.randomtype: false

# All random packets
# A string
#extcap.randpkt.allrandom: false

# Type of packet
# A string
#extcap.randpkt.type: 

# Run in debug mode
# A string
#extcap.randpkt.debug: false

# Use a file for debug
# A string
#extcap.randpkt.debugfile: 

# Listen port
# A string
#extcap.udpdump.port: 5555

# Payload type
# A string
#extcap.udpdump.payload: data

# Run in debug mode
# A string
#extcap.udpdump.debug: false

# Use a file for debug
# A string
#extcap.udpdump.debugfile: 

# Starting position
# A string
#extcap.sdjournal.startfrom: 

# Run in debug mode
# A string
#extcap.sdjournal.debug: false

# Use a file for debug
# A string
#extcap.sdjournal.debugfile: 

####### Name Resolution ########

# Resolve Ethernet MAC addresses to host names from the preferences or system's Ethers file, or to a manufacturer based name.
# TRUE or FALSE (case-insensitive)
#nameres.mac_name: TRUE

# Resolve TCP/UDP ports into service names
# TRUE or FALSE (case-insensitive)
#nameres.transport_name: FALSE

# Resolve IPv4, IPv6, and IPX addresses into host names. The next set of check boxes determines how name resolution should be performed. If no other options are checked name resolution is made from Wireshark's host file and capture file name resolution blocks.
# TRUE or FALSE (case-insensitive)
#nameres.network_name: FALSE

# Whether address/name pairs found in captured DNS packets should be used by Wireshark for name resolution.
# TRUE or FALSE (case-insensitive)
#nameres.dns_pkt_addr_resolution: TRUE

# Use your system's configured name resolver (usually DNS) to resolve network names. Only applies when network name resolution is enabled.
# TRUE or FALSE (case-insensitive)
#nameres.use_external_name_resolver: TRUE

# Uses DNS Servers list to resolve network names if TRUE.  If FALSE, default information is used
# TRUE or FALSE (case-insensitive)
#nameres.use_custom_dns_servers: FALSE

# The maximum number of DNS requests that may be active at any time. A large value (many thousands) might overload the network or make your DNS server behave badly.
# A decimal number
#nameres.name_resolve_concurrency: 500

# By default "hosts" files will be loaded from multiple sources. Checking this box only loads the "hosts" in the current profile.
# TRUE or FALSE (case-insensitive)
#nameres.hosts_file_handling: FALSE

# Resolve VLAN IDs to network names from the preferences "vlans" file. Format of the file is: "ID<Tab>Name". One line per VLAN, e.g.: 1 Management
# TRUE or FALSE (case-insensitive)
#nameres.vlan_name: FALSE

# Resolve SS7 Point Codes to node names from the profiles "ss7pcs" file. Format of the file is: "Network_Indicator<Dash>PC_Decimal<Tab>Name". One line per Point Code, e.g.: 2-1234 MyPointCode1
# TRUE or FALSE (case-insensitive)
#nameres.ss7_pc_name: FALSE

# Resolve Object IDs to object names from the MIB and PIB modules defined below. You must restart Wireshark for this change to take effect
# TRUE or FALSE (case-insensitive)
#nameres.load_smi_modules: FALSE

# While loading MIB or PIB modules errors may be detected, which are reported. Some errors can be ignored. If unsure, set to false.
# TRUE or FALSE (case-insensitive)
#nameres.suppress_smi_errors: FALSE

####### Protocols ########

# Display all hidden protocol items in the packet list.
# TRUE or FALSE (case-insensitive)
#protocols.display_hidden_proto_items: FALSE

# Display all byte fields with a space character between each byte in the packet list.
# TRUE or FALSE (case-insensitive)
#protocols.display_byte_fields_with_spaces: FALSE

# Look for dissectors that left some bytes undecoded.
# TRUE or FALSE (case-insensitive)
#protocols.enable_incomplete_dissectors_check: FALSE

# Protocols may use things like VLAN ID or interface ID to narrow the potential for duplicate conversations.Currently only ICMP and ICMPv6 use this preference to add VLAN ID to conversation tracking
# TRUE or FALSE (case-insensitive)
#protocols.strict_conversation_tracking_heuristics: FALSE

# Use a registered heuristic sub-dissector to decode the data payload
# TRUE or FALSE (case-insensitive)
#lbmc.use_heuristic_subdissectors: TRUE

# Reassemble data message fragments
# TRUE or FALSE (case-insensitive)
#lbmc.reassemble_fragments: FALSE

# Recognize and dissect payloads containing LBMPDM messages (requires reassembly to be enabled)
# TRUE or FALSE (case-insensitive)
#lbmc.dissect_lbmpdm: FALSE

# Set the low end of the TCP port range
# A decimal number
#lbmpdm_tcp.port_low: 14371

# Set the high end of the port range
# A decimal number
#lbmpdm_tcp.port_high: 14390

# Use table of LBMPDM-TCP tags to decode the packet instead of above values
# TRUE or FALSE (case-insensitive)
#lbmpdm_tcp.use_lbmpdm_tcp_domain: FALSE

# Set the UDP port for incoming multicast topic resolution (context resolver_multicast_incoming_port)
# A decimal number
#lbmr.mc_incoming_port: 12965

# Set the multicast address for incoming multicast topic resolution (context resolver_multicast_incoming_address)
# A string
#lbmr.mc_incoming_address: 224.9.10.11

# Set the UDP port for outgoing multicast topic resolution (context resolver_multicast_outgoing_port)
# A decimal number
#lbmr.mc_outgoing_port: 12965

# Set the multicast address for outgoing multicast topic resolution (context resolver_multicast_outgoing_address)
# A string
#lbmr.mc_outgoing_address: 224.9.10.11

# Set the low UDP port for unicast topic resolution (context resolver_unicast_port_low)
# A decimal number
#lbmr.uc_port_low: 14402

# Set the high UDP port for unicast topic resolution (context resolver_unicast_port_high)
# A decimal number
#lbmr.uc_port_high: 14406

# Set the destination port for unicast topic resolution (context resolver_unicast_destination_port)
# A decimal number
#lbmr.uc_dest_port: 15380

# Set the address of the unicast resolver daemon (context resolver_unicast_address)
# A string
#lbmr.uc_address: 0.0.0.0

# Use table of LBMR tags to decode the packet instead of above values
# TRUE or FALSE (case-insensitive)
#lbmr.use_lbmr_domain: FALSE

# Set the low end of the LBT-RM multicast address range (context transport_lbtrm_multicast_address_low)
# A string
#lbtrm.mc_address_low: 224.10.10.10

# Set the high end of the LBT-RM multicast address range (context transport_lbtrm_multicast_address_high)
# A string
#lbtrm.mc_address_high: 224.10.10.14

# Set the low end of the LBT-RM UDP destination port range (source transport_lbtrm_destination_port)
# A decimal number
#lbtrm.dport_low: 14400

# Set the high end of the LBT-RM UDP destination port range (source transport_lbtrm_destination_port)
# A decimal number
#lbtrm.dport_high: 14400

# Set the low end of the LBT-RM UDP source port range (context transport_lbtrm_source_port_low)
# A decimal number
#lbtrm.sport_low: 14390

# Set the high end of the LBT-RM UDP source port range (context transport_lbtrm_source_port_high)
# A decimal number
#lbtrm.sport_high: 14399

# Set the incoming MIM multicast address (context mim_incoming_address)
# A string
#lbtrm.mim_incoming_address: 224.10.10.21

# Set the outgoing MIM multicast address (context mim_outgoing_address)
# A string
#lbtrm.mim_outgoing_address: 224.10.10.21

# Set the incoming MIM UDP port (context mim_incoming_destination_port)
# A decimal number
#lbtrm.mim_incoming_dport: 14401

# Set the outgoing MIM UDP port (context mim_outgoing_destination_port)
# A decimal number
#lbtrm.mim_outgoing_dport: 14401

# Separate multiple NAKs from a single packet into distinct Expert Info entries
# TRUE or FALSE (case-insensitive)
#lbtrm.expert_separate_naks: FALSE

# Separate multiple NCFs from a single packet into distinct Expert Info entries
# TRUE or FALSE (case-insensitive)
#lbtrm.expert_separate_ncfs: FALSE

# Perform analysis on LBT-RM sequence numbers to determine out-of-order, gaps, loss, etc
# TRUE or FALSE (case-insensitive)
#lbtrm.sequence_analysis: FALSE

# Use table of LBT-RM tags to decode the packet instead of above values
# TRUE or FALSE (case-insensitive)
#lbtrm.use_lbtrm_domain: FALSE

# Set the low end of the LBT-RU source UDP port range (context transport_lbtru_port_low)
# A decimal number
#lbtru.source_port_low: 14380

# Set the high end of the LBT-RU source UDP port range (context transport_lbtru_port_high)
# A decimal number
#lbtru.source_port_high: 14389

# Set the low end of the LBT-RU receiver UDP port range (receiver transport_lbtru_port_low)
# A decimal number
#lbtru.receiver_port_low: 14360

# Set the high end of the LBT-RU receiver UDP port range (receiver transport_lbtru_port_high)
# A decimal number
#lbtru.receiver_port_high: 14379

# Separate multiple NAKs from a single packet into distinct Expert Info entries
# TRUE or FALSE (case-insensitive)
#lbtru.expert_separate_naks: FALSE

# Separate multiple NCFs from a single packet into distinct Expert Info entries
# TRUE or FALSE (case-insensitive)
#lbtru.expert_separate_ncfs: FALSE

# Perform analysis on LBT-RU sequence numbers to determine out-of-order, gaps, loss, etc
# TRUE or FALSE (case-insensitive)
#lbtru.sequence_analysis: FALSE

# Use table of LBT-RU tags to decode the packet instead of above values
# TRUE or FALSE (case-insensitive)
#lbtru.use_lbtru_domain: FALSE

# Set the low end of the LBT-TCP source TCP port range (context transport_tcp_port_low)
# A decimal number
#lbttcp.source_port_low: 14371

# Set the high end of the LBT-TCP source TCP port range (context transport_tcp_port_high)
# A decimal number
#lbttcp.source_port_high: 14390

# Set the low end of the LBT-TCP request TCP port range (context request_tcp_port_low)
# A decimal number
#lbttcp.request_port_low: 14391

# Set the high end of the LBT-TCP request TCP port range (context request_tcp_port_high)
# A decimal number
#lbttcp.request_port_high: 14395

# Set the low end of the LBT-TCP UME Store TCP port range
# A decimal number
#lbttcp.store_port_low: 0

# Set the high end of the LBT-TCP UME Store TCP port range
# A decimal number
#lbttcp.store_port_high: 0

# Use table of LBT-TCP tags to decode the packet instead of above values
# TRUE or FALSE (case-insensitive)
#lbttcp.use_lbttcp_domain: FALSE

# Enable this option to recognise all traffic on RTP dynamic payload type 96 (0x60) as FEC data corresponding to Pro-MPEG Code of Practice #3 release 2
# TRUE or FALSE (case-insensitive)
#2dparityfec.enable: FALSE

# Derive IID from a short 16-bit address according to RFC 4944 (using the PAN ID).
# TRUE or FALSE (case-insensitive)
#6lowpan.rfc4944_short_address_format: FALSE

# Linux kernels before version 4.12 does toggle the Universal/Local bit.
# TRUE or FALSE (case-insensitive)
#6lowpan.iid_has_universal_local_bit: FALSE

# Whether the IPv6 summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#6lowpan.summary_in_tree: TRUE

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context0: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context1: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context2: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context3: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context4: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context5: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context6: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context7: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context8: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context9: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context10: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context11: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context12: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context13: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context14: 

# IPv6 prefix to use for stateful address decompression.
# A string
#6lowpan.context15: 

# Some generators incorrectly indicate long preamble when the preamble was actuallyshort. Always assume short preamble when calculating duration.
# TRUE or FALSE (case-insensitive)
#wlan_radio.always_short_preamble: FALSE

# Some generators timestamp the end of the PPDU rather than the start of the (A)MPDU.
# TRUE or FALSE (case-insensitive)
#wlan_radio.tsf_at_end: TRUE

# Enables an additional panel for navigating through packets
# TRUE or FALSE (case-insensitive)
#wlan_radio.timeline: FALSE

# Radiotap has a bit to indicate whether the FCS is still on the frame or not. Some generators (e.g. AirPcap) use a non-standard radiotap flag 14 to put the FCS into the header.
# TRUE or FALSE (case-insensitive)
#radiotap.bit14_fcs_in_header: FALSE

# Some generators use rates with bit 7 set to indicate an MCS, e.g. BSD. others (Linux, AirPcap) do not.
# TRUE or FALSE (case-insensitive)
#radiotap.interpret_high_rates_as_mcs: FALSE

# Whether to use the FCS bit, assume the FCS is always present, or assume the FCS is never present.
# One of: Use the FCS bit, Assume all packets have an FCS at the end, Assume all packets don't have an FCS at the end
# (case-insensitive).
#radiotap.fcs_handling: Use the FCS bit

# Use ipaccess nanoBTS specific definitions for OML
# One of: ETSI/3GPP TS 12.21, Siemens, ip.access, Ericsson OM2000
# (case-insensitive).
#gsm_abis_oml.oml_dialect: ETSI/3GPP TS 12.21

# Enable Streaming DMX extension dissector (ANSI BSR E1.31)
# TRUE or FALSE (case-insensitive)
#acn.dmx_enable: FALSE

# Display format
# One of: Hex    , Decimal, Percent
# (case-insensitive).
#acn.dmx_display_view: Hex    

# Display zeros instead of dots
# TRUE or FALSE (case-insensitive)
#acn.dmx_display_zeros: FALSE

# Display leading zeros on levels
# TRUE or FALSE (case-insensitive)
#acn.dmx_display_leading_zeros: FALSE

# Display line format
# One of: 20 per line, 16 per line
# (case-insensitive).
#acn.dmx_display_line_format: 20 per line

# Server Port
# A decimal number
#adb_cs.server_port: 5037

# Dissect more detail for framebuffer service
# TRUE or FALSE (case-insensitive)
#adb_service.framebuffer_more_details: FALSE

# Specify if the Data sections of packets should be dissected or not
# TRUE or FALSE (case-insensitive)
#adwin.dissect_data: TRUE

# Include next/previous frame for channel, stream, and term, and other transport sequence analysis.
# TRUE or FALSE (case-insensitive)
#aeron.sequence_analysis: FALSE

# Include stream analysis, tracking publisher and subscriber positions. Requires "Analyze transport sequencing".
# TRUE or FALSE (case-insensitive)
#aeron.stream_analysis: FALSE

# Reassemble fragmented data messages. Requires "Analyze transport sequencing" and "Analyze stream sequencing".
# TRUE or FALSE (case-insensitive)
#aeron.reassemble_fragments: FALSE

# Use a registered heuristic sub-dissector to decode the payload data. Requires "Analyze transport sequencing", "Analyze stream sequencing", and "Reassemble fragmented data".
# TRUE or FALSE (case-insensitive)
#aeron.use_heuristic_subdissectors: FALSE

# Whether the AIM dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#aim.desegment: TRUE

# Whether the LCT header Codepoint field should be considered the FEC Encoding ID of carried object
# TRUE or FALSE (case-insensitive)
#alc.lct.codepoint_as_fec_id: TRUE

# How to decode LCT header extension 192
# One of: Don't decode, Decode as FLUTE extension (EXT_FDT)
# (case-insensitive).
#alc.lct.ext.192: Decode as FLUTE extension (EXT_FDT)

# How to decode LCT header extension 193
# One of: Don't decode, Decode as FLUTE extension (EXT_CENC)
# (case-insensitive).
#alc.lct.ext.193: Decode as FLUTE extension (EXT_CENC)

# Whether persistent call leg information is to be kept
# TRUE or FALSE (case-insensitive)
#alcap.leg_info: TRUE

# Set the TCP port for AMQP over SSL/TLS(if other than the default of 5671)
# A decimal number
#amqp.tls.port: 5671

# The dynamic payload types which will be interpreted as AMR(default 0)
# A string denoting an positive integer range (e.g., "1-20,30-40")
#amr.dynamic.payload.type: 

# The dynamic payload types which will be interpreted as AMR-WB(default 0)
# A string denoting an positive integer range (e.g., "1-20,30-40")
#amr.wb.dynamic.payload.type: 

# Type of AMR encoding of the payload
# One of: RFC 3267 octet aligned, RFC 3267 BW-efficient, AMR IF1, AMR IF2
# (case-insensitive).
#amr.encoding.version: RFC 3267 octet aligned

# The AMR mode
# One of: Narrowband AMR, Wideband AMR
# (case-insensitive).
#amr.mode: Narrowband AMR

# (if other than the default of IOS 4.0.1)
# One of: IS-634 rev. 0, TSB-80, IS-634-A, IOS 2.x, IOS 3.x, IOS 4.0.1, IOS 5.0.1
# (case-insensitive).
#ansi_a_bsmap.global_variant: IOS 4.0.1

# Whether the mobile ID and service options are displayed in the INFO column
# TRUE or FALSE (case-insensitive)
#ansi_a_bsmap.top_display_mid_so: TRUE

# ANSI MAP SSNs to decode as ANSI MAP
# A string denoting an positive integer range (e.g., "1-20,30-40")
#ansi_map.map.ssn: 5-14

# Type of matching invoke/response, risk of mismatch if loose matching chosen
# One of: Transaction ID only, Transaction ID and Source, Transaction ID Source and Destination
# (case-insensitive).
#ansi_map.transaction.matchtype: Transaction ID and Source

# Type of matching invoke/response, risk of mismatch if loose matching chosen
# One of: Transaction ID only, Transaction ID and Source, Transaction ID Source and Destination
# (case-insensitive).
#ansi_tcap.transaction.matchtype: Transaction ID only

# Whether the AOL dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#aol.desegment: TRUE

# Attempt to display common APRS protocol violations correctly
# TRUE or FALSE (case-insensitive)
#aprs.showaprslax: FALSE

# Attempt to detect excessive rate of ARP requests
# TRUE or FALSE (case-insensitive)
#arp.detect_request_storms: FALSE

# Number of requests needed within period to indicate a storm
# A decimal number
#arp.detect_storm_number_of_packets: 30

# Period in milliseconds during which a packet storm may be detected
# A decimal number
#arp.detect_storm_period: 100

# Attempt to detect duplicate use of IP addresses
# TRUE or FALSE (case-insensitive)
#arp.detect_duplicate_ips: TRUE

# Try to resolve physical addresses to host names from ARP requests/responses
# TRUE or FALSE (case-insensitive)
#arp.register_network_address_binding: TRUE

# Select the CAT001 version
# One of: Version 1.2
# (case-insensitive).
#asterix.i001_version: Version 1.2

# Select the CAT002 version
# One of: Version 1.0
# (case-insensitive).
#asterix.i002_version: Version 1.0

# Select the CAT004 version
# One of: Version 1.7
# (case-insensitive).
#asterix.i004_version: Version 1.7

# Select the CAT008 version
# One of: Version 1.1
# (case-insensitive).
#asterix.i008_version: Version 1.1

# Select the CAT009 version
# One of: Version 2.0
# (case-insensitive).
#asterix.i009_version: Version 2.0

# Select the CAT019 version
# One of: Version 1.3
# (case-insensitive).
#asterix.i019_version: Version 1.3

# Select the CAT020 version
# One of: Version 1.9
# (case-insensitive).
#asterix.i020_version: Version 1.9

# Select the CAT021 version
# One of: Version 2.3, Version 2.1, Version 0.26, Version 0.23
# (case-insensitive).
#asterix.i021_version: Version 2.3

# Select the CAT023 version
# One of: Version 1.2
# (case-insensitive).
#asterix.i023_version: Version 1.2

# Select the CAT025 version
# One of: Version 1.1
# (case-insensitive).
#asterix.i025_version: Version 1.1

# Select the CAT032 version
# One of: Version 1.0
# (case-insensitive).
#asterix.i032_version: Version 1.0

# Select the CAT034 version
# One of: Version 1.27
# (case-insensitive).
#asterix.i034_version: Version 1.27

# Select the CAT048 version
# One of: Version 1.23, Version 1.21, Version 1.17
# (case-insensitive).
#asterix.i048_version: Version 1.23

# Select the CAT062 version
# One of: Version 1.18, Version 1.17, Version 1.16, Version 0.17
# (case-insensitive).
#asterix.i062_version: Version 1.18

# Select the CAT063 version
# One of: Version 1.4
# (case-insensitive).
#asterix.i063_version: Version 1.4

# Select the CAT065 version
# One of: Version 1.4, Version 1.3
# (case-insensitive).
#asterix.i065_version: Version 1.4

# Force treat packets as DTE (PC) or DCE (Modem) role
# One of: Off, Sent is DTE, Rcvd is DCE, Sent is DCE, Rcvd is DTE
# (case-insensitive).
#at.role: Off

# Autodection between LANE and SSCOP is hard. As default LANE is preferred
# TRUE or FALSE (case-insensitive)
#atm.dissect_lane_as_sscop: FALSE

# Whether the ATP dissector should reassemble messages spanning multiple DDP packets
# TRUE or FALSE (case-insensitive)
#atp.desegment: TRUE

# In the standard the Source Node Identifier is the first byte and the Control Bit Vector is the second byte. Using this parameter they can be swapped
# TRUE or FALSE (case-insensitive)
#autosar-nm.swap_ctrl_and_src: TRUE

# Revision 4.3.1 of the specification doesn't have 'NM Coordinator Id' in Control Bit Vector. Using this parameter one may switch to a mode compatible with revision 3.2 of the specification.
# TRUE or FALSE (case-insensitive)
#autosar-nm.interpret_coord_id: FALSE

# Identifier that is used to filter packets that should be dissected. Set bit 31 when defining an extended id. (works with the mask defined below)
# A hexadecimal number
#autosar-nm.can_id: 0

# Mask applied to CAN identifiers when decoding whether a packet should dissected. Use 0xFFFFFFFF mask to require exact match.
# A hexadecimal number
#autosar-nm.can_id_mask: 0

# Enable checksum calculation.
# TRUE or FALSE (case-insensitive)
#ax25_kiss.showcksum: FALSE

# Enable decoding of the payload as APRS.
# TRUE or FALSE (case-insensitive)
#ax25_nol3.showaprs: FALSE

# Enable decoding of the payload as DX cluster info.
# TRUE or FALSE (case-insensitive)
#ax25_nol3.showcluster: FALSE

# Ethertype used to indicate B.A.T.M.A.N. packet.
# A hexadecimal number
#batadv.batmanadv.ethertype: 0x4305

# Whether the Bazaar dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#bzr.desegment: TRUE

# Specifies that BEEP requires CRLF as a terminator, and not just CR or LF
# TRUE or FALSE (case-insensitive)
#beep.strict_header_terminator: TRUE

# Whether the dissector should also display internal ASN.1 BER details such as Identifier and Length fields
# TRUE or FALSE (case-insensitive)
#ber.show_internals: FALSE

# Whether the dissector should decode unexpected tags as ASN.1 BER encoded data
# TRUE or FALSE (case-insensitive)
#ber.decode_unexpected: FALSE

# Whether the dissector should try decoding OCTET STRINGs as constructed ASN.1 BER encoded data
# TRUE or FALSE (case-insensitive)
#ber.decode_octetstring: FALSE

# Whether the dissector should try decoding unknown primitive as constructed ASN.1 BER encoded data
# TRUE or FALSE (case-insensitive)
#ber.decode_primitive: FALSE

# Whether the dissector should warn if excessive leading zero (0) bits
# TRUE or FALSE (case-insensitive)
#ber.warn_too_many_bytes: FALSE

# Whether the BGP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#bgp.desegment: TRUE

# BGP dissector detect the length of the AS number in AS_PATH attributes automatically or manually (NOTE: Automatic detection is not 100% accurate)
# One of: Auto-detect, 2 octet, 4 octet
# (case-insensitive).
#bgp.asn_len: Auto-detect

# Whether the Bitcoin dissector should desegment all messages spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#bitcoin.desegment: TRUE

# Whether the BitTorrent dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#bittorrent.desegment: TRUE

# Enabling this will tell which BitTorrent client that produced the handshake message
# TRUE or FALSE (case-insensitive)
#bittorrent.decode_client: FALSE

# Force decoding stream as A2DP with Content Protection SCMS-T 
# TRUE or FALSE (case-insensitive)
#bta2dp.a2dp.content_protection.scms_t: FALSE

# Force decoding stream as A2DP with specified codec
# One of: Default, SBC, MPEG12 AUDIO, MPEG24 AAC, aptX, aptX HD, LDAC
# (case-insensitive).
#bta2dp.a2dp.codec: Default

# Dissecting the top protocols
# TRUE or FALSE (case-insensitive)
#btbnep.bnep.top_dissect: TRUE

# If "yes" localhost will be treat as Client, "no" as Server
# One of: Default, Yes, No
# (case-insensitive).
#bthcrp.hcrp.force_client: Default

# L2CAP PSM for Control
# A decimal number
#bthcrp.hcrp.control.psm: 0

# L2CAP PSM for Data
# A decimal number
#bthcrp.hcrp.data.psm: 0

# L2CAP PSM for Notification
# A decimal number
#bthcrp.hcrp.notification.psm: 0

# Force treat packets as AG or HS role
# One of: Off, Sent is AG, Rcvd is HS, Sent is HS, Rcvd is AG
# (case-insensitive).
#bthfp.hfp.hfp_role: Off

# Show what is deprecated in HID 1.1
# TRUE or FALSE (case-insensitive)
#bthid.hid.deprecated: FALSE

# Force treat packets as AG or HS role
# One of: Off, Sent is AG, Rcvd is HS, Sent is HS, Rcvd is AG
# (case-insensitive).
#bthsp.hsp.hsp_role: Off

# Detect retransmission based on SN (Sequence Number)
# TRUE or FALSE (case-insensitive)
#btle.detect_retransmit: TRUE

# Turn on/off decode by next rules
# TRUE or FALSE (case-insensitive)
#btrfcomm.rfcomm.decode_by.enabled: FALSE

# Dissecting the top protocols
# One of: off, Put higher dissectors under this one, On top
# (case-insensitive).
#btsap.sap.top_dissect: Put higher dissectors under this one

# Force decoding stream as VDP with Content Protection SCMS-T 
# TRUE or FALSE (case-insensitive)
#btvdp.vdp.content_protection.scms_t: FALSE

# Force decoding stream as VDP with specified codec
# One of: H263, MPEG4 VSP
# (case-insensitive).
#btvdp.vdp.codec: H263

# Whether the ACL dissector should reassemble fragmented PDUs
# TRUE or FALSE (case-insensitive)
#bthci_acl.hci_acl_reassembly: TRUE

# Whether the BMP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#bmp.desegment: TRUE

# For the sake of sub-dissectors registering to accept data from the BSSAP/BSAP dissector, this defines whether it is identified as BSSAP or BSAP.
# One of: BSSAP, BSAP
# (case-insensitive).
#bssap.bsap_or_bssap: BSSAP

# GSM-A is the interface between the BSC and the MSC. Lb is the interface between the BSC and the SMLC.
# One of: GSM A, Lb
# (case-insensitive).
#bssap.gsm_or_lb_interface: GSM A

# Set Subsystem number used for BSSAP+
# A decimal number
#bssap_plus.ssn: 98

# Decode NRI (for use with SGSN in Pool)
# TRUE or FALSE (case-insensitive)
#bssgp.decode_nri: FALSE

# NRI length, in bits
# A decimal number
#bssgp.nri_length: 4

# Dissect next layer
# TRUE or FALSE (case-insensitive)
#btsnoop.dissect_next_layer: FALSE

# Whether the C12.22 dissector should reassemble all messages spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#c1222.desegment: TRUE

# Base object identifier for use in resolving relative object identifiers
# A string
#c1222.baseoid: 

# Whether the C12.22 dissector should verify the crypto for all relevant messages
# TRUE or FALSE (case-insensitive)
#c1222.decrypt: TRUE

# Whether the C12.22 dissector should interpret procedure numbers as big-endian
# TRUE or FALSE (case-insensitive)
#c1222.big_endian: FALSE

# The date format: (DD/MM) or (MM/DD)
# One of: DD/MM/YYYY, MM/DD/YYYY
# (case-insensitive).
#camel.date.format: DD/MM/YYYY

# TCAP Subsystem numbers used for Camel
# A string denoting an positive integer range (e.g., "1-20,30-40")
#camel.tcap.ssn: 146

# Enable response time analysis
# TRUE or FALSE (case-insensitive)
#camel.srt: FALSE

# Statistics for Response Time
# TRUE or FALSE (case-insensitive)
#camel.persistentsrt: FALSE

# Whether the CAN ID/flags field should be byte-swapped
# TRUE or FALSE (case-insensitive)
#can.byte_swap: FALSE

# Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to "decode as"
# TRUE or FALSE (case-insensitive)
#can.try_heuristic_first: FALSE

# Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to "decode as"
# TRUE or FALSE (case-insensitive)
#acf-can.try_heuristic_first: FALSE

# Enable support of Cisco Wireless Controller (based on old 8 draft revision).
# TRUE or FALSE (case-insensitive)
#capwap.draft_8_cisco: FALSE

# Reassemble fragmented CAPWAP packets.
# TRUE or FALSE (case-insensitive)
#capwap.reassemble: TRUE

# Swap frame control bytes (needed for some APs).
# TRUE or FALSE (case-insensitive)
#capwap.swap_fc: TRUE

# Whether the CAST dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#cast.reassembly: TRUE

# Whether the checksum of all messages should be validated or not
# TRUE or FALSE (case-insensitive)
#cattp.checksum: TRUE

# Specify how the dissector should handle the CCSDS checkword
# One of: Use header flag, Override header flag to be false, Override header flag to be true
# (case-insensitive).
#ccsds.global_pref_checkword: Use header flag

# Whether or not the RTP header is present in the CES payload.
# TRUE or FALSE (case-insensitive)
#cesoeth.rtp_header: FALSE

# Heuristically determine if an RTP header is present in the CES payload.
# TRUE or FALSE (case-insensitive)
#cesoeth.rtp_header_heuristic: TRUE

# Set the port(s) for NetFlow messages (default: 2055,9996)
# A string denoting an positive integer range (e.g., "1-20,30-40")
#cflow.netflow.ports: 2055,9996

# Set the port(s) for IPFIX messages (default: 4739)
# A string denoting an positive integer range (e.g., "1-20,30-40")
#cflow.ipfix.ports: 4739

# Set the number of fields allowed in a template.  Use 0 (zero) for unlimited.   (default: 60)
# A decimal number
#cflow.max_template_fields: 60

# Whether the Netflow/Ipfix dissector should reassemble messages spanning multiple TCP segments.  To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#cflow.desegment: TRUE

# Whether to validate the Frame Check Sequence
# TRUE or FALSE (case-insensitive)
#cfp.check_fcs: FALSE

# The type of CHDLC frame checksum (none, 16-bit, 32-bit)
# One of: None, 16-Bit, 32-Bit
# (case-insensitive).
#chdlc.fcs_type: None

# The version of CIGI with which to dissect packets
# One of: From Packet, CIGI 2, CIGI 3
# (case-insensitive).
#cigi.version: From Packet

# The byte order with which to dissect CIGI packets (CIGI3)
# One of: From Packet, Big-Endian, Little-Endian
# (case-insensitive).
#cigi.byte_order: From Packet

# IPv4 address or hostname of the host
# A string
#cigi.host: 

# IPv4 address or hostname of the image generator
# A string
#cigi.ig: 

# Whether the CIP dissector should display enhanced/verbose data in the Info column for CIP explicit messages
# TRUE or FALSE (case-insensitive)
#cip.enhanced_info_column: TRUE

# NSAP selector for Transport Protocol (last byte in hex)
# A hexadecimal number
#clnp.tp_nsap_selector: 0x21

# Always try to decode NSDU as transport PDUs
# TRUE or FALSE (case-insensitive)
#clnp.always_decode_transport: FALSE

# Whether segmented CLNP datagrams should be reassembled
# TRUE or FALSE (case-insensitive)
#clnp.reassemble: TRUE

# Whether ATN security label should be decoded
# TRUE or FALSE (case-insensitive)
#clnp.decode_atn_options: FALSE

# Whether the CMP-over-TCP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#cmp.desegment: TRUE

# Decode this TCP port's traffic as CMP-over-HTTP. Set to "0" to disable. Use this if the Content-Type is not set correctly.
# A decimal number
#cmp.http_alternate_port: 0

# Decode this TCP port's traffic as TCP-transport-style CMP-over-HTTP. Set to "0" to disable. Use this if the Content-Type is not set correctly.
# A decimal number
#cmp.tcp_style_http_alternate_port: 0

# Whether the COPS dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#cops.desegment: TRUE

# Decode the COPS messages using PacketCable clients. (Select port 2126)
# TRUE or FALSE (case-insensitive)
#cops.packetcable: TRUE

# Semicolon-separated  list of keys for decryption(e.g. key1;key2;...
# A string
#corosync_totemnet.private_keys: 

# Whether segmented COTP datagrams should be reassembled. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#cotp.reassemble: TRUE

# How TSAPs should be displayed
# One of: As strings if printable, As strings, As bytes
# (case-insensitive).
#cotp.tsap_display: As strings if printable

# Whether to decode OSI TPDUs with ATN (Aereonautical Telecommunications Network) extensions. To use this option, you must also enable "Always try to decode NSDU as transport PDUs" in the CLNP protocol settings.
# TRUE or FALSE (case-insensitive)
#cotp.decode_atn: FALSE

# Whether the memcache dissector should reassemble PDUs spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#couchbase.desegment_pdus: TRUE

# The port used for communicating with the data service via SSL/TLS
# A decimal number
#couchbase.tls.port: 11207

# Whether the SEL Protocol dissector should automatically pre-process Telnet data to remove IAC bytes
# TRUE or FALSE (case-insensitive)
#cp2179.telnetclean: TRUE

# Set the port for InstanceToInstance messages (if other than the default of 5001)
# A decimal number
#cpfi.udp.port2: 5001

# Control the way the '-->' is displayed. When enabled, keeps the 'lowest valued' endpoint of the src-dest pair on the left, and the arrow moves to distinguish source from dest. When disabled, keeps the arrow pointing right so the source of the frame is always on the left.
# TRUE or FALSE (case-insensitive)
#cpfi.arrow_ctl: TRUE

# Show not dissected data on new Packet Bytes pane
# TRUE or FALSE (case-insensitive)
#data.datapref.newpane: FALSE

# Try to uncompress zlib compressed data and show as uncompressed if successful
# TRUE or FALSE (case-insensitive)
#data.uncompress_data: FALSE

# Show data as text in the Packet Details pane
# TRUE or FALSE (case-insensitive)
#data.show_as_text: FALSE

# Whether or not MD5 hashes should be generated and shown for each payload.
# TRUE or FALSE (case-insensitive)
#data.md5_hash: FALSE

# Whether the LAN sync dissector should reassemble PDUs spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#db-lsp.desegment_pdus: TRUE

# Try to decode the payload using an heuristic sub-dissector
# TRUE or FALSE (case-insensitive)
#db-lsp.try_heuristic: TRUE

# Whether the DCCP summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#dccp.summary_in_tree: TRUE

# Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port
# TRUE or FALSE (case-insensitive)
#dccp.try_heuristic_first: FALSE

# Whether to check the validity of the DCCP checksum
# TRUE or FALSE (case-insensitive)
#dccp.check_checksum: TRUE

# Whether the DCE/RPC dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#dcerpc.desegment_dcerpc: TRUE

# Whether the DCE/RPC dissector should reassemble fragmented DCE/RPC PDUs
# TRUE or FALSE (case-insensitive)
#dcerpc.reassemble_dcerpc: TRUE

# Display some DCOM unmarshalled fields usually hidden
# TRUE or FALSE (case-insensitive)
#dcom.display_unmarshalling_details: FALSE

# If a payload looks like it's embedded in an IP primitive message, and there is a Wireshark dissector matching the DCT2000 protocol name, try parsing the payload using that dissector
# TRUE or FALSE (case-insensitive)
#dct2000.ipprim_heuristic: TRUE

# If a payload looks like it's embedded in an SCTP primitive message, and there is a Wireshark dissector matching the DCT2000 protocol name, try parsing the payload using that dissector
# TRUE or FALSE (case-insensitive)
#dct2000.sctpprim_heuristic: TRUE

# When set, attempt to decode LTE RRC frames. Note that this won't affect other protocols that also call the LTE RRC dissector
# TRUE or FALSE (case-insensitive)
#dct2000.decode_lte_rrc: TRUE

# When set, look for formatted messages indicating specific events.  This may be quite slow, so should be disabled if LTE MAC is not being analysed
# TRUE or FALSE (case-insensitive)
#dct2000.decode_mac_lte_oob_messages: TRUE

# When set, look for some older protocol names so thatthey may be matched with wireshark dissectors.
# TRUE or FALSE (case-insensitive)
#dct2000.convert_old_protocol_names: FALSE

# Novell Servers option 85 can be configured as a string instead of address
# TRUE or FALSE (case-insensitive)
#dhcp.novellserverstring: FALSE

# The PacketCable CCC protocol version
# One of: PKT-SP-PROV-I05-021127, IETF Draft 5, RFC 3495
# (case-insensitive).
#dhcp.pkt.ccc.protocol_version: RFC 3495

# Option Number for PacketCable CableLabs Client Configuration
# A decimal number
#dhcp.pkt.ccc.option: 122

# Endianness applied to UUID fields
# One of: Little Endian, Big Endian
# (case-insensitive).
#dhcp.uuid.endian: Little Endian

# Whether the DHCP failover dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#dhcpfo.desegment: TRUE

# Whether Option 18 is dissected as CableLab or RFC 3315
# TRUE or FALSE (case-insensitive)
#dhcpv6.cablelabs_interface_id: FALSE

# Whether the Bulk Leasequery dissector should desegment all messages spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#dhcpv6.bulk_leasequery.desegment: TRUE

# SCTP ports to be decoded as Diameter (default: 3868)
# A string denoting an positive integer range (e.g., "1-20,30-40")
#diameter.sctp.ports: 3868

# Whether the Diameter dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#diameter.desegment: TRUE

# Create DICOM File Meta Header according to PS 3.10 on export for PDUs. If the captured PDV does not contain a SOP Class UID and SOP Instance UID (e.g. for command PDVs), wireshark specific ones will be created.
# TRUE or FALSE (case-insensitive)
#dicom.export_header: TRUE

# Do not show items below this size in the export list. Set it to 0, to see DICOM commands and responses in the list. Set it higher, to just export DICOM IODs (i.e. CT Images, RT Structures).
# A decimal number
#dicom.export_minsize: 4096

# Create a node for sequences and items, and show children in a hierarchy. De-select this option, if you prefer a flat display or e.g. when using TShark to create a text output.
# TRUE or FALSE (case-insensitive)
#dicom.seq_tree: TRUE

# Create a node for a tag and show tag details as single elements. This can be useful to debug a tag and to allow display filters on these attributes. When using TShark to create a text output, it's better to have it disabled. 
# TRUE or FALSE (case-insensitive)
#dicom.tag_tree: FALSE

# Show message ID and number of completed, remaining, warned or failed operations in header and info column.
# TRUE or FALSE (case-insensitive)
#dicom.cmd_details: TRUE

# Decode all DICOM tags in the last PDV. This will ensure the proper reassembly. De-select, to troubleshoot PDU length issues, or to understand PDV fragmentation. When not set, the decoding may fail and the exports may become corrupt.
# TRUE or FALSE (case-insensitive)
#dicom.pdv_reassemble: TRUE

# Whether the DISTCC dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#distcc.desegment_distcc_over_tcp: TRUE

# Whether DJIUAV should reassemble messages spanning multiple TCP segments (required to get useful results)
# TRUE or FALSE (case-insensitive)
#djiuav.desegment: TRUE

# Set the SCTP port for Distributed Lock Manager
# A decimal number
#dlm3.sctp.port: 21064

# Select the type of decoding for nationally-defined values
# One of: None (raw data), As for regular, Thales XOmail
# (case-insensitive).
#dmp.national_decode: As for regular

# Select the nation of sending server.  This is used when presenting security classification values in messages with security policy set to National (nation of local server)
# One of: None, Albania, Armenia, Austria, Azerbaijan, Belarus, Belgium, Bosnia and Hercegowina, Bulgaria, Canada, Croatia, Czech Republic, Denmark, Estonia, Euro-Atlantic Partnership Council (EAPC), European Union (EU), Finland, Former Yugoslav Republic of Macedonia, France, Georgia, Germany, Greece, Hungary, Iceland, International Security Assistance Force (ISAF), Ireland, Italy, Kazakhstan, Kyrgyztan, Latvia, Lithuania, Luxembourg, Malta, Moldova, Montenegro, Netherlands, Norway, Partnership for Peace (PfP), Poland, Portugal, Romania, Russian Federation, Serbia, Slovakia, Slovenia, Spain, Sweden, Switzerland, Tajikistan, Turkey, Turkmenistan, United Kingdom, United States, Ukraine, Uzbekistan, Western European Union (WEU)
# (case-insensitive).
#dmp.local_nation: None

# Calculate sequence/acknowledgement analysis
# TRUE or FALSE (case-insensitive)
#dmp.seq_ack_analysis: TRUE

# Align identifiers in info list (does not align when retransmission or duplicate acknowledgement indication)
# TRUE or FALSE (case-insensitive)
#dmp.align_ids: FALSE

# The way DMX values are displayed
# One of: Percent, Hexadecimal, Decimal
# (case-insensitive).
#dmx_chan.dmx_disp_chan_val_type: Percent

# The way DMX channel numbers are displayed
# One of: Hexadecimal, Decimal
# (case-insensitive).
#dmx_chan.dmx_disp_chan_nr_type: Hexadecimal

# The number of columns for the DMX display
# One of: 6, 10, 12, 16, 24
# (case-insensitive).
#dmx_chan.dmx_disp_col_count: 16

# Whether the DNP3 dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#dnp3.desegment: TRUE

# Whether the DNS dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#dns.desegment_dns_messages: TRUE

# Number of seconds allowed between DNS requests with the same transaction ID to consider it a retransmission. Otherwise its considered a new request.
# A decimal number
#dns.retransmission_timer: 5

# Whether or not to validate the Header Check Sequence
# TRUE or FALSE (case-insensitive)
#docsis.check_fcs: TRUE

# Whether or not to attempt to dissect encrypted DOCSIS payload
# TRUE or FALSE (case-insensitive)
#docsis.dissect_encrypted_frames: FALSE

# Specifies that decryption should be attempted on all packets, even if the session initialization wasn't captured.
# TRUE or FALSE (case-insensitive)
#dof.custom_dof_decrypt_all: FALSE

# Specifies that operations should be tracked across multiple packets, providing summary lists. This takes time and memory.
# TRUE or FALSE (case-insensitive)
#dof.custom_dof_track_operations: FALSE

# Limits the number of operations shown before and after the current operations
# A decimal number
#dof.custom_dof_track_operations_window: 5

# Whether the DRDA dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#drda.desegment: TRUE

# Whether the DSI dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#dsi.desegment: TRUE

# redirect dtls debug to file name; leave empty to disable debug, use "-" to redirect output to stderr
# 
# A path to a file
#dtls.debug_file: 

# Pre-Shared-Key as HEX string. Should be 0 to 16 bytes.
# A string
#dtls.psk: 

# SAC Encryption Key (16 hex bytes)
# A string
#dvb-ci.sek: 

# SAC Init Vector (16 hex bytes)
# A string
#dvb-ci.siv: 

# Dissect the content of messages transmitted on the Low-Speed Communication resource. This requires a dissector for the protocol and target port contained in the connection descriptor.
# TRUE or FALSE (case-insensitive)
#dvb-ci.dissect_lsc_msg: FALSE

# Check this to enable full protocol dissection of data above GSE Layer
# TRUE or FALSE (case-insensitive)
#dvb-s2_modeadapt.full_decode: FALSE

# Allow only packets with Major=0x03//Minor=0xFF as DVMRP V3 packets
# TRUE or FALSE (case-insensitive)
#dvmrp.strict_v3: FALSE

# Decode the Message Types according to eCPRI Specification V1.2
# TRUE or FALSE (case-insensitive)
#ecpri.ecpripref.msg.decoding: TRUE

# Whether the eDonkey dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#edonkey.desegment: TRUE

# Whether the EtherNet/IP dissector should desegment all messages spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#enip.desegment: TRUE

# Determines whether all I/O connections will assume a 32-bit header in the O->T direction
# TRUE or FALSE (case-insensitive)
#enip.o2t_run_idle: TRUE

# Determines whether all I/O connections will assume a 32-bit header in the T->O direction
# TRUE or FALSE (case-insensitive)
#enip.t2o_run_idle: FALSE

# The way DMX values are displayed
# One of: Percent, Hexadecimal, Decimal
# (case-insensitive).
#enttec.dmx_disp_chan_val_type: Percent

# The way DMX channel numbers are displayed
# One of: Hexadecimal, Decimal
# (case-insensitive).
#enttec.dmx_disp_chan_nr_type: Hexadecimal

# The number of columns for the DMX display
# One of: 6, 10, 12, 16, 24
# (case-insensitive).
#enttec.dmx_disp_col_count: 16

# If you are capturing in networks with multiplexed or slow nodes, this can be useful
# TRUE or FALSE (case-insensitive)
#epl.show_soc_flags: FALSE

# For analysis purposes one might want to show the command layer even if the dissectore assumes a duplicated frame
# TRUE or FALSE (case-insensitive)
#epl.show_duplicated_command_layer: FALSE

# For analysis purposes one might want to see how long the current mapping has been active for and what OD write caused it
# TRUE or FALSE (case-insensitive)
#epl.show_pdo_meta_info: FALSE

# Partition PDOs according to ObjectMappings sent via SDO
# TRUE or FALSE (case-insensitive)
#epl.use_sdo_mappings: TRUE

# If you want to parse the defaultValue (XDD) and actualValue (XDC) attributes for ObjectMappings in order to detect default PDO mappings, which may not be sent over SDO 
# TRUE or FALSE (case-insensitive)
#epl.use_xdc_mappings: TRUE

# If a data field has untyped data under 8 byte long, interpret it as unsigned little endian integer and show decimal and hexadecimal representation thereof. Otherwise use stock data dissector
# TRUE or FALSE (case-insensitive)
#epl.interpret_untyped_as_le: TRUE

# If you have a capture without IdentResponse and many nodes, it's easier to set a default profile here than to add entries for all MAC address or Node IDs
# A path to a file
#epl.default_profile: 

# Protocol encapsulated in HDLC records
# One of: Cisco HDLC, PPP serial, Frame Relay, SS7 MTP2, Attempt to guess
# (case-insensitive).
#erf.hdlc_type: Attempt to guess

# Whether raw ATM cells should be treated as the first cell of an AAL5 PDU
# TRUE or FALSE (case-insensitive)
#erf.rawcell_first: FALSE

# Protocol encapsulated in ATM AAL5 packets
# One of: Attempt to guess, LLC multiplexed, Unspecified
# (case-insensitive).
#erf.aal5_type: Attempt to guess

# The packets contain the optional Incremental Redundancy (IR) fields
# TRUE or FALSE (case-insensitive)
#gsm_abis_pgsl.ir: FALSE

# This is done only if the Decoding is not SET or the packet does not belong to a SA. Assumes a 12 byte auth (HMAC-SHA1-96/HMAC-MD5-96/AES-XCBC-MAC-96) and attempts decode based on the ethertype 13 bytes from packet end
# TRUE or FALSE (case-insensitive)
#esp.enable_null_encryption_decode_heuristic: FALSE

# Check that successive frames increase sequence number by 1 within an SPI.  This should work OK when only one host is sending frames on an SPI
# TRUE or FALSE (case-insensitive)
#esp.do_esp_sequence_analysis: TRUE

# Attempt to decode based on the SAD described hereafter.
# TRUE or FALSE (case-insensitive)
#esp.enable_encryption_decode: FALSE

# Attempt to Check ESP Authentication based on the SAD described hereafter.
# TRUE or FALSE (case-insensitive)
#esp.enable_authentication_check: FALSE

# Whether the E-Tag summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#etag.summary_in_tree: TRUE

# Place the hash/symbol files (generated by the Apache Etch compiler) ending with .ewh here
# A path to a directory
#etch.file: 

# Some devices add trailing data to frames. When this setting is checked the Ethernet dissector will assume there has been added padding to the frame before the trailer was added. Uncheck if a device added a trailer before the frame was padded.
# TRUE or FALSE (case-insensitive)
#eth.assume_padding: TRUE

# Some TAPs add a fixed length ethernet trailer at the end of the frame, but before the (optional) FCS. Make sure it gets interpreted correctly.
# A decimal number
#eth.trailer_length: 0

# Some Ethernet adapters and drivers include the FCS at the end of a packet, others do not.  The Ethernet dissector attempts to guess whether a captured packet has an FCS, but it cannot always guess correctly.
# TRUE or FALSE (case-insensitive)
#eth.assume_fcs: FALSE

# Whether to validate the Frame Check Sequence
# TRUE or FALSE (case-insensitive)
#eth.check_fcs: FALSE

# Whether packets should be interpreted as coming from CheckPoint FireWall-1 monitor file if they look as if they do
# TRUE or FALSE (case-insensitive)
#eth.interpret_as_fw1_monitor: FALSE

# When capturing on a Cisco FEX some frames start with an extra destination mac
# TRUE or FALSE (case-insensitive)
#eth.deduplicate_dmac: FALSE

# Set the condition that must be true for the CCSDS dissector to be called
# TRUE or FALSE (case-insensitive)
#eth.ccsds_heuristic_length: FALSE

# Set the condition that must be true for the CCSDS dissector to be called
# TRUE or FALSE (case-insensitive)
#eth.ccsds_heuristic_version: FALSE

# Set the condition that must be true for the CCSDS dissector to be called
# TRUE or FALSE (case-insensitive)
#eth.ccsds_heuristic_header: FALSE

# Set the condition that must be true for the CCSDS dissector to be called
# TRUE or FALSE (case-insensitive)
#eth.ccsds_heuristic_bit: FALSE

# Whether the EVRC dissector should process payload type 60 as legacy EVRC packets
# TRUE or FALSE (case-insensitive)
#evrc.legacy_pt_60: FALSE

# The dynamic payload type which will be interpreted as EVS; The value must be greater than 95
# A decimal number
#evs.dynamic.payload.type: 0

# Controls the display of the session's username in the info column.  This is only displayed if the packet containing it was seen during this capture session.
# TRUE or FALSE (case-insensitive)
#exec.info_show_username: TRUE

# Controls the display of the command being run on the server by this session in the info column.  This is only displayed if the packet containing it was seen during this capture session.
# TRUE or FALSE (case-insensitive)
#exec.info_show_command: FALSE

# Disable this if you do not want this dissector to populate well-known fields in other dissectors (i.e. ip.addr, ipv6.addr, tcp.port and udp.port).  Enabling this will allow filters that reference those fields to also find data in the trailers but will reduce performance.  After disabling, you should restart Wireshark to get performance back.
# TRUE or FALSE (case-insensitive)
#f5ethtrailer.pop_other_fields: FALSE

# Enabling this will perform analysis of the trailer data.  It will enable taps on other protocols and slow down Wireshark.
# TRUE or FALSE (case-insensitive)
#f5ethtrailer.perform_analysis: TRUE

# In/out only removes slot/tmm information.  Brief shortens the string to >S/T (for in) or <S/T (for out).  See "Brief in/out characters" below.
# One of: None, Full, In/out only, Brief, Brief in/out only
# (case-insensitive).
#f5ethtrailer.info_type: Full

# A string specifying the characters to use to represent "in" and "out" in the brief summary.  The default is "><" ('>' for in and '<' for out).  If this is not set or is less than two characters, the default is used.  If it is longer than two characters, the extra characters are ignored.
# A string
#f5ethtrailer.brief_inout_chars: 

# If the platform in the F5 FILEINFO packet matches the provided regex, slot information will be displayed in the info column; otherwise, it will not.  A reasonable value is "^(A.*|Z101)$".  If the regex is empty or there is no platform information in the capture, slot information is always displayed.
# A string
#f5ethtrailer.slots_regex: 

# If present, include the RST cause text from the trailer in the "info" column of the packet list pane.
# TRUE or FALSE (case-insensitive)
#f5ethtrailer.rstcause_in_info: TRUE

# If enabled, KEYLOG entires will be added to the TLS decode in the f5ethtrailer protocol tree.  It will populate the f5ethtrailer.tls.keylog field.
# TRUE or FALSE (case-insensitive)
#f5ethtrailer.generate_keylog: TRUE

# If enabled, reassembly of multi-frame sequences is done
# TRUE or FALSE (case-insensitive)
#fc.reassemble: TRUE

# This is the size of non-last frames in a multi-frame sequence
# A decimal number
#fc.max_frame_size: 1024

# Whether the FDDI dissector should add 3-byte padding to all captured FDDI packets (useful with e.g. Tru64 UNIX tcpdump)
# TRUE or FALSE (case-insensitive)
#fddi.padding: FALSE

# Whether the FCIP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#fcip.desegment: TRUE

# Port number used for FCIP
# A decimal number
#fcip.target_port: 3225

# Dissect next layer
# TRUE or FALSE (case-insensitive)
#file-pcap.dissect_next_layer: FALSE

# Dissect next layer
# TRUE or FALSE (case-insensitive)
#file-pcapng.dissect_next_layer: FALSE

# Whether the FIX dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#fix.desegment: TRUE

# Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to "decode as"
# TRUE or FALSE (case-insensitive)
#flexray.try_heuristic_first: FALSE

# With this option display filters for fmp fhandle a RPC call, even if the actual fhandle is only present in one of the packets
# TRUE or FALSE (case-insensitive)
#fmp.fhandle_find_both_reqrep: FALSE

# Decode packets on this sctp port as ForCES
# A decimal number
#forces.sctp_high_prio_port: 0

# Decode packets on this sctp port as ForCES
# A decimal number
#forces.sctp_med_prio_port: 0

# Decode packets on this sctp port as ForCES
# A decimal number
#forces.sctp_low_prio_port: 0

# Show reported release info
# TRUE or FALSE (case-insensitive)
#fp.show_release_info: TRUE

# Call MAC dissector for payloads
# TRUE or FALSE (case-insensitive)
#fp.call_mac: TRUE

# Validate FP payload checksums
# TRUE or FALSE (case-insensitive)
#fp.payload_checksum: TRUE

# Validate FP header checksums
# TRUE or FALSE (case-insensitive)
#fp.header_checksum: TRUE

# For each PCH data frame, Try to show the paging indications bitmap found in the previous frame
# TRUE or FALSE (case-insensitive)
#fp.track_paging_indications: TRUE

# Whether the UID value should be appended in the protocol tree
# TRUE or FALSE (case-insensitive)
#fp_mux.uid_in_tree: TRUE

# Whether to try heuristic FP dissectors for the muxed payloads
# TRUE or FALSE (case-insensitive)
#fp_mux.call_heur_fp: TRUE

# Encapsulation
# One of: FRF 3.2/Cisco HDLC, GPRS Network Service, Raw Ethernet, LAPB (T1.617a-1994 Annex G)
# (case-insensitive).
#fr.encap: FRF 3.2/Cisco HDLC

# Show offset of frame in capture file
# TRUE or FALSE (case-insensitive)
#frame.show_file_off: FALSE

# Treat all frames as DOCSIS Frames
# TRUE or FALSE (case-insensitive)
#frame.force_docsis_encap: FALSE

# Whether or not MD5 hashes should be generated for each frame, useful for finding duplicate frames.
# TRUE or FALSE (case-insensitive)
#frame.generate_md5_hash: FALSE

# Whether or not an Epoch time entry should be generated for each frame.
# TRUE or FALSE (case-insensitive)
#frame.generate_epoch_time: TRUE

# Whether or not the number of bits in the frame should be shown.
# TRUE or FALSE (case-insensitive)
#frame.generate_bits_field: TRUE

# Whether or not 'packet size limited during capture' message in shown in Info column.
# TRUE or FALSE (case-insensitive)
#frame.disable_packet_size_limited_in_summary: FALSE

# Whether the FireWall-1 summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#fw1.summary_in_tree: TRUE

# Whether the Firewall-1 monitor file includes UUID information
# TRUE or FALSE (case-insensitive)
#fw1.with_uuid: FALSE

# Whether the interface list includes the chain position
# TRUE or FALSE (case-insensitive)
#fw1.iflist_with_chain: FALSE

# Whether the Gadu-Gadu dissector should reassemble messages spanning multiple TCP segments.To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#gadu-gadu.desegment: TRUE

# Whether the Gearman dissector should desegment all messages spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#gearman.desegment: TRUE

# Whether the GED125 dissector should desegment all messages spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#ged125.desegment_body: TRUE

# Whether the GIOP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#giop.desegment_giop_messages: TRUE

# Whether fragmented GIOP messages should be reassembled
# TRUE or FALSE (case-insensitive)
#giop.reassemble: TRUE

# Maximum allowed message size in bytes (default=10485760)
# A decimal number
#giop.max_message_size: 10485760

# File containing stringified IORs, one per line.
# A path to a file
#giop.ior_txt: IOR.txt

# Whether the GIT dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#git.desegment: TRUE

# Whether the Gigamon header summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#gmhdr.summary_in_tree: TRUE

# Whether the Gigamon Trailer summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#gmtrailer.summary_in_tree: TRUE

# Whether the Gigamon trailer containing HW timestamp, source id and original CRC should be decoded
# TRUE or FALSE (case-insensitive)
#gmtrailer.decode_trailer_timestamp: TRUE

# Make the GeoNetworking dissector analyze GeoNetworking sequence numbers to find and flag duplicate packet (Annex A)
# TRUE or FALSE (case-insensitive)
#gnw.analyze_sequence_numbers: TRUE

# Whether to autodetect the cipher bit (because it might be set on unciphered data)
# TRUE or FALSE (case-insensitive)
#llcgprs.autodetect_cipher_bit: FALSE

# Help for debug...
# TRUE or FALSE (case-insensitive)
#gquic.debug.quic: FALSE

# Normally application/grpc message is protobuf, but sometime the true message is json. If this option in on, we always check whether the message is JSON (body starts with '{' and ends with '}') regardless of grpc_message_type_subdissector_table settings (which dissect grpc message according to content-type).
# TRUE or FALSE (case-insensitive)
#grpc.detect_json_automaticlly: TRUE

# If turned on, http2 will reassemble gRPC message as soon as possible. Or else the gRPC message will be reassembled at the end of each HTTP2 STREAM. If your .proto files contains streaming RPCs (declaring RPC operation input/output message type with 'stream' label), you need to keep this option on.
# TRUE or FALSE (case-insensitive)
#grpc.streaming_reassembly_mode: TRUE

# Embed gRPC messages under HTTP2 protocol tree items.
# TRUE or FALSE (case-insensitive)
#grpc.embeded_under_http2: FALSE

# Whether the Gryphon dissector should desegment all messages spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#gryphon.desegment: TRUE

# No description
# TRUE or FALSE (case-insensitive)
#gsm_ipa.hsl_debug_in_root_tree: FALSE

# No description
# TRUE or FALSE (case-insensitive)
#gsm_ipa.hsl_debug_in_info: FALSE

# Whether the dissector should reassemble SMS spanning multiple packets
# TRUE or FALSE (case-insensitive)
#gsm_sms.reassemble: TRUE

# Whether the dissector should take into account info coming from lower layers (like GSM-MAP) to perform SMS reassembly
# TRUE or FALSE (case-insensitive)
#gsm_sms.reassemble_with_lower_layers_info: TRUE

# Always decode a GSM Short Message as Connectionless WSP if a Port Number Information Element is present in the SMS User Data Header.
# TRUE or FALSE (case-insensitive)
#gsm_sms_ud.port_number_udh_means_wsp: FALSE

# Always try subdissection of the 1st fragment of a fragmented GSM Short Message. If reassembly is possible, the Short Message may be dissected twice (once as a short frame, once in its entirety).
# TRUE or FALSE (case-insensitive)
#gsm_sms_ud.try_dissect_1st_fragment: FALSE

# Prevent sub-dissectors from replacing column data with their own. Eg. Prevent WSP dissector overwriting SMPP information.
# TRUE or FALSE (case-insensitive)
#gsm_sms_ud.prevent_dissectors_chg_cols: FALSE

# Treat ARFCN 512-810 as DCS 1800 rather than PCS 1900
# TRUE or FALSE (case-insensitive)
#gsm_um.dcs1800: TRUE

# Dissect Q.931 User-To-User information
# TRUE or FALSE (case-insensitive)
#gsm-r-uus1.dissect_q931_u2u: FALSE

# Dissect GSM-A User-To-User information
# TRUE or FALSE (case-insensitive)
#gsm-r-uus1.dissect_gsm_a_u2u: TRUE

# TCAP Subsystem numbers used for GSM MAP
# A string denoting an positive integer range (e.g., "1-20,30-40")
#gsm_map.tcap.ssn: 6-9,145,148-150

# How to treat Application context
# One of: Use application context from the trace, Treat as AC 1, Treat as AC 2, Treat as AC 3
# (case-insensitive).
#gsm_map.application.context.version: Use application context from the trace

# When enabled, dissector will use the non 3GPP standard extensions from Ericsson (that can override the standard ones)
# TRUE or FALSE (case-insensitive)
#gsm_map.ericsson.proprietary.extensions: FALSE

# Whether or not to try reassembling GSSAPI blobs spanning multiple (SMB/SessionSetup) PDUs
# TRUE or FALSE (case-insensitive)
#gss-api.gssapi_reassembly: TRUE

# Show GSUP Source/Destination names as text in the Packet Details pane
# TRUE or FALSE (case-insensitive)
#gsup.show_name_as_text: TRUE

# GTPv0 and GTP' port (default 3386)
# A decimal number
#gtp.v0_port: 3386

# GTPv1 and GTPv2 control plane port (default 2123)
# A decimal number
#gtp.v1c_port: 2123

# GTPv1 user plane port (default 2152)
# A decimal number
#gtp.v1u_port: 2152

# Dissect T-PDU as
# One of: None, TPDU Heuristic, PDCP-LTE, PDCP-NR, SYNC
# (case-insensitive).
#gtp.dissect_tpdu_as: TPDU Heuristic

# Request/reply pair matches only if their timestamps are closer than that value, in ms (default 0, i.e. don't use timestamps)
# A decimal number
#gtp.pair_max_interval: 0

# GTP ETSI order
# TRUE or FALSE (case-insensitive)
#gtp.check_etsi: FALSE

# Dissect GTP over TCP
# TRUE or FALSE (case-insensitive)
#gtp.dissect_gtp_over_tcp: TRUE

# Track GTP session
# TRUE or FALSE (case-insensitive)
#gtp.track_gtp_session: FALSE

# Use this setting to decode the Transparent Containers in the SRVCC PS-to-CS messages.
# This is needed until there's a reliable way to determine the contents of the transparent containers.
# One of: Don't decode, Assume UTRAN target
# (case-insensitive).
#gtpv2.decode_srvcc_p2c_trans_cont_target: Don't decode

# Request/reply pair matches only if their timestamps are closer than that value, in ms (default 0, i.e. don't use timestamps)
# A decimal number
#gtpv2.pair_max_interval: 0

# H.225 Server TLS Port
# A decimal number
#h225.tls.port: 1300

# Whether the H.225 dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#h225.reassembly: TRUE

# ON - display tunnelled H.245 inside H.225.0 tree, OFF - display tunnelled H.245 in root tree after H.225.0
# TRUE or FALSE (case-insensitive)
#h225.h245_in_tree: TRUE

# ON - display tunnelled protocols inside H.225.0 tree, OFF - display tunnelled protocols in root tree after H.225.0
# TRUE or FALSE (case-insensitive)
#h225.tp_in_tree: TRUE

# Whether the H.245 dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#h245.reassembly: TRUE

# Whether the dissector should show short names or the long names from the standard
# TRUE or FALSE (case-insensitive)
#h245.shorttypes: FALSE

# Whether the dissector should print items of h245 Info column in reversed order
# TRUE or FALSE (case-insensitive)
#h245.prepend: FALSE

# Desegment H.501 messages that span more TCP segments
# TRUE or FALSE (case-insensitive)
#h501.desegment: TRUE

# Maintain relationships between transactions and contexts and display an extra tree showing context data
# TRUE or FALSE (case-insensitive)
#h248.ctx_info: FALSE

# Desegment H.248 messages that span more TCP segments
# TRUE or FALSE (case-insensitive)
#h248.desegment: TRUE

# The dynamic payload type which will be interpreted as H264; The value must be greater than 95
# A decimal number
#h263p.dynamic.payload.type: 0

# Dynamic payload types which will be interpreted as H264; Values must be in the range 96 - 127
# A string denoting an positive integer range (e.g., "1-20,30-40")
#h264.dynamic.payload.type: 

# Dynamic payload types which will be interpreted as H265; Values must be in the range 96 - 127
# A string denoting an positive integer range (e.g., "1-20,30-40")
#h265.dynamic.payload.type: 

# Whether the HART-IP dissector should desegment all messages spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#hart_ip.desegment: TRUE

# Whether the hazel dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#hzlcst.desegment: TRUE

# The ethernet type used for L2 communications
# A decimal number
#hcrt.dissector_ethertype: 61522

# Specifies that the raw text of the HL7 message should be displayed in addition to the dissection tree
# TRUE or FALSE (case-insensitive)
#hl7.display_raw: FALSE

# Specifies that the LLP session information should be displayed (Start/End Of Block) in addition to the dissection tree
# TRUE or FALSE (case-insensitive)
#hl7.display_llp: FALSE

# Set the port for HNBAP messages (Default of 29169)
# A decimal number
#hnbap.port: 29169

# Whether the HPFEEDS dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#hpfeeds.desegment_hpfeeds_messages: TRUE

# Try to decode the payload using an heuristic sub-dissector
# TRUE or FALSE (case-insensitive)
#hpfeeds.try_heuristic: TRUE

# Whether the HTTP dissector should reassemble headers of a request spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#http.desegment_headers: TRUE

# Whether the HTTP dissector should use the "Content-length:" value, if present, to reassemble the body of a request spanning multiple TCP segments, and reassemble chunked data spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#http.desegment_body: TRUE

# Whether to reassemble bodies of entities that are transferred using the "Transfer-Encoding: chunked" method
# TRUE or FALSE (case-insensitive)
#http.dechunk_body: TRUE

# Whether to uncompress entity bodies that are compressed using "Content-Encoding: "
# TRUE or FALSE (case-insensitive)
#http.decompress_body: TRUE

# SCTP Ports range
# A string denoting an positive integer range (e.g., "1-20,30-40")
#http.sctp.port: 80

# SSL/TLS Ports range
# A string denoting an positive integer range (e.g., "1-20,30-40")
#http.tls.port: 443

# The UDP port for RROCE messages (default 4791)
# A decimal number
#infiniband.rroce.port: 4791

# Try to decode a packet using an heuristic sub-dissector before using Decode As
# TRUE or FALSE (case-insensitive)
#infiniband.try_heuristic_first: TRUE

# Maximum number of batch requests allowed
# A decimal number
#icep.max_batch_requests: 64

# Maximum length allowed of an ICEP string
# A decimal number
#icep.max_ice_string_len: 512

# Maximum number of context pairs allowed
# A decimal number
#icep.max_ice_context_pairs: 64

# Whether the 128th and following bytes of the ICMP payload should be decoded as MPLS extensions or as a portion of the original packet
# TRUE or FALSE (case-insensitive)
#icmp.favor_icmp_mpls: FALSE

# Length of the Cause of Transmission Field, configurable in '101 and fixed at 2 octets with '104
# One of: 1 octet, 2 octet
# (case-insensitive).
#iec60870_101.cot_len: 1 octet

# Length of the Common ASDU Address Field, configurable in '101 and fixed at 2 octets with '104
# One of: 1 octet, 2 octet
# (case-insensitive).
#iec60870_101.asdu_addr_len: 1 octet

# Length of the Information Object Address Field, configurable in '101 and fixed at 3 octets with '104
# One of: 2 octet, 3 octet
# (case-insensitive).
#iec60870_101.asdu_ioa_len: 2 octet

# Whether fragmented 802.11 datagrams should be reassembled
# TRUE or FALSE (case-insensitive)
#wlan.defragment: TRUE

# Don't dissect 802.11n draft HT elements (which might contain duplicate information).
# TRUE or FALSE (case-insensitive)
#wlan.ignore_draft_ht: FALSE

# Whether retransmitted 802.11 frames should be subdissected
# TRUE or FALSE (case-insensitive)
#wlan.retransmitted: TRUE

# Some 802.11 cards include the FCS at the end of a packet, others do not.
# TRUE or FALSE (case-insensitive)
#wlan.check_fcs: FALSE

# Whether to validate the FCS checksum or not.
# TRUE or FALSE (case-insensitive)
#wlan.check_checksum: FALSE

# Some 802.11 cards leave the Protection bit set even though the packet is decrypted, and some also leave the IV (initialization vector).
# One of: No, Yes - without IV, Yes - with IV
# (case-insensitive).
#wlan.ignore_wep: No

# Whether to enable MIC Length override or not.
# TRUE or FALSE (case-insensitive)
#wlan.wpa_key_mic_len_enable: FALSE

# Some Key MIC lengths are greater than 16 bytes, so set the length you require
# A decimal number
#wlan.wpa_key_mic_len: 0

# Enable WEP and WPA/WPA2 decryption
# TRUE or FALSE (case-insensitive)
#wlan.enable_decryption: TRUE

# (Hexadecimal) Ethertype used to indicate IEEE 802.15.4 frame.
# A hexadecimal number
#wpan.802154_ethertype: 0x809a

# The FCS format in the captured payload
# One of: TI CC24xx metadata, ITU-T CRC-16, ITU-T CRC-32
# (case-insensitive).
#wpan.fcs_format: ITU-T CRC-16

# Dissect payload only if FCS is valid.
# TRUE or FALSE (case-insensitive)
#wpan.802154_fcs_ok: TRUE

# Match frames with ACK request to ACK packets
# TRUE or FALSE (case-insensitive)
#wpan.802154_ack_tracking: FALSE

# Parse assuming 802.15.4e quirks for compatibility
# TRUE or FALSE (case-insensitive)
#wpan.802154e_compatibility: FALSE

# Specifies the security suite to use for 802.15.4-2003 secured frames (only supported suites are listed). Option ignored for 802.15.4-2006 and unsecured frames.
# One of: AES-128 Encryption, 128-bit Integrity Protection, AES-128 Encryption, 64-bit Integrity Protection, AES-128 Encryption, 32-bit Integrity Protection
# (case-insensitive).
#wpan.802154_sec_suite: AES-128 Encryption, 64-bit Integrity Protection

# Set if the manufacturer extends the authentication data with the security header. Option ignored for 802.15.4-2006 and unsecured frames.
# TRUE or FALSE (case-insensitive)
#wpan.802154_extend_auth: TRUE

# (Hexadecimal) Ethertype used to indicate IEEE 802.1ah tag.
# A hexadecimal number
#ieee8021ah.8021ah_ethertype: 0x88e7

# Whether the iFCP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#ifcp.desegment: TRUE

# Whether the ILP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#ilp.desegment_ilp_messages: TRUE

# Whether to use heuristics for post-STARTTLS detection of encrypted IMAP conversations
# TRUE or FALSE (case-insensitive)
#imap.ssl_heuristic: TRUE

# TCAP Subsystem numbers used for INAP
# A string denoting an positive integer range (e.g., "1-20,30-40")
#inap.ssn: 106,241

# Whether the IPDC dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#ipdc.desegment_ipdc_messages: TRUE

# Range of session IDs to be decoded as SAMIS-TYPE-1 records
# A string denoting an positive integer range (e.g., "1-20,30-40")
#ipdr.sessions.samis_type_1: 

# Dissect IPMB commands
# TRUE or FALSE (case-insensitive)
#ipmi.dissect_bus_commands: FALSE

# FRU Language Code is English; strings are ASCII+LATIN1 (vs. Unicode)
# TRUE or FALSE (case-insensitive)
#ipmi.fru_langcode_is_english: TRUE

# Do not search for responses coming after this timeout (milliseconds)
# A decimal number
#ipmi.response_after_req: 5000

# Allow for responses before requests (milliseconds)
# A decimal number
#ipmi.response_before_req: 0

# Format of messages embedded into Send/Get/Forward Message
# One of: None, IPMB, Session-based (LAN, ...), Use heuristics
# (case-insensitive).
#ipmi.msgfmt: Use heuristics

# Selects which OEM format is used for commands that IPMI does not define
# One of: None, Pigeon Point Systems
# (case-insensitive).
#ipmi.selected_oem: None

# Whether the IPv4 type-of-service field should be decoded as a Differentiated Services field (see RFC2474/RFC2475)
# TRUE or FALSE (case-insensitive)
#ip.decode_tos_as_diffserv: TRUE

# Whether fragmented IPv4 datagrams should be reassembled
# TRUE or FALSE (case-insensitive)
#ip.defragment: TRUE

# Whether the IPv4 summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#ip.summary_in_tree: TRUE

# Whether to validate the IPv4 checksum
# TRUE or FALSE (case-insensitive)
#ip.check_checksum: FALSE

# Whether to correct for TSO-enabled (TCP segmentation offload) hardware captures, such as spoofing the IP packet length
# TRUE or FALSE (case-insensitive)
#ip.tso_support: TRUE

# Whether to look up IP addresses in each MaxMind database we have loaded
# TRUE or FALSE (case-insensitive)
#ip.use_geoip: TRUE

# Whether to interpret the originally reserved flag as security flag
# TRUE or FALSE (case-insensitive)
#ip.security_flag: FALSE

# Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port
# TRUE or FALSE (case-insensitive)
#ip.try_heuristic_first: FALSE

# Whether fragmented IPv6 datagrams should be reassembled
# TRUE or FALSE (case-insensitive)
#ipv6.defragment: TRUE

# Whether the IPv6 summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#ipv6.summary_in_tree: TRUE

# Whether to look up IPv6 addresses in each MaxMind database we have loaded
# TRUE or FALSE (case-insensitive)
#ipv6.use_geoip: TRUE

# Check that all RPL Source Routed packets conform to RFC 6554 and do not visit a node more than once
# TRUE or FALSE (case-insensitive)
#ipv6.perform_strict_rpl_srh_rfc_checking: FALSE

# Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port
# TRUE or FALSE (case-insensitive)
#ipv6.try_heuristic_first: FALSE

# Whether to display IPv6 extension headers as a separate protocol or a sub-protocol of the IPv6 packet
# TRUE or FALSE (case-insensitive)
#ipv6.exthdr_under_root_protocol_tree: FALSE

# If enabled the Length field in octets will be hidden
# TRUE or FALSE (case-insensitive)
#ipv6.exthdr_hide_len_oct_field: FALSE

# Whether to correct for TSO-enabled (TCP segmentation offload) hardware captures, such as spoofing the IPv6 packet length
# TRUE or FALSE (case-insensitive)
#ipv6.tso_support: FALSE

# The iSCSI protocol version
# One of: Draft 08, Draft 09, Draft 11, Draft 12, Draft 13
# (case-insensitive).
#iscsi.protocol_version: Draft 13

# Whether the iSCSI dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#iscsi.desegment_iscsi_messages: TRUE

# When enabled, packets that appear bogus are ignored
# TRUE or FALSE (case-insensitive)
#iscsi.bogus_pdu_filter: TRUE

# Ignore packets that haven't set the F bit when they should have
# TRUE or FALSE (case-insensitive)
#iscsi.demand_good_f_bit: FALSE

# Treat packets whose data segment length is greater than this value as bogus
# A decimal number
#iscsi.bogus_pdu_max_data_len: 262144

# Range of iSCSI target ports(default 3260)
# A string denoting an positive integer range (e.g., "1-20,30-40")
#iscsi.target_ports: 3260

# System port number of iSCSI target
# A decimal number
#iscsi.target_system_port: 860

# The protocol running on the D channel
# One of: LAPD, DPNSS
# (case-insensitive).
#isdn.dchannel_protocol: LAPD

# Range of iSER target ports(default 3260)
# A string denoting an positive integer range (e.g., "1-20,30-40")
#iser.target_ports: 3260

# The dynamic payload type which will be interpreted as ISMACryp
# A decimal number
#ismacryp.dynamic.payload.type: 0

# ISMACryp version
# One of: ISMACryp v1.1, ISMACryp v2.0
# (case-insensitive).
#ismacryp.version: ISMACryp v1.1

# Indicates whether or not the ISMACryp version deduced from RTP payload type, if present, is used or whether the version above is used
# TRUE or FALSE (case-insensitive)
#ismacryp.override_rtp_pt: FALSE

# Set the length of the IV in the ISMACryp AU Header in bytes
# A decimal number
#ismacryp.iv_length: 4

# Set the length of the Delta IV in the ISMACryp AU Header in bytes
# A decimal number
#ismacryp.delta_iv_length: 0

# Set the length of the Key Indicator in the ISMACryp AU Header in bytes
# A decimal number
#ismacryp.key_indicator_length: 0

# Indicates whether or not the Key Indicator is present in all AU Headers (T/F)
# TRUE or FALSE (case-insensitive)
#ismacryp.key_indicator_per_au_flag: FALSE

# Indicates whether or not selective encryption is enabled (T/F)
# TRUE or FALSE (case-insensitive)
#ismacryp.selective_encryption: TRUE

# Indicates whether or not slice start / end is present (T/F)
# TRUE or FALSE (case-insensitive)
#ismacryp.slice_indication: FALSE

# Indicates whether or not padding information is present (T/F)
# TRUE or FALSE (case-insensitive)
#ismacryp.padding_indication: FALSE

# RFC3640 mode
# One of: aac-hbr, mpeg4-video, avc-video
# (case-insensitive).
#ismacryp.rfc3640_mode: avc-video

# Indicates use of user mode instead of RFC3640 modes (T/F)
# TRUE or FALSE (case-insensitive)
#ismacryp.user_mode: FALSE

# Set the length of the AU size in the AU Header in bits
# A decimal number
#ismacryp.au_size_length: 0

# Set the length of the AU index in the AU Header in bits
# A decimal number
#ismacryp.au_index_length: 0

# Set the length of the AU delta index in the AU Header in bits
# A decimal number
#ismacryp.au_index_delta_length: 0

# Set the length of the CTS delta field in the AU Header in bits
# A decimal number
#ismacryp.cts_delta_length: 0

# Set the length of the DTS delta field in the AU Header in bits
# A decimal number
#ismacryp.dts_delta_length: 0

# Indicates whether or not the RAP field is present in the AU Header (T/F)
# TRUE or FALSE (case-insensitive)
#ismacryp.random_access_indication: FALSE

# Indicates the number of bits on which the stream state field is encoded in the AU Header (bits)
# A decimal number
#ismacryp.stream_state_indication: 0

# Whether the iSNS dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#isns.desegment: TRUE

# Addressing of ISO 15765. Normal or Extended
# One of: Normal addressing, Extended addressing
# (case-insensitive).
#iso15765.addressing: Normal addressing

# Window of ISO 15765 fragments
# A decimal number
#iso15765.window: 8

# Endian of the length field. Big endian or Little endian
# One of: Big endian, Little endian
# (case-insensitive).
#iso8583.len_endian: Little endian

#  charset for numbers
# One of: Digits represented as ASCII Characters, Digits represented in nibbles
# (case-insensitive).
#iso8583.charset: Digits represented as ASCII Characters

#  binary data representation
# One of: Bin data represented as Hex Ascii characters, Bin data not encoded
# (case-insensitive).
#iso8583.binencode: Bin data represented as Hex Ascii characters

# File containing a translation from object ID to string
# A path to a file
#isobus.vt.object_ids: 

# Note national variants may not be fully supported
# One of: ITU Standard, French National Standard, Israeli National Standard, Russian National Standard, Japan National Standard, Japan National Standard (TTC)
# (case-insensitive).
#isup.variant: ITU Standard

# Show the CIC value (in addition to the message type) in the Info column
# TRUE or FALSE (case-insensitive)
#isup.show_cic_in_info: TRUE

# Whether APM messages datagrams should be reassembled
# TRUE or FALSE (case-insensitive)
#isup.defragment_apm: TRUE

# The MPLS label (aka Flow Bundle ID) used by ITDM traffic.
# A hexadecimal number
#itdm.mpls_label: 0x99887

# Flow Number used by I-TDM Control Protocol traffic.
# A decimal number
#itdm.ctl_flowno: 0

# Support Implementers Guide (version 01)
# TRUE or FALSE (case-insensitive)
#iua.support_ig: FALSE

# Use SAPI values as specified in TS 48 056
# TRUE or FALSE (case-insensitive)
#iua.use_gsm_sapi_values: TRUE

# Whether IuUP Payload bits should be dissected
# TRUE or FALSE (case-insensitive)
#iuup.dissect_payload: FALSE

# The payload contains a two byte pseudoheader indicating direction and circuit_id
# TRUE or FALSE (case-insensitive)
#iuup.two_byte_pseudoheader: FALSE

# The dynamic payload type which will be interpreted as IuUP
# A decimal number
#iuup.dynamic.payload.type: 0

# Whether the trailer summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#ixiatrailer.summary_in_tree: TRUE

# Display JSON like in browsers devtool
# TRUE or FALSE (case-insensitive)
#json.compact_form: FALSE

# Enable to have correctly typed MIME media dissected as JXTA Messages.
# TRUE or FALSE (case-insensitive)
#jxta.msg.mediatype: TRUE

# Whether the JXTA dissector should reassemble messages spanning multiple UDP/TCP/SCTP segments. To use this option you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings  and enable "Reassemble fragmented IP datagrams" in the IP protocol settings.
# TRUE or FALSE (case-insensitive)
#jxta.desegment: TRUE

# No description
# TRUE or FALSE (case-insensitive)
#kafka.show_string_bytes_lengths: FALSE

# Set the SCTP port for kNet messages
# A decimal number
#knet.sctp.port: 2345

# Keyring.XML file (exported from ETS)
# A path to a file
#kip.key_file: 

# Keyring password
# A string
#kip.key_file_pwd: 

# Output file (- for stdout) for keys extracted from key file
# A path to a file
#kip.key_info_file: 

# KNX decryption key (format: 16 bytes as hex; example: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF)
# A string
#kip.key_1: 

# KNX decryption key (format: 16 bytes as hex; example: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF)
# A string
#kip.key_2: 

# KNX decryption key (format: 16 bytes as hex; example: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF)
# A string
#kip.key_3: 

# KNX decryption key (format: 16 bytes as hex; example: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF)
# A string
#kip.key_4: 

# KNX decryption key (format: 16 bytes as hex; example: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF)
# A string
#kip.key_5: 

# KNX decryption key (format: 16 bytes as hex; example: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF)
# A string
#kip.key_6: 

# KNX decryption key (format: 16 bytes as hex; example: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF)
# A string
#kip.key_7: 

# KNX decryption key (format: 16 bytes as hex; example: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF)
# A string
#kip.key_8: 

# KNX decryption key (format: 16 bytes as hex; example: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF)
# A string
#kip.key_9: 

# KNX decryption key (format: 16 bytes as hex; example: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF)
# A string
#kip.key_10: 

# Whether the Kpasswd dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#kpasswd.desegment: TRUE

# Whether the Kerberos dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#kerberos.desegment: TRUE

# Whether the dissector should try to decrypt encrypted Kerberos blobs. This requires that the proper keytab file is installed as well.
# TRUE or FALSE (case-insensitive)
#kerberos.decrypt: FALSE

# The keytab file containing all the secrets
# A path to a file
#kerberos.file: 

# KT allows binary values in keys and values. Attempt to show an ASCII representation anyway (which might be prematurely terminated by a NULL!
# TRUE or FALSE (case-insensitive)
#kt.present_key_val_as_ascii: FALSE

# Whether the L&G 8979 dissector should desegment all messages spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#lg8979.desegment: TRUE

# L2TPv3 Cookie Size
# One of: Detect, None, 4 Byte Cookie, 8 Byte Cookie
# (case-insensitive).
#l2tp.cookie_size: Detect

# L2TPv3 L2-Specific Sublayer
# One of: Detect, None, Default L2-Specific, ATM-Specific, LAPD-Specific, DOCSIS DMPT-Specific
# (case-insensitive).
#l2tp.l2_specific: Detect

# Shared secret used for control message digest authentication
# A string
#l2tp.shared_secret: 

# Use SAPI values as specified in TS 48 056
# TRUE or FALSE (case-insensitive)
#lapd.use_gsm_sapi_values: FALSE

# RTP payload type for embedded LAPD. It must be one of the dynamic types from 96 to 127. Set it to 0 to disable.
# A decimal number
#lapd.rtp_payload_type: 0

# SCTP Payload Protocol Identifier for LAPD. It is a 32 bits value from 0 to 4294967295. Set it to 0 to disable.
# A decimal number
#lapd.sctp_payload_protocol_identifier: 0

# Whether the dissector should defragment LAPDm messages spanning multiple packets.
# TRUE or FALSE (case-insensitive)
#lapdm.reassemble: TRUE

# Whether the Laplink dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#laplink.desegment_laplink_over_tcp: TRUE

# Set the SCTP port for LCSAP messages
# A decimal number
#lcsap.sctp.port: 9082

# Whether the LDAP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#ldap.desegment_ldap_messages: TRUE

# Set the port for LDAP operations over TLS
# A decimal number
#ldap.tls.port: 636

# Whether the LDP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#ldp.desegment_ldp_messages: TRUE

# Which Information will be showed at Column Information is decided by the selection
# One of: Default Column Info, PROFINET Special Column Info
# (case-insensitive).
#lldp.column_info_selection: Default Column Info

# Dissect this ethertype as LLT traffic in addition to the default, 0xCAFE.
# A hexadecimal number
#llt.alternate_ethertype: 0

# Whether LMP contains a checksum which can be checked
# TRUE or FALSE (case-insensitive)
#lmp.checksum: FALSE

# There might be plugins corresponding to different version of the specification If they are present they should be listed here.
# One of: FD1, Rel8 dec 2008
# (case-insensitive).
#log3gpp.rrc_release_version: Rel8 dec 2008

# There might be plugins corresponding to different version of the specification If they are present they should be listed here.
# One of: FD1, Rel8 dec 2008
# (case-insensitive).
#log3gpp.nas_eps_release_version: Rel8 dec 2008

# Use oneline info column by replace all new line characters by spaces
# TRUE or FALSE (case-insensitive)
#logcat.oneline_info_column: TRUE

# Swap frame control bytes (needed for some APs
# TRUE or FALSE (case-insensitive)
#lwapp.swap_fc: FALSE

# Whether to validate the LWL4 crc when crc bit is not set
# TRUE or FALSE (case-insensitive)
#lwl4.check_crc: TRUE

# 128-bit decryption key in hexadecimal format
# A string
#lwm.lwmes_key: 

# Version used by Wireshark
# One of: Internet Draft version 2, Internet Draft version 8, RFC 4165
# (case-insensitive).
#m2pa.version: RFC 4165

# Set the port for M2PA messages (default: 3565)
# A decimal number
#m2pa.port: 3565

# The value of the parameter tag for protocol data 1
# One of: 0x000e (Draft 7), 0x0300 (RFC3331)
# (case-insensitive).
#m2ua.protocol_data_1_tag: 0x0300 (RFC3331)

# Version used by Wireshark
# One of: Internet Draft version 5, Internet Draft version 6, Internet Draft version 7, RFC 4666
# (case-insensitive).
#m3ua.version: RFC 4666

# TSN size in bits, either 6 or 14 bit
# One of: 6 bits, 14 bits
# (case-insensitive).
#mac.tsn_size: 6 bits

# Number of Re-Transmits before expert warning triggered
# A decimal number
#mac-lte.retx_count_warn: 3

# Attempt to decode BCH, PCH and CCCH data using LTE RRC dissector
# TRUE or FALSE (case-insensitive)
#mac-lte.attempt_rrc_decode: TRUE

# Attempt to dissect frames that have failed CRC check
# TRUE or FALSE (case-insensitive)
#mac-lte.attempt_to_dissect_crc_failures: FALSE

# Will call LTE RLC dissector with standard settings as per RRC spec
# TRUE or FALSE (case-insensitive)
#mac-lte.attempt_to_dissect_srb_sdus: TRUE

# Will call LTE RLC dissector for MCH LCID 0
# TRUE or FALSE (case-insensitive)
#mac-lte.attempt_to_dissect_mcch: FALSE

# Call RLC dissector MTCH LCIDs
# TRUE or FALSE (case-insensitive)
#mac-lte.call_rlc_for_mtch: FALSE

# Set whether LCID -> drb Table is taken from static table (below) or from info learned from control protocol (e.g. RRC)
# One of: From static table, From configuration protocol
# (case-insensitive).
#mac-lte.lcid_to_drb_mapping_source: From static table

# If any BSR report is >= this number, an expert warning will be added
# A decimal number
#mac-lte.bsr_warn_threshold: 50

# Track status of SRs, providing links between requests, failure indications and grants
# TRUE or FALSE (case-insensitive)
#mac-lte.track_sr: TRUE

# Can show PHY, MAC or RLC layer info in Info column
# One of: PHY Info, MAC Info, RLC Info
# (case-insensitive).
#mac-lte.layer_to_show: RLC Info

# Attempt to decode 6 bytes of Contention Resolution body as an UL CCCH PDU
# TRUE or FALSE (case-insensitive)
#mac-lte.decode_cr_body: FALSE

# Apply DRX config and show DRX state within each UE
# TRUE or FALSE (case-insensitive)
#mac-lte.show_drx: FALSE

# Add as a generated field the middle of the range indicated by the BSR index
# TRUE or FALSE (case-insensitive)
#mac-lte.show_bsr_median: FALSE

# Attempt to decode BCCH, PCCH and CCCH data using NR RRC dissector
# TRUE or FALSE (case-insensitive)
#mac-nr.attempt_rrc_decode: TRUE

# Will call NR RLC dissector with standard settings as per RRC spec
# TRUE or FALSE (case-insensitive)
#mac-nr.attempt_to_dissect_srb_sdus: TRUE

# Set whether LCID -> drb Table is taken from static table (below) or from info learned from control protocol (i.e. RRC)
# One of: From static table, From configuration protocol
# (case-insensitive).
#mac-nr.lcid_to_drb_mapping_source: From static table

# The name of the file containing the mate module's configuration
# A path to a file
#mate.config: 

# Decode control data received on "usb.control" with an unknown interface class as MBIM
# TRUE or FALSE (case-insensitive)
#mbim.control_decode_unknown_itf: FALSE

# Format used for SMS PDU decoding
# One of: Automatic, 3GPP, 3GPP2
# (case-insensitive).
#mbim.sms_pdu_format: Automatic

# Set the UDP port for the MCPE Server
# A decimal number
#mcpe.udp.port: 19132

# A frame is considered for decoding as MDSHDR if either ethertype is 0xFCFC or zero. Turn this flag off if you don't want ethertype zero to be decoded as MDSHDR. This might be useful to avoid problems with test frames.
# TRUE or FALSE (case-insensitive)
#mdshdr.decode_if_etype_zero: FALSE

# Set the SCTP port for MEGACO text messages
# A decimal number
#megaco.sctp.txt_port: 2944

# Specifies that the raw text of the MEGACO message should be displayed instead of (or in addition to) the dissection tree
# TRUE or FALSE (case-insensitive)
#megaco.display_raw_text: TRUE

# Specifies that the dissection tree of the MEGACO message should be displayed instead of (or in addition to) the raw text
# TRUE or FALSE (case-insensitive)
#megaco.display_dissect_tree: TRUE

# Maintain relationships between transactions and contexts and display an extra tree showing context data
# TRUE or FALSE (case-insensitive)
#megaco.ctx_info: FALSE

# Whether the MEMCACHE dissector should reassemble headers of a request spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#memcache.desegment_headers: TRUE

# Whether the memcache dissector should reassemble PDUs spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#memcache.desegment_pdus: TRUE

# Set the UDP port for gateway messages (if other than the default of 2427)
# A decimal number
#mgcp.tcp.gateway_port: 2427

# Set the TCP port for gateway messages (if other than the default of 2427)
# A decimal number
#mgcp.udp.gateway_port: 2427

# Set the TCP port for callagent messages (if other than the default of 2727)
# A decimal number
#mgcp.tcp.callagent_port: 2727

# Set the UDP port for callagent messages (if other than the default of 2727)
# A decimal number
#mgcp.udp.callagent_port: 2727

# Specifies that the raw text of the MGCP message should be displayed instead of (or in addition to) the dissection tree
# TRUE or FALSE (case-insensitive)
#mgcp.display_raw_text: FALSE

# Display the number of MGCP messages found in a packet in the protocol column.
# TRUE or FALSE (case-insensitive)
#mgcp.display_mgcp_message_count: FALSE

# Display multipart bodies with no media type dissector as raw text (may cause problems with binary data).
# TRUE or FALSE (case-insensitive)
#mime_multipart.display_unknown_body_as_text: FALSE

# Remove any base64 content-transfer encoding from bodies. This supports export of the body and its further dissection.
# TRUE or FALSE (case-insensitive)
#mime_multipart.remove_base64_encoding: FALSE

# Dissect payload only if MIC is valid.
# TRUE or FALSE (case-insensitive)
#mle.meshlink_mic_ok: FALSE

# Register Format
# One of: UINT16     , INT16      , UINT32     , INT32      , IEEE FLT   , MODICON FLT
# (case-insensitive).
#modbus.mbus_register_format: UINT16     

# Whether the Modbus RTU dissector should desegment all messages spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#mbrtu.desegment: TRUE

# Whether to validate the CRC
# TRUE or FALSE (case-insensitive)
#mbrtu.crc_verification: FALSE

# Whether the Modbus RTU dissector should desegment all messages spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#mbtcp.desegment: TRUE

# The dynamic payload type which will be interpreted as MP4V-ES
# A decimal number
#mp4v-es.dynamic.payload.type: 0

# Whether the section dissector should verify the CRC or checksum
# TRUE or FALSE (case-insensitive)
#mpeg_dsmcc.verify_crc: FALSE

# Whether the section dissector should verify the CRC
# TRUE or FALSE (case-insensitive)
#mpeg_sect.verify_crc: FALSE

# Lowest label is used to segregate flows inside a pseudowire
# TRUE or FALSE (case-insensitive)
#mpls.flowlabel_in_mpls_header: FALSE

# Enable to allow non-zero Length in Control Word. This may be needed to correctly decode traffic from some legacy devices which generate non-zero Length even if there is no padding in the packet. Note that Length should have proper value (dissector checks this anyway).
# 
# Disable to blame all packets with CW.Length <> 0. This conforms to RFC4717.
# TRUE or FALSE (case-insensitive)
#mplspwatmaal5sdu.allow_cw_length_nonzero_aal5: FALSE

# Enable to use reserved bits (8..9) of Control Word as an extension of CW.Length. This may be needed to correctly decode traffic from some legacy devices which uses reserved bits as extension of Length
# 
# Disable to blame all packets with CW.Reserved <> 0. This conforms to RFC4717.
# TRUE or FALSE (case-insensitive)
#mplspwatmaal5sdu.extend_cw_length_with_rsvd_aal5: FALSE

# Enable to allow non-zero Length in Control Word. This may be needed to correctly decode traffic from some legacy devices which generate non-zero Length even if there is no padding in the packet. Note that Length should have proper value (dissector checks this anyway).
# 
# Disable to blame all packets with CW.Length <> 0. This conforms to RFC4717.
# TRUE or FALSE (case-insensitive)
#mplspwatmn1cw.allow_cw_length_nonzero: FALSE

# Enable to use reserved bits (8..9) of Control Word as an extension of CW.Length. This may be needed to correctly decode traffic from some legacy devices which uses reserved bits as extension of Length
# 
# Disable to blame all packets with CW.Reserved <> 0. This conforms to RFC4717.
# TRUE or FALSE (case-insensitive)
#mplspwatmn1cw.extend_cw_length_with_rsvd: FALSE

# To use this option you must also enable "Analyze TCP sequence numbers". 
# TRUE or FALSE (case-insensitive)
#mptcp.analyze_mptcp: TRUE

# In case you don't capture the key, it will use the first DSN seen
# TRUE or FALSE (case-insensitive)
#mptcp.relative_sequence_numbers: TRUE

# Scales logarithmically with the number of packetsYou need to capture the handshake for this to work."Map TCP subflows to their respective MPTCP connections"
# TRUE or FALSE (case-insensitive)
#mptcp.analyze_mappings: FALSE

# (Greedy algorithm: Scales linearly with number of subflows and logarithmic scaling with number of packets)You need to enable DSS mapping analysis for this option to work
# TRUE or FALSE (case-insensitive)
#mptcp.intersubflows_retransmission: FALSE

# Whether the MQ dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#mq.desegment: TRUE

# Whether the MQ dissector should reassemble MQ messages spanning multiple TSH segments
# TRUE or FALSE (case-insensitive)
#mq.reassembly: TRUE

# When dissecting PCF there can be a lot of parameters. You can limit the number of parameter decoded, before it continue with the next PCF.
# A decimal number
#mqpcf.maxprm: 999

# When dissecting a parameter of a PCFm, if it is a StringList, IntegerList or Integer64 List,  You can limit the number of elements displayed, before it continues with the next Parameter.
# A decimal number
#mqpcf.maxlst: 20000

# Show Publish Message as text
# TRUE or FALSE (case-insensitive)
#mqtt.show_msg_as_text: FALSE

# Specifies that the raw text of the MSRP message should be displayed in addition to the dissection tree
# TRUE or FALSE (case-insensitive)
#msrp.display_raw_text: TRUE

# Where available, show which protocol and frame caused this MSRP stream to be created
# TRUE or FALSE (case-insensitive)
#msrp.show_setup_info: TRUE

# Whether the MTP2 dissector should use extended sequence numbers as described in Q.703, Annex A as a default.
# TRUE or FALSE (case-insensitive)
#mtp2.use_extended_sequence_numbers: FALSE

# Some SS7 capture hardware includes the FCS at the end of the packet, others do not.
# TRUE or FALSE (case-insensitive)
#mtp2.capture_contains_frame_check_sequence: FALSE

# Reverse the bit order inside bytes specified in Q.703.
# TRUE or FALSE (case-insensitive)
#mtp2.reverse_bit_order_mtp2: FALSE

# RTP payload types for embedded packets in RTP stream. Must be of the dynamic types from 96 to 127.
# A string denoting an positive integer range (e.g., "1-20,30-40")
#mtp2.rtp_payload_type: 

# This only works for SCCP traffic for now
# TRUE or FALSE (case-insensitive)
#mtp3.heuristic_standard: FALSE

# The SS7 standard used in MTP3 packets
# One of: ITU, ANSI, Chinese ITU, Japan
# (case-insensitive).
#mtp3.standard: ITU

# The structure of the pointcodes in ITU networks
# One of: Unstructured, 3-8-3, 4-3-4-3
# (case-insensitive).
#mtp3.itu_pc_structure: Unstructured

# The structure of the pointcodes in Japan networks
# One of: Unstructured, 7-4-5, 3-4-4-5
# (case-insensitive).
#mtp3.japan_pc_structure: Unstructured

# Use 5-bit (instead of 8-bit) SLS in ANSI MTP3 packets
# TRUE or FALSE (case-insensitive)
#mtp3.ansi_5_bit_sls: FALSE

# Use 5-bit (instead of 4-bit) SLS in Japan MTP3 packets
# TRUE or FALSE (case-insensitive)
#mtp3.japan_5_bit_sls: FALSE

# Format for point code in the address columns
# One of: Decimal, Hexadecimal, NI-Decimal, NI-Hexadecimal, Dashed
# (case-insensitive).
#mtp3.addr_format: Dashed

# Decode the spare bits of the SIO as the MSU priority (a national option in ITU)
# TRUE or FALSE (case-insensitive)
#mtp3.itu_priority: FALSE

# Whether the MySQL dissector should reassemble MySQL buffers spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#mysql.desegment_buffers: TRUE

# Whether the MySQL dissector should display the SQL query string in the INFO column.
# TRUE or FALSE (case-insensitive)
#mysql.show_sql_query: FALSE

# This should work when the NAS ciphering algorithm is NULL (5G-EEA0)
# TRUE or FALSE (case-insensitive)
#nas-5gs.null_decipher: FALSE

# Always dissect NAS EPS messages as plain
# TRUE or FALSE (case-insensitive)
#nas-eps.dissect_plain: FALSE

# This should work when the NAS ciphering algorithm is NULL (128-EEA0)
# TRUE or FALSE (case-insensitive)
#nas-eps.null_decipher: TRUE

# No description
# TRUE or FALSE (case-insensitive)
#nas-eps.user_data_container_as_ip: TRUE

# Whether the Nasdaq ITCH dissector should decode Chi X extensions.
# TRUE or FALSE (case-insensitive)
#nasdaq_itch.chi_x: TRUE

# Whether the Nasdaq-SoupTCP dissector should reassemble messages spanning multiple TCP segments.
# TRUE or FALSE (case-insensitive)
#nasdaq_soup.desegment: TRUE

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch1_content: MAC_CONTENT_DCCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch2_content: MAC_CONTENT_DCCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch3_content: MAC_CONTENT_DCCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch4_content: MAC_CONTENT_DCCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch5_content: MAC_CONTENT_CS_DTCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch6_content: MAC_CONTENT_CS_DTCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch7_content: MAC_CONTENT_CS_DTCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch8_content: MAC_CONTENT_DCCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch9_content: MAC_CONTENT_PS_DTCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch10_content: MAC_CONTENT_UNKNOWN

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch11_content: MAC_CONTENT_PS_DTCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch12_content: MAC_CONTENT_PS_DTCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch13_content: MAC_CONTENT_CS_DTCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch14_content: MAC_CONTENT_PS_DTCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch15_content: MAC_CONTENT_CCCH

# foo
# One of: MAC_CONTENT_UNKNOWN, MAC_CONTENT_DCCH, MAC_CONTENT_PS_DTCH, MAC_CONTENT_CS_DTCH, MAC_CONTENT_CCCH
# (case-insensitive).
#nbap.lch16_content: MAC_CONTENT_DCCH

# Encoding used for the IB-SG-DATA element carrying segments of information blocks
# One of: Encoding Variant 1 (TS 25.433 Annex D.2), Encoding Variant 2 (TS 25.433 Annex D.3)
# (case-insensitive).
#nbap.ib_sg_data_encoding: Encoding Variant 1 (TS 25.433 Annex D.2)

# Whether the NBD dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings
# TRUE or FALSE (case-insensitive)
#nbd.desegment_nbd_messages: TRUE

# Whether the NBSS dissector should reassemble packets spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#nbss.desegment_nbss_commands: TRUE

# Whether the NCP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#ncp.desegment: TRUE

# Whether the NCP dissector should defragment NDS messages spanning multiple reply packets.
# TRUE or FALSE (case-insensitive)
#ncp.defragment_nds: TRUE

# Dissect the NetWare Information Structure as NetWare 5.x or higher or as older NetWare 3.x.
# TRUE or FALSE (case-insensitive)
#ncp.newstyle: TRUE

# Whether the NCP dissector should echo the NDS Entry ID to name resolves to the expert table.
# TRUE or FALSE (case-insensitive)
#ncp.eid_2_expert: TRUE

# Whether the NCP dissector should echo NCP connection information to the expert table.
# TRUE or FALSE (case-insensitive)
#ncp.connection_2_expert: FALSE

# Whether the NCP dissector should echo protocol errors to the expert table.
# TRUE or FALSE (case-insensitive)
#ncp.error_2_expert: TRUE

# Whether the NCP dissector should echo server information to the expert table.
# TRUE or FALSE (case-insensitive)
#ncp.server_2_expert: TRUE

# Whether the NCP dissector should echo file open/close/oplock information to the expert table.
# TRUE or FALSE (case-insensitive)
#ncp.file_2_expert: FALSE

# Version of the NDMP protocol to assume if the version can not be automatically detected from the capture
# One of: Version 2, Version 3, Version 4, Version 5
# (case-insensitive).
#ndmp.default_protocol_version: Version 4

# Whether the NDMP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#ndmp.desegment: TRUE

# Whether the dissector should defragment NDMP messages spanning multiple packets.
# TRUE or FALSE (case-insensitive)
#ndmp.defragment: TRUE

# Whether the NDPS dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#ndps.desegment_tcp: TRUE

# Whether the NDPS dissector should reassemble fragmented NDPS messages spanning multiple SPX packets
# TRUE or FALSE (case-insensitive)
#ndps.desegment_spx: TRUE

# Whether or not the NDPS dissector should show object id's and other details
# TRUE or FALSE (case-insensitive)
#ndps.show_oid: FALSE

# Whether the NetBIOS dissector should defragment messages spanning multiple frames
# TRUE or FALSE (case-insensitive)
#netbios.defragment: TRUE

# Whether the Netsync dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#netsync.desegment_netsync_messages: TRUE

# Whether the dissector should snoop the FH to filename mappings by looking inside certain packets
# TRUE or FALSE (case-insensitive)
#nfs.file_name_snooping: FALSE

# Whether the dissector should snoop the full pathname for files for matching FH's
# TRUE or FALSE (case-insensitive)
#nfs.file_full_name_snooping: FALSE

# With this option display filters for nfs fhandles (nfs.fh.{name|full_name|hash}) will find both the request and response packets for a RPC call, even if the actual fhandle is only present in one of the packets
# TRUE or FALSE (case-insensitive)
#nfs.fhandle_find_both_reqrep: FALSE

# When enabled, this option will print the NFSv4 tag (if one exists) in the Info column in the Summary pane
# TRUE or FALSE (case-insensitive)
#nfs.display_nfsv4_tag: TRUE

# When enabled, shows only the significant NFSv4 Operations in the info column.  Others (like GETFH, PUTFH, etc) are not displayed
# TRUE or FALSE (case-insensitive)
#nfs.display_major_nfsv4_ops: TRUE

# Set the SCTP port for NGAP messages
# A decimal number
#ngap.sctp.port: 38412

# Dissect TransparentContainers that are opaque to NGAP
# TRUE or FALSE (case-insensitive)
#ngap.dissect_container: TRUE

# Select whether target NG-RAN container should be decoded automatically (based on NG Setup procedure) or manually
# One of: automatic, gNB, ng-eNB
# (case-insensitive).
#ngap.dissect_target_ng_ran_container_as: automatic

# Whether the Authentication Extension data contains the source address. Some Cisco IOS implementations forgo this part of RFC2332.
# TRUE or FALSE (case-insensitive)
#nhrp.auth_ext_has_addr: TRUE

# Whether the dissector will track and match MSG and RES calls for asynchronous NLM
# TRUE or FALSE (case-insensitive)
#nlm.msg_res_matching: FALSE

# NT Password (used to decrypt payloads)
# A string
#ntlmssp.nt_password: 

# Range of NVMe Subsystem ports(default 4420)
# A string denoting an positive integer range (e.g., "1-20,30-40")
#nvme-rdma.subsystem_ports: 4420

# Range of NVMe Subsystem ports(default 4420)
# A string denoting an positive integer range (e.g., "1-20,30-40")
#nvme-tcp.subsystem_ports: 4420

# Whether to validate the PDU header digest or not.
# TRUE or FALSE (case-insensitive)
#nvme-tcp.check_hdgst: FALSE

# Whether to validate the PDU data digest or not.
# TRUE or FALSE (case-insensitive)
#nvme-tcp.check_ddgst: FALSE

# Whether the dissector should put the internal OER data in the tree or if it should hide it
# TRUE or FALSE (case-insensitive)
#oer.display_internal_oer_fields: FALSE

# Dissect custom olsr.org message types (compatible with rfc routing agents)
# TRUE or FALSE (case-insensitive)
#olsr.ff_olsrorg: TRUE

# Dissect custom nrlolsr tc message (incompatible with rfc routing agents)
# TRUE or FALSE (case-insensitive)
#olsr.nrlolsr: TRUE

# SSL/TLS Ports range
# A string denoting an positive integer range (e.g., "1-20,30-40")
#opa.fe.tls.port: 3249-3252

# Attempt to parse mad payload even when MAD.Status is non-zero
# TRUE or FALSE (case-insensitive)
#opa.mad.parse_mad_error: FALSE

# Attempt to reassemble the mad payload of RMPP segments
# TRUE or FALSE (case-insensitive)
#opa.mad.reassemble_rmpp: TRUE

# Whether the OpenFlow dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#openflow.desegment: TRUE

# To be able to fully dissect SSDO and SPDO packages, a valid UDID for the SCM has to be provided
# A string
#opensafety.scm_udid: 00:00:00:00:00:00

# Automatically assign a detected SCM UDID (by reading SNMT->SNTM_assign_UDID_SCM) and set it for the file
# TRUE or FALSE (case-insensitive)
#opensafety.scm_udid_autoset: TRUE

# A comma-separated list of nodes to be filtered during dissection
# A string
#opensafety.filter_nodes: 

# If set to true, only nodes in the list will be shown, otherwise they will be hidden
# TRUE or FALSE (case-insensitive)
#opensafety.filter_show_nodes_in_filterlist: TRUE

# Port used by any UDP demo implementation to transport data
# A decimal number
#opensafety.network_udp_port: 9877

# UDP port used by SercosIII to transport data
# A decimal number
#opensafety.network_udp_port_sercosiii: 8755

# In an SercosIII/UDP transport stream, openSAFETY frame 2 will be expected before frame 1
# TRUE or FALSE (case-insensitive)
#opensafety.network_udp_frame_first_sercosiii: FALSE

# In the transport stream, openSAFETY frame 2 will be expected before frame 1
# TRUE or FALSE (case-insensitive)
#opensafety.network_udp_frame_first: FALSE

# Modbus/TCP words can be transcoded either big- or little endian. Default will be little endian
# TRUE or FALSE (case-insensitive)
#opensafety.mbtcp_big_endian: FALSE

# Enables additional information in the dissection for better debugging an openSAFETY trace
# TRUE or FALSE (case-insensitive)
#opensafety.debug_verbose: FALSE

# Enable heuristic dissection for openSAFETY over UDP encoded traffic
# TRUE or FALSE (case-insensitive)
#opensafety.enable_udp: TRUE

# Enable heuristic dissection for Modbus/TCP
# TRUE or FALSE (case-insensitive)
#opensafety.enable_mbtcp: TRUE

# Display the data between openSAFETY packets
# TRUE or FALSE (case-insensitive)
#opensafety.display_intergap_data: FALSE

# SPDOs may only be found in cyclic data, SSDOs/SNMTS only in acyclic data
# TRUE or FALSE (case-insensitive)
#opensafety.classify_transport: TRUE

# Port used by the openSAFETY over UDP data transport
# A decimal number
#opensafety_udp.network_udp_port: 9877

# If tls-auth detection fails, you can choose to override detection and set tls-auth yourself
# TRUE or FALSE (case-insensitive)
#openvpn.tls_auth_detection_override: FALSE

# If the parameter --tls-auth is used, the following preferences must also be defined.
# TRUE or FALSE (case-insensitive)
#openvpn.tls_auth: FALSE

# If the parameter --tls-auth is used, a HMAC header is being inserted.
# The default HMAC algorithm is SHA-1 which generates a 160 bit HMAC, therefore 20 bytes should be ok.
# The value must be between 20 (160 bits) and 64 (512 bits).
# A decimal number
#openvpn.tls_auth_hmac_size: 20

# If the parameter --tls-auth is used, an additional packet-id for replay protection is inserted after the HMAC signature. This field can either be 4 bytes or 8 bytes including an optional time_t timestamp long.
#  This option is only evaluated if tls_auth_hmac_size > 0.
#  The default value is TRUE.
# TRUE or FALSE (case-insensitive)
#openvpn.long_format: TRUE

# Whether the Openwire dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#openwire.desegment: TRUE

# Whether verbose type and length information are displayed in the protocol tree
# TRUE or FALSE (case-insensitive)
#openwire.verbose_type: FALSE

# Whether the OPSI dissector should desegment all messages spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#opsi.desegment_opsi_messages: TRUE

# Whether segmented TPKT datagrams should be reassembled
# TRUE or FALSE (case-insensitive)
#osi.tpkt_reassemble: FALSE

# Whether segmented RTSE datagrams should be reassembled. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#rtse.reassemble: TRUE

# Whether the IDMP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#idmp.desegment_idmp_messages: TRUE

# Whether segmented IDMP datagrams should be reassembled. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#idmp.reassemble: TRUE

# Reassemble fragmented P_Mul packets
# TRUE or FALSE (case-insensitive)
#p_mul.reassemble: TRUE

# Make the P_Mul dissector use relative message id number instead of absolute ones
# TRUE or FALSE (case-insensitive)
#p_mul.relative_msgid: TRUE

# Calculate sequence/acknowledgement analysis
# TRUE or FALSE (case-insensitive)
#p_mul.seq_ack_analysis: TRUE

# Type of content in Data_PDU
# One of: No decoding, BER encoded ASN.1, Compressed Data Type
# (case-insensitive).
#p_mul.decode: No decoding

# Attempt to decode parts of the message that aren't fully understood yet
# TRUE or FALSE (case-insensitive)
#papi.experimental_decode: FALSE

# SCCP (and SUA) SSNs to decode as PCAP
# A string denoting an positive integer range (e.g., "1-20,30-40")
#pcap.ssn: 

# Whether the PCLI summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#pcli.summary_in_tree: TRUE

# Show uncompressed User-Plane data as IP
# TRUE or FALSE (case-insensitive)
#pdcp-lte.show_user_plane_as_ip: TRUE

# Show unciphered Signalling-Plane data as RRC
# TRUE or FALSE (case-insensitive)
#pdcp-lte.show_signalling_plane_as_rrc: TRUE

# Do sequence number analysis
# One of: No-Analysis, Only-RLC-frames, Only-PDCP-frames
# (case-insensitive).
#pdcp-lte.check_sequence_numbers: Only-RLC-frames

# Attempt to decode ROHC data
# TRUE or FALSE (case-insensitive)
#pdcp-lte.dissect_rohc: FALSE

# Can show RLC, PDCP or Traffic layer info in Info column
# One of: RLC Info, PDCP Info, Traffic Info
# (case-insensitive).
#pdcp-lte.layer_to_show: RLC Info

# If RRC Security Info not seen, e.g. in Handover
# One of: EEA0 (NULL), EEA1 (SNOW3G), EEA2 (AES), EEA3 (ZUC)
# (case-insensitive).
#pdcp-lte.default_ciphering_algorithm: EEA0 (NULL)

# If RRC Security Info not seen, e.g. in Handover
# One of: EIA0 (NULL), EIA1 (SNOW3G), EIA2 (AES), EIA3 (ZUC)
# (case-insensitive).
#pdcp-lte.default_integrity_algorithm: EIA0 (NULL)

# N.B. only possible if build with algorithm support, and have key available and configured
# TRUE or FALSE (case-insensitive)
#pdcp-lte.decipher_signalling: TRUE

# N.B. only possible if build with algorithm support, and have key available and configured
# TRUE or FALSE (case-insensitive)
#pdcp-lte.decipher_userplane: FALSE

# N.B. only possible if build with algorithm support, and have key available and configured
# TRUE or FALSE (case-insensitive)
#pdcp-lte.verify_integrity: TRUE

# Ignore the LTE RRC security algorithm configuration, to be used when PDCP is already deciphered in the capture
# TRUE or FALSE (case-insensitive)
#pdcp-lte.ignore_rrc_sec_params: FALSE

# Show uncompressed User-Plane data as IP
# TRUE or FALSE (case-insensitive)
#pdcp-nr.show_user_plane_as_ip: TRUE

# Show unciphered Signalling-Plane data as RRC
# TRUE or FALSE (case-insensitive)
#pdcp-nr.show_signalling_plane_as_rrc: TRUE

# Do sequence number analysis
# One of: No-Analysis, Only-RLC-frames, Only-PDCP-frames
# (case-insensitive).
#pdcp-nr.check_sequence_numbers: Only-RLC-frames

# Attempt to decode ROHC data
# TRUE or FALSE (case-insensitive)
#pdcp-nr.dissect_rohc: FALSE

# Can show RLC, PDCP or Traffic layer info in Info column
# One of: RLC Info, PDCP Info, Traffic Info
# (case-insensitive).
#pdcp-nr.layer_to_show: RLC Info

# Whether the dissector should put the internal PER data in the tree or if it should hide it
# TRUE or FALSE (case-insensitive)
#per.display_internal_per_fields: FALSE

# PFCP port (default 8805)
# A decimal number
#pfcp.port_pfcp: 8805

# Track PFCP session
# TRUE or FALSE (case-insensitive)
#pfcp.track_pfcp_session: FALSE

# Whether or not UID and PID fields are dissected in big or little endian
# TRUE or FALSE (case-insensitive)
#pflog.uid_endian: TRUE

# Whether to check the validity of the PGM checksum
# TRUE or FALSE (case-insensitive)
#pgm.check_checksum: TRUE

# Whether the PIM payload is shown off of the main tree or encapsulated within the PIM options
# TRUE or FALSE (case-insensitive)
#pim.payload_tree: TRUE

# The password to used to decrypt the encrypted elements within the PKCS#12 file
# A string
#pkcs12.password: 

# Whether to try and decrypt the encrypted data within the PKCS#12 with a NULL password
# TRUE or FALSE (case-insensitive)
#pkcs12.try_null_password: FALSE

# Whether the PN-RT summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#pn_rt.summary_in_tree: TRUE

# Reassemble PNIO Fragments and get them decoded
# TRUE or FALSE (case-insensitive)
#pn_rt.desegment: TRUE

# Protocol payload type
# One of: Data, Sony FeliCa, NXP MiFare, ISO 7816
# (case-insensitive).
#pn532.prtype532: Data

# Whether the PNIO dissector is allowed to use detailed PROFIsafe dissection of cyclic data frames
# TRUE or FALSE (case-insensitive)
#pn_io.pnio_ps_selection: TRUE

# Select your Networkpath to your GSD-Files.
# A path to a directory
#pn_io.pnio_ps_networkpath: 

# Whether the POP dissector should reassemble RETR and TOP responses and spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#pop.desegment_data: TRUE

# Whether fragmented 802.11 aggregated MPDUs should be reassembled
# TRUE or FALSE (case-insensitive)
#ppi.reassemble: TRUE

# The type of PPP frame checksum (none, 16-bit, 32-bit)
# One of: None, 16-Bit, 32-Bit
# (case-insensitive).
#ppp.fcs_type: None

# Default Protocol ID to be used for PPPMuxCP
# A hexadecimal number
#ppp.default_proto_id: 0

# Whether PPP Multilink frames use 12-bit sequence numbers
# TRUE or FALSE (case-insensitive)
#mp.short_seqno: FALSE

# Maximum number of PPP Multilink fragments to try to reassemble into one frame
# A decimal number
#mp.max_fragments: 6

# Age off unreassmbled fragments after this many packets
# A decimal number
#mp.fragment_aging: 4000

# Show values of tags and lengths of data fields
# TRUE or FALSE (case-insensitive)
#pppoed.show_tags_and_lengths: FALSE

# Show the names of message, field, enum and enum_value. Show the wire type and field number format of field. Show value nodes of field and enum_value.
# TRUE or FALSE (case-insensitive)
#protobuf.show_details: FALSE

# Show all fields of bytes type as string. For example ETCD string
# TRUE or FALSE (case-insensitive)
#protobuf.bytes_as_string: FALSE

# Try to dissect all undefined length-delimited fields as string.
# TRUE or FALSE (case-insensitive)
#protobuf.try_dissect_as_string: FALSE

# Try to show all possible field types for each undefined field according to wire type.
# TRUE or FALSE (case-insensitive)
#protobuf.show_all_types: FALSE

# Properly translates vendor specific opcodes
# One of: Unknown vendor, Eastman Kodak, Canon, Nikon, Casio EX-F1, Microsoft / MTP, Olympus E series
# (case-insensitive).
#ptpip.vendor: Unknown vendor

# Whether the PVFS dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#pvfs.desegment: TRUE

# Whether the Q.931 dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#q931.desegment_h323_messages: TRUE

# Reassemble segmented Q.931 messages (Q.931 - Annex H)
# TRUE or FALSE (case-insensitive)
#q931.reassembly: TRUE

# Decode ISO/IEC cause coding standard as ITU-T
# TRUE or FALSE (case-insensitive)
#q931.iso_iec_cause_coding: FALSE

# Type of Facility encoding
# One of: Dissect facility as QSIG, Dissect facility as ETSI
# (case-insensitive).
#q932.facility_encoding: Dissect facility as QSIG

# Set the UDP base port for the Quake III Arena Server
# A decimal number
#quake3.udp.arena_port: 27960

# Set the UDP base port for the Quake III Arena Master Server
# A decimal number
#quake3.udp.master_port: 27950

# Shared secret used to decode User Passwords and validate Response Authenticators
# A string
#radius.shared_secret: 

# Whether to check or not if Response Authenticator is correct. You need to define shared secret for this to work.
# TRUE or FALSE (case-insensitive)
#radius.validate_authenticator: FALSE

# Whether to add or not to the tree the AVP's payload length
# TRUE or FALSE (case-insensitive)
#radius.show_length: FALSE

# Whether to interpret 241-246 as extended attributes according to RFC 6929
# TRUE or FALSE (case-insensitive)
#radius.disable_extended_attributes: FALSE

# The SCCP SubSystem Number for RANAP (default 142)
# A decimal number
#ranap.sccp_ssn: 142

# Attempt to dissect RRC message embedded in RRC-Container IE
# TRUE or FALSE (case-insensitive)
#ranap.dissect_rrc_container: FALSE

# Where available, show which protocol and frame caused this RDT stream to be created
# TRUE or FALSE (case-insensitive)
#rdt.show_setup_info: TRUE

# Whether fragmented RELOAD datagrams should be reassembled
# TRUE or FALSE (case-insensitive)
#reload.defragment: TRUE

# Length of the NodeId as defined in the overlay.
# A decimal number
#reload.nodeid_length: 16

# topology plugin defined in the overlay
# A string
#reload.topology_plugin: CHORD-RELOAD

# Display the third and forth bytes of the RIPv2 header as the Routing Domain field (introduced in RFC 1388 [January 1993] and obsolete as of RFC 1723 [November 1994])
# TRUE or FALSE (case-insensitive)
#rip.display_routing_domain: FALSE

# When enabled, try to reassemble SDUs from the various PDUs received
# TRUE or FALSE (case-insensitive)
#rlc.perform_reassembly: TRUE

# When enabled, if data is not present, don't report as an error, but instead add expert info to indicate that headers were omitted
# TRUE or FALSE (case-insensitive)
#rlc.header_only_mode: FALSE

# When enabled, RLC will ignore sequence numbers reported in 'Security Mode Command'/'Security Mode Complete' (RRC) messages when checking if frames are ciphered
# TRUE or FALSE (case-insensitive)
#rlc.ignore_rrc_cipher_indication: FALSE

# When enabled, RLC will assume all payloads in RLC frames are ciphered
# TRUE or FALSE (case-insensitive)
#rlc.ciphered_data: FALSE

# LI size in bits, either 7 or 15 bit
# One of: 7 bits, 15 bits, Let upper layers decide
# (case-insensitive).
#rlc.li_size: Let upper layers decide

# Attempt to keep track of PDUs for AM channels, and point out problems
# One of: No-Analysis, Only-MAC-frames, Only-RLC-frames
# (case-insensitive).
#rlc-lte.do_sequence_analysis_am: Only-MAC-frames

# Attempt to keep track of PDUs for UM channels, and point out problems
# One of: No-Analysis, Only-MAC-frames, Only-RLC-frames
# (case-insensitive).
#rlc-lte.do_sequence_analysis: Only-MAC-frames

# Call PDCP dissector for signalling PDUs.  Note that without reassembly, it canonly be called for complete PDUs (i.e. not segmented over RLC)
# TRUE or FALSE (case-insensitive)
#rlc-lte.call_pdcp_for_srb: TRUE

# Call PDCP dissector for user-plane PDUs.  Note that without reassembly, it canonly be called for complete PDUs (i.e. not segmented over RLC)
# One of: Off, 7-bit SN, 12-bit SN, 15-bit SN, 18-bit SN, Use signalled value
# (case-insensitive).
#rlc-lte.call_pdcp_for_drb: Use signalled value

# Call RRC dissector for CCCH PDUs
# TRUE or FALSE (case-insensitive)
#rlc-lte.call_rrc_for_ccch: TRUE

# Call RRC dissector for MCCH PDUs  Note that without reassembly, it canonly be called for complete PDUs (i.e. not segmented over RLC)
# TRUE or FALSE (case-insensitive)
#rlc-lte.call_rrc_for_mcch: FALSE

# Call ip dissector for MTCH PDUs  Note that without reassembly, it canonly be called for complete PDUs (i.e. not segmented over RLC)
# TRUE or FALSE (case-insensitive)
#rlc-lte.call_ip_for_mtch: FALSE

# When enabled, if data is not present, don't report as an error, but instead add expert info to indicate that headers were omitted
# TRUE or FALSE (case-insensitive)
#rlc-lte.header_only_mode: FALSE

# When enabled, attempts to re-assemble upper-layer SDUs that are split over more than one RLC PDU.  Note: does not currently support out-of-order or re-segmentation. N.B. sequence analysis must also be turned on in order for reassembly to work
# TRUE or FALSE (case-insensitive)
#rlc-lte.reassembly: TRUE

# Call PDCP dissector for signalling PDUs.  Note that without reassembly, it canonly be called for complete PDUs (i.e. not segmented over RLC)
# TRUE or FALSE (case-insensitive)
#rlc-nr.call_pdcp_for_srb: TRUE

# Call PDCP dissector for UL user-plane PDUs.  Note that without reassembly, it canonly be called for complete PDUs (i.e. not segmented over RLC)
# One of: Off, 12-bit SN, 18-bit SN, Use signalled value
# (case-insensitive).
#rlc-nr.call_pdcp_for_ul_drb: Off

# Call PDCP dissector for DL user-plane PDUs.  Note that without reassembly, it canonly be called for complete PDUs (i.e. not segmented over RLC)
# One of: Off, 12-bit SN, 18-bit SN, Use signalled value
# (case-insensitive).
#rlc-nr.call_pdcp_for_dl_drb: Off

# Call RRC dissector for CCCH PDUs
# TRUE or FALSE (case-insensitive)
#rlc-nr.call_rrc_for_ccch: TRUE

# When enabled, if data is not present, don't report as an error, but instead add expert info to indicate that headers were omitted
# TRUE or FALSE (case-insensitive)
#rlc-nr.header_only_mode: FALSE

# N.B. This should be considered experimental/incomplete, in that it doesn't try to discard reassembled state when reestablishmenment happens, or in certain packet-loss cases
# TRUE or FALSE (case-insensitive)
#rlc-nr.reassemble_um_frames: FALSE

# Whether the RPC dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#rpc.desegment_rpc_over_tcp: TRUE

# Whether the RPC dissector should defragment RPC-over-TCP messages.
# TRUE or FALSE (case-insensitive)
#rpc.defragment_rpc_over_tcp: TRUE

# Set the maximum size of RPCoverTCP PDUs.  If the size field of the record marker is larger than this value it will not be considered a valid RPC PDU.
# A decimal number
#rpc.max_tcp_pdu_size: 4194304

# Whether the RPC dissector should attempt to dissect RPC PDUs containing programs that are not known to Wireshark. This will make the heuristics significantly weaker and elevate the risk for falsely identifying and misdissecting packets significantly.
# TRUE or FALSE (case-insensitive)
#rpc.dissect_unknown_programs: FALSE

# Whether the RPC dissector should attempt to locate RPC PDU boundaries when initial fragment alignment is not known.  This may cause false positives, or slow operation.
# TRUE or FALSE (case-insensitive)
#rpc.find_fragment_start: FALSE

# Whether the RPCAP dissector should reassemble PDUs spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#rpcap.desegment_pdus: TRUE

# Whether the packets should be decoded according to the link-layer type.
# TRUE or FALSE (case-insensitive)
#rpcap.decode_content: TRUE

# Default link-layer type to use if an Open Reply packet has not been received.
# A decimal number
#rpcap.linktype: 4294967295

# RPKI-Router Protocol TCP TLS port if other than the default
# A decimal number
#rpkirtr.tcp.rpkirtr_tls.port: 324

# Controls the display of the session's client username in the info column.  This is only displayed if the packet containing it was seen during this capture session.
# TRUE or FALSE (case-insensitive)
#rsh.info_show_client_username: FALSE

# Controls the display of the session's server username in the info column.  This is only displayed if the packet containing it was seen during this capture session.
# TRUE or FALSE (case-insensitive)
#rsh.info_show_server_username: TRUE

# Controls the display of the command being run on the server by this session in the info column.  This is only displayed if the packet containing it was seen during this capture session.
# TRUE or FALSE (case-insensitive)
#rsh.info_show_command: FALSE

# Use ipaccess nanoBTS specific definitions for RSL
# TRUE or FALSE (case-insensitive)
#gsm_abis_rsl.use_ipaccess_rsl: FALSE

# The Physical Context Information field is not specified This information should be not be analysed by BSC, but merely forwarded from one TRX/channel to another.
# TRUE or FALSE (case-insensitive)
#gsm_abis_rsl.dissect_phy_ctx_inf: TRUE

# Specifies whether Wireshark should decode and display sub-messages within BUNDLE messages
# TRUE or FALSE (case-insensitive)
#rsvp.process_bundle: TRUE

# Specifies how Wireshark should dissect generalized labels
# One of: data (no interpretation), SONET/SDH ("S, U, K, L, M" scheme), Wavelength Label (fixed or flexi grid), ODUk Label
# (case-insensitive).
#rsvp.generalized_label_options: data (no interpretation)

# Set the TCP port for RSYNC messages
# A decimal number
#rsync.tcp_port: 873

# Whether the RSYNC dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#rsync.desegment: TRUE

# RTCDC SCTP PPID if other than the default
# A decimal number
#rtcdc.sctp.ppi: 50

# Where available, show which protocol and frame caused this RTCP stream to be created
# TRUE or FALSE (case-insensitive)
#rtcp.show_setup_info: TRUE

# Try to work out network delay by comparing time between packets as captured and delays as seen by endpoint
# TRUE or FALSE (case-insensitive)
#rtcp.show_roundtrip_calculation: FALSE

# Minimum (absolute) calculated roundtrip delay time in milliseconds that should be reported
# A decimal number
#rtcp.roundtrip_min_threshhold: 10

# Whether the RTMPT dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#rtmpt.desegment: TRUE

# The largest acceptable packet size for reassembly
# A decimal number
#rtmpt.max_packet_size: 32768

# Where available, show which protocol and frame caused this RTP stream to be created
# TRUE or FALSE (case-insensitive)
#rtp.show_setup_info: TRUE

# Whether subdissector can request RTP streams to be reassembled
# TRUE or FALSE (case-insensitive)
#rtp.desegment_rtp_streams: TRUE

# If an RTP version 0 packet is encountered, it can be treated as an invalid or ZRTP packet, a CLASSIC-STUN packet, or a T.38 packet
# One of: Invalid or ZRTP packets, STUN packets, CLASSIC-STUN packets, T.38 packets, SPRT packets
# (case-insensitive).
#rtp.version0_type: Invalid or ZRTP packets

# Payload Type for RFC2198 Redundant Audio Data
# A decimal number
#rtp.rfc2198_payload_type: 99

# This is the value of the Payload Type field that specifies RTP Events
# A decimal number
#rtpevent.event_payload_type_value: 101

# This is the value of the Payload Type field that specifies Cisco Named Signaling Events
# A decimal number
#rtpevent.cisco_nse_payload_type_value: 100

# This is the value of the Payload Type field that specifies RTP-MIDI
# A decimal number
#rtpmidi.midi_payload_type_value: 0

# Specifies that RTP/RTCP/T.38/MSRP/etc streams are decoded based upon port numbers found in RTPproxy answers
# TRUE or FALSE (case-insensitive)
#rtpproxy.establish_conversation: TRUE

# Maximum timeout value in waiting for reply from RTPProxy (in milliseconds).
# A decimal number
#rtpproxy.reply.timeout: 1000

# Specifies the maximum number of samples dissected in a DATA_BATCH submessage. Increasing this value may affect performances if the trace has a lot of big batched samples.
# A decimal number
#rtps.max_batch_samples_dissected: 16

# Shows the Topic Name and Type Name of the samples.
# TRUE or FALSE (case-insensitive)
#rtps.enable_topic_info: FALSE

# Enables the reassembly of DATA_FRAG submessages.
# TRUE or FALSE (case-insensitive)
#rtps.enable_rtps_reassembly: FALSE

# Whether the RTSP dissector should reassemble headers of a request spanning multiple TCP segments.  To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#rtsp.desegment_headers: TRUE

# Whether the RTSP dissector should use the "Content-length:" value to desegment the body of a request spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#rtsp.desegment_body: TRUE

# Set the port for RUA messages (Default of 29169)
# A decimal number
#rua.port: 29169

# S101 TCP port if other than the default
# A decimal number
#s101.tcp.port: 9000

# Set the SCTP port for S1AP messages
# A decimal number
#s1ap.sctp.port: 36412

# Dissect TransparentContainers that are opaque to S1AP
# TRUE or FALSE (case-insensitive)
#s1ap.dissect_container: TRUE

# Select whether LTE TransparentContainer should be dissected as NB-IOT or legacy LTE
# One of: Automatic, Legacy LTE, NB-IoT
# (case-insensitive).
#s1ap.dissect_lte_container_as: Automatic

# Show length of text field
# TRUE or FALSE (case-insensitive)
#sametime.show_length: FALSE

# reassemble packets
# TRUE or FALSE (case-insensitive)
#sametime.reassemble: TRUE

# Whether the SASP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#sasp.desegment_sasp_messages: TRUE

# The source point code (usually MSC) (to determine whether message is uplink or downlink)
# A hexadecimal number
#sccp.source_pc: 0

# Show parameter length in the protocol tree
# TRUE or FALSE (case-insensitive)
#sccp.show_length: FALSE

# Whether SCCP messages should be reassembled
# TRUE or FALSE (case-insensitive)
#sccp.defragment_xudt: TRUE

# Whether to keep information about messages and their associations
# TRUE or FALSE (case-insensitive)
#sccp.trace_sccp: FALSE

# Show SLR, DLR, and CAUSE Parameters in the Information Column of the Summary
# TRUE or FALSE (case-insensitive)
#sccp.show_more_info: FALSE

# Set the source and destination addresses to the GT digits (if present).  This may affect TCAP's ability to recognize which messages belong to which TCAP session.
# TRUE or FALSE (case-insensitive)
#sccp.set_addresses: FALSE

# The protocol which should be used to dissect the payload if nothing else has claimed it
# A string
#sccp.default_payload: 

# When Target Cannot Be Identified, Decode SCSI Messages As
# One of: Block Device, Sequential Device, Object Based Storage Device, Medium Changer Device, Multimedia Device
# (case-insensitive).
#scsi.decode_scsi_messages_as: Block Device

# Whether fragmented SCSI DATA IN/OUT transfers should be reassembled
# TRUE or FALSE (case-insensitive)
#scsi.defragment: FALSE

# Show source and destination port numbers in the protocol tree
# TRUE or FALSE (case-insensitive)
#sctp.show_port_numbers_in_tree: TRUE

# The type of checksum used in SCTP packets
# One of: None, Adler 32, CRC 32c, Automatic
# (case-insensitive).
#sctp.checksum: None

# Show always SCTP control chunks in the Info column
# TRUE or FALSE (case-insensitive)
#sctp.show_always_control_chunks: TRUE

# Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port or PPI
# TRUE or FALSE (case-insensitive)
#sctp.try_heuristic_first: FALSE

# Whether fragmented SCTP user messages should be reassembled
# TRUE or FALSE (case-insensitive)
#sctp.reassembly: TRUE

# Match TSNs and their SACKs
# TRUE or FALSE (case-insensitive)
#sctp.tsn_analysis: TRUE

# Match verification tags(CPU intense)
# TRUE or FALSE (case-insensitive)
#sctp.association_index: FALSE

# Dissect upper layer protocols
# TRUE or FALSE (case-insensitive)
#sctp.ulp_dissection: TRUE

# Data rate
# One of: Attempt to guess, OC-3, OC-12, OC-24, OC-48
# (case-insensitive).
#sdh.data.rate: OC-3

# Specifies that RTP/RTCP/T.38/MSRP/etc streams are decoded based upon port numbers found in SDP payload
# TRUE or FALSE (case-insensitive)
#sdp.establish_conversation: TRUE

# Whether the SEL Protocol dissector should desegment all messages spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#selfm.desegment: TRUE

# Whether the SEL Protocol dissector should automatically pre-process Telnet data to remove duplicate 0xFF IAC bytes
# TRUE or FALSE (case-insensitive)
#selfm.telnetclean: TRUE

# Perform CRC16 validation on Fast Messages
# TRUE or FALSE (case-insensitive)
#selfm.crc_verification: FALSE

# List of word bits contained in SER equations (Comma-separated, no Quotes or Checksums)
# A string
#selfm.ser_list: 

# Whether the session dissector should reassemble messages spanning multiple SES segments
# TRUE or FALSE (case-insensitive)
#ses.desegment: TRUE

# Enabling dissection makes it easy to view protocol details in each of the sampled headers.  Disabling dissection may reduce noise caused when display filters match the contents of any sampled header(s).
# TRUE or FALSE (case-insensitive)
#sflow.enable_dissection: TRUE

# This option only makes sense if dissection of sampled headers is enabled and probably not even then.
# TRUE or FALSE (case-insensitive)
#sflow.enable_analysis: FALSE

# Port numbers used for SGsAP traffic (default 29118)
# A string denoting an positive integer range (e.g., "1-20,30-40")
#sgsap.sctp_ports: 29118

# Preference whether to Dissect the UDVM code or not
# TRUE or FALSE (case-insensitive)
#sigcomp.display.udvm.code: FALSE

# preference whether to display the bytecode in UDVM operands or not
# TRUE or FALSE (case-insensitive)
#sigcomp.display.bytecode: FALSE

# preference whether to decompress message or not
# TRUE or FALSE (case-insensitive)
#sigcomp.decomp.msg: FALSE

# preference whether to display the decompressed message as raw text or not
# TRUE or FALSE (case-insensitive)
#sigcomp.display.decomp.msg.as.txt: FALSE

# 'No-Printout' = UDVM executes silently, then increasing detail about execution of UDVM instructions; Warning! CPU intense at high detail
# One of: No-Printout, Low-detail, Medium-detail, High-detail
# (case-insensitive).
#sigcomp.show.udvm.execution: No-Printout

# Set the CA_system_ID used to decode ECM datagram as MIKEY
# A hexadecimal number
#simulcrypt.ca_system_id_mikey: 0x9999

# SIP Server TLS Port
# A decimal number
#sip.tls.port: 5061

# Specifies that the raw text of the SIP message should be displayed in addition to the dissection tree
# TRUE or FALSE (case-insensitive)
#sip.display_raw_text: FALSE

# If the raw text of the SIP message is displayed, the trailing carriage return and line feed are not shown
# TRUE or FALSE (case-insensitive)
#sip.display_raw_text_without_crlf: FALSE

# If enabled, only SIP/2.0 traffic will be dissected as SIP. Disable it to allow SIP traffic with a different version to be dissected as SIP.
# TRUE or FALSE (case-insensitive)
#sip.strict_sip_version: TRUE

# Whether the SIP dissector should reassemble headers of a request spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#sip.desegment_headers: TRUE

# Whether the SIP dissector should use the "Content-length:" value, if present, to reassemble the body of a request spanning multiple TCP segments, and reassemble chunked data spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#sip.desegment_body: TRUE

# Whether retransmissions are detected coming from the same source port only.
# TRUE or FALSE (case-insensitive)
#sip.retrans_the_same_sport: TRUE

# Whether SIP should delay tracking the media (e.g., RTP/RTCP) until an SDP offer is answered. If enabled, mid-dialog changes to SDP and media state only take effect if and when an SDP offer is successfully answered; however enabling this prevents tracking media in early-media call scenarios
# TRUE or FALSE (case-insensitive)
#sip.delay_sdp_changes: FALSE

# Whether the generated call id should be hidden (not displayed) in the tree or not.
# TRUE or FALSE (case-insensitive)
#sip.hide_generatd_call_id: FALSE

# Validate SIP authorizations with known credentials
# TRUE or FALSE (case-insensitive)
#sip.validate_authorization: FALSE

# Whether the SKINNY dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#skinny.desegment: TRUE

# Whether the dissector should reassemble the payload of SMB Transaction commands spanning multiple SMB PDUs
# TRUE or FALSE (case-insensitive)
#smb.trans_reassembly: TRUE

# Whether the dissector should reassemble DCERPC over SMB commands
# TRUE or FALSE (case-insensitive)
#smb.dcerpc_reassembly: TRUE

# Whether the dissector should snoop SMB and related CIFS protocols to discover and display Names associated with SIDs
# TRUE or FALSE (case-insensitive)
#smb.sid_name_snooping: FALSE

# Whether the dissector should display SIDs and RIDs in hexadecimal rather than decimal
# TRUE or FALSE (case-insensitive)
#smb.sid_display_hex: FALSE

# Whether the export object functionality will take the full path file name as file identifier
# TRUE or FALSE (case-insensitive)
#smb.eosmb_take_name_as_fid: FALSE

# Whether the export object functionality will take the full path file name as file identifier
# TRUE or FALSE (case-insensitive)
#smb2.eosmb2_take_name_as_fid: FALSE

# Whether the dissector should reassemble Named Pipes over SMB2 commands
# TRUE or FALSE (case-insensitive)
#smb2.pipe_reassembly: TRUE

# Whether the SMB Direct dissector should reassemble fragmented payloads
# TRUE or FALSE (case-insensitive)
#smb_direct.reassemble_smb_direct: TRUE

# Enable reassembling (default is enabled)
# TRUE or FALSE (case-insensitive)
#sml.reassemble: TRUE

# Enable crc (default is disabled)
# TRUE or FALSE (case-insensitive)
#sml.crc: FALSE

# Whether the SMP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#smp.desegment: TRUE

# Whether the SMPP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#smpp.reassemble_smpp_over_tcp: TRUE

# Whether to decode the SMS contents when DCS is equal to 0 (zero).
# One of: None, ASCII, IA5, ISO-8859-1, ISO-8859-5, ISO-8859-8, UCS2
# (case-insensitive).
#smpp.decode_sms_over_smpp: None

# Whether the SMTP dissector should reassemble command and response lines spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#smtp.desegment_lines: TRUE

# Whether the SMTP dissector should reassemble DATA command and lines spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#smtp.desegment_data: TRUE

# Whether the SMTP dissector should decode Base64 encoded AUTH parameters
# TRUE or FALSE (case-insensitive)
#smtp.decryption: FALSE

# Whether fragmented BIUs should be reassembled
# TRUE or FALSE (case-insensitive)
#sna.defragment: TRUE

# Whether the SNMP OID should be shown in the info column
# TRUE or FALSE (case-insensitive)
#snmp.display_oid: TRUE

# Whether the SNMP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#snmp.desegment: TRUE

# ON - display dissected variables inside SNMP tree, OFF - display dissected variables in root tree after SNMP
# TRUE or FALSE (case-insensitive)
#snmp.var_in_tree: TRUE

# Set whether dissector should run Snort itself or use user packet comments
# One of: Not looking for Snort alerts, From running Snort, From user comments
# (case-insensitive).
#snort.alerts_source: Not looking for Snort alerts

# The name of the snort binary file to run
# A path to a file
#snort.binary: /usr/sbin/snort

# The name of the file containing the snort IDS configuration.  Typically snort.conf
# A path to a file
#snort.config: /etc/snort/snort.conf

# Whether or not information about the rule set and detected alerts should be shown in the tree of every snort PDU tree
# TRUE or FALSE (case-insensitive)
#snort.show_rule_set_stats: FALSE

# Whether or not expert info should be used to highlight fired alerts
# TRUE or FALSE (case-insensitive)
#snort.show_alert_expert_info: FALSE

# Attempt to show alert in reassembled frame where possible
# TRUE or FALSE (case-insensitive)
#snort.show_alert_in_reassembled_frame: FALSE

# Show unidentified fields ("padding") in packet dissections
# TRUE or FALSE (case-insensitive)
#solaredge.unknown: TRUE

# Inverter system encryption key
# A string
#solaredge.system_encryption_key: 

# SOME/IP Port Ranges UDP.
# A string denoting an positive integer range (e.g., "1-20,30-40")
#someip.ports.udp: 

# SOME/IP Port Ranges TCP.
# A string denoting an positive integer range (e.g., "1-20,30-40")
#someip.ports.tcp: 

# Reassemble SOME/IP-TP segments
# TRUE or FALSE (case-insensitive)
#someip.reassemble_tp: TRUE

# Should the SOME/IP Dissector use the payload dissector?
# TRUE or FALSE (case-insensitive)
#someip.payload_dissector_activated: FALSE

# SOME/IP Ignore Port Ranges UDP. These ports are not automatically added by the SOME/IP-SD.
# A string denoting an positive integer range (e.g., "1-20,30-40")
#someipsd.ports.udp.ignore: 

# SOME/IP Ignore Port Ranges TCP. These ports are not automatically added by the SOME/IP-SD.
# A string denoting an positive integer range (e.g., "1-20,30-40")
#someipsd.ports.tcp.ignore: 

# Whether the SoulSeek dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#slsk.desegment: TRUE

# Whether the SoulSeek dissector should decompress all zlib compressed packets inside messages
# TRUE or FALSE (case-insensitive)
#slsk.decompress: TRUE

# Whether the SoupBinTCP dissector should reassemble messages spanning multiple TCP segments.
# TRUE or FALSE (case-insensitive)
#soupbintcp.desegment: TRUE

# Whether the SPDY dissector should reassemble multiple data frames into an entity body.
# TRUE or FALSE (case-insensitive)
#spdy.assemble_data_frames: TRUE

# Whether to uncompress SPDY headers.
# TRUE or FALSE (case-insensitive)
#spdy.decompress_headers: TRUE

# Whether to uncompress entity bodies that are compressed using "Content-Encoding: "
# TRUE or FALSE (case-insensitive)
#spdy.decompress_body: TRUE

# Where available, show which protocol and frame caused this SPRT stream to be created
# TRUE or FALSE (case-insensitive)
#sprt.show_setup_info: TRUE

# Show the DLCI field in I_OCTET messages as well as the frame that enabled/disabled the DLCI
# TRUE or FALSE (case-insensitive)
#sprt.show_dlci_info: TRUE

# Whether the SRVLOC dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#srvloc.desegment_tcp: TRUE

# SSCOP payload (dissector to call on SSCOP payload)
# One of: Data (no further dissection), Q.2931, SSCF-NNI (MTP3-b), ALCAP, NBAP
# (case-insensitive).
#sscop.payload: Q.2931

# Whether the SSH dissector should reassemble SSH buffers spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#ssh.desegment_buffers: TRUE

# Whether the STANAG 5066 DTS Layer dissector should reassemble DPDUs spanning multiple TCP segments
# TRUE or FALSE (case-insensitive)
#s5066dts.proto_desegment: TRUE

# Whether the S5066 SIS dissector should reassemble PDUs spanning multiple TCP segments. The default is to use reassembly.
# TRUE or FALSE (case-insensitive)
#s5066sis.desegment_pdus: TRUE

# Whether the S5066 SIS dissector should dissect this edition of the STANAG. This edition was never formally approved and is very rare. The common edition is edition 1.2.
# TRUE or FALSE (case-insensitive)
#s5066sis.edition_one: FALSE

# Whether the StarTeam dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#starteam.desegment: TRUE

#  Steam IHS Discovery UDP port if other than the default
# A decimal number
#steam_ihs_discovery.udp.port: 27036

# Whether the BPDU dissector should use 802.1t System ID Extensions when dissecting the Bridge Identifier
# TRUE or FALSE (case-insensitive)
#stp.use_system_id_extension: TRUE

# Reassembles greater than MTU sized STT packets broken into segments on transmit
# TRUE or FALSE (case-insensitive)
#stt.reassemble: TRUE

# Whether to validate the STT checksum or not.
# TRUE or FALSE (case-insensitive)
#stt.check_checksum: FALSE

# Version used by Wireshark
# One of: Internet Draft version 08, RFC 3868
# (case-insensitive).
#sua.version: RFC 3868

# Set the source and destination addresses to the PC or GT digits, depending on the routing indicator.  This may affect TCAP's ability to recognize which messages belong to which TCAP session.
# TRUE or FALSE (case-insensitive)
#sua.set_addresses: FALSE

# No description
# TRUE or FALSE (case-insensitive)
#sv.decode_data_as_phsmeas: FALSE

# Whether the T.38 dissector should decode using the Pre-Corrigendum T.38 ASN.1 specification (1998).
# TRUE or FALSE (case-insensitive)
#t38.use_pre_corrigendum_asn1_specification: TRUE

# Whether a UDP packet that looks like RTP version 2 packet will be dissected as RTP packet or T.38 packet. If enabled there is a risk that T.38 UDPTL packets with sequence number higher than 32767 may be dissected as RTP.
# TRUE or FALSE (case-insensitive)
#t38.dissect_possible_rtpv2_packets_as_rtp: FALSE

# Whether the dissector should reassemble T.38 PDUs spanning multiple TCP segments when TPKT is used over TCP. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#t38.reassembly: TRUE

# Whether T.38 is used with TPKT for TCP
# One of: Never, Always, Maybe
# (case-insensitive).
#t38.tpkt_usage: Maybe

# Where available, show which protocol and frame caused this T.38 stream to be created
# TRUE or FALSE (case-insensitive)
#t38.show_setup_info: TRUE

# Whether the TACACS+ dissector should reassemble messages spanning multiple TCP segments.  To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#tacplus.desegment: TRUE

# TACACS+ Encryption Key
# A string
#tacplus.key: 

# Whether the TALI dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#tali.reassemble: TRUE

# SCCP (and SUA) SSNs to decode as TCAP
# A string denoting an positive integer range (e.g., "1-20,30-40")
#tcap.ssn: 

# Activate the analyse for Response Time
# TRUE or FALSE (case-insensitive)
#tcap.srt: FALSE

# Statistics for Response Time
# TRUE or FALSE (case-insensitive)
#tcap.persistentsrt: FALSE

# Maximal delay for message repetition
# A decimal number
#tcap.repetitiontimeout: 10

# Maximal delay for message lost
# A decimal number
#tcap.losttimeout: 30

# Whether the TCP summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#tcp.summary_in_tree: TRUE

# Whether to validate the TCP checksum or not.  (Invalid checksums will cause reassembly, if enabled, to fail.)
# TRUE or FALSE (case-insensitive)
#tcp.check_checksum: FALSE

# Whether subdissector can request TCP streams to be reassembled
# TRUE or FALSE (case-insensitive)
#tcp.desegment_tcp_streams: TRUE

# Whether out-of-order segments should be buffered and reordered before passing it to a subdissector. To use this option you must also enable "Allow subdissector to reassemble TCP streams".
# TRUE or FALSE (case-insensitive)
#tcp.reassemble_out_of_order: FALSE

# Make the TCP dissector analyze TCP sequence numbers to find and flag segment retransmissions, missing segments and RTT
# TRUE or FALSE (case-insensitive)
#tcp.analyze_sequence_numbers: TRUE

# Make the TCP dissector use relative sequence numbers instead of absolute ones. To use this option you must also enable "Analyze TCP sequence numbers". 
# TRUE or FALSE (case-insensitive)
#tcp.relative_sequence_numbers: TRUE

# Make the TCP dissector use this scaling factor for streams where the signalled scaling factor is not visible in the capture
# One of: Not known, 0 (no scaling), 1 (multiply by 2), 2 (multiply by 4), 3 (multiply by 8), 4 (multiply by 16), 5 (multiply by 32), 6 (multiply by 64), 7 (multiply by 128), 8 (multiply by 256), 9 (multiply by 512), 10 (multiply by 1024), 11 (multiply by 2048), 12 (multiply by 4096), 13 (multiply by 8192), 14 (multiply by 16384)
# (case-insensitive).
#tcp.default_window_scaling: Not known

# Make the TCP dissector track the number on un-ACKed bytes of data are in flight per packet. To use this option you must also enable "Analyze TCP sequence numbers". This takes a lot of memory but allows you to track how much data are in flight at a time and graphing it in io-graphs
# TRUE or FALSE (case-insensitive)
#tcp.track_bytes_in_flight: TRUE

# Calculate timestamps relative to the first frame and the previous frame in the tcp conversation
# TRUE or FALSE (case-insensitive)
#tcp.calculate_timestamps: TRUE

# Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port
# TRUE or FALSE (case-insensitive)
#tcp.try_heuristic_first: FALSE

# Do not place the TCP Timestamps in the summary line
# TRUE or FALSE (case-insensitive)
#tcp.ignore_tcp_timestamps: FALSE

# Do not call any subdissectors for Retransmitted or OutOfOrder segments
# TRUE or FALSE (case-insensitive)
#tcp.no_subdissector_on_error: TRUE

# Assume TCP Experimental Options (253, 254) have a Magic Number and use it for dissection
# TRUE or FALSE (case-insensitive)
#tcp.dissect_experimental_options_with_magic: TRUE

# Collect and store process information retrieved from IPFIX dissector
# TRUE or FALSE (case-insensitive)
#tcp.display_process_info_from_ipfix: FALSE

# Whether the TCPROS dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#tcpros.desegment_tcpros_messages: TRUE

# The TDMoE channel that contains the D-Channel.
# A decimal number
#tdmoe.d_channel: 24

# The TDMoD channel that contains the D-Channel.
# A decimal number
#tdmop.d_channel: 16

# The bitmask of channels in uncompressed TDMoP frame
# A hexadecimal number
#tdmop.ts_mask: 0xffffffff

# The ethertype assigned to TDMoP (without IP/UDP) stream
# A hexadecimal number
#tdmop.ethertype: 0

# Whether the TDS dissector should reassemble TDS buffers spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#tds.desegment_buffers: TRUE

# Whether the TDS dissector should defragment messages spanning multiple Netlib buffers
# TRUE or FALSE (case-insensitive)
#tds.defragment: TRUE

# Hint as to version of TDS protocol being decoded
# One of: Not Specified, TDS 4.x, TDS 5.0, TDS 7.0, TDS 7.1, TDS 7.2, TDS 7.3, TDS 7.3A, TDS 7.3B, TDS 7.4
# (case-insensitive).
#tds.protocol_type: Not Specified

# Hint as to whether to decode TDS protocol as little-endian or big-endian. (TDS7/8 always decoded as little-endian)
# One of: Little Endian, Big Endian
# (case-insensitive).
#tds.endian_type: Little Endian

# Whether the captured data include carrier number
# TRUE or FALSE (case-insensitive)
#tetra.include_carrier_number: TRUE

# 32-bit sequence counter for hash
# A string
#thread.thr_seq_ctr: 

# Set if the PAN ID should be used as the first two octets of the master key (PAN ID LSB), (PAN ID MSB), Key[2]...
# TRUE or FALSE (case-insensitive)
#thread.thr_use_pan_id_in_key: FALSE

# Set if the Thread sequence counter should be automatically acquired from Key ID mode 2 MLE messages.
# TRUE or FALSE (case-insensitive)
#thread.thr_auto_acq_thr_seq_ctr: TRUE

# Thrift TLS Port
# A decimal number
#thrift.tls.port: 0

# Try the default RSA key in use by nearly all Open Tibia servers
# TRUE or FALSE (case-insensitive)
#tibia.try_otserv_key: TRUE

# Shows active character for every packet
# TRUE or FALSE (case-insensitive)
#tibia.show_char_name: TRUE

# Shows account name/password or session key for every packet
# TRUE or FALSE (case-insensitive)
#tibia.show_acc_info: TRUE

# Shows which XTEA key was applied for a packet
# TRUE or FALSE (case-insensitive)
#tibia.show_xtea_key: FALSE

# Only decrypt packets and dissect login packets. Pass game commands to the data dissector
# TRUE or FALSE (case-insensitive)
#tibia.dissect_game_commands: FALSE

# Whether the Tibia dissector should reassemble packets spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#tibia.reassemble_tcp_segments: TRUE

# Time display type
# One of: UTC, Local
# (case-insensitive).
#time.display_time_type: Local

# Whether TIPCv1 SEGMENTATION_MANAGER datagrams should be reassembled
# TRUE or FALSE (case-insensitive)
#tipc.defragment: TRUE

# Whether to try to dissect TIPC data or not
# TRUE or FALSE (case-insensitive)
#tipc.dissect_tipc_data: TRUE

# Try to decode a TIPCv2 packet using an heuristic sub-dissector before using a registered sub-dissector
# TRUE or FALSE (case-insensitive)
#tipc.try_heuristic_first: FALSE

# TIPC 1.7 removes/adds fields (not) available in TIPC 1.5/1.6 while keeping the version number 2 in the packages. "ALL" shows all fields that were ever used in both versions.
# One of: ALL, TIPC 1.5/1.6, TIPC 1.7
# (case-insensitive).
#tipc.handle_v2_as: ALL

# Whether the TIPC-over-TCP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#tipc.desegment: TRUE

# Redirect TLS debug to the file specified. Leave empty to disable debugging or use "-" to redirect output to stderr.
# A path to a file
#tls.debug_file: 

# Whether the TLS dissector should reassemble TLS records spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#tls.desegment_ssl_records: TRUE

# Whether the TLS dissector should reassemble TLS Application Data spanning multiple TLS records. 
# TRUE or FALSE (case-insensitive)
#tls.desegment_ssl_application_data: TRUE

# For troubleshooting ignore the mac check result and decrypt also if the Message Authentication Code (MAC) fails.
# TRUE or FALSE (case-insensitive)
#tls.ignore_ssl_mac_failed: FALSE

# Pre-Shared-Key as HEX string. Should be 0 to 16 bytes.
# A string
#tls.psk: 

# The name of a file which contains a list of 
# (pre-)master secrets in one of the following formats:
# 
# RSA <EPMS> <PMS>
# RSA Session-ID:<SSLID> Master-Key:<MS>
# CLIENT_RANDOM <CRAND> <MS>
# PMS_CLIENT_RANDOM <CRAND> <PMS>
# 
# Where:
# <EPMS> = First 8 bytes of the Encrypted PMS
# <PMS> = The Pre-Master-Secret (PMS) used to derive the MS
# <SSLID> = The SSL Session ID
# <MS> = The Master-Secret (MS)
# <CRAND> = The Client's random number from the ClientHello message
# 
# (All fields are in hex notation)
# A path to a file
#tls.keylog_file: 

# Whether the TNS dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#tns.desegment_tns_messages: TRUE

# Whether Linux mangling of the link-layer header should be checked for and worked around
# TRUE or FALSE (case-insensitive)
#tr.fix_linux_botches: FALSE

# Whether the TPKT dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#tpkt.desegment: TRUE

# TCP ports to be decoded as TPKT (default: 102)
# A string denoting an positive integer range (e.g., "1-20,30-40")
#tpkt.tcp.ports: 102

# Whether to load the Database or not; not loading the DB disables the protocol; Wireshark has to be restarted for the setting to take effect.
# TRUE or FALSE (case-insensitive)
#tpncp.load_db: FALSE

# No description
# A decimal number
#tpncp.tcp.trunkpack_port: 2424

# No description
# A decimal number
#tpncp.udp.trunkpack_port: 2424

# Position of the capture unit that produced this trace.  This setting affects the way TRANSUM handles TCP Retransmissions.  See the manual for details.
# One of: Client, Intermediate, Service
# (case-insensitive).
#transum.capture_position: Client

# Set this to match to the TCP subdissector reassembly setting
# TRUE or FALSE (case-insensitive)
#transum.reassembly: TRUE

# Add and remove ports numbers separated by commas
# Ranges are supported e.g. 25,80,2000-3000,5432
# A string denoting an positive integer range (e.g., "1-20,30-40")
#transum.tcp_port_ranges: 25,80,443,1433

# Add and remove ports numbers separated by commas
# Ranges are supported e.g. 123,137-139,520-521,2049
# A string denoting an positive integer range (e.g., "1-20,30-40")
#transum.udp_port_ranges: 137-139

# Set this to discard any packet in the direction client to service,
# with a 1-byte payload of 0x00 and the ACK flag set
# TRUE or FALSE (case-insensitive)
#transum.orphan_ka_discard: FALSE

# RTE data will be added to the first request packet
# TRUE or FALSE (case-insensitive)
#transum.rte_on_first_req: FALSE

# RTE data will be added to the last request packet
# TRUE or FALSE (case-insensitive)
#transum.rte_on_last_req: TRUE

# RTE data will be added to the first response packet
# TRUE or FALSE (case-insensitive)
#transum.rte_on_first_rsp: FALSE

# RTE data will be added to the last response packet
# TRUE or FALSE (case-insensitive)
#transum.rte_on_last_rsp: FALSE

# Set this only to troubleshoot problems
# TRUE or FALSE (case-insensitive)
#transum.debug_enabled: FALSE

# Critical Traffic Mask (base hex)
# A hexadecimal number
#tte.ct_mask_value: 0

# Critical Traffic Marker (base hex)
# A hexadecimal number
#tte.ct_marker_value: 0xffffffff

# Setup RTP/RTCP conversations when parsing Start/Record RTP messages
# TRUE or FALSE (case-insensitive)
#ua3g.setup_conversations: TRUE

# NOE SIP Protocol
# TRUE or FALSE (case-insensitive)
#uasip.noesip: FALSE

# IPv4 address of the proxy (Invalid values will be ignored)
# A string
#uasip.proxy_ipaddr: 

# IPv4 (or IPv6) address of the call server. (Used only in case of identical source and destination ports)
# A string
#uaudp.system_ip: 

# Whether the UCP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#ucp.desegment_ucp_messages: TRUE

# Whether the UDP summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#udp.summary_in_tree: TRUE

# Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port
# TRUE or FALSE (case-insensitive)
#udp.try_heuristic_first: FALSE

# Whether to validate the UDP checksum
# TRUE or FALSE (case-insensitive)
#udp.check_checksum: FALSE

# Collect process flow information from IPFIX
# TRUE or FALSE (case-insensitive)
#udp.process_info: FALSE

# Calculate timestamps relative to the first frame and the previous frame in the udp conversation
# TRUE or FALSE (case-insensitive)
#udp.calculate_timestamps: TRUE

# Ignore an invalid checksum coverage field and continue dissection
# TRUE or FALSE (case-insensitive)
#udplite.ignore_checksum_coverage: TRUE

# Whether to validate the UDP-Lite checksum
# TRUE or FALSE (case-insensitive)
#udplite.check_checksum: FALSE

# Calculate timestamps relative to the first frame and the previous frame in the udp-lite conversation
# TRUE or FALSE (case-insensitive)
#udplite.calculate_timestamps: TRUE

# Whether the ULP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#ulp.desegment_ulp_messages: TRUE

# Whether the UMA dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#uma.desegment_ucp_messages: TRUE

# Try to decode a packet using a heuristic sub-dissector before attempting to dissect the packet using the "usb.bulk", "usb.interrupt" or "usb.control" dissector tables.
# TRUE or FALSE (case-insensitive)
#usb.try_heuristics: TRUE

# Activate workaround for weird Ettus UHD header offset on data packets
# TRUE or FALSE (case-insensitive)
#vrt.ettus_uhd_header_format: FALSE

# Whether the vlan summary line should be shown in the protocol tree
# TRUE or FALSE (case-insensitive)
#vlan.summary_in_tree: TRUE

# The (hexadecimal) Ethertype used to indicate 802.1QinQ VLAN in VLAN tunneling.
# A hexadecimal number
#vlan.qinq_ethertype: 0x9100

# IEEE 802.1Q specification version used (802.1Q-1998 uses 802.1D-2004 for PRI values)
# One of: IEEE 802.1Q-1998, IEEE 802.1Q-2005, IEEE 802.1Q-2011
# (case-insensitive).
#vlan.version: IEEE 802.1Q-2011

# Number of priorities supported, and number of those drop eligible (not used for 802.1Q-1998)
# One of: 8 Priorities, 0 Drop Eligible, 7 Priorities, 1 Drop Eligible, 6 Priorities, 2 Drop Eligible, 5 Priorities, 3 Drop Eligible
# (case-insensitive).
#vlan.priority_drop: 8 Priorities, 0 Drop Eligible

# Whether the VNC dissector should reassemble messages spanning multiple TCP segments.  To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#vnc.desegment: TRUE

# Dynamic payload types which will be interpreted as vp8; Values must be in the range 96 - 127
# A string denoting an positive integer range (e.g., "1-20,30-40")
#vp8.dynamic.payload.type: 

# There is some ambiguity on how to calculate V3 checksumsAs in V3 will use a pseudo header(which may only be implemented for IPv6 by some manufacturers)
# TRUE or FALSE (case-insensitive)
#vrrp.v3_checksum_as_in_v2: FALSE

# Enable this preference if you want to view the WBXML tokens without the representation in a media type (e.g., WML). Tokens will show up as Tag_0x12, attrStart_0x08 or attrValue_0x0B for example.
# TRUE or FALSE (case-insensitive)
#wbxml.skip_wbxml_token_mapping: FALSE

# Enable this preference if you want to skip the parsing of the WBXML tokens that constitute the body of the WBXML document. Only the WBXML header will be dissected (and visualized) then.
# TRUE or FALSE (case-insensitive)
#wbxml.disable_wbxml_token_parsing: FALSE

# Select dissector for websocket text
# One of: No subdissection, Line based text, As json, As SIP
# (case-insensitive).
#websocket.text_type: No subdissection

# No description
# TRUE or FALSE (case-insensitive)
#websocket.decompress: TRUE

# Set the maximum Basic CID used in the Wimax decoder (if other than the default of 320).  Note: The maximum Primary CID is double the maximum Basic CID.
# A decimal number
#wmx.basic_cid_max: 320

# Set to TRUE to use the Corrigendum 2 version of Wimax message decoding. Set to FALSE to use the 802.16e-2005  version.
# TRUE or FALSE (case-insensitive)
#wmx.corrigendum_2_version: FALSE

# Show transaction ID direction bit separately from the rest of the transaction ID field.
# TRUE or FALSE (case-insensitive)
#wimaxasncp.show_transaction_id_d_bit: FALSE

# Print debug output to the console.
# TRUE or FALSE (case-insensitive)
#wimaxasncp.debug_enabled: FALSE

# Version of the NWG that the R6 protocol complies with
# One of: R1.0 v1.0.0, R1.0 v1.2.0, R1.0 v1.2.1
# (case-insensitive).
#wimaxasncp.nwg_version: R1.0 v1.2.1

# Whether the WINS-Replication dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#winsrepl.reassemble: TRUE

# Whether the IP dissector should dissect decrypted transport data.
# TRUE or FALSE (case-insensitive)
#wg.dissect_packet: TRUE

# The path to the file which contains a list of secrets in the following format:
# "<key-type> = <base64-encoded-key>" (without quotes, leading spaces and spaces around '=' are ignored).
# <key-type> is one of: LOCAL_STATIC_PRIVATE_KEY, REMOTE_STATIC_PUBLIC_KEY, LOCAL_EPHEMERAL_PRIVATE_KEY or PRESHARED_KEY.
# A path to a file
#wg.keylog_file: 

# Whether the wow dissector should reassemble messages spanning multiple TCP segments.  To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#wow.desegment: TRUE

# If CALL REQUEST not seen or didn't specify protocol, dissect as QLLC/SNA
# TRUE or FALSE (case-insensitive)
#x25.payload_is_qllc_sna: FALSE

# If CALL REQUEST has no data, assume the protocol handled is COTP
# TRUE or FALSE (case-insensitive)
#x25.call_request_nodata_is_cotp: FALSE

# If CALL REQUEST not seen or didn't specify protocol, check user data before checking heuristic dissectors
# TRUE or FALSE (case-insensitive)
#x25.payload_check_data: FALSE

# Reassemble fragmented X.25 packets
# TRUE or FALSE (case-insensitive)
#x25.reassemble: TRUE

# Whether the X11 dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#x11.desegment: TRUE

# Set the SCTP port for X2AP messages
# A decimal number
#x2ap.sctp.port: 36422

# Select whether RRC Context should be dissected as legacy LTE or NB-IOT
# One of: LTE, NB-IoT
# (case-insensitive).
#x2ap.dissect_rrc_context_as: LTE

# Try to recognize XML encoded in Unicode (UCS-2BE)
# TRUE or FALSE (case-insensitive)
#xml.heuristic_unicode: FALSE

# Whether the XMPP dissector should reassemble messages. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings
# TRUE or FALSE (case-insensitive)
#xmpp.desegment: TRUE

# Set the SCTP port for XnAP messages
# A decimal number
#xnap.sctp.port: 38422

# Select whether target NG-RAN container should be decoded automatically (based on Xn Setup procedure) or manually
# One of: automatic, gNB, ng-eNB
# (case-insensitive).
#xnap.dissect_target_ng_ran_container_as: automatic

# Whether the X.25-over-TCP dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings
# TRUE or FALSE (case-insensitive)
#xot.desegment: TRUE

# Whether the X.25-over-TCP dissector should reassemble all X.25 packets before calling the X25 dissector. If the TCP packets arrive out-of-order, the X.25 reassembly can otherwise fail. To use this option, you should also enable "Reassemble X.25-over-TCP messages spanning multiple TCP segments", "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings and "Reassemble fragmented X.25 packets" in the X.25 protocol settings.
# TRUE or FALSE (case-insensitive)
#xot.x25_desegment: FALSE

# Whether the YAMI dissector should reassemble messages spanning multiple TCP segments.To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#yami.desegment: TRUE

# Whether the YMSG dissector should reassemble messages spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#ymsg.desegment: TRUE

# Whether the Z39.50 dissector should reassemble TDS buffers spanning multiple TCP segments. To use this option, you must also enable "Allow subdissectors to reassemble TCP streams" in the TCP protocol settings.
# TRUE or FALSE (case-insensitive)
#z3950.desegment_buffers: TRUE

# Specifies the security level to use in the
# decryption process. This value is ignored
# for ZigBee 2004 and unsecured networks.
# One of: No Security, No Encryption, 32-bit Integrity Protection, No Encryption, 64-bit Integrity Protection, No Encryption, 128-bit Integrity Protection, AES-128 Encryption, No Integrity Protection, AES-128 Encryption, 32-bit Integrity Protection, AES-128 Encryption, 64-bit Integrity Protection, AES-128 Encryption, 128-bit Integrity Protection
# (case-insensitive).
#zbee_nwk.seclevel: AES-128 Encryption, 32-bit Integrity Protection

# Specifies the ZigBee Smart Energy version used when dissecting ZigBee APS messages within the Smart Energy Profile
# One of: SE 1.1b, SE 1.2, SE 1.2a, SE 1.2b, SE 1.4
# (case-insensitive).
#zbee_aps.zbeeseversion: SE 1.4

####### Statistics ########

# Determines time between tap updates
# A decimal number
#statistics.update_interval: 3000

# If enabled burst rates will be calcuted for statistics that use the stats_tree system. Burst rates are calculated over a much shorter time interval than the rate column.
# TRUE or FALSE (case-insensitive)
#statistics.st_enable_burstinfo: TRUE

# If selected the stats_tree statistics nodes will show the count of events within the burst window instead of a burst rate. Burst rate is calculated as number of events within burst window divided by the burst windown length.
# TRUE or FALSE (case-insensitive)
#statistics.st_burst_showcount: FALSE

# Sets the duration of the time interval into which events are grouped when calculating the burst rate. Higher resolution (smaller number) increases processing overhead.
# A decimal number
#statistics.st_burst_resolution: 5

# Sets the duration of the sliding window during which the burst rate is measured. Longer window relative to burst rate resolution increases processing overhead. Will be truncated to a multiple of burst resolution.
# A decimal number
#statistics.st_burst_windowlen: 100

# Sets the default column by which stats based on the stats_tree system is sorted.
# One of: Node name (topic/item), Item count, Average value of the node, Minimum value of the node, Maximum value of the node, Burst rate of the node
# (case-insensitive).
#statistics.st_sort_defcolflag: Item count

# When selected, statistics based on the stats_tree system will by default be sorted in descending order.
# TRUE or FALSE (case-insensitive)
#statistics.st_sort_defdescending: TRUE

# When selected, the item/node names of statistics based on the stats_tree system will be sorted taking case into account. Else the case of the name will be ignored.
# TRUE or FALSE (case-insensitive)
#statistics.st_sort_casesensitve: TRUE

# When selected, the stats_tree nodes representing a range of values (0-49, 50-100, etc.) will always be sorted by name (the range of the node). Else range nodes are sorted by the same column as the rest of  the tree.
# TRUE or FALSE (case-insensitive)
#statistics.st_sort_rng_nameonly: TRUE

# When selected, the stats_tree nodes representing a range of values (0-49, 50-100, etc.) will always be sorted ascending; else it follows the sort direction of the tree. Only effective if "Always sort 'range' nodes by name" is also selected.
# TRUE or FALSE (case-insensitive)
#statistics.st_sort_rng_fixorder: TRUE

# When selected, the full name (including menu path) of the stats_tree plug-in is show in windows. If cleared the plug-in name is shown without menu path (only the part of the name after last '/' character.)
# TRUE or FALSE (case-insensitive)
#statistics.st_sort_showfullname: FALSE
`
	for _, win := range []bool{false, true} {
		var td string
		if win {
			td = strings.ReplaceAll(inp1, "\n", "\r\n")
		} else {
			td = inp1
		}
		parsed, err := ParseReader("", strings.NewReader(td))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Result is %v of type %T\n", parsed, parsed)

		cfg := parsed.(*Config)
		assert.Contains(t, cfg.Lists, "gui.column.format")
		assert.Contains(t, cfg.Lists, "gui.column.hidden")
		assert.Contains(t, cfg.Strings, "gui.qt.font_name")

		assert.Equal(t, 20, len(cfg.Lists["gui.column.format"]))
		assert.Equal(t, "\"gcla1\"", cfg.Lists["gui.column.format"][14])
		assert.Equal(t, "\"%Yut\"", cfg.Lists["gui.column.format"][15])

		assert.Equal(t, 2, len(cfg.Lists["gui.column.hidden"]))
		assert.Equal(t, "%Yut", cfg.Lists["gui.column.hidden"][0])
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
