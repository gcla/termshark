// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package pdmltree

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================

var p1 string = `<packet>
  <proto name="geninfo" pos="0" showname="General information" size="1453">
    <field name="num" pos="0" show="1" showname="Number" value="1" size="1453"/>
    <field name="len" pos="0" show="1453" showname="Frame Length" value="5ad" size="1453"/>
    <field name="caplen" pos="0" show="1453" showname="Captured Length" value="5ad" size="1453"/>
    <field name="timestamp" pos="0" show="Dec 31, 1969 19:00:00.000000000 EST" showname="Captured Time" value="0.000000000" size="1453"/>
  </proto>
  <proto name="frame" showname="Frame 1: 1453 bytes on wire (11624 bits), 1453 bytes captured (11624 bits)" size="1453" pos="0">
    <field name="frame.encap_type" showname="Encapsulation type: Ethernet (1)" size="0" pos="0" show="1"/>
    <field name="frame.time" showname="Arrival Time: Dec 31, 1969 19:00:00.000000000 EST" size="0" pos="0" show="Dec 31, 1969 19:00:00.000000000 EST"/>
    <field name="frame.offset_shift" showname="Time shift for this packet: 0.000000000 seconds" size="0" pos="0" show="0.000000000"/>
    <field name="frame.time_epoch" showname="Epoch Time: 0.000000000 seconds" size="0" pos="0" show="0.000000000"/>
    <field name="frame.time_delta" showname="Time delta from previous captured frame: 0.000000000 seconds" size="0" pos="0" show="0.000000000"/>
    <field name="frame.time_delta_displayed" showname="Time delta from previous displayed frame: 0.000000000 seconds" size="0" pos="0" show="0.000000000"/>
    <field name="frame.time_relative" showname="Time since reference or first frame: 0.000000000 seconds" size="0" pos="0" show="0.000000000"/>
    <field name="frame.number" showname="Frame Number: 1" size="0" pos="0" show="1"/>
    <field name="frame.len" showname="Frame Length: 1453 bytes (11624 bits)" size="0" pos="0" show="1453"/>
    <field name="frame.cap_len" showname="Capture Length: 1453 bytes (11624 bits)" size="0" pos="0" show="1453"/>
    <field name="frame.marked" showname="Frame is marked: False" size="0" pos="0" show="0"/>
    <field name="frame.ignored" showname="Frame is ignored: False" size="0" pos="0" show="0"/>
    <field name="frame.protocols" showname="Protocols in frame: eth:ethertype:ip:gre:erspan:eth:ethertype:ip:tcp" size="0" pos="0" show="eth:ethertype:ip:gre:erspan:eth:ethertype:ip:tcp"/>
  </proto>
  <proto name="eth" showname="Ethernet II, Src: ExtremeN_98:89:ab (00:04:96:98:89:ab), Dst: Vmware_6b:a9:f7 (00:0c:29:6b:a9:f7)" size="14" pos="0">
    <field name="eth.dst" showname="Destination: Vmware_6b:a9:f7 (00:0c:29:6b:a9:f7)" size="6" pos="0" show="00:0c:29:6b:a9:f7" value="000c296ba9f7">
      <field name="eth.dst_resolved" showname="Destination (resolved): Vmware_6b:a9:f7" hide="yes" size="6" pos="0" show="Vmware_6b:a9:f7" value="000c296ba9f7"/>
      <field name="eth.addr" showname="Address: Vmware_6b:a9:f7 (00:0c:29:6b:a9:f7)" size="6" pos="0" show="00:0c:29:6b:a9:f7" value="000c296ba9f7"/>
      <field name="eth.addr_resolved" showname="Address (resolved): Vmware_6b:a9:f7" hide="yes" size="6" pos="0" show="Vmware_6b:a9:f7" value="000c296ba9f7"/>
      <field name="eth.lg" showname=".... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)" size="3" pos="0" show="0" value="0" unmaskedvalue="000c29"/>
      <field name="eth.ig" showname=".... ...0 .... .... .... .... = IG bit: Individual address (unicast)" size="3" pos="0" show="0" value="0" unmaskedvalue="000c29"/>
    </field>
    <field name="eth.src" showname="Source: ExtremeN_98:89:ab (00:04:96:98:89:ab)" size="6" pos="6" show="00:04:96:98:89:ab" value="0004969889ab">
      <field name="eth.src_resolved" showname="Source (resolved): ExtremeN_98:89:ab" hide="yes" size="6" pos="6" show="ExtremeN_98:89:ab" value="0004969889ab"/>
      <field name="eth.addr" showname="Address: ExtremeN_98:89:ab (00:04:96:98:89:ab)" size="6" pos="6" show="00:04:96:98:89:ab" value="0004969889ab"/>
      <field name="eth.addr_resolved" showname="Address (resolved): ExtremeN_98:89:ab" hide="yes" size="6" pos="6" show="ExtremeN_98:89:ab" value="0004969889ab"/>
      <field name="eth.lg" showname=".... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)" size="3" pos="6" show="0" value="0" unmaskedvalue="000496"/>
      <field name="eth.ig" showname=".... ...0 .... .... .... .... = IG bit: Individual address (unicast)" size="3" pos="6" show="0" value="0" unmaskedvalue="000496"/>
    </field>
    <field name="eth.type" showname="Type: IPv4 (0x0800)" size="2" pos="12" show="0x00000800" value="0800"/>
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 10.54.116.174, Dst: 10.54.116.137" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 1439" size="2" pos="16" show="1439" value="059f"/>
    <field name="ip.id" showname="Identification: 0x0000 (0)" size="2" pos="18" show="0x00000000" value="0000"/>
    <field name="ip.flags" showname="Flags: 0x0000" size="2" pos="20" show="0x00000000" value="0000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.flags.df" showname=".0.. .... .... .... = Don&#x27;t fragment: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 64" size="1" pos="22" show="64" value="40"/>
    <field name="ip.proto" showname="Protocol: Generic Routing Encapsulation (47)" size="1" pos="23" show="47" value="2f"/>
    <field name="ip.checksum" showname="Header checksum: 0x778d [correct]" size="2" pos="24" show="0x0000778d" value="778d"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0x778d" size="2" pos="24" show="0x0000778d" value="778d"/>
    <field name="ip.src" showname="Source: 10.54.116.174" size="4" pos="26" show="10.54.116.174" value="0a3674ae"/>
    <field name="ip.addr" showname="Source or Destination Address: 10.54.116.174" hide="yes" size="4" pos="26" show="10.54.116.174" value="0a3674ae"/>
    <field name="ip.src_host" showname="Source Host: 10.54.116.174" hide="yes" size="4" pos="26" show="10.54.116.174" value="0a3674ae"/>
    <field name="ip.host" showname="Source or Destination Host: 10.54.116.174" hide="yes" size="4" pos="26" show="10.54.116.174" value="0a3674ae"/>
    <field name="ip.dst" showname="Destination: 10.54.116.137" size="4" pos="30" show="10.54.116.137" value="0a367489"/>
    <field name="ip.addr" showname="Source or Destination Address: 10.54.116.137" hide="yes" size="4" pos="30" show="10.54.116.137" value="0a367489"/>
    <field name="ip.dst_host" showname="Destination Host: 10.54.116.137" hide="yes" size="4" pos="30" show="10.54.116.137" value="0a367489"/>
    <field name="ip.host" showname="Source or Destination Host: 10.54.116.137" hide="yes" size="4" pos="30" show="10.54.116.137" value="0a367489"/>
  </proto>
  <proto name="gre" showname="Generic Routing Encapsulation (ERSPAN)" size="4" pos="34">
    <field name="gre.flags_and_version" showname="Flags and Version: 0x0000" size="2" pos="34" show="0x00000000" value="0000">
      <field name="gre.flags.checksum" showname="0... .... .... .... = Checksum Bit: No" size="2" pos="34" show="0" value="0" unmaskedvalue="0000"/>
      <field name="gre.flags.routing" showname=".0.. .... .... .... = Routing Bit: No" size="2" pos="34" show="0" value="0" unmaskedvalue="0000"/>
      <field name="gre.flags.key" showname="..0. .... .... .... = Key Bit: No" size="2" pos="34" show="0" value="0" unmaskedvalue="0000"/>
      <field name="gre.flags.sequence_number" showname="...0 .... .... .... = Sequence Number Bit: No" size="2" pos="34" show="0" value="0" unmaskedvalue="0000"/>
      <field name="gre.flags.strict_source_route" showname=".... 0... .... .... = Strict Source Route Bit: No" size="2" pos="34" show="0" value="0" unmaskedvalue="0000"/>
      <field name="gre.flags.recursion_control" showname=".... .000 .... .... = Recursion control: 0" size="2" pos="34" show="0" value="0" unmaskedvalue="0000"/>
      <field name="gre.flags.reserved" showname=".... .... 0000 0... = Flags (Reserved): 0" size="2" pos="34" show="0" value="0" unmaskedvalue="0000"/>
      <field name="gre.flags.version" showname=".... .... .... .000 = Version: GRE (0)" size="2" pos="34" show="0" value="0" unmaskedvalue="0000"/>
    </field>
    <field name="gre.proto" showname="Protocol Type: ERSPAN (0x88be)" size="2" pos="36" show="0x000088be" value="88be"/>
  </proto>
  <proto name="erspan" showname="Encapsulated Remote Switch Packet ANalysis Type I" size="1415" pos="38"/>
  <proto name="eth" showname="Ethernet II, Src: BrocadeC_96:32:82 (00:24:38:96:32:82), Dst: MurataMa_29:5e:de (1c:99:4c:29:5e:de)" size="14" pos="38">
    <field name="eth.dst" showname="Destination: MurataMa_29:5e:de (1c:99:4c:29:5e:de)" size="6" pos="38" show="1c:99:4c:29:5e:de" value="1c994c295ede">
      <field name="eth.dst_resolved" showname="Destination (resolved): MurataMa_29:5e:de" hide="yes" size="6" pos="38" show="MurataMa_29:5e:de" value="1c994c295ede"/>
      <field name="eth.addr" showname="Address: MurataMa_29:5e:de (1c:99:4c:29:5e:de)" size="6" pos="38" show="1c:99:4c:29:5e:de" value="1c994c295ede"/>
      <field name="eth.addr_resolved" showname="Address (resolved): MurataMa_29:5e:de" hide="yes" size="6" pos="38" show="MurataMa_29:5e:de" value="1c994c295ede"/>
      <field name="eth.lg" showname=".... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)" size="3" pos="38" show="0" value="0" unmaskedvalue="1c994c"/>
      <field name="eth.ig" showname=".... ...0 .... .... .... .... = IG bit: Individual address (unicast)" size="3" pos="38" show="0" value="0" unmaskedvalue="1c994c"/>
    </field>
    <field name="eth.src" showname="Source: BrocadeC_96:32:82 (00:24:38:96:32:82)" size="6" pos="44" show="00:24:38:96:32:82" value="002438963282">
      <field name="eth.src_resolved" showname="Source (resolved): BrocadeC_96:32:82" hide="yes" size="6" pos="44" show="BrocadeC_96:32:82" value="002438963282"/>
      <field name="eth.addr" showname="Address: BrocadeC_96:32:82 (00:24:38:96:32:82)" size="6" pos="44" show="00:24:38:96:32:82" value="002438963282"/>
      <field name="eth.addr_resolved" showname="Address (resolved): BrocadeC_96:32:82" hide="yes" size="6" pos="44" show="BrocadeC_96:32:82" value="002438963282"/>
      <field name="eth.lg" showname=".... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)" size="3" pos="44" show="0" value="0" unmaskedvalue="002438"/>
      <field name="eth.ig" showname=".... ...0 .... .... .... .... = IG bit: Individual address (unicast)" size="3" pos="44" show="0" value="0" unmaskedvalue="002438"/>
    </field>
    <field name="eth.type" showname="Type: IPv4 (0x0800)" size="2" pos="50" show="0x00000800" value="0800"/>
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 174.35.22.19, Dst: 10.241.226.76" size="20" pos="52">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="52" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="52" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x20 (DSCP: CS1, ECN: Not-ECT)" size="1" pos="53" show="0x00000020" value="20">
      <field name="ip.dsfield.dscp" showname="0010 00.. = Differentiated Services Codepoint: Class Selector 1 (8)" size="1" pos="53" show="8" value="8" unmaskedvalue="20"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="53" show="0" value="0" unmaskedvalue="20"/>
    </field>
    <field name="ip.len" showname="Total Length: 1401" size="2" pos="54" show="1401" value="0579"/>
    <field name="ip.id" showname="Identification: 0x6a43 (27203)" size="2" pos="56" show="0x00006a43" value="6a43"/>
    <field name="ip.flags" showname="Flags: 0x4000, Don&#x27;t fragment" size="2" pos="58" show="0x00004000" value="4000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="58" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.flags.df" showname=".1.. .... .... .... = Don&#x27;t fragment: Set" size="2" pos="58" show="1" value="1" unmaskedvalue="4000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="58" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="58" show="0" value="0" unmaskedvalue="4000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 52" size="1" pos="60" show="52" value="34"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="61" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0x25a8 [correct]" size="2" pos="62" show="0x000025a8" value="25a8"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="62" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0x25a8" size="2" pos="62" show="0x000025a8" value="25a8"/>
    <field name="ip.src" showname="Source: 174.35.22.19" size="4" pos="64" show="174.35.22.19" value="ae231613"/>
    <field name="ip.addr" showname="Source or Destination Address: 174.35.22.19" hide="yes" size="4" pos="64" show="174.35.22.19" value="ae231613"/>
    <field name="ip.src_host" showname="Source Host: 174.35.22.19" hide="yes" size="4" pos="64" show="174.35.22.19" value="ae231613"/>
    <field name="ip.host" showname="Source or Destination Host: 174.35.22.19" hide="yes" size="4" pos="64" show="174.35.22.19" value="ae231613"/>
    <field name="ip.dst" showname="Destination: 10.241.226.76" size="4" pos="68" show="10.241.226.76" value="0af1e24c"/>
    <field name="ip.addr" showname="Source or Destination Address: 10.241.226.76" hide="yes" size="4" pos="68" show="10.241.226.76" value="0af1e24c"/>
    <field name="ip.dst_host" showname="Destination Host: 10.241.226.76" hide="yes" size="4" pos="68" show="10.241.226.76" value="0af1e24c"/>
    <field name="ip.host" showname="Source or Destination Host: 10.241.226.76" hide="yes" size="4" pos="68" show="10.241.226.76" value="0af1e24c"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 80, Dst Port: 38292, Seq: 1, Ack: 1, Len: 1349" size="32" pos="72">
    <field name="tcp.srcport" showname="Source Port: 80" size="2" pos="72" show="80" value="0050"/>
    <field name="tcp.dstport" showname="Destination Port: 38292" size="2" pos="74" show="38292" value="9594"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="72" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 38292" hide="yes" size="2" pos="74" show="38292" value="9594"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="72" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 1349" size="1" pos="84" show="1349" value="80"/>
    <field name="tcp.seq" showname="Sequence number: 1    (relative sequence number)" size="4" pos="76" show="1" value="7592da70"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 1350    (relative sequence number)" size="0" pos="72" show="1350"/>
    <field name="tcp.ack" showname="Acknowledgment number: 1    (relative ack number)" size="4" pos="80" show="1" value="0886d393"/>
    <field name="tcp.hdr_len" showname="1000 .... = Header Length: 32 bytes (8)" size="1" pos="84" show="32" value="80"/>
    <field name="tcp.flags" showname="Flags: 0x018 (PSH, ACK)" size="2" pos="84" show="0x00000018" value="18" unmaskedvalue="8018">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="84" show="0" value="0" unmaskedvalue="80"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="84" show="0" value="0" unmaskedvalue="80"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="85" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="85" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="85" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="85" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.push" showname=".... .... 1... = Push: Set" size="1" pos="85" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="85" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="85" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.fin" showname=".... .... ...0 = Fin: Not set" size="1" pos="85" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" size="2" pos="84" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" value="8018"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 1016" size="2" pos="86" show="1016" value="03f8"/>
    <field name="tcp.window_size" showname="Calculated window size: 1016" size="2" pos="86" show="1016" value="03f8"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="86" show="-1" value="03f8"/>
    <field name="tcp.checksum" showname="Checksum: 0x6823 [unverified]" size="2" pos="88" show="0x00006823" value="6823"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="88" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="90" show="0" value="0000"/>
    <field name="tcp.options" showname="Options: (12 bytes), No-Operation (NOP), No-Operation (NOP), Timestamps" size="12" pos="92" show="01:01:08:0a:db:d8:bf:88:00:90:57:d8" value="0101080adbd8bf88009057d8">
      <field name="tcp.options.nop" showname="TCP Option - No-Operation (NOP)" size="1" pos="92" show="01" value="01">
        <field name="tcp.option_kind" showname="Kind: No-Operation (1)" size="1" pos="92" show="1" value="01"/>
      </field>
      <field name="tcp.options.nop" showname="TCP Option - No-Operation (NOP)" size="1" pos="93" show="01" value="01">
        <field name="tcp.option_kind" showname="Kind: No-Operation (1)" size="1" pos="93" show="1" value="01"/>
      </field>
      <field name="tcp.options.timestamp" showname="TCP Option - Timestamps: TSval 3688415112, TSecr 9459672" size="10" pos="94" show="08:0a:db:d8:bf:88:00:90:57:d8" value="080adbd8bf88009057d8">
        <field name="tcp.option_kind" showname="Kind: Time Stamp Option (8)" size="1" pos="94" show="8" value="08"/>
        <field name="tcp.option_len" showname="Length: 10" size="1" pos="95" show="10" value="0a"/>
        <field name="tcp.options.timestamp.tsval" showname="Timestamp value: 3688415112" size="4" pos="96" show="3688415112" value="dbd8bf88"/>
        <field name="tcp.options.timestamp.tsecr" showname="Timestamp echo reply: 9459672" size="4" pos="100" show="9459672" value="009057d8"/>
      </field>
    </field>
    <field name="tcp.analysis" showname="SEQ/ACK analysis" size="0" pos="72" show="" value="">
      <field name="tcp.analysis.bytes_in_flight" showname="Bytes in flight: 1349" size="0" pos="72" show="1349"/>
      <field name="tcp.analysis.push_bytes_sent" showname="Bytes sent since last PSH flag: 1349" size="0" pos="72" show="1349"/>
    </field>
    <field name="" show="Timestamps" size="0" pos="72">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 0.000000000 seconds" size="0" pos="72" show="0.000000000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 0.000000000 seconds" size="0" pos="72" show="0.000000000"/>
    </field>
    <field name="tcp.payload" showname="TCP payload (1349 bytes)" size="1349" pos="104" show="59:10:b2:87:2c:5d:81:5a:b8:37:24:81:a4:07:65:2b:96:22:72:0b:19:48:04:68:83:e4:b8:ea:6f:8f:08:78:74:e7:5e:11:16:05:8f:48:66:6f:8f:af:21:fa:27:29:8f:c8:52:90:78:e0:17:82:42:9e:08:23:fa:2b:5a:52:d8:62:81:f1:f5:b3:d3:48:a1:f5:2c:9d:1c:79:b2:25:47:16:4c:2b:51:11:6a:67:f3:70:02:9b:b4:9a:39:e0:eb:0e:af:21:0a:3d:eb:ad:ac:55:ca:2f:64:49:a1:1d:c2:13:36:10:e3:5a:2d:2e:d1:6e:6e:a4:4e:d0:ad:27:d9:7a:d5:df:4a:d8:b7:a6:eb:15:9f:a8:02:b4:2b:02:4d:6f:48:1e:f2:7b:61:35:8b:8b:66:89:70:48:24:14:15:aa:32:97:6f:11:1a:d5:89:f8:ba:61:02:d5:69:da:35:0f:f3:68:47:4e:d3:ae:59:8a:32:41:87:ab:43:6a:34:48:96:b4:e2:84:2f:5d:e0:69:b5:3a:cb:fe:04:14:52:16:25:70:b9:f2:36:ad:b3:fc:76:47:79:07:5b:79:61:d9:1b:ac:1b:94:8d:bb:61:99:ac:35:6d:ae:e5:d9:ce:da:94:6f:00:cd:89:84:5a:3e:03:bd:2b:9e:66:35:92:7e:45:04:01:79:0d:20:09:c0:56:28:23:10:ad:59:b6:6a:c6:b2:08:a5:31:cf:d2:46:c8:f3:f8:12:49:c8:77:c4:17:56:c1:97:28:24:0d:81:af:eb:ad:08:eb:22:6c:72:38:c2:f0:37:45:18:56:40:18:56:84:98:7d:46:10:b3:95:20:d6:86:54:1b:77:dd:fa:d2:b6:a8:00:0f:12:15:e0:23:a3:02:bb:2f:2a:c8:a3:c1:62:82:f9:41:31:c1:17:20:a7:88:df:16:26:06:1c:76:e4:23:90:b1:cb:26:bd:8f:32:51:a0:0f:b6:0c:4b:57:2c:ea:33:45:ba:a5:68:8a:a6:fb:98:22:4b:d1:14:4d:67:2a:a6:48:58:b6:1e:53:64:2b:98:a2:eb:9b:7e:5f:3f:ff:99:7c:bd:a5:66:88:8c:33:32:44:c6:e0:be:fe:13:49:0e:f2:f5:9d:71:12:51:21:0b:fc:d7:42:40:96:80:69:db:14:f3:3c:c4:cc:f9:f7:84:98:5a:34:ad:00:b1:c9:40:10:13:65:dc:f5:81:18:33:be:29:c6:8c:01:bd:bd:75:46:20:b3:4e:ec:ed:cd:41:bc:bd:79:a4:b7:9f:f4:78:fb:2b:3e:98:b7:b7:f5:c3:2a:00:80:02:48:e4:45:f6:5e:24:10:b0:2d:28:1e:87:e3:5d:76:e9:6d:95:e3:6f:26:1e:af:11:17:db:ba:86:25:fe:0a:3c:e9:86:f5:12:f8:03:fb:07:2c:30:4f:5e:48:e8:ce:fc:5d:ab:03:26:56:b5:67:a6:52:75:a0:df:9e:19:2a:e9:cb:c7:8f:0a:16:0d:97:d1:c7:36:8b:86:ff:6f:d1:ce:c6:a2:ed:13:36:bc:93:d0:d8:2f:40:58:26:94:fe:55:d6:05:04:a0:5a:ca:8c:48:0c:bb:49:bc:95:80:9d:e8:83:c5:f2:c4:47:a0:9b:22:6e:37:0d:f1:30:5f:00:d1:98:cd:cd:be:78:c2:fe:9e:f8:33:95:42:76:dc:83:bf:41:f1:27:9e:24:1e:8a:bf:f3:8b:da:0d:c5:a8:dd:3c:0d:fc:f0:21:51:bb:79:da:80:c2:1a:24:a0:b0:8e:0c:28:a6:3d:01:c5:97:9c:a6:83:45:14:c6:41:11:45:69:93:60:58:54:98:24:8f:f3:40:c9:8c:6d:1d:b2:23:06:30:15:6d:90:a8:2c:29:db:a0:89:a2:0d:b2:94:6c:90:d1:5f:c1:14:e9:e6:40:36:68:47:0c:60:fd:b4:36:68:9f:10:c0:3a:71:e5:c0:38:69:e5:a0:84:46:e0:ef:17:12:d4:23:76:b8:73:d5:70:fa:24:50:32:2d:25:77:de:0f:a5:d9:5e:48:da:85:24:fd:7f:11:49:c6:f9:04:d3:6a:48:3a:dc:9b:db:83:78:73:fb:48:6f:3e:eb:f1:e6:37:d4:8f:d4:fd:b9:79:1a:7f:5e:be:23:20:33:0a:f5:47:02:ed:51:d9:8e:27:0a:03:3c:15:98:d8:ea:36:c9:b6:55:53:7c:5b:c5:26:99:fd:29:c6:d3:d7:f5:ab:fe:7d:bd:fb:0e:9b:f4:e3:3d:17:50:4c:f0:45:48:73:36:36:c9:3e:a9:77:57:76:ea:43:f9:f2:93:e0:c6:56:c2:8d:dd:7a:fc:7f:44:a9:5f:09:37:cf:3e:4e:fb:11:61:83:15:61:33:3f:23:d8:cc:4f:eb:ca:27:83:b8:f2:c9:91:ae:7c:de:97:98:af:f2:64:38:4f:8e:8f:f6:e4:04:c5:24:4d:9b:12:fe:2e:eb:f3:cc:1b:01:db:05:bd:2e:df:f6:1b:ec:99:ff:6c:8f:07:92:aa:56:6a:3a:57:b2:52:66:af:95:1a:ac:7e:78:c4:0b:7e:d6:37:b5:52:d6:90:af:1f:9d:91:77:b7:4f:eb:dd:eb:a7:f7:fb:3f:ef:1f:ca:df:9f:04:49:13:b5:b7:67:fa:91:64:2a:20:e9:46:e5:d9:be:f2:8b:7c:4f:91:74:7e:fe:de:50:cc:dd:71:69:04:ce:01:49:58:09:49:87:3b:fc:e9:20:0e:7f:7a:a4:c3:2f:3f:31:f9:bc:c7:bf:14:5f:a7:30:90:bf:37:0f:f2:f7:ff:a6:c9:a3:f4:c6:85:a7:06:24:33:ee:4b:47:de:93:bc:6f:0c:ac:f3:77:e1:f4:65:45:51:c6:01:43:79:f8:d9:1e:35:c5:89:6a:4d:71:a6:54:53:9c:f4:e7:21:2a:76:e9:ba:df:2a:59:3f:53:f2:2e:9e:b5:29:59:a5:33:f2:ef:6a:56:e9:38:ff:2e:20:b3:9f:7f:af:47:0c:e0:df:4f:82:a3:a9:3e:10:8e:94:de:8e:fd:a6:55:b0:1f:09:48:3f:a5:7b:77:ea:4f:fe:15:54:f1:c7:f1:78:fc:98:c8:2f:fd:79:57:5d:21:f9:6d:1d:6f:c1:b7:df:34:be:dd:d1:1a:4e:39:30:4f:45:96:cd:52:e4:73:2f:0f:69:94:21:b8:66:51:46:23:9f:fa:88:8b:0f:cd:c0:74:08:d8:d0:12:c0:97:67:80:51:f6:17:74:05:b0:05:e0:58:0b:17:b7:31:cb:18:fd:11:b5:58:c5:60:90:0a:87:b5:62:4b:96:51:7f:8c:de:06:01:fa:2c:56:91:a2:cf:54:7c:4f:0d:10:21:66:28:fd:38:6c:23:f7:73:2f:73:cb:28:03:15:61:86:d8:c1:82:2e:99:12:2a:be:03:2a:61:4b:f9:39:4e:f7:73:a7:89:3e:35:b3:09:94:75:58:5f:8a:af:2e:6a:7f:3b:95:fb:f2:97:ff:0e:00:18:98:8b:73:d8:4a:00:00" value="5910b2872c5d815ab8372481a407652b9622720b1948046883e4b8ea6f8f087874e75e1116058f48666f8faf21fa27298fc8529078e01782429e0823fa2b5a52d86281f1f5b3d348a1f52c9d1c79b22547164c2b51116a67f370029bb49a39e0eb0eaf210a3debadac55ca2f6449a11dc2133610e35a2d2ed16e6ea44ed0ad27d97ad5df4ad8b7a6eb159fa802b42b024d6f481ef27b61358b8b66897048241415aa32976f111ad589f8ba6102d569da350ff368474ed3ae598a324187ab436a344896b4e2842f5de069b53acbfe041452162570b9f236adb3fc764779075b7961d91bac1b948dbb6199ac356daee5d9ceda946f00cd89845a3e03bd2b9e6635927e450401790d2009c056282310ad59b66ac6b208a531cfd246c8f3f81249c877c41756c19728240d81afebad08eb226c7238c2f03745185640185684987d4610b39520d686541b77ddfad2b6a8000f1215e023a302bb2f2ac8a3c16282f94131c11720a788df1626061c76e42390b1cb26bd8f3251a00fb60c4b572cea3345baa5688aa6fb98224bd1144d672aa64858b61e53642b98a2eb9b7e5f3fff997cbda566888c333244c6e0befe13490ef2f59d711251210bfcd74240968069db14f33cc4ccf9f784985a34ad00b1c940101365dcf5811833be29c68c01bdbd754620b34eecedcd41bcbd79a4b79ff478fb2b3e98b7b7f5c32a00800248e445f65e2410b02d281e87e35d76e96d95e36f261eaf1117dbba8625fe0a3ce986f512f803fb072c304f5e48e8cefc5dab032656b567a65275a0df9e192ae9cbc78f0a160d97d1c7368b86ff6fd1cec6a2ed1336bc93d0d82f40582694fe55d60504a05aca8c480cbb49bc95809de883c5f2c447a09b226e370df1305f00d198cdcdbe78c2fe9ef833954276dc83bf41f1279e241e8abff38bda0dc5a8dd3c0dfcf02151bb79da80c21a24a0b08e0c28a63d01c5979ca6834514c6411145699360585498248ff340c98c6d1db2230630156d90a82c29dba089a20db2946c90d15fc114e9e6403668470c60fdb436689f10c03a71e5c03869e5a08446e0ef1712d42376b873d570fa2450322d2577de0fa5d95e48da8524fd7f1149c6f904d36a483adc9bdb837873fb486f3eebf1e637d48fd4fdb9791a7f5ebe2320330af54702ed51d98e270a033c1598d8ea36c9b655537c5bc52699fd29c6d3d7f5abfe7dbdfb0e9bf4e33d17504cf04548733636c93ea9775776ea43f9f293e0c656c28ddd7afc7f44a95f0937cf3e4efb1161831561333f23d8cc4febca2783b8f2c991ae7cde9798aff264384f8e8ff6e404c5244d9b12fe2eebf3cc1b01db05bd2edff61bec99ff6c8f0792aa566a3a57b25266af951aac7e78c40b7ed637b552d690af1f9d9177b74febddeba7f7fb3fef1fcadf9f044913b5b767fa91642a20e946e5d9bef28b7c4f91747efede50ccdd716904ce0149580949873bfce9200e7f7aa4c32f3f31f9bcc7bf145fa73090bf370ff2f7ffa6c9a3f4c685a7062433ee4b47de93bc6f0cacf377e1f4654551c6014379f8d91e35c5896a4d71a654539cf4e7212a76e9badf2a593f53f22e9eb52959a533f2ef6a56e938ff2e20b39f7faf470ce0df4f82a3a93e108e94de8efda655b01f09483fa57b77ea4ffe1554f1c7f178fc98c82ffd79575d21f96d1d6fc1b7df34beddd11a4e39304f4596cd52e4732f0f699421b8665146239ffa888b0fcdc07408d8d012c097678051f6177405b005e0580b17b731cb18fd11b558c560900a87b5624b96517f8cde0601fa2c5691a2cf547c4f0d10216628fd386c23f7732f73cb2803156186d8c1822e99122abe032a614bf9394ef773a7893e35b3099475585f8aaf2e6a7f3b95fbf297ff0e0018988b73d84a0000"/>
  </proto>
</packet>`

func TestPdml1(t *testing.T) {

	dummy := make(ExpandedPaths, 0)
	tree := DecodePacket([]byte(p1))
	tree.ApplyExpandedPaths(&dummy)

	assert.Equal(t, 8, len(tree.Children_))
	assert.Equal(t, 13, len(tree.Children_[0].Children_))
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
