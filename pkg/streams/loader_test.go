// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package streams

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================

type payloadTracker struct {
	indices []int
}

func (p *payloadTracker) TrackPayloadPacket(packet int) {
	p.indices = append(p.indices, packet)
}

//======================================================================

func TestDecode1(t *testing.T) {
	pdml := `<?xml version="1.0" encoding="utf-8"?>
<?xml-stylesheet type="text/xsl" href="pdml2html.xsl"?>
<!-- You can find pdml2html.xsl in /usr/share/wireshark or at https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=pdml2html.xsl. -->
<pdml version="0" creator="wireshark/2.6.10" time="Sat Oct 12 14:00:09 2019" capture_file="/home/gcla/http1.pcap">
<packet>
  <proto name="geninfo" pos="0" showname="General information" size="997">
    <field name="num" pos="0" show="1" showname="Number" value="1" size="997"/>
    <field name="len" pos="0" show="997" showname="Frame Length" value="3e5" size="997"/>
    <field name="caplen" pos="0" show="997" showname="Captured Length" value="3e5" size="997"/>
    <field name="timestamp" pos="0" show="Jan 25, 2011 13:52:22.484409000 EST" showname="Captured Time" value="1295981542.484409000" size="997"/>
  </proto>
  <proto name="frame" showname="Frame 1: 997 bytes on wire (7976 bits), 997 bytes captured (7976 bits)" size="997" pos="0">
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Micro-St_9a:f1:f5 (40:61:86:9a:f1:f5), Dst: Sophos_15:f9:80 (00:1a:8c:15:f9:80)" size="14" pos="0">
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 192.168.3.131, Dst: 72.14.213.138" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 983" size="2" pos="16" show="983" value="03d7"/>
    <field name="ip.id" showname="Identification: 0x76e0 (30432)" size="2" pos="18" show="0x000076e0" value="76e0"/>
    <field name="ip.flags" showname="Flags: 0x4000, Don&#x27;t fragment" size="2" pos="20" show="0x00004000" value="4000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.flags.df" showname=".1.. .... .... .... = Don&#x27;t fragment: Set" size="2" pos="20" show="1" value="1" unmaskedvalue="4000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 128" size="1" pos="22" show="128" value="80"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0x9e7c [correct]" size="2" pos="24" show="0x00009e7c" value="9e7c"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0x9e7c" size="2" pos="24" show="0x00009e7c" value="9e7c"/>
    <field name="ip.src" showname="Source: 192.168.3.131" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.src_host" showname="Source Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.dst" showname="Destination: 72.14.213.138" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.addr" showname="Source or Destination Address: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.dst_host" showname="Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.host" showname="Source or Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 57011, Dst Port: 80, Seq: 1, Ack: 1, Len: 943" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 57011" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.dstport" showname="Destination Port: 80" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 57011" hide="yes" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="34" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 943" size="1" pos="46" show="943" value="50"/>
    <field name="tcp.seq" showname="Sequence number: 1    (relative sequence number)" size="4" pos="38" show="1" value="978a2298"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 944    (relative sequence number)" size="0" pos="34" show="944"/>
    <field name="tcp.ack" showname="Acknowledgment number: 1    (relative ack number)" size="4" pos="42" show="1" value="90b8a4df"/>
    <field name="tcp.hdr_len" showname="0101 .... = Header Length: 20 bytes (5)" size="1" pos="46" show="20" value="50"/>
    <field name="tcp.flags" showname="Flags: 0x018 (PSH, ACK)" size="2" pos="46" show="0x00000018" value="18" unmaskedvalue="5018">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.push" showname=".... .... 1... = Push: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.fin" showname=".... .... ...0 = Fin: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" size="2" pos="46" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" value="5018"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 16288" size="2" pos="48" show="16288" value="3fa0"/>
    <field name="tcp.window_size" showname="Calculated window size: 16288" size="2" pos="48" show="16288" value="3fa0"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="48" show="-1" value="3fa0"/>
    <field name="tcp.checksum" showname="Checksum: 0x5df8 [unverified]" size="2" pos="50" show="0x00005df8" value="5df8"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="50" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="tcp.analysis" showname="SEQ/ACK analysis" size="0" pos="34" show="" value="">
      <field name="tcp.analysis.bytes_in_flight" showname="Bytes in flight: 943" size="0" pos="34" show="943"/>
      <field name="tcp.analysis.push_bytes_sent" showname="Bytes sent since last PSH flag: 943" size="0" pos="34" show="943"/>
    </field>
    <field name="" show="Timestamps" size="0" pos="34">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 0.000000000 seconds" size="0" pos="34" show="0.000000000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 0.000000000 seconds" size="0" pos="34" show="0.000000000"/>
    </field>
    <field name="tcp.payload" showname="TCP payload (943 bytes)" size="943" pos="54" show="47:45:54:20:2f:63:6f:6d:70:6c:65:74:65:2f:73:65:61:72:63:68:3f:63:6c:69:65:6e:74:3d:63:68:72:6f:6d:65:26:68:6c:3d:65:6e:2d:55:53:26:71:3d:63:72:20:48:54:54:50:2f:31:2e:31:0d:0a:48:6f:73:74:3a:20:63:6c:69:65:6e:74:73:31:2e:67:6f:6f:67:6c:65:2e:63:61:0d:0a:43:6f:6e:6e:65:63:74:69:6f:6e:3a:20:6b:65:65:70:2d:61:6c:69:76:65:0d:0a:55:73:65:72:2d:41:67:65:6e:74:3a:20:4d:6f:7a:69:6c:6c:61:2f:35:2e:30:20:28:57:69:6e:64:6f:77:73:3b:20:55:3b:20:57:69:6e:64:6f:77:73:20:4e:54:20:36:2e:31:3b:20:65:6e:2d:55:53:29:20:41:70:70:6c:65:57:65:62:4b:69:74:2f:35:33:34:2e:31:30:20:28:4b:48:54:4d:4c:2c:20:6c:69:6b:65:20:47:65:63:6b:6f:29:20:43:68:72:6f:6d:65:2f:38:2e:30:2e:35:35:32:2e:32:33:37:20:53:61:66:61:72:69:2f:35:33:34:2e:31:30:0d:0a:41:63:63:65:70:74:2d:45:6e:63:6f:64:69:6e:67:3a:20:67:7a:69:70:2c:64:65:66:6c:61:74:65:2c:73:64:63:68:0d:0a:41:63:63:65:70:74:2d:4c:61:6e:67:75:61:67:65:3a:20:65:6e:2d:55:53:2c:65:6e:3b:71:3d:30:2e:38:0d:0a:41:63:63:65:70:74:2d:43:68:61:72:73:65:74:3a:20:49:53:4f:2d:38:38:35:39:2d:31:2c:75:74:66:2d:38:3b:71:3d:30:2e:37:2c:2a:3b:71:3d:30:2e:33:0d:0a:43:6f:6f:6b:69:65:3a:20:50:52:45:46:3d:49:44:3d:63:32:65:33:35:30:30:31:32:32:35:38:64:66:31:63:3a:55:3d:33:38:36:61:36:65:62:65:66:30:64:62:32:38:37:63:3a:46:46:3d:30:3a:54:4d:3d:31:32:39:34:31:36:34:32:39:34:3a:4c:4d:3d:31:32:39:34:31:36:34:32:39:34:3a:53:3d:62:63:75:77:4d:36:56:68:35:65:63:4b:78:71:6d:6b:3b:20:53:49:44:3d:44:51:41:41:41:4e:34:41:41:41:42:33:4d:77:37:68:53:41:58:6d:32:39:73:76:66:5a:51:78:52:68:61:45:56:4c:35:78:5f:37:4a:45:79:57:45:79:77:50:74:66:49:4b:6d:56:32:51:4d:43:5a:36:31:56:66:53:76:47:78:67:2d:57:43:77:53:37:4f:59:6e:45:6f:6e:61:76:64:52:65:69:54:67:5a:5f:33:4a:61:6c:63:50:79:49:6e:78:59:62:48:47:36:36:38:68:62:68:66:56:52:78:43:48:57:72:61:43:38:6c:4e:68:68:68:5a:76:43:34:35:4c:33:32:57:44:6a:6b:50:52:52:79:30:71:6d:6f:7a:5f:33:53:47:7a:44:44:67:75:6d:42:32:6d:67:79:6a:54:48:69:71:52:64:67:45:6d:6f:70:73:45:76:6f:75:6f:62:53:5a:44:52:78:69:78:58:64:41:4e:76:54:48:79:71:38:35:50:6d:56:6e:7a:4b:48:4b:5f:2d:78:37:68:56:64:59:68:75:34:34:4a:36:50:5f:6f:49:34:62:5a:57:6e:48:41:39:36:36:51:6e:61:37:33:71:35:59:4f:50:50:65:76:76:5a:51:56:58:38:46:37:31:6e:56:6a:44:6b:34:61:4a:4d:35:4b:68:6c:41:51:77:42:44:78:35:66:7a:72:56:39:57:6b:5f:52:5f:59:2d:65:67:7a:30:73:44:4c:39:6f:43:33:66:42:55:52:47:56:77:70:34:79:77:51:3b:20:48:53:49:44:3d:41:71:67:4d:33:4a:6c:7a:72:56:41:33:51:6b:69:79:7a:3b:20:4e:49:44:3d:34:33:3d:46:5f:6f:53:5a:57:79:6f:39:4e:69:61:64:6b:31:37:6d:36:35:51:74:4d:39:61:6c:42:4a:51:34:59:4c:30:42:30:79:41:50:37:31:72:75:4e:71:61:35:73:56:34:4a:4f:52:49:6d:73:51:6f:76:55:31:50:57:32:50:45:49:49:37:61:2d:35:4b:55:69:34:59:43:52:4d:43:65:79:74:75:68:69:77:6b:57:67:53:6c:57:74:48:45:41:6a:5f:6e:74:5f:45:46:38:79:38:34:4d:4e:6d:72:74:6d:52:7a:4b:39:4b:74:68:39:36:4e:34:2d:62:50:5a:0d:0a:0d:0a" value="474554202f636f6d706c6574652f7365617263683f636c69656e743d6368726f6d6526686c3d656e2d555326713d637220485454502f312e310d0a486f73743a20636c69656e7473312e676f6f676c652e63610d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f77733b20553b2057696e646f7773204e5420362e313b20656e2d555329204170706c655765624b69742f3533342e313020284b48544d4c2c206c696b65204765636b6f29204368726f6d652f382e302e3535322e323337205361666172692f3533342e31300d0a4163636570742d456e636f64696e673a20677a69702c6465666c6174652c736463680d0a4163636570742d4c616e67756167653a20656e2d55532c656e3b713d302e380d0a4163636570742d436861727365743a2049534f2d383835392d312c7574662d383b713d302e372c2a3b713d302e330d0a436f6f6b69653a20505245463d49443d633265333530303132323538646631633a553d333836613665626566306462323837633a46463d303a544d3d313239343136343239343a4c4d3d313239343136343239343a533d626375774d3656683565634b78716d6b3b205349443d44514141414e3441414142334d7737685341586d32397376665a517852686145564c35785f374a457957457977507466494b6d5632514d435a3631566653764778672d57437753374f596e456f6e61766452656954675a5f334a616c635079496e785962484736363868626866565278434857726143386c4e6868685a764334354c333257446a6b5052527930716d6f7a5f3353477a444467756d42326d67796a54486971526467456d6f707345766f756f62535a44527869785864414e76544879713835506d566e7a4b484b5f2d783768566459687534344a36505f6f4934625a576e4841393636516e6137337135594f50506576765a515658384637316e566a446b34614a4d354b686c41517742447835667a725639576b5f525f592d65677a3073444c396f43336642555247567770347977513b20485349443d4171674d334a6c7a72564133516b69797a3b204e49443d34333d465f6f535a57796f394e6961646b31376d363551744d39616c424a5134594c304230794150373172754e7161357356344a4f52496d73516f7655315057325045494937612d354b5569345943524d43657974756869776b5767536c57744845416a5f6e745f4546387938344d4e6d72746d527a4b394b746839364e342d62505a0d0a0d0a"/>
  </proto>
  <proto name="http" showname="Hypertext Transfer Protocol" size="943" pos="54">
  </proto>
</packet>


<packet>
  <proto name="geninfo" pos="0" showname="General information" size="440">
    <field name="num" pos="0" show="2" showname="Number" value="2" size="440"/>
    <field name="len" pos="0" show="440" showname="Frame Length" value="1b8" size="440"/>
    <field name="caplen" pos="0" show="440" showname="Captured Length" value="1b8" size="440"/>
    <field name="timestamp" pos="0" show="Jan 25, 2011 13:52:22.514250000 EST" showname="Captured Time" value="1295981542.514250000" size="440"/>
  </proto>
  <proto name="frame" showname="Frame 2: 440 bytes on wire (3520 bits), 440 bytes captured (3520 bits)" size="440" pos="0">
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Sophos_15:f9:80 (00:1a:8c:15:f9:80), Dst: Micro-St_9a:f1:f5 (40:61:86:9a:f1:f5)" size="14" pos="0">
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 72.14.213.138, Dst: 192.168.3.131" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 426" size="2" pos="16" show="426" value="01aa"/>
    <field name="ip.id" showname="Identification: 0x2d62 (11618)" size="2" pos="18" show="0x00002d62" value="2d62"/>
    <field name="ip.flags" showname="Flags: 0x0000" size="2" pos="20" show="0x00000000" value="0000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.flags.df" showname=".0.. .... .... .... = Don&#x27;t fragment: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 52" size="1" pos="22" show="52" value="34"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0x7628 [correct]" size="2" pos="24" show="0x00007628" value="7628"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0x7628" size="2" pos="24" show="0x00007628" value="7628"/>
    <field name="ip.src" showname="Source: 72.14.213.138" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.addr" showname="Source or Destination Address: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.src_host" showname="Source Host: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.host" showname="Source or Destination Host: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.dst" showname="Destination: 192.168.3.131" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.dst_host" showname="Destination Host: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 80, Dst Port: 57011, Seq: 1, Ack: 944, Len: 386" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 80" size="2" pos="34" show="80" value="0050"/>
    <field name="tcp.dstport" showname="Destination Port: 57011" size="2" pos="36" show="57011" value="deb3"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="34" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 57011" hide="yes" size="2" pos="36" show="57011" value="deb3"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="34" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 386" size="1" pos="46" show="386" value="50"/>
    <field name="tcp.seq" showname="Sequence number: 1    (relative sequence number)" size="4" pos="38" show="1" value="90b8a4df"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 387    (relative sequence number)" size="0" pos="34" show="387"/>
    <field name="tcp.ack" showname="Acknowledgment number: 944    (relative ack number)" size="4" pos="42" show="944" value="978a2647"/>
    <field name="tcp.hdr_len" showname="0101 .... = Header Length: 20 bytes (5)" size="1" pos="46" show="20" value="50"/>
    <field name="tcp.flags" showname="Flags: 0x018 (PSH, ACK)" size="2" pos="46" show="0x00000018" value="18" unmaskedvalue="5018">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.push" showname=".... .... 1... = Push: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.fin" showname=".... .... ...0 = Fin: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" size="2" pos="46" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" value="5018"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 947" size="2" pos="48" show="947" value="03b3"/>
    <field name="tcp.window_size" showname="Calculated window size: 947" size="2" pos="48" show="947" value="03b3"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="48" show="-1" value="03b3"/>
    <field name="tcp.checksum" showname="Checksum: 0xd77c [unverified]" size="2" pos="50" show="0x0000d77c" value="d77c"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="50" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="tcp.analysis" showname="SEQ/ACK analysis" size="0" pos="34" show="" value="">
      <field name="tcp.analysis.acks_frame" showname="This is an ACK to the segment in frame: 1" size="0" pos="34" show="1"/>
      <field name="tcp.analysis.ack_rtt" showname="The RTT to ACK the segment was: 0.029841000 seconds" size="0" pos="34" show="0.029841000"/>
      <field name="tcp.analysis.bytes_in_flight" showname="Bytes in flight: 386" size="0" pos="34" show="386"/>
      <field name="tcp.analysis.push_bytes_sent" showname="Bytes sent since last PSH flag: 386" size="0" pos="34" show="386"/>
    </field>
    <field name="" show="Timestamps" size="0" pos="34">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 0.029841000 seconds" size="0" pos="34" show="0.029841000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 0.029841000 seconds" size="0" pos="34" show="0.029841000"/>
    </field>
    <field name="tcp.payload" showname="TCP payload (386 bytes)" size="386" pos="54" show="48:54:54:50:2f:31:2e:31:20:32:30:30:20:4f:4b:0d:0a:44:61:74:65:3a:20:54:75:65:2c:20:32:35:20:4a:61:6e:20:32:30:31:31:20:31:39:3a:30:35:3a:35:36:20:47:4d:54:0d:0a:45:78:70:69:72:65:73:3a:20:54:75:65:2c:20:32:35:20:4a:61:6e:20:32:30:31:31:20:31:39:3a:30:35:3a:35:36:20:47:4d:54:0d:0a:43:61:63:68:65:2d:43:6f:6e:74:72:6f:6c:3a:20:70:72:69:76:61:74:65:2c:20:6d:61:78:2d:61:67:65:3d:33:36:30:30:0d:0a:43:6f:6e:74:65:6e:74:2d:54:79:70:65:3a:20:74:65:78:74:2f:6a:61:76:61:73:63:72:69:70:74:3b:20:63:68:61:72:73:65:74:3d:55:54:46:2d:38:0d:0a:43:6f:6e:74:65:6e:74:2d:45:6e:63:6f:64:69:6e:67:3a:20:67:7a:69:70:0d:0a:53:65:72:76:65:72:3a:20:67:77:73:0d:0a:43:6f:6e:74:65:6e:74:2d:4c:65:6e:67:74:68:3a:20:31:31:35:0d:0a:58:2d:58:53:53:2d:50:72:6f:74:65:63:74:69:6f:6e:3a:20:31:3b:20:6d:6f:64:65:3d:62:6c:6f:63:6b:0d:0a:0d:0a:1f:8b:08:00:00:00:00:00:02:ff:8b:56:4a:2e:52:d2:89:06:92:89:99:e9:c5:39:99:c5:25:4a:3a:48:1c:85:b2:c4:bc:e4:fc:d2:b2:d4:22:88:30:8a:a4:5e:72:a2:52:2c:50:2f:50:10:8a:80:bc:58:9d:6a:a5:f4:fc:fc:f4:9c:54:ab:e2:d2:f4:f4:d4:e2:92:92:ca:82:54:25:ab:68:a5:c0:50:d7:a0:48:a0:2a:74:da:cf:31:cc:d3:dd:31:c4:d3:df:4f:29:b6:36:16:00:ea:d3:60:e5:91:00:00:00" value="485454502f312e3120323030204f4b0d0a446174653a205475652c203235204a616e20323031312031393a30353a353620474d540d0a457870697265733a205475652c203235204a616e20323031312031393a30353a353620474d540d0a43616368652d436f6e74726f6c3a20707269766174652c206d61782d6167653d333630300d0a436f6e74656e742d547970653a20746578742f6a6176617363726970743b20636861727365743d5554462d380d0a436f6e74656e742d456e636f64696e673a20677a69700d0a5365727665723a206777730d0a436f6e74656e742d4c656e6774683a203131350d0a582d5853532d50726f74656374696f6e3a20313b206d6f64653d626c6f636b0d0a0d0a1f8b08000000000002ff8b564a2e52d28906928999e9c53999c5254a3a481c85b2c4bce4fcd2b2d42288308aa45e72a2522c502f50108a80bc589d6aa5f4fcfcf49c54abe2d2f4f4d4e29292ca825425ab68a5c050d7a048a02a74dacf31ccd3dd31c4d3df4f29b6361600ead360e591000000"/>
  </proto>
  <proto name="http" showname="Hypertext Transfer Protocol" size="271" pos="54">
  </proto>
</packet>


<packet>
  <proto name="geninfo" pos="0" showname="General information" size="54">
    <field name="num" pos="0" show="3" showname="Number" value="3" size="54"/>
    <field name="len" pos="0" show="54" showname="Frame Length" value="36" size="54"/>
    <field name="caplen" pos="0" show="54" showname="Captured Length" value="36" size="54"/>
    <field name="timestamp" pos="0" show="Jan 25, 2011 13:52:22.713832000 EST" showname="Captured Time" value="1295981542.713832000" size="54"/>
  </proto>
  <proto name="frame" showname="Frame 3: 54 bytes on wire (432 bits), 54 bytes captured (432 bits)" size="54" pos="0">
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Micro-St_9a:f1:f5 (40:61:86:9a:f1:f5), Dst: Sophos_15:f9:80 (00:1a:8c:15:f9:80)" size="14" pos="0">
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 192.168.3.131, Dst: 72.14.213.138" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 40" size="2" pos="16" show="40" value="0028"/>
    <field name="ip.id" showname="Identification: 0x76ef (30447)" size="2" pos="18" show="0x000076ef" value="76ef"/>
    <field name="ip.flags" showname="Flags: 0x4000, Don&#x27;t fragment" size="2" pos="20" show="0x00004000" value="4000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.flags.df" showname=".1.. .... .... .... = Don&#x27;t fragment: Set" size="2" pos="20" show="1" value="1" unmaskedvalue="4000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 128" size="1" pos="22" show="128" value="80"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0xa21c [correct]" size="2" pos="24" show="0x0000a21c" value="a21c"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0xa21c" size="2" pos="24" show="0x0000a21c" value="a21c"/>
    <field name="ip.src" showname="Source: 192.168.3.131" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.src_host" showname="Source Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.dst" showname="Destination: 72.14.213.138" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.addr" showname="Source or Destination Address: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.dst_host" showname="Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.host" showname="Source or Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 57011, Dst Port: 80, Seq: 944, Ack: 387, Len: 0" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 57011" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.dstport" showname="Destination Port: 80" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 57011" hide="yes" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="34" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 0" size="1" pos="46" show="0" value="50"/>
    <field name="tcp.seq" showname="Sequence number: 944    (relative sequence number)" size="4" pos="38" show="944" value="978a2647"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 944    (relative sequence number)" size="0" pos="34" show="944"/>
    <field name="tcp.ack" showname="Acknowledgment number: 387    (relative ack number)" size="4" pos="42" show="387" value="90b8a661"/>
    <field name="tcp.hdr_len" showname="0101 .... = Header Length: 20 bytes (5)" size="1" pos="46" show="20" value="50"/>
    <field name="tcp.flags" showname="Flags: 0x010 (ACK)" size="2" pos="46" show="0x00000010" value="10" unmaskedvalue="5010">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="10"/>
      <field name="tcp.flags.push" showname=".... .... 0... = Push: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.fin" showname=".... .... ...0 = Fin: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7" size="2" pos="46" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7" value="5010"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 16192" size="2" pos="48" show="16192" value="3f40"/>
    <field name="tcp.window_size" showname="Calculated window size: 16192" size="2" pos="48" show="16192" value="3f40"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="48" show="-1" value="3f40"/>
    <field name="tcp.checksum" showname="Checksum: 0xbae0 [unverified]" size="2" pos="50" show="0x0000bae0" value="bae0"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="50" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="tcp.analysis" showname="SEQ/ACK analysis" size="0" pos="34" show="" value="">
      <field name="tcp.analysis.acks_frame" showname="This is an ACK to the segment in frame: 2" size="0" pos="34" show="2"/>
      <field name="tcp.analysis.ack_rtt" showname="The RTT to ACK the segment was: 0.199582000 seconds" size="0" pos="34" show="0.199582000"/>
    </field>
    <field name="" show="Timestamps" size="0" pos="34">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 0.229423000 seconds" size="0" pos="34" show="0.229423000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 0.199582000 seconds" size="0" pos="34" show="0.199582000"/>
    </field>
  </proto>
</packet>


<packet>
  <proto name="geninfo" pos="0" showname="General information" size="999">
    <field name="num" pos="0" show="4" showname="Number" value="4" size="999"/>
    <field name="len" pos="0" show="999" showname="Frame Length" value="3e7" size="999"/>
    <field name="caplen" pos="0" show="999" showname="Captured Length" value="3e7" size="999"/>
    <field name="timestamp" pos="0" show="Jan 25, 2011 13:52:23.265531000 EST" showname="Captured Time" value="1295981543.265531000" size="999"/>
  </proto>
  <proto name="frame" showname="Frame 4: 999 bytes on wire (7992 bits), 999 bytes captured (7992 bits)" size="999" pos="0">
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Micro-St_9a:f1:f5 (40:61:86:9a:f1:f5), Dst: Sophos_15:f9:80 (00:1a:8c:15:f9:80)" size="14" pos="0">
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 192.168.3.131, Dst: 72.14.213.138" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 985" size="2" pos="16" show="985" value="03d9"/>
    <field name="ip.id" showname="Identification: 0x76f0 (30448)" size="2" pos="18" show="0x000076f0" value="76f0"/>
    <field name="ip.flags" showname="Flags: 0x4000, Don&#x27;t fragment" size="2" pos="20" show="0x00004000" value="4000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.flags.df" showname=".1.. .... .... .... = Don&#x27;t fragment: Set" size="2" pos="20" show="1" value="1" unmaskedvalue="4000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 128" size="1" pos="22" show="128" value="80"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0x9e6a [correct]" size="2" pos="24" show="0x00009e6a" value="9e6a"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0x9e6a" size="2" pos="24" show="0x00009e6a" value="9e6a"/>
    <field name="ip.src" showname="Source: 192.168.3.131" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.src_host" showname="Source Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.dst" showname="Destination: 72.14.213.138" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.addr" showname="Source or Destination Address: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.dst_host" showname="Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.host" showname="Source or Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 57011, Dst Port: 80, Seq: 944, Ack: 387, Len: 945" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 57011" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.dstport" showname="Destination Port: 80" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 57011" hide="yes" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="34" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 945" size="1" pos="46" show="945" value="50"/>
    <field name="tcp.seq" showname="Sequence number: 944    (relative sequence number)" size="4" pos="38" show="944" value="978a2647"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 1889    (relative sequence number)" size="0" pos="34" show="1889"/>
    <field name="tcp.ack" showname="Acknowledgment number: 387    (relative ack number)" size="4" pos="42" show="387" value="90b8a661"/>
    <field name="tcp.hdr_len" showname="0101 .... = Header Length: 20 bytes (5)" size="1" pos="46" show="20" value="50"/>
    <field name="tcp.flags" showname="Flags: 0x018 (PSH, ACK)" size="2" pos="46" show="0x00000018" value="18" unmaskedvalue="5018">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.push" showname=".... .... 1... = Push: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.fin" showname=".... .... ...0 = Fin: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" size="2" pos="46" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" value="5018"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 16192" size="2" pos="48" show="16192" value="3f40"/>
    <field name="tcp.window_size" showname="Calculated window size: 16192" size="2" pos="48" show="16192" value="3f40"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="48" show="-1" value="3f40"/>
    <field name="tcp.checksum" showname="Checksum: 0xf7bb [unverified]" size="2" pos="50" show="0x0000f7bb" value="f7bb"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="50" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="tcp.analysis" showname="SEQ/ACK analysis" size="0" pos="34" show="" value="">
      <field name="tcp.analysis.bytes_in_flight" showname="Bytes in flight: 945" size="0" pos="34" show="945"/>
      <field name="tcp.analysis.push_bytes_sent" showname="Bytes sent since last PSH flag: 945" size="0" pos="34" show="945"/>
    </field>
    <field name="" show="Timestamps" size="0" pos="34">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 0.781122000 seconds" size="0" pos="34" show="0.781122000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 0.551699000 seconds" size="0" pos="34" show="0.551699000"/>
    </field>
    <field name="tcp.payload" showname="TCP payload (945 bytes)" size="945" pos="54" show="47:45:54:20:2f:63:6f:6d:70:6c:65:74:65:2f:73:65:61:72:63:68:3f:63:6c:69:65:6e:74:3d:63:68:72:6f:6d:65:26:68:6c:3d:65:6e:2d:55:53:26:71:3d:63:72:61:69:20:48:54:54:50:2f:31:2e:31:0d:0a:48:6f:73:74:3a:20:63:6c:69:65:6e:74:73:31:2e:67:6f:6f:67:6c:65:2e:63:61:0d:0a:43:6f:6e:6e:65:63:74:69:6f:6e:3a:20:6b:65:65:70:2d:61:6c:69:76:65:0d:0a:55:73:65:72:2d:41:67:65:6e:74:3a:20:4d:6f:7a:69:6c:6c:61:2f:35:2e:30:20:28:57:69:6e:64:6f:77:73:3b:20:55:3b:20:57:69:6e:64:6f:77:73:20:4e:54:20:36:2e:31:3b:20:65:6e:2d:55:53:29:20:41:70:70:6c:65:57:65:62:4b:69:74:2f:35:33:34:2e:31:30:20:28:4b:48:54:4d:4c:2c:20:6c:69:6b:65:20:47:65:63:6b:6f:29:20:43:68:72:6f:6d:65:2f:38:2e:30:2e:35:35:32:2e:32:33:37:20:53:61:66:61:72:69:2f:35:33:34:2e:31:30:0d:0a:41:63:63:65:70:74:2d:45:6e:63:6f:64:69:6e:67:3a:20:67:7a:69:70:2c:64:65:66:6c:61:74:65:2c:73:64:63:68:0d:0a:41:63:63:65:70:74:2d:4c:61:6e:67:75:61:67:65:3a:20:65:6e:2d:55:53:2c:65:6e:3b:71:3d:30:2e:38:0d:0a:41:63:63:65:70:74:2d:43:68:61:72:73:65:74:3a:20:49:53:4f:2d:38:38:35:39:2d:31:2c:75:74:66:2d:38:3b:71:3d:30:2e:37:2c:2a:3b:71:3d:30:2e:33:0d:0a:43:6f:6f:6b:69:65:3a:20:50:52:45:46:3d:49:44:3d:63:32:65:33:35:30:30:31:32:32:35:38:64:66:31:63:3a:55:3d:33:38:36:61:36:65:62:65:66:30:64:62:32:38:37:63:3a:46:46:3d:30:3a:54:4d:3d:31:32:39:34:31:36:34:32:39:34:3a:4c:4d:3d:31:32:39:34:31:36:34:32:39:34:3a:53:3d:62:63:75:77:4d:36:56:68:35:65:63:4b:78:71:6d:6b:3b:20:53:49:44:3d:44:51:41:41:41:4e:34:41:41:41:42:33:4d:77:37:68:53:41:58:6d:32:39:73:76:66:5a:51:78:52:68:61:45:56:4c:35:78:5f:37:4a:45:79:57:45:79:77:50:74:66:49:4b:6d:56:32:51:4d:43:5a:36:31:56:66:53:76:47:78:67:2d:57:43:77:53:37:4f:59:6e:45:6f:6e:61:76:64:52:65:69:54:67:5a:5f:33:4a:61:6c:63:50:79:49:6e:78:59:62:48:47:36:36:38:68:62:68:66:56:52:78:43:48:57:72:61:43:38:6c:4e:68:68:68:5a:76:43:34:35:4c:33:32:57:44:6a:6b:50:52:52:79:30:71:6d:6f:7a:5f:33:53:47:7a:44:44:67:75:6d:42:32:6d:67:79:6a:54:48:69:71:52:64:67:45:6d:6f:70:73:45:76:6f:75:6f:62:53:5a:44:52:78:69:78:58:64:41:4e:76:54:48:79:71:38:35:50:6d:56:6e:7a:4b:48:4b:5f:2d:78:37:68:56:64:59:68:75:34:34:4a:36:50:5f:6f:49:34:62:5a:57:6e:48:41:39:36:36:51:6e:61:37:33:71:35:59:4f:50:50:65:76:76:5a:51:56:58:38:46:37:31:6e:56:6a:44:6b:34:61:4a:4d:35:4b:68:6c:41:51:77:42:44:78:35:66:7a:72:56:39:57:6b:5f:52:5f:59:2d:65:67:7a:30:73:44:4c:39:6f:43:33:66:42:55:52:47:56:77:70:34:79:77:51:3b:20:48:53:49:44:3d:41:71:67:4d:33:4a:6c:7a:72:56:41:33:51:6b:69:79:7a:3b:20:4e:49:44:3d:34:33:3d:46:5f:6f:53:5a:57:79:6f:39:4e:69:61:64:6b:31:37:6d:36:35:51:74:4d:39:61:6c:42:4a:51:34:59:4c:30:42:30:79:41:50:37:31:72:75:4e:71:61:35:73:56:34:4a:4f:52:49:6d:73:51:6f:76:55:31:50:57:32:50:45:49:49:37:61:2d:35:4b:55:69:34:59:43:52:4d:43:65:79:74:75:68:69:77:6b:57:67:53:6c:57:74:48:45:41:6a:5f:6e:74:5f:45:46:38:79:38:34:4d:4e:6d:72:74:6d:52:7a:4b:39:4b:74:68:39:36:4e:34:2d:62:50:5a:0d:0a:0d:0a" value="474554202f636f6d706c6574652f7365617263683f636c69656e743d6368726f6d6526686c3d656e2d555326713d6372616920485454502f312e310d0a486f73743a20636c69656e7473312e676f6f676c652e63610d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f77733b20553b2057696e646f7773204e5420362e313b20656e2d555329204170706c655765624b69742f3533342e313020284b48544d4c2c206c696b65204765636b6f29204368726f6d652f382e302e3535322e323337205361666172692f3533342e31300d0a4163636570742d456e636f64696e673a20677a69702c6465666c6174652c736463680d0a4163636570742d4c616e67756167653a20656e2d55532c656e3b713d302e380d0a4163636570742d436861727365743a2049534f2d383835392d312c7574662d383b713d302e372c2a3b713d302e330d0a436f6f6b69653a20505245463d49443d633265333530303132323538646631633a553d333836613665626566306462323837633a46463d303a544d3d313239343136343239343a4c4d3d313239343136343239343a533d626375774d3656683565634b78716d6b3b205349443d44514141414e3441414142334d7737685341586d32397376665a517852686145564c35785f374a457957457977507466494b6d5632514d435a3631566653764778672d57437753374f596e456f6e61766452656954675a5f334a616c635079496e785962484736363868626866565278434857726143386c4e6868685a764334354c333257446a6b5052527930716d6f7a5f3353477a444467756d42326d67796a54486971526467456d6f707345766f756f62535a44527869785864414e76544879713835506d566e7a4b484b5f2d783768566459687534344a36505f6f4934625a576e4841393636516e6137337135594f50506576765a515658384637316e566a446b34614a4d354b686c41517742447835667a725639576b5f525f592d65677a3073444c396f43336642555247567770347977513b20485349443d4171674d334a6c7a72564133516b69797a3b204e49443d34333d465f6f535a57796f394e6961646b31376d363551744d39616c424a5134594c304230794150373172754e7161357356344a4f52496d73516f7655315057325045494937612d354b5569345943524d43657974756869776b5767536c57744845416a5f6e745f4546387938344d4e6d72746d527a4b394b746839364e342d62505a0d0a0d0a"/>
  </proto>
  <proto name="http" showname="Hypertext Transfer Protocol" size="945" pos="54">
  </proto>
</packet>


<packet>
  <proto name="geninfo" pos="0" showname="General information" size="523">
    <field name="num" pos="0" show="5" showname="Number" value="5" size="523"/>
    <field name="len" pos="0" show="523" showname="Frame Length" value="20b" size="523"/>
    <field name="caplen" pos="0" show="523" showname="Captured Length" value="20b" size="523"/>
    <field name="timestamp" pos="0" show="Jan 25, 2011 13:52:23.300298000 EST" showname="Captured Time" value="1295981543.300298000" size="523"/>
  </proto>
  <proto name="frame" showname="Frame 5: 523 bytes on wire (4184 bits), 523 bytes captured (4184 bits)" size="523" pos="0">
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Sophos_15:f9:80 (00:1a:8c:15:f9:80), Dst: Micro-St_9a:f1:f5 (40:61:86:9a:f1:f5)" size="14" pos="0">
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 72.14.213.138, Dst: 192.168.3.131" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 509" size="2" pos="16" show="509" value="01fd"/>
    <field name="ip.id" showname="Identification: 0x2d63 (11619)" size="2" pos="18" show="0x00002d63" value="2d63"/>
    <field name="ip.flags" showname="Flags: 0x0000" size="2" pos="20" show="0x00000000" value="0000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.flags.df" showname=".0.. .... .... .... = Don&#x27;t fragment: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 52" size="1" pos="22" show="52" value="34"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0x75d4 [correct]" size="2" pos="24" show="0x000075d4" value="75d4"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0x75d4" size="2" pos="24" show="0x000075d4" value="75d4"/>
    <field name="ip.src" showname="Source: 72.14.213.138" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.addr" showname="Source or Destination Address: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.src_host" showname="Source Host: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.host" showname="Source or Destination Host: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.dst" showname="Destination: 192.168.3.131" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.dst_host" showname="Destination Host: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 80, Dst Port: 57011, Seq: 387, Ack: 1889, Len: 469" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 80" size="2" pos="34" show="80" value="0050"/>
    <field name="tcp.dstport" showname="Destination Port: 57011" size="2" pos="36" show="57011" value="deb3"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="34" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 57011" hide="yes" size="2" pos="36" show="57011" value="deb3"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="34" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 469" size="1" pos="46" show="469" value="50"/>
    <field name="tcp.seq" showname="Sequence number: 387    (relative sequence number)" size="4" pos="38" show="387" value="90b8a661"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 856    (relative sequence number)" size="0" pos="34" show="856"/>
    <field name="tcp.ack" showname="Acknowledgment number: 1889    (relative ack number)" size="4" pos="42" show="1889" value="978a29f8"/>
    <field name="tcp.hdr_len" showname="0101 .... = Header Length: 20 bytes (5)" size="1" pos="46" show="20" value="50"/>
    <field name="tcp.flags" showname="Flags: 0x018 (PSH, ACK)" size="2" pos="46" show="0x00000018" value="18" unmaskedvalue="5018">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.push" showname=".... .... 1... = Push: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.fin" showname=".... .... ...0 = Fin: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" size="2" pos="46" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" value="5018"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 980" size="2" pos="48" show="980" value="03d4"/>
    <field name="tcp.window_size" showname="Calculated window size: 980" size="2" pos="48" show="980" value="03d4"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="48" show="-1" value="03d4"/>
    <field name="tcp.checksum" showname="Checksum: 0xf8e3 [unverified]" size="2" pos="50" show="0x0000f8e3" value="f8e3"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="50" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="tcp.analysis" showname="SEQ/ACK analysis" size="0" pos="34" show="" value="">
      <field name="tcp.analysis.acks_frame" showname="This is an ACK to the segment in frame: 4" size="0" pos="34" show="4"/>
      <field name="tcp.analysis.ack_rtt" showname="The RTT to ACK the segment was: 0.034767000 seconds" size="0" pos="34" show="0.034767000"/>
      <field name="tcp.analysis.bytes_in_flight" showname="Bytes in flight: 469" size="0" pos="34" show="469"/>
      <field name="tcp.analysis.push_bytes_sent" showname="Bytes sent since last PSH flag: 469" size="0" pos="34" show="469"/>
    </field>
    <field name="" show="Timestamps" size="0" pos="34">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 0.815889000 seconds" size="0" pos="34" show="0.815889000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 0.034767000 seconds" size="0" pos="34" show="0.034767000"/>
    </field>
    <field name="tcp.payload" showname="TCP payload (469 bytes)" size="469" pos="54" show="48:54:54:50:2f:31:2e:31:20:32:30:30:20:4f:4b:0d:0a:44:61:74:65:3a:20:54:75:65:2c:20:32:35:20:4a:61:6e:20:32:30:31:31:20:31:39:3a:30:35:3a:35:36:20:47:4d:54:0d:0a:45:78:70:69:72:65:73:3a:20:54:75:65:2c:20:32:35:20:4a:61:6e:20:32:30:31:31:20:31:39:3a:30:35:3a:35:36:20:47:4d:54:0d:0a:43:61:63:68:65:2d:43:6f:6e:74:72:6f:6c:3a:20:70:72:69:76:61:74:65:2c:20:6d:61:78:2d:61:67:65:3d:33:36:30:30:0d:0a:43:6f:6e:74:65:6e:74:2d:54:79:70:65:3a:20:74:65:78:74:2f:6a:61:76:61:73:63:72:69:70:74:3b:20:63:68:61:72:73:65:74:3d:55:54:46:2d:38:0d:0a:43:6f:6e:74:65:6e:74:2d:45:6e:63:6f:64:69:6e:67:3a:20:67:7a:69:70:0d:0a:53:65:72:76:65:72:3a:20:67:77:73:0d:0a:43:6f:6e:74:65:6e:74:2d:4c:65:6e:67:74:68:3a:20:31:39:38:0d:0a:58:2d:58:53:53:2d:50:72:6f:74:65:63:74:69:6f:6e:3a:20:31:3b:20:6d:6f:64:65:3d:62:6c:6f:63:6b:0d:0a:0d:0a:1f:8b:08:00:00:00:00:00:02:ff:65:cd:4d:0b:c2:30:0c:06:e0:bf:52:72:2e:ee:be:9b:07:11:2f:8a:a2:82:6c:3b:d4:1a:6b:a5:6b:46:d3:6e:88:f8:df:ad:28:f8:05:81:90:87:97:bc:15:e8:a0:2c:c8:0a:4e:31:76:65:5d:d4:c5:30:0c:a3:07:1a:76:96:e3:88:82:a9:0b:90:f0:a6:af:43:f4:ca:6b:4a:3d:86:1f:b6:3a:52:b0:0a:9a:fc:fb:c3:b5:53:cc:f6:68:f1:c0:a5:38:d3:9e:a5:38:51:62:eb:8d:14:1d:06:26:af:5c:b6:23:05:c1:ca:a1:14:8c:21:ff:c2:6c:9a:da:36:79:1b:2f:52:60:8f:3e:3e:63:a9:e5:dc:fc:9a:5c:d6:c8:2b:18:22:e3:b0:e4:64:0c:72:8c:97:0e:a1:ac:60:3e:de:ce:a6:e3:f5:6c:31:cf:d1:e5:66:b2:da:fd:ed:e6:d6:dc:01:db:25:7c:14:12:01:00:00" value="485454502f312e3120323030204f4b0d0a446174653a205475652c203235204a616e20323031312031393a30353a353620474d540d0a457870697265733a205475652c203235204a616e20323031312031393a30353a353620474d540d0a43616368652d436f6e74726f6c3a20707269766174652c206d61782d6167653d333630300d0a436f6e74656e742d547970653a20746578742f6a6176617363726970743b20636861727365743d5554462d380d0a436f6e74656e742d456e636f64696e673a20677a69700d0a5365727665723a206777730d0a436f6e74656e742d4c656e6774683a203139380d0a582d5853532d50726f74656374696f6e3a20313b206d6f64653d626c6f636b0d0a0d0a1f8b08000000000002ff65cd4d0bc2300c06e0bf52722eeebe9b07112f8aa2826c3bd41a6ba56b46d36e88f8dfad28f80581908797bc15e8a02cc80a4e3176655dd4c5300ca3071a7696e38882a90b90f0a6af43f4ca6b4a3d861fb63a52b00a9afcfbc3b553ccf668f1c0a538d39ea5385162eb8d141d0626af5cb62305c1caa1148c21ffc26c9ada36791b2f52608f3e3e63a9e5dcfc9a5cd6c82b1822e3b0e4640c728c970ea1ac603edecea6e3f56c31cfd1e566b2dafdede6d6dc01db257c1412010000"/>
  </proto>
  <proto name="http" showname="Hypertext Transfer Protocol" size="271" pos="54">
  </proto>
</packet>


<packet>
  <proto name="geninfo" pos="0" showname="General information" size="54">
    <field name="num" pos="0" show="6" showname="Number" value="6" size="54"/>
    <field name="len" pos="0" show="54" showname="Frame Length" value="36" size="54"/>
    <field name="caplen" pos="0" show="54" showname="Captured Length" value="36" size="54"/>
    <field name="timestamp" pos="0" show="Jan 25, 2011 13:52:23.499908000 EST" showname="Captured Time" value="1295981543.499908000" size="54"/>
  </proto>
  <proto name="frame" showname="Frame 6: 54 bytes on wire (432 bits), 54 bytes captured (432 bits)" size="54" pos="0">
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Micro-St_9a:f1:f5 (40:61:86:9a:f1:f5), Dst: Sophos_15:f9:80 (00:1a:8c:15:f9:80)" size="14" pos="0">
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 192.168.3.131, Dst: 72.14.213.138" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 40" size="2" pos="16" show="40" value="0028"/>
    <field name="ip.id" showname="Identification: 0x76f1 (30449)" size="2" pos="18" show="0x000076f1" value="76f1"/>
    <field name="ip.flags" showname="Flags: 0x4000, Don&#x27;t fragment" size="2" pos="20" show="0x00004000" value="4000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.flags.df" showname=".1.. .... .... .... = Don&#x27;t fragment: Set" size="2" pos="20" show="1" value="1" unmaskedvalue="4000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 128" size="1" pos="22" show="128" value="80"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0xa21a [correct]" size="2" pos="24" show="0x0000a21a" value="a21a"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0xa21a" size="2" pos="24" show="0x0000a21a" value="a21a"/>
    <field name="ip.src" showname="Source: 192.168.3.131" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.src_host" showname="Source Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.dst" showname="Destination: 72.14.213.138" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.addr" showname="Source or Destination Address: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.dst_host" showname="Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.host" showname="Source or Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 57011, Dst Port: 80, Seq: 1889, Ack: 856, Len: 0" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 57011" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.dstport" showname="Destination Port: 80" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 57011" hide="yes" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="34" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 0" size="1" pos="46" show="0" value="50"/>
    <field name="tcp.seq" showname="Sequence number: 1889    (relative sequence number)" size="4" pos="38" show="1889" value="978a29f8"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 1889    (relative sequence number)" size="0" pos="34" show="1889"/>
    <field name="tcp.ack" showname="Acknowledgment number: 856    (relative ack number)" size="4" pos="42" show="856" value="90b8a836"/>
    <field name="tcp.hdr_len" showname="0101 .... = Header Length: 20 bytes (5)" size="1" pos="46" show="20" value="50"/>
    <field name="tcp.flags" showname="Flags: 0x010 (ACK)" size="2" pos="46" show="0x00000010" value="10" unmaskedvalue="5010">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="10"/>
      <field name="tcp.flags.push" showname=".... .... 0... = Push: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.fin" showname=".... .... ...0 = Fin: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7" size="2" pos="46" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7" value="5010"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 16445" size="2" pos="48" show="16445" value="403d"/>
    <field name="tcp.window_size" showname="Calculated window size: 16445" size="2" pos="48" show="16445" value="403d"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="48" show="-1" value="403d"/>
    <field name="tcp.checksum" showname="Checksum: 0xb45d [unverified]" size="2" pos="50" show="0x0000b45d" value="b45d"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="50" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="tcp.analysis" showname="SEQ/ACK analysis" size="0" pos="34" show="" value="">
      <field name="tcp.analysis.acks_frame" showname="This is an ACK to the segment in frame: 5" size="0" pos="34" show="5"/>
      <field name="tcp.analysis.ack_rtt" showname="The RTT to ACK the segment was: 0.199610000 seconds" size="0" pos="34" show="0.199610000"/>
    </field>
    <field name="" show="Timestamps" size="0" pos="34">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 1.015499000 seconds" size="0" pos="34" show="1.015499000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 0.199610000 seconds" size="0" pos="34" show="0.199610000"/>
    </field>
  </proto>
</packet>


<packet>
  <proto name="geninfo" pos="0" showname="General information" size="1005">
    <field name="num" pos="0" show="7" showname="Number" value="7" size="1005"/>
    <field name="len" pos="0" show="1005" showname="Frame Length" value="3ed" size="1005"/>
    <field name="caplen" pos="0" show="1005" showname="Captured Length" value="3ed" size="1005"/>
    <field name="timestamp" pos="0" show="Jan 25, 2011 13:52:24.198549000 EST" showname="Captured Time" value="1295981544.198549000" size="1005"/>
  </proto>
  <proto name="frame" showname="Frame 7: 1005 bytes on wire (8040 bits), 1005 bytes captured (8040 bits)" size="1005" pos="0">
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Micro-St_9a:f1:f5 (40:61:86:9a:f1:f5), Dst: Sophos_15:f9:80 (00:1a:8c:15:f9:80)" size="14" pos="0">
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 192.168.3.131, Dst: 72.14.213.138" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 991" size="2" pos="16" show="991" value="03df"/>
    <field name="ip.id" showname="Identification: 0x7700 (30464)" size="2" pos="18" show="0x00007700" value="7700"/>
    <field name="ip.flags" showname="Flags: 0x4000, Don&#x27;t fragment" size="2" pos="20" show="0x00004000" value="4000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.flags.df" showname=".1.. .... .... .... = Don&#x27;t fragment: Set" size="2" pos="20" show="1" value="1" unmaskedvalue="4000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 128" size="1" pos="22" show="128" value="80"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0x9e54 [correct]" size="2" pos="24" show="0x00009e54" value="9e54"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0x9e54" size="2" pos="24" show="0x00009e54" value="9e54"/>
    <field name="ip.src" showname="Source: 192.168.3.131" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.src_host" showname="Source Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.dst" showname="Destination: 72.14.213.138" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.addr" showname="Source or Destination Address: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.dst_host" showname="Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.host" showname="Source or Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 57011, Dst Port: 80, Seq: 1889, Ack: 856, Len: 951" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 57011" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.dstport" showname="Destination Port: 80" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 57011" hide="yes" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="34" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 951" size="1" pos="46" show="951" value="50"/>
    <field name="tcp.seq" showname="Sequence number: 1889    (relative sequence number)" size="4" pos="38" show="1889" value="978a29f8"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 2840    (relative sequence number)" size="0" pos="34" show="2840"/>
    <field name="tcp.ack" showname="Acknowledgment number: 856    (relative ack number)" size="4" pos="42" show="856" value="90b8a836"/>
    <field name="tcp.hdr_len" showname="0101 .... = Header Length: 20 bytes (5)" size="1" pos="46" show="20" value="50"/>
    <field name="tcp.flags" showname="Flags: 0x018 (PSH, ACK)" size="2" pos="46" show="0x00000018" value="18" unmaskedvalue="5018">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.push" showname=".... .... 1... = Push: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.fin" showname=".... .... ...0 = Fin: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" size="2" pos="46" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" value="5018"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 16445" size="2" pos="48" show="16445" value="403d"/>
    <field name="tcp.window_size" showname="Calculated window size: 16445" size="2" pos="48" show="16445" value="403d"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="48" show="-1" value="403d"/>
    <field name="tcp.checksum" showname="Checksum: 0xa9e1 [unverified]" size="2" pos="50" show="0x0000a9e1" value="a9e1"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="50" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="tcp.analysis" showname="SEQ/ACK analysis" size="0" pos="34" show="" value="">
      <field name="tcp.analysis.bytes_in_flight" showname="Bytes in flight: 951" size="0" pos="34" show="951"/>
      <field name="tcp.analysis.push_bytes_sent" showname="Bytes sent since last PSH flag: 951" size="0" pos="34" show="951"/>
    </field>
    <field name="" show="Timestamps" size="0" pos="34">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 1.714140000 seconds" size="0" pos="34" show="1.714140000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 0.698641000 seconds" size="0" pos="34" show="0.698641000"/>
    </field>
    <field name="tcp.payload" showname="TCP payload (951 bytes)" size="951" pos="54" show="47:45:54:20:2f:63:6f:6d:70:6c:65:74:65:2f:73:65:61:72:63:68:3f:63:6c:69:65:6e:74:3d:63:68:72:6f:6d:65:26:68:6c:3d:65:6e:2d:55:53:26:71:3d:63:72:61:69:67:73:6c:69:73:74:20:48:54:54:50:2f:31:2e:31:0d:0a:48:6f:73:74:3a:20:63:6c:69:65:6e:74:73:31:2e:67:6f:6f:67:6c:65:2e:63:61:0d:0a:43:6f:6e:6e:65:63:74:69:6f:6e:3a:20:6b:65:65:70:2d:61:6c:69:76:65:0d:0a:55:73:65:72:2d:41:67:65:6e:74:3a:20:4d:6f:7a:69:6c:6c:61:2f:35:2e:30:20:28:57:69:6e:64:6f:77:73:3b:20:55:3b:20:57:69:6e:64:6f:77:73:20:4e:54:20:36:2e:31:3b:20:65:6e:2d:55:53:29:20:41:70:70:6c:65:57:65:62:4b:69:74:2f:35:33:34:2e:31:30:20:28:4b:48:54:4d:4c:2c:20:6c:69:6b:65:20:47:65:63:6b:6f:29:20:43:68:72:6f:6d:65:2f:38:2e:30:2e:35:35:32:2e:32:33:37:20:53:61:66:61:72:69:2f:35:33:34:2e:31:30:0d:0a:41:63:63:65:70:74:2d:45:6e:63:6f:64:69:6e:67:3a:20:67:7a:69:70:2c:64:65:66:6c:61:74:65:2c:73:64:63:68:0d:0a:41:63:63:65:70:74:2d:4c:61:6e:67:75:61:67:65:3a:20:65:6e:2d:55:53:2c:65:6e:3b:71:3d:30:2e:38:0d:0a:41:63:63:65:70:74:2d:43:68:61:72:73:65:74:3a:20:49:53:4f:2d:38:38:35:39:2d:31:2c:75:74:66:2d:38:3b:71:3d:30:2e:37:2c:2a:3b:71:3d:30:2e:33:0d:0a:43:6f:6f:6b:69:65:3a:20:50:52:45:46:3d:49:44:3d:63:32:65:33:35:30:30:31:32:32:35:38:64:66:31:63:3a:55:3d:33:38:36:61:36:65:62:65:66:30:64:62:32:38:37:63:3a:46:46:3d:30:3a:54:4d:3d:31:32:39:34:31:36:34:32:39:34:3a:4c:4d:3d:31:32:39:34:31:36:34:32:39:34:3a:53:3d:62:63:75:77:4d:36:56:68:35:65:63:4b:78:71:6d:6b:3b:20:53:49:44:3d:44:51:41:41:41:4e:34:41:41:41:42:33:4d:77:37:68:53:41:58:6d:32:39:73:76:66:5a:51:78:52:68:61:45:56:4c:35:78:5f:37:4a:45:79:57:45:79:77:50:74:66:49:4b:6d:56:32:51:4d:43:5a:36:31:56:66:53:76:47:78:67:2d:57:43:77:53:37:4f:59:6e:45:6f:6e:61:76:64:52:65:69:54:67:5a:5f:33:4a:61:6c:63:50:79:49:6e:78:59:62:48:47:36:36:38:68:62:68:66:56:52:78:43:48:57:72:61:43:38:6c:4e:68:68:68:5a:76:43:34:35:4c:33:32:57:44:6a:6b:50:52:52:79:30:71:6d:6f:7a:5f:33:53:47:7a:44:44:67:75:6d:42:32:6d:67:79:6a:54:48:69:71:52:64:67:45:6d:6f:70:73:45:76:6f:75:6f:62:53:5a:44:52:78:69:78:58:64:41:4e:76:54:48:79:71:38:35:50:6d:56:6e:7a:4b:48:4b:5f:2d:78:37:68:56:64:59:68:75:34:34:4a:36:50:5f:6f:49:34:62:5a:57:6e:48:41:39:36:36:51:6e:61:37:33:71:35:59:4f:50:50:65:76:76:5a:51:56:58:38:46:37:31:6e:56:6a:44:6b:34:61:4a:4d:35:4b:68:6c:41:51:77:42:44:78:35:66:7a:72:56:39:57:6b:5f:52:5f:59:2d:65:67:7a:30:73:44:4c:39:6f:43:33:66:42:55:52:47:56:77:70:34:79:77:51:3b:20:48:53:49:44:3d:41:71:67:4d:33:4a:6c:7a:72:56:41:33:51:6b:69:79:7a:3b:20:4e:49:44:3d:34:33:3d:46:5f:6f:53:5a:57:79:6f:39:4e:69:61:64:6b:31:37:6d:36:35:51:74:4d:39:61:6c:42:4a:51:34:59:4c:30:42:30:79:41:50:37:31:72:75:4e:71:61:35:73:56:34:4a:4f:52:49:6d:73:51:6f:76:55:31:50:57:32:50:45:49:49:37:61:2d:35:4b:55:69:34:59:43:52:4d:43:65:79:74:75:68:69:77:6b:57:67:53:6c:57:74:48:45:41:6a:5f:6e:74:5f:45:46:38:79:38:34:4d:4e:6d:72:74:6d:52:7a:4b:39:4b:74:68:39:36:4e:34:2d:62:50:5a:0d:0a:0d:0a" value="474554202f636f6d706c6574652f7365617263683f636c69656e743d6368726f6d6526686c3d656e2d555326713d6372616967736c69737420485454502f312e310d0a486f73743a20636c69656e7473312e676f6f676c652e63610d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f77733b20553b2057696e646f7773204e5420362e313b20656e2d555329204170706c655765624b69742f3533342e313020284b48544d4c2c206c696b65204765636b6f29204368726f6d652f382e302e3535322e323337205361666172692f3533342e31300d0a4163636570742d456e636f64696e673a20677a69702c6465666c6174652c736463680d0a4163636570742d4c616e67756167653a20656e2d55532c656e3b713d302e380d0a4163636570742d436861727365743a2049534f2d383835392d312c7574662d383b713d302e372c2a3b713d302e330d0a436f6f6b69653a20505245463d49443d633265333530303132323538646631633a553d333836613665626566306462323837633a46463d303a544d3d313239343136343239343a4c4d3d313239343136343239343a533d626375774d3656683565634b78716d6b3b205349443d44514141414e3441414142334d7737685341586d32397376665a517852686145564c35785f374a457957457977507466494b6d5632514d435a3631566653764778672d57437753374f596e456f6e61766452656954675a5f334a616c635079496e785962484736363868626866565278434857726143386c4e6868685a764334354c333257446a6b5052527930716d6f7a5f3353477a444467756d42326d67796a54486971526467456d6f707345766f756f62535a44527869785864414e76544879713835506d566e7a4b484b5f2d783768566459687534344a36505f6f4934625a576e4841393636516e6137337135594f50506576765a515658384637316e566a446b34614a4d354b686c41517742447835667a725639576b5f525f592d65677a3073444c396f43336642555247567770347977513b20485349443d4171674d334a6c7a72564133516b69797a3b204e49443d34333d465f6f535a57796f394e6961646b31376d363551744d39616c424a5134594c304230794150373172754e7161357356344a4f52496d73516f7655315057325045494937612d354b5569345943524d43657974756869776b5767536c57744845416a5f6e745f4546387938344d4e6d72746d527a4b394b746839364e342d62505a0d0a0d0a"/>
  </proto>
  <proto name="http" showname="Hypertext Transfer Protocol" size="951" pos="54">
  </proto>
</packet>


<packet>
  <proto name="geninfo" pos="0" showname="General information" size="533">
    <field name="num" pos="0" show="8" showname="Number" value="8" size="533"/>
    <field name="len" pos="0" show="533" showname="Frame Length" value="215" size="533"/>
    <field name="caplen" pos="0" show="533" showname="Captured Length" value="215" size="533"/>
    <field name="timestamp" pos="0" show="Jan 25, 2011 13:52:24.232473000 EST" showname="Captured Time" value="1295981544.232473000" size="533"/>
  </proto>
  <proto name="frame" showname="Frame 8: 533 bytes on wire (4264 bits), 533 bytes captured (4264 bits)" size="533" pos="0">
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Sophos_15:f9:80 (00:1a:8c:15:f9:80), Dst: Micro-St_9a:f1:f5 (40:61:86:9a:f1:f5)" size="14" pos="0">
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 72.14.213.138, Dst: 192.168.3.131" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 519" size="2" pos="16" show="519" value="0207"/>
    <field name="ip.id" showname="Identification: 0x2d64 (11620)" size="2" pos="18" show="0x00002d64" value="2d64"/>
    <field name="ip.flags" showname="Flags: 0x0000" size="2" pos="20" show="0x00000000" value="0000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.flags.df" showname=".0.. .... .... .... = Don&#x27;t fragment: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 52" size="1" pos="22" show="52" value="34"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0x75c9 [correct]" size="2" pos="24" show="0x000075c9" value="75c9"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0x75c9" size="2" pos="24" show="0x000075c9" value="75c9"/>
    <field name="ip.src" showname="Source: 72.14.213.138" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.addr" showname="Source or Destination Address: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.src_host" showname="Source Host: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.host" showname="Source or Destination Host: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.dst" showname="Destination: 192.168.3.131" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.dst_host" showname="Destination Host: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 80, Dst Port: 57011, Seq: 856, Ack: 2840, Len: 479" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 80" size="2" pos="34" show="80" value="0050"/>
    <field name="tcp.dstport" showname="Destination Port: 57011" size="2" pos="36" show="57011" value="deb3"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="34" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 57011" hide="yes" size="2" pos="36" show="57011" value="deb3"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="34" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 479" size="1" pos="46" show="479" value="50"/>
    <field name="tcp.seq" showname="Sequence number: 856    (relative sequence number)" size="4" pos="38" show="856" value="90b8a836"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 1335    (relative sequence number)" size="0" pos="34" show="1335"/>
    <field name="tcp.ack" showname="Acknowledgment number: 2840    (relative ack number)" size="4" pos="42" show="2840" value="978a2daf"/>
    <field name="tcp.hdr_len" showname="0101 .... = Header Length: 20 bytes (5)" size="1" pos="46" show="20" value="50"/>
    <field name="tcp.flags" showname="Flags: 0x018 (PSH, ACK)" size="2" pos="46" show="0x00000018" value="18" unmaskedvalue="5018">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.push" showname=".... .... 1... = Push: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="18"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.fin" showname=".... .... ...0 = Fin: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="18"/>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" size="2" pos="46" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7AP\xc2\xb7\xc2\xb7\xc2\xb7" value="5018"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 1002" size="2" pos="48" show="1002" value="03ea"/>
    <field name="tcp.window_size" showname="Calculated window size: 1002" size="2" pos="48" show="1002" value="03ea"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="48" show="-1" value="03ea"/>
    <field name="tcp.checksum" showname="Checksum: 0x2f97 [unverified]" size="2" pos="50" show="0x00002f97" value="2f97"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="50" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="tcp.analysis" showname="SEQ/ACK analysis" size="0" pos="34" show="" value="">
      <field name="tcp.analysis.acks_frame" showname="This is an ACK to the segment in frame: 7" size="0" pos="34" show="7"/>
      <field name="tcp.analysis.ack_rtt" showname="The RTT to ACK the segment was: 0.033924000 seconds" size="0" pos="34" show="0.033924000"/>
      <field name="tcp.analysis.bytes_in_flight" showname="Bytes in flight: 479" size="0" pos="34" show="479"/>
      <field name="tcp.analysis.push_bytes_sent" showname="Bytes sent since last PSH flag: 479" size="0" pos="34" show="479"/>
    </field>
    <field name="" show="Timestamps" size="0" pos="34">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 1.748064000 seconds" size="0" pos="34" show="1.748064000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 0.033924000 seconds" size="0" pos="34" show="0.033924000"/>
    </field>
    <field name="tcp.payload" showname="TCP payload (479 bytes)" size="479" pos="54" show="48:54:54:50:2f:31:2e:31:20:32:30:30:20:4f:4b:0d:0a:44:61:74:65:3a:20:54:75:65:2c:20:32:35:20:4a:61:6e:20:32:30:31:31:20:31:39:3a:30:35:3a:35:37:20:47:4d:54:0d:0a:45:78:70:69:72:65:73:3a:20:54:75:65:2c:20:32:35:20:4a:61:6e:20:32:30:31:31:20:31:39:3a:30:35:3a:35:37:20:47:4d:54:0d:0a:43:61:63:68:65:2d:43:6f:6e:74:72:6f:6c:3a:20:70:72:69:76:61:74:65:2c:20:6d:61:78:2d:61:67:65:3d:33:36:30:30:0d:0a:43:6f:6e:74:65:6e:74:2d:54:79:70:65:3a:20:74:65:78:74:2f:6a:61:76:61:73:63:72:69:70:74:3b:20:63:68:61:72:73:65:74:3d:55:54:46:2d:38:0d:0a:43:6f:6e:74:65:6e:74:2d:45:6e:63:6f:64:69:6e:67:3a:20:67:7a:69:70:0d:0a:53:65:72:76:65:72:3a:20:67:77:73:0d:0a:43:6f:6e:74:65:6e:74:2d:4c:65:6e:67:74:68:3a:20:32:30:38:0d:0a:58:2d:58:53:53:2d:50:72:6f:74:65:63:74:69:6f:6e:3a:20:31:3b:20:6d:6f:64:65:3d:62:6c:6f:63:6b:0d:0a:0d:0a:1f:8b:08:00:00:00:00:00:02:ff:65:8e:41:6b:c3:30:0c:85:ff:8a:f1:d9:34:f7:dc:ba:51:4a:2e:29:1b:db:a0:24:3e:68:ae:ea:b9:38:76:b0:94:40:19:fb:ef:55:a1:34:db:0a:02:3d:3d:be:c7:53:a7:5d:81:e0:29:06:62:6d:3a:fd:c5:3c:d6:7d:d5:57:33:24:97:a7:19:cb:6a:01:56:0e:fa:4a:9b:3f:91:5f:87:ba:67:fe:d9:c1:71:2e:01:b4:95:82:c5:af:17:de:a8:a7:67:e5:22:10:85:63:c0:03:a9:63:2e:ea:94:3f:c9:28:18:a1:f0:80:89:45:8f:58:28:27:88:22:af:00:41:44:a3:08:8b:14:a0:78:2e:0f:c3:94:02:9f:25:95:0e:0a:e7:6b:4a:5e:b9:8d:b4:5b:f3:ad:7d:ce:3e:62:4d:93:f7:48:cc:e7:11:75:dd:e9:76:fd:d1:6c:d7:6f:cd:ae:15:f4:e5:7d:f3:ba:7f:d8:f6:c7:5e:00:69:ed:ae:39:2e:01:00:00" value="485454502f312e3120323030204f4b0d0a446174653a205475652c203235204a616e20323031312031393a30353a353720474d540d0a457870697265733a205475652c203235204a616e20323031312031393a30353a353720474d540d0a43616368652d436f6e74726f6c3a20707269766174652c206d61782d6167653d333630300d0a436f6e74656e742d547970653a20746578742f6a6176617363726970743b20636861727365743d5554462d380d0a436f6e74656e742d456e636f64696e673a20677a69700d0a5365727665723a206777730d0a436f6e74656e742d4c656e6774683a203230380d0a582d5853532d50726f74656374696f6e3a20313b206d6f64653d626c6f636b0d0a0d0a1f8b08000000000002ff658e416bc3300c85ff8af1d934f7dcba514a2e291bdba0243e68aeeab93876b0944019fbef55a134db0a023d3dbec753a75d81e02906626d3afdc53cd67dd557332497a719cb6a01560efa4a9b3f915f87ba67fed9c1712e01b49582c5af17dea8a767e522108563c003a9632eea943fc92818a1f08089458f5828278822af004144a3088b14a0782e0fc394029f25950e0ae76b4a5eb98db45bf3ad7dce3e624d93f748cce71175dde976fdd16cd76fcdae15f4e57df3ba7fd8f6c75e0069edae392e010000"/>
  </proto>
  <proto name="http" showname="Hypertext Transfer Protocol" size="271" pos="54">
  </proto>
</packet>


<packet>
  <proto name="geninfo" pos="0" showname="General information" size="54">
    <field name="num" pos="0" show="9" showname="Number" value="9" size="54"/>
    <field name="len" pos="0" show="54" showname="Frame Length" value="36" size="54"/>
    <field name="caplen" pos="0" show="54" showname="Captured Length" value="36" size="54"/>
    <field name="timestamp" pos="0" show="Jan 25, 2011 13:52:24.437888000 EST" showname="Captured Time" value="1295981544.437888000" size="54"/>
  </proto>
  <proto name="frame" showname="Frame 9: 54 bytes on wire (432 bits), 54 bytes captured (432 bits)" size="54" pos="0">
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Micro-St_9a:f1:f5 (40:61:86:9a:f1:f5), Dst: Sophos_15:f9:80 (00:1a:8c:15:f9:80)" size="14" pos="0">
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 192.168.3.131, Dst: 72.14.213.138" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 40" size="2" pos="16" show="40" value="0028"/>
    <field name="ip.id" showname="Identification: 0x7701 (30465)" size="2" pos="18" show="0x00007701" value="7701"/>
    <field name="ip.flags" showname="Flags: 0x4000, Don&#x27;t fragment" size="2" pos="20" show="0x00004000" value="4000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.flags.df" showname=".1.. .... .... .... = Don&#x27;t fragment: Set" size="2" pos="20" show="1" value="1" unmaskedvalue="4000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 128" size="1" pos="22" show="128" value="80"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0xa20a [correct]" size="2" pos="24" show="0x0000a20a" value="a20a"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0xa20a" size="2" pos="24" show="0x0000a20a" value="a20a"/>
    <field name="ip.src" showname="Source: 192.168.3.131" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.src_host" showname="Source Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.dst" showname="Destination: 72.14.213.138" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.addr" showname="Source or Destination Address: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.dst_host" showname="Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.host" showname="Source or Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 57011, Dst Port: 80, Seq: 2840, Ack: 1335, Len: 0" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 57011" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.dstport" showname="Destination Port: 80" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 57011" hide="yes" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="34" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 0" size="1" pos="46" show="0" value="50"/>
    <field name="tcp.seq" showname="Sequence number: 2840    (relative sequence number)" size="4" pos="38" show="2840" value="978a2daf"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 2840    (relative sequence number)" size="0" pos="34" show="2840"/>
    <field name="tcp.ack" showname="Acknowledgment number: 1335    (relative ack number)" size="4" pos="42" show="1335" value="90b8aa15"/>
    <field name="tcp.hdr_len" showname="0101 .... = Header Length: 20 bytes (5)" size="1" pos="46" show="20" value="50"/>
    <field name="tcp.flags" showname="Flags: 0x010 (ACK)" size="2" pos="46" show="0x00000010" value="10" unmaskedvalue="5010">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="10"/>
      <field name="tcp.flags.push" showname=".... .... 0... = Push: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.fin" showname=".... .... ...0 = Fin: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7" size="2" pos="46" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7" value="5010"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 16325" size="2" pos="48" show="16325" value="3fc5"/>
    <field name="tcp.window_size" showname="Calculated window size: 16325" size="2" pos="48" show="16325" value="3fc5"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="48" show="-1" value="3fc5"/>
    <field name="tcp.checksum" showname="Checksum: 0xaf3f [unverified]" size="2" pos="50" show="0x0000af3f" value="af3f"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="50" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="tcp.analysis" showname="SEQ/ACK analysis" size="0" pos="34" show="" value="">
      <field name="tcp.analysis.acks_frame" showname="This is an ACK to the segment in frame: 8" size="0" pos="34" show="8"/>
      <field name="tcp.analysis.ack_rtt" showname="The RTT to ACK the segment was: 0.205415000 seconds" size="0" pos="34" show="0.205415000"/>
    </field>
    <field name="" show="Timestamps" size="0" pos="34">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 1.953479000 seconds" size="0" pos="34" show="1.953479000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 0.205415000 seconds" size="0" pos="34" show="0.205415000"/>
    </field>
  </proto>
</packet>


<packet>
  <proto name="geninfo" pos="0" showname="General information" size="60">
    <field name="num" pos="0" show="10" showname="Number" value="a" size="60"/>
    <field name="len" pos="0" show="60" showname="Frame Length" value="3c" size="60"/>
    <field name="caplen" pos="0" show="60" showname="Captured Length" value="3c" size="60"/>
    <field name="timestamp" pos="0" show="Jan 25, 2011 13:56:24.236472000 EST" showname="Captured Time" value="1295981784.236472000" size="60"/>
  </proto>
  <proto name="frame" showname="Frame 10: 60 bytes on wire (480 bits), 60 bytes captured (480 bits)" size="60" pos="0">
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Sophos_15:f9:80 (00:1a:8c:15:f9:80), Dst: Micro-St_9a:f1:f5 (40:61:86:9a:f1:f5)" size="14" pos="0">
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 72.14.213.138, Dst: 192.168.3.131" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 40" size="2" pos="16" show="40" value="0028"/>
    <field name="ip.id" showname="Identification: 0x2d65 (11621)" size="2" pos="18" show="0x00002d65" value="2d65"/>
    <field name="ip.flags" showname="Flags: 0x0000" size="2" pos="20" show="0x00000000" value="0000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.flags.df" showname=".0.. .... .... .... = Don&#x27;t fragment: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 52" size="1" pos="22" show="52" value="34"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0x77a7 [correct]" size="2" pos="24" show="0x000077a7" value="77a7"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0x77a7" size="2" pos="24" show="0x000077a7" value="77a7"/>
    <field name="ip.src" showname="Source: 72.14.213.138" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.addr" showname="Source or Destination Address: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.src_host" showname="Source Host: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.host" showname="Source or Destination Host: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.dst" showname="Destination: 192.168.3.131" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.dst_host" showname="Destination Host: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 80, Dst Port: 57011, Seq: 1335, Ack: 2840, Len: 0" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 80" size="2" pos="34" show="80" value="0050"/>
    <field name="tcp.dstport" showname="Destination Port: 57011" size="2" pos="36" show="57011" value="deb3"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="34" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 57011" hide="yes" size="2" pos="36" show="57011" value="deb3"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="34" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 0" size="1" pos="46" show="0" value="50"/>
    <field name="tcp.seq" showname="Sequence number: 1335    (relative sequence number)" size="4" pos="38" show="1335" value="90b8aa15"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 1335    (relative sequence number)" size="0" pos="34" show="1335"/>
    <field name="tcp.ack" showname="Acknowledgment number: 2840    (relative ack number)" size="4" pos="42" show="2840" value="978a2daf"/>
    <field name="tcp.hdr_len" showname="0101 .... = Header Length: 20 bytes (5)" size="1" pos="46" show="20" value="50"/>
    <field name="tcp.flags" showname="Flags: 0x011 (FIN, ACK)" size="2" pos="46" show="0x00000011" value="11" unmaskedvalue="5011">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="11"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="11"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="11"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="11"/>
      <field name="tcp.flags.push" showname=".... .... 0... = Push: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="11"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="11"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="11"/>
      <field name="tcp.flags.fin" showname=".... .... ...1 = Fin: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="11">
        <field name="_ws.expert" showname="Expert Info (Chat/Sequence): Connection finish (FIN)" size="0" pos="47">
          <field name="tcp.connection.fin" showname="Connection finish (FIN)" size="0" pos="0" show="" value=""/>
          <field name="_ws.expert.message" showname="Message: Connection finish (FIN)" hide="yes" size="0" pos="0" show="Connection finish (FIN)"/>
          <field name="_ws.expert.severity" showname="Severity level: Chat" size="0" pos="0" show="2097152"/>
          <field name="_ws.expert.group" showname="Group: Sequence" size="0" pos="0" show="33554432"/>
        </field>
      </field>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7F" size="2" pos="46" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7F" value="5011"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 1002" size="2" pos="48" show="1002" value="03ea"/>
    <field name="tcp.window_size" showname="Calculated window size: 1002" size="2" pos="48" show="1002" value="03ea"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="48" show="-1" value="03ea"/>
    <field name="tcp.checksum" showname="Checksum: 0xeb19 [unverified]" size="2" pos="50" show="0x0000eb19" value="eb19"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="50" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="" show="Timestamps" size="0" pos="34">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 241.752063000 seconds" size="0" pos="34" show="241.752063000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 239.798584000 seconds" size="0" pos="34" show="239.798584000"/>
    </field>
  </proto>
</packet>


<packet>
  <proto name="geninfo" pos="0" showname="General information" size="54">
    <field name="num" pos="0" show="11" showname="Number" value="b" size="54"/>
    <field name="len" pos="0" show="54" showname="Frame Length" value="36" size="54"/>
    <field name="caplen" pos="0" show="54" showname="Captured Length" value="36" size="54"/>
    <field name="timestamp" pos="0" show="Jan 25, 2011 13:56:24.236530000 EST" showname="Captured Time" value="1295981784.236530000" size="54"/>
  </proto>
  <proto name="frame" showname="Frame 11: 54 bytes on wire (432 bits), 54 bytes captured (432 bits)" size="54" pos="0">
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Micro-St_9a:f1:f5 (40:61:86:9a:f1:f5), Dst: Sophos_15:f9:80 (00:1a:8c:15:f9:80)" size="14" pos="0">
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 192.168.3.131, Dst: 72.14.213.138" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 40" size="2" pos="16" show="40" value="0028"/>
    <field name="ip.id" showname="Identification: 0x06cc (1740)" size="2" pos="18" show="0x000006cc" value="06cc"/>
    <field name="ip.flags" showname="Flags: 0x4000, Don&#x27;t fragment" size="2" pos="20" show="0x00004000" value="4000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.flags.df" showname=".1.. .... .... .... = Don&#x27;t fragment: Set" size="2" pos="20" show="1" value="1" unmaskedvalue="4000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 128" size="1" pos="22" show="128" value="80"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0x1240 [correct]" size="2" pos="24" show="0x00001240" value="1240"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0x1240" size="2" pos="24" show="0x00001240" value="1240"/>
    <field name="ip.src" showname="Source: 192.168.3.131" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.src_host" showname="Source Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.dst" showname="Destination: 72.14.213.138" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.addr" showname="Source or Destination Address: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.dst_host" showname="Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.host" showname="Source or Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 57011, Dst Port: 80, Seq: 2840, Ack: 1336, Len: 0" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 57011" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.dstport" showname="Destination Port: 80" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 57011" hide="yes" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="34" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 0" size="1" pos="46" show="0" value="50"/>
    <field name="tcp.seq" showname="Sequence number: 2840    (relative sequence number)" size="4" pos="38" show="2840" value="978a2daf"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 2840    (relative sequence number)" size="0" pos="34" show="2840"/>
    <field name="tcp.ack" showname="Acknowledgment number: 1336    (relative ack number)" size="4" pos="42" show="1336" value="90b8aa16"/>
    <field name="tcp.hdr_len" showname="0101 .... = Header Length: 20 bytes (5)" size="1" pos="46" show="20" value="50"/>
    <field name="tcp.flags" showname="Flags: 0x010 (ACK)" size="2" pos="46" show="0x00000010" value="10" unmaskedvalue="5010">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="10"/>
      <field name="tcp.flags.push" showname=".... .... 0... = Push: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.fin" showname=".... .... ...0 = Fin: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7" size="2" pos="46" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7" value="5010"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 16325" size="2" pos="48" show="16325" value="3fc5"/>
    <field name="tcp.window_size" showname="Calculated window size: 16325" size="2" pos="48" show="16325" value="3fc5"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="48" show="-1" value="3fc5"/>
    <field name="tcp.checksum" showname="Checksum: 0xaf3e [unverified]" size="2" pos="50" show="0x0000af3e" value="af3e"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="50" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="tcp.analysis" showname="SEQ/ACK analysis" size="0" pos="34" show="" value="">
      <field name="tcp.analysis.acks_frame" showname="This is an ACK to the segment in frame: 10" size="0" pos="34" show="10"/>
      <field name="tcp.analysis.ack_rtt" showname="The RTT to ACK the segment was: 0.000058000 seconds" size="0" pos="34" show="0.000058000"/>
    </field>
    <field name="" show="Timestamps" size="0" pos="34">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 241.752121000 seconds" size="0" pos="34" show="241.752121000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 0.000058000 seconds" size="0" pos="34" show="0.000058000"/>
    </field>
  </proto>
</packet>


<packet>
  <proto name="geninfo" pos="0" showname="General information" size="54">
    <field name="num" pos="0" show="12" showname="Number" value="c" size="54"/>
    <field name="len" pos="0" show="54" showname="Frame Length" value="36" size="54"/>
    <field name="caplen" pos="0" show="54" showname="Captured Length" value="36" size="54"/>
    <field name="timestamp" pos="0" show="Jan 25, 2011 13:56:31.427816000 EST" showname="Captured Time" value="1295981791.427816000" size="54"/>
  </proto>
  <proto name="frame" showname="Frame 12: 54 bytes on wire (432 bits), 54 bytes captured (432 bits)" size="54" pos="0">
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Micro-St_9a:f1:f5 (40:61:86:9a:f1:f5), Dst: Sophos_15:f9:80 (00:1a:8c:15:f9:80)" size="14" pos="0">
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 192.168.3.131, Dst: 72.14.213.138" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 40" size="2" pos="16" show="40" value="0028"/>
    <field name="ip.id" showname="Identification: 0x0739 (1849)" size="2" pos="18" show="0x00000739" value="0739"/>
    <field name="ip.flags" showname="Flags: 0x4000, Don&#x27;t fragment" size="2" pos="20" show="0x00004000" value="4000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.flags.df" showname=".1.. .... .... .... = Don&#x27;t fragment: Set" size="2" pos="20" show="1" value="1" unmaskedvalue="4000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="4000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 128" size="1" pos="22" show="128" value="80"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0x11d3 [correct]" size="2" pos="24" show="0x000011d3" value="11d3"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0x11d3" size="2" pos="24" show="0x000011d3" value="11d3"/>
    <field name="ip.src" showname="Source: 192.168.3.131" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.src_host" showname="Source Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.3.131" hide="yes" size="4" pos="26" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.dst" showname="Destination: 72.14.213.138" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.addr" showname="Source or Destination Address: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.dst_host" showname="Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.host" showname="Source or Destination Host: 72.14.213.138" hide="yes" size="4" pos="30" show="72.14.213.138" value="480ed58a"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 57011, Dst Port: 80, Seq: 2840, Ack: 1336, Len: 0" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 57011" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.dstport" showname="Destination Port: 80" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 57011" hide="yes" size="2" pos="34" show="57011" value="deb3"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="34" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 0" size="1" pos="46" show="0" value="50"/>
    <field name="tcp.seq" showname="Sequence number: 2840    (relative sequence number)" size="4" pos="38" show="2840" value="978a2daf"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 2840    (relative sequence number)" size="0" pos="34" show="2840"/>
    <field name="tcp.ack" showname="Acknowledgment number: 1336    (relative ack number)" size="4" pos="42" show="1336" value="90b8aa16"/>
    <field name="tcp.hdr_len" showname="0101 .... = Header Length: 20 bytes (5)" size="1" pos="46" show="20" value="50"/>
    <field name="tcp.flags" showname="Flags: 0x011 (FIN, ACK)" size="2" pos="46" show="0x00000011" value="11" unmaskedvalue="5011">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="11"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="11"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="11"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="11"/>
      <field name="tcp.flags.push" showname=".... .... 0... = Push: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="11"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="11"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="11"/>
      <field name="tcp.flags.fin" showname=".... .... ...1 = Fin: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="11">
        <field name="_ws.expert" showname="Expert Info (Chat/Sequence): Connection finish (FIN)" size="0" pos="47">
          <field name="tcp.connection.fin" showname="Connection finish (FIN)" size="0" pos="0" show="" value=""/>
          <field name="_ws.expert.message" showname="Message: Connection finish (FIN)" hide="yes" size="0" pos="0" show="Connection finish (FIN)"/>
          <field name="_ws.expert.severity" showname="Severity level: Chat" size="0" pos="0" show="2097152"/>
          <field name="_ws.expert.group" showname="Group: Sequence" size="0" pos="0" show="33554432"/>
        </field>
      </field>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7F" size="2" pos="46" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7F" value="5011"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 16325" size="2" pos="48" show="16325" value="3fc5"/>
    <field name="tcp.window_size" showname="Calculated window size: 16325" size="2" pos="48" show="16325" value="3fc5"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="48" show="-1" value="3fc5"/>
    <field name="tcp.checksum" showname="Checksum: 0xaf3d [unverified]" size="2" pos="50" show="0x0000af3d" value="af3d"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="50" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="" show="Timestamps" size="0" pos="34">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 248.943407000 seconds" size="0" pos="34" show="248.943407000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 7.191286000 seconds" size="0" pos="34" show="7.191286000"/>
    </field>
  </proto>
</packet>


<packet>
  <proto name="geninfo" pos="0" showname="General information" size="60">
    <field name="num" pos="0" show="13" showname="Number" value="d" size="60"/>
    <field name="len" pos="0" show="60" showname="Frame Length" value="3c" size="60"/>
    <field name="caplen" pos="0" show="60" showname="Captured Length" value="3c" size="60"/>
    <field name="timestamp" pos="0" show="Jan 25, 2011 13:56:31.446407000 EST" showname="Captured Time" value="1295981791.446407000" size="60"/>
  </proto>
  <proto name="frame" showname="Frame 13: 60 bytes on wire (480 bits), 60 bytes captured (480 bits)" size="60" pos="0">
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Sophos_15:f9:80 (00:1a:8c:15:f9:80), Dst: Micro-St_9a:f1:f5 (40:61:86:9a:f1:f5)" size="14" pos="0">
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 72.14.213.138, Dst: 192.168.3.131" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 40" size="2" pos="16" show="40" value="0028"/>
    <field name="ip.id" showname="Identification: 0x2d66 (11622)" size="2" pos="18" show="0x00002d66" value="2d66"/>
    <field name="ip.flags" showname="Flags: 0x0000" size="2" pos="20" show="0x00000000" value="0000">
      <field name="ip.flags.rb" showname="0... .... .... .... = Reserved bit: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.flags.df" showname=".0.. .... .... .... = Don&#x27;t fragment: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.flags.mf" showname="..0. .... .... .... = More fragments: Not set" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
      <field name="ip.frag_offset" showname="...0 0000 0000 0000 = Fragment offset: 0" size="2" pos="20" show="0" value="0" unmaskedvalue="0000"/>
    </field>
    <field name="ip.ttl" showname="Time to live: 52" size="1" pos="22" show="52" value="34"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0x77a6 [correct]" size="2" pos="24" show="0x000077a6" value="77a6"/>
    <field name="ip.checksum.status" showname="Header checksum status: Good" size="0" pos="24" show="1"/>
    <field name="ip.checksum_calculated" showname="Calculated Checksum: 0x77a6" size="2" pos="24" show="0x000077a6" value="77a6"/>
    <field name="ip.src" showname="Source: 72.14.213.138" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.addr" showname="Source or Destination Address: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.src_host" showname="Source Host: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.host" showname="Source or Destination Host: 72.14.213.138" hide="yes" size="4" pos="26" show="72.14.213.138" value="480ed58a"/>
    <field name="ip.dst" showname="Destination: 192.168.3.131" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.dst_host" showname="Destination Host: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.3.131" hide="yes" size="4" pos="30" show="192.168.3.131" value="c0a80383"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 80, Dst Port: 57011, Seq: 1336, Ack: 2841, Len: 0" size="20" pos="34">
    <field name="tcp.srcport" showname="Source Port: 80" size="2" pos="34" show="80" value="0050"/>
    <field name="tcp.dstport" showname="Destination Port: 57011" size="2" pos="36" show="57011" value="deb3"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="34" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 57011" hide="yes" size="2" pos="36" show="57011" value="deb3"/>
    <field name="tcp.stream" showname="Stream index: 0" size="0" pos="34" show="0"/>
    <field name="tcp.len" showname="TCP Segment Len: 0" size="1" pos="46" show="0" value="50"/>
    <field name="tcp.seq" showname="Sequence number: 1336    (relative sequence number)" size="4" pos="38" show="1336" value="90b8aa16"/>
    <field name="tcp.nxtseq" showname="Next sequence number: 1336    (relative sequence number)" size="0" pos="34" show="1336"/>
    <field name="tcp.ack" showname="Acknowledgment number: 2841    (relative ack number)" size="4" pos="42" show="2841" value="978a2db0"/>
    <field name="tcp.hdr_len" showname="0101 .... = Header Length: 20 bytes (5)" size="1" pos="46" show="20" value="50"/>
    <field name="tcp.flags" showname="Flags: 0x010 (ACK)" size="2" pos="46" show="0x00000010" value="10" unmaskedvalue="5010">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="50"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.ack" showname=".... ...1 .... = Acknowledgment: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="10"/>
      <field name="tcp.flags.push" showname=".... .... 0... = Push: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.syn" showname=".... .... ..0. = Syn: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.fin" showname=".... .... ...0 = Fin: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="10"/>
      <field name="tcp.flags.str" showname="TCP Flags: \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7" size="2" pos="46" show="\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7A\xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb7" value="5010"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 1002" size="2" pos="48" show="1002" value="03ea"/>
    <field name="tcp.window_size" showname="Calculated window size: 1002" size="2" pos="48" show="1002" value="03ea"/>
    <field name="tcp.window_size_scalefactor" showname="Window size scaling factor: -1 (unknown)" size="2" pos="48" show="-1" value="03ea"/>
    <field name="tcp.checksum" showname="Checksum: 0xeb18 [unverified]" size="2" pos="50" show="0x0000eb18" value="eb18"/>
    <field name="tcp.checksum.status" showname="Checksum Status: Unverified" size="0" pos="50" show="2"/>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="tcp.analysis" showname="SEQ/ACK analysis" size="0" pos="34" show="" value="">
      <field name="tcp.analysis.acks_frame" showname="This is an ACK to the segment in frame: 12" size="0" pos="34" show="12"/>
      <field name="tcp.analysis.ack_rtt" showname="The RTT to ACK the segment was: 0.018591000 seconds" size="0" pos="34" show="0.018591000"/>
    </field>
    <field name="" show="Timestamps" size="0" pos="34">
      <field name="tcp.time_relative" showname="Time since first frame in this TCP stream: 248.961998000 seconds" size="0" pos="34" show="248.961998000"/>
      <field name="tcp.time_delta" showname="Time since previous frame in this TCP stream: 0.018591000 seconds" size="0" pos="34" show="0.018591000"/>
    </field>
  </proto>
</packet>


</pdml>`

	pt := &payloadTracker{
		indices: make([]int, 0),
	}

	decodeStreamXml(strings.NewReader(pdml), "tcp", context.TODO(), pt)

	assert.Equal(t, []int{0, 1, 3, 4, 6, 7}, pt.indices)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
