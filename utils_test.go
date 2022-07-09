// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"bytes"
	"os"
	"testing"

	"github.com/blang/semver"
	"github.com/gcla/termshark/v2/pkg/format"
	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestApplyArgs(t *testing.T) {
	cmd := []string{"echo", "something", "$3", "else", "$1", "$3"}
	args := []string{"a1", "a2"}
	eres := []string{"echo", "something", "$3", "else", "a1", "$3"}
	res, total := ApplyArguments(cmd, args)
	assert.Equal(t, eres, res)
	assert.Equal(t, total, 1)

	args = []string{"a1", "a2", "a3"}
	eres = []string{"echo", "something", "a3", "else", "a1", "a3"}
	res, total = ApplyArguments(cmd, args)
	assert.Equal(t, eres, res)
	assert.Equal(t, total, 3)
}

func TestArgConv(t *testing.T) {
	var tests = []struct {
		arg  string
		flag string
		val  string
		res  bool
	}{
		{"--tshark-d=foo", "d", "foo", true},
		{"--tshark-abc=foo", "", "", false},
		{"--tshark-V=true", "V", "", true},
		{"--tshark-V=false", "", "", false},
		{"--ts-V=wow", "", "", false},
	}

	for _, test := range tests {
		f, v, ok := ConvertArgToTShark(test.arg)
		assert.Equal(t, test.res, ok)
		if test.res {
			assert.Equal(t, test.flag, f)
			assert.Equal(t, test.val, v)
		}
	}
}

func TestVer1(t *testing.T) {
	out1 := `TShark (Wireshark) 2.6.6 (Git v2.6.6 packaged as 2.6.6-1~ubuntu18.04.0)

Copyright 1998-2019 Gerald Combs <gerald@wireshark.org> and contributors.`

	v1, err := TSharkVersionFromOutput(out1)
	assert.NoError(t, err)
	res, _ := semver.Make("2.6.6")
	assert.Equal(t, res, v1)
}

func TestVer2(t *testing.T) {
	out1 := `TShark 1.6.7

Copyright 1998-2012 Gerald Combs <gerald@wireshark.org> and contributors.
This is free software; see the source for copying conditions. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Compiled (64-bit) with GLib 2.32.0, with libpcap (version unknown), with libz
1.2.3.4, with POSIX capabilities (Linux), without libpcre, with SMI 0.4.8, with
c-ares 1.7.5, with Lua 5.1, without Python, with GnuTLS 2.12.14, with Gcrypt
1.5.0, with MIT Kerberos, with GeoIP.

Running on Linux 3.2.0-126-generic, with libpcap version 1.1.1, with libz
1.2.3.4.
`

	v1, err := TSharkVersionFromOutput(out1)
	assert.NoError(t, err)
	res, _ := semver.Make("1.6.7")
	assert.Equal(t, res, v1)
}

func TestInterfaces1(t *testing.T) {
	out1 := `
1. \Device\NPF_{BAC1CFBD-DE27-4023-B478-0C490B99DC5E} (Local Area Connection 2)
2. \Device\NPF_{78032B7E-4968-42D3-9F37-287EA86C0AAA} (Local Area Connection* 10)
3. \Device\NPF_{84E7CAE6-E96F-4F31-96FD-170B0F514AB2} (Npcap Loopback Adapter)
4. \Device\NPF_NdisWanIpv6 (NdisWan Adapter)
5. \Device\NPF_{503E1F71-C57C-438D-B004-EA5563723C16} (Local Area Connection 5)
6. \Device\NPF_{15DDE443-C208-4328-8919-9666682EE804} (Local Area Connection* 11)
`[1:]
	interfaces, err := interfacesFrom(bytes.NewReader([]byte(out1)))
	assert.NoError(t, err)
	assert.Equal(t, 6, len(interfaces))
	v := interfaces[2]
	assert.Equal(t, `\Device\NPF_{78032B7E-4968-42D3-9F37-287EA86C0AAA}`, v[1])
	assert.Equal(t, `Local Area Connection* 10`, v[0])
}

func TestInterfaces2(t *testing.T) {
	out1 := `
1. eth0
2. ham0
3. docker0
4. vethd45103d
5. lo (Loopback)
6. mpqemubr0-dummy
7. nflog
8. nfqueue
9. bluetooth0
10. virbr0-nic
11. vboxnet0
12. ciscodump (Cisco remote capture)
13. dpauxmon (DisplayPort AUX channel monitor capture)
14. randpkt (Random packet generator)
15. sdjournal (systemd Journal Export)
16. sshdump (SSH remote capture)
17. udpdump (UDP Listener remote capture)
`[1:]
	interfaces, err := interfacesFrom(bytes.NewReader([]byte(out1)))
	assert.NoError(t, err)
	assert.Equal(t, 17, len(interfaces))
	v := interfaces[3]
	assert.Equal(t, `docker0`, v[0])
	v = interfaces[12]
	assert.Equal(t, `Cisco remote capture`, v[0])
	assert.Equal(t, `ciscodump`, v[1])
}

func TestConv1(t *testing.T) {
	var tests = []struct {
		arg string
		res string
	}{
		{"hello\x41world\x42", "helloAworldB"},
		{"80 \xe2\x86\x92 53347", "80 → 53347"},
		{"hello\x41world\x42 foo \\000 bar", "helloAworldB foo \\000 bar"},
	}

	for _, test := range tests {
		outs := format.TranslateHexCodes([]byte(test.arg))
		assert.Equal(t, string(outs), test.res)
	}
}

func TestIPComp1(t *testing.T) {
	var ip IPCompare
	assert.True(t, ip.Less("x", "y"))
	assert.True(t, ip.Less("192.168.0.4", "y"))
	assert.False(t, ip.Less("y", "192.168.0.4"))
	assert.True(t, ip.Less("192.168.0.253", "192.168.1.4"))
	assert.False(t, ip.Less("192.168.1.4", "192.168.0.253"))
	assert.True(t, ip.Less("192.168.0.253", "::ffff:192.168.1.4"))
	assert.True(t, ip.Less("::ffff:192.168.0.253", "192.168.1.4"))
	assert.True(t, ip.Less("192.168.0.253", "2001:db8::68"))
	assert.False(t, ip.Less("2001:db8::68", "192.168.0.253"))
}

func TestMACComp1(t *testing.T) {
	var mac MACCompare
	assert.True(t, mac.Less("x", "y"))
	assert.True(t, mac.Less("11:22:33:44:55:66", "y"))
	assert.True(t, mac.Less("xx:22:33:44:55:66", "y"))
	assert.False(t, mac.Less("xx:22:33:44:55:66", "11:22:33:44:55:66"))
	assert.True(t, mac.Less("11:22:33:44:55:66", "11:22:33:44:55:67"))
	assert.False(t, mac.Less("11:22:33:44:55:66", "11:22:33:44:54:66"))
}

func TestFolders(t *testing.T) {
	tmp := os.Getenv("TMPDIR")
	os.Setenv("TMPDIR", "/foo")
	defer os.Setenv("TMPDIR", tmp)

	val, err := TsharkSetting("Temp")
	assert.NoError(t, err)
	assert.Equal(t, "/foo", val)

	val, err = TsharkSetting("Deliberately missing")
	assert.Error(t, err)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
