// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"bytes"
	"testing"

	"github.com/blang/semver"
	"github.com/stretchr/testify/assert"
)

//======================================================================

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
3. \Device\NPF_NdisWanIp (NdisWan Adapter)
4. \Device\NPF_NdisWanBh (NdisWan Adapter)
5. \Device\NPF_{84E7CAE6-E96F-4F31-96FD-170B0F514AB2} (Npcap Loopback Adapter)
6. \Device\NPF_NdisWanIpv6 (NdisWan Adapter)
7. \Device\NPF_{503E1F71-C57C-438D-B004-EA5563723C16} (Local Area Connection 5)
8. \Device\NPF_{15DDE443-C208-4328-8919-9666682EE804} (Local Area Connection* 11)
`[1:]
	interfaces, err := interfacesFrom(bytes.NewReader([]byte(out1)))
	assert.NoError(t, err)
	assert.Equal(t, 8, len(interfaces))
	assert.Equal(t, `\Device\NPF_{78032B7E-4968-42D3-9F37-287EA86C0AAA}`, interfaces[1])
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
