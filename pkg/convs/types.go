// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package convs

import "fmt"

type Ethernet struct{}
type IPv4 struct{}
type IPv6 struct{}
type UDP struct{}
type TCP struct{}

var OfficialNameToType = map[string]string{
	Ethernet{}.String(): Ethernet{}.Short(),
	IPv4{}.String():     IPv4{}.Short(),
	IPv6{}.String():     IPv6{}.Short(),
	UDP{}.String():      UDP{}.Short(),
	TCP{}.String():      TCP{}.Short(),
}

//======================================================================

func (t Ethernet) String() string {
	return "Ethernet"
}

func (t Ethernet) Short() string {
	return "eth"
}

func (t Ethernet) FilterTo(vals ...string) string {
	return fmt.Sprintf("eth.dst == %s", vals[0])
}

func (t Ethernet) FilterFrom(vals ...string) string {
	return fmt.Sprintf("eth.src == %s", vals[0])
}

func (t Ethernet) FilterAny(vals ...string) string {
	return fmt.Sprintf("eth.addr == %s", vals[0])
}

func (t Ethernet) AIndex() []int {
	return []int{0}
}

func (t Ethernet) BIndex() []int {
	return []int{1}
}

//======================================================================

func (t IPv4) String() string {
	return "IPv4"
}

func (t IPv4) Short() string {
	return "ip"
}

func (t IPv4) FilterTo(vals ...string) string {
	return fmt.Sprintf("ip.dst == %s", vals[0])
}

func (t IPv4) FilterFrom(vals ...string) string {
	return fmt.Sprintf("ip.src == %s", vals[0])
}

func (t IPv4) FilterAny(vals ...string) string {
	return fmt.Sprintf("ip.addr == %s", vals[0])
}

func (t IPv4) AIndex() []int {
	return []int{0}
}

func (t IPv4) BIndex() []int {
	return []int{1}
}

//======================================================================

func (t IPv6) String() string {
	return "IPv6"
}

func (t IPv6) Short() string {
	return "ipv6"
}

func (t IPv6) FilterTo(vals ...string) string {
	return fmt.Sprintf("ipv6.dst == %s", vals[0])
}

func (t IPv6) FilterFrom(vals ...string) string {
	return fmt.Sprintf("ipv6.src == %s", vals[0])
}

func (t IPv6) FilterAny(vals ...string) string {
	return fmt.Sprintf("ipv6.addr == %s", vals[0])
}

func (t IPv6) AIndex() []int {
	return []int{0}
}

func (t IPv6) BIndex() []int {
	return []int{1}
}

//======================================================================

func (t UDP) String() string {
	return "UDP"
}

func (t UDP) Short() string {
	return "udp"
}

func (t UDP) FilterTo(vals ...string) string {
	return fmt.Sprintf("%s && udp.dstport == %s", IPv4{}.FilterTo(vals[0]), vals[1])
}

func (t UDP) FilterFrom(vals ...string) string {
	return fmt.Sprintf("%s && udp.srcport == %s", IPv4{}.FilterFrom(vals[0]), vals[1])
}

func (t UDP) FilterAny(vals ...string) string {
	return fmt.Sprintf("%s && udp.port == %s", IPv4{}.FilterAny(vals[0]), vals[1])
}

func (t UDP) AIndex() []int {
	return []int{0, 1}
}

func (t UDP) BIndex() []int {
	return []int{2, 3}
}

//======================================================================

func (t TCP) String() string {
	return "TCP"
}

func (t TCP) Short() string {
	return "tcp"
}

func (t TCP) FilterTo(vals ...string) string {
	return fmt.Sprintf("%s && tcp.dstport == %s", IPv4{}.FilterTo(vals[0]), vals[1])
}

func (t TCP) FilterFrom(vals ...string) string {
	return fmt.Sprintf("%s && tcp.srcport == %s", IPv4{}.FilterFrom(vals[0]), vals[1])
}

func (t TCP) FilterAny(vals ...string) string {
	return fmt.Sprintf("%s && tcp.port == %s", IPv4{}.FilterAny(vals[0]), vals[1])
}

func (t TCP) AIndex() []int {
	return []int{0, 1}
}

func (t TCP) BIndex() []int {
	return []int{2, 3}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
