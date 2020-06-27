#!/usr/bin/env bash

set -e

echo Started some simple termshark tests.

echo Installing termshark for test use.

go install ./...

echo Making a test pcap.

cat <<EOF | xxd -r -p > /tmp/test.pcap
d4c3b2a102000400
0000000000000000
0000040006000000
f32a395200000000
4d0000004d000000
1040002035012b59
0006291793f8aaaa
0300000008004500
0037f93900004011
a6dbc0a82c7bc0a8
2cd5f93900450023
8d730001433a5c49
424d54435049505c
6c63636d2e31006f
6374657400f32a39
52000000004d0000
004d000000104000
2035012b59000629
1793f8aaaa030000
00080045000037f9
3900004011a6dbc0
a82c7bc0a82cd5f9
39004500238d7300
01433a5c49424d54
435049505c6c6363
6d2e31006f637465
7400
EOF

echo Running termshark cli tests.

# if timeout is invoked because termshark is stuck, the exit code will be non-zero
export TS="timeout 10s $GOPATH/bin/termshark"

# stdout is not a tty, so falls back to tshark
$TS -r /tmp/test.pcap | grep '192.168.44.213 TFTP 77'

[[ $($TS -r /tmp/test.pcap -T psml -n | grep '<packet>' | wc -l) == 2 ]]

# only display the second line via tshark
[[ $($TS -r /tmp/test.pcap 'frame.number == 2' | wc -l) == 1 ]]

[[ $($TS -r /tmp/test.pcap --pass-thru | wc -l) == 2 ]]

[[ $($TS -r /tmp/test.pcap --pass-thru=true | wc -l) == 2 ]]

# run in script so termshark thinks it's in a tty
cat version.go | grep -o -E "v[0-9]+\.[0-9]+(\.[0-9]+)?" | \
    xargs -i bash -c "script -q -e -c \"$TS -v\" | grep {}"

echo Running termshark UI tests.

# Load a pcap, quit
{ sleep 5s ; echo q ; echo ; } | \
    socat - EXEC:"sh -c \\\"stty rows 50 cols 80 && TERM=xterm $TS -r /tmp/test.pcap\\\"",pty,setsid,ctty 

# Run with stdout not a tty, but disable the pass-thru to tshark
{ sleep 5s ; echo q ; echo ; } | \
    socat - EXEC:"sh -c \\\"stty rows 50 cols 80 && TERM=xterm $TS -r /tmp/test.pcap --pass-thru=false | cat\\\"",pty,setsid,ctty 

# Load a pcap, very rudimentary scrape for an IP, quit
{ sleep 5s ; echo q ; echo ; } | \
    socat - EXEC:"sh -c \\\"stty rows 50 cols 80 && TERM=xterm $TS -r /tmp/test.pcap\\\"",pty,setsid,ctty | \
    grep -a 192.168.44.123 > /dev/null

# Load a pcap from stdin
{ sleep 5s ; echo q ; echo ; } | \
    socat - EXEC:"sh -c \\\"stty rows 50 cols 80 && cat /tmp/test.pcap | TERM=xterm $TS -i -\\\"",pty,setsid,ctty | \
    grep -a 192.168.44.123 > /dev/null

# Display filter at end of command line
{ sleep 5s ; echo q ; echo ; } | \
    socat - EXEC:"sh -c \\\"stty rows 50 cols 80 && TERM=xterm $TS -r scripts/pcaps/telnet-cooked.pcap \'frame.number == 2\'\\\"",pty,setsid,ctty | \
    grep -a "Frame 2: 74 bytes" > /dev/null

echo Tests were successful.
