# GoSniff
A network sniffer in the go language

* Very basic for now, working on it step by step,
using gopacket libs as base.

##### Usage:
-BPF syntax

sudo ./gosniff --interface eth0 --sniff "tcp and port 80"
