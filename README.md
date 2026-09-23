# CodeAlpha_NetworkSniffer

A basic network packet sniffer written in Python, built for Task 1 of the CodeAlpha
Cyber Security internship.

It listens to network traffic and prints a short, readable summary for every packet
it sees — the source and destination IP, the protocol, the ports, and a preview of
the data inside.

## What it does

- Captures live traffic using Scapy
- Picks out TCP, UDP and ICMP packets
- Shows a payload preview (readable text when it can, hex when it can't)
- Can filter by protocol or by host
- Can save everything to a log file

## Setup

```bash
pip install scapy
```

## How to run

```bash
# capture everything (needs root for raw sockets)
sudo python3 sniffer.py

# only TCP to/from one host, stop after 50 packets, and log to a file
sudo python3 sniffer.py --proto tcp --host 8.8.8.8 --count 50 --log capture.log

# read a saved .pcap instead of live traffic (no root needed)
python3 sniffer.py --pcap capture.pcap
```

## Example output

```
[1] 05:41:06 TCP   192.168.1.10 -> 93.184.216.34 :54321 -> :80
      ascii: GET / HTTP/1.1..Host: example.com....
[2] 05:41:06 UDP   192.168.1.10 -> 10.0.0.5 :5000 -> :4444
      hex: de ad be ef 00 11 22 33
[3] 05:41:06 ICMP  192.168.1.10 -> 1.1.1.1
```

## A note on the payload preview

If most of the bytes are printable it shows them as text, otherwise it shows hex, so
the output stays clean either way. It's cut off at 48 bytes to keep each line short.

Only run this on networks and machines you own or have permission to test.
