"""
CodeAlpha - Task 1: Basic Network Sniffer
------------------------------------------
Captures live network traffic with Scapy and prints a readable summary for
each packet: source/destination IP, protocol, ports, and a payload preview.
Optional filtering (by protocol or host) and logging to a file are supported.

Run (Linux):   sudo python3 sniffer.py
With options:  sudo python3 sniffer.py --proto tcp --host 8.8.8.8 --log capture.log
Read a pcap:   python3 sniffer.py --pcap sample.pcap        (no root needed)

Ethics note: only capture traffic on networks/machines you own or are
authorised to monitor.
"""

import argparse
import sys
from datetime import datetime

from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, Raw

packet_count = 0
log_file = None


def preview_payload(packet):
    """Return a short, readable preview of the packet payload (Step 4).

    Printable bytes are shown as ASCII; everything else falls back to hex so
    the line stays on one row and never dumps binary garbage to the terminal.
    """
    if not packet.haslayer(Raw):
        return None
    data = bytes(packet[Raw].load)[:48]
    # If most bytes are printable ASCII, show text; otherwise show hex.
    printable = sum(32 <= b < 127 for b in data)
    if data and printable / len(data) > 0.7:
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        return f"ascii: {text}"
    return f"hex: {data.hex(' ')}"


def handle_packet(packet):
    global packet_count

    # Step 2: only IP packets carry the src/dst/protocol info we want.
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Step 2: identify protocol and pull ports where they exist.
    ports = ""
    if TCP in packet:
        proto = "TCP"
        ports = f":{packet[TCP].sport} -> :{packet[TCP].dport}"
    elif UDP in packet:
        proto = "UDP"
        ports = f":{packet[UDP].sport} -> :{packet[UDP].dport}"
    elif ICMP in packet:
        proto = "ICMP"
    else:
        proto = "OTHER"

    packet_count += 1

    # Step 3: running count + one summary line per packet.
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{packet_count}] {ts} {proto:5} {src_ip} -> {dst_ip} {ports}".rstrip()

    # Step 4: payload preview when present.
    payload = preview_payload(packet)

    print(line)
    if payload:
        print(f"      {payload}")

    # Step 6: optional log file.
    if log_file:
        log_file.write(line + "\n")
        if payload:
            log_file.write(f"      {payload}\n")
        log_file.flush()


def build_filter(args):
    """Step 5: build a BPF filter string from CLI options.

    BPF filtering happens in the kernel, so it is far more efficient than
    dropping packets in Python.
    """
    parts = []
    if args.proto:
        parts.append(args.proto.lower())  # tcp / udp / icmp
    if args.host:
        parts.append(f"host {args.host}")
    return " and ".join(parts) if parts else None


def main():
    global log_file

    parser = argparse.ArgumentParser(description="CodeAlpha basic network sniffer")
    parser.add_argument("-i", "--iface", help="interface to sniff (default: all)")
    parser.add_argument("--proto", choices=["tcp", "udp", "icmp"],
                        help="only capture this protocol (Step 5 filter)")
    parser.add_argument("--host", help="only capture traffic to/from this IP (Step 5 filter)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="stop after N packets (0 = run until Ctrl+C)")
    parser.add_argument("--log", help="also append summaries to this file (Step 6)")
    parser.add_argument("--pcap", help="read packets from a .pcap file instead of live capture")
    args = parser.parse_args()

    if args.log:
        log_file = open(args.log, "a")
        log_file.write(f"\n=== capture started {datetime.now().isoformat()} ===\n")

    # Offline mode: parse a saved capture (handy for testing without root).
    if args.pcap:
        print(f"Reading packets from {args.pcap} ...")
        for pkt in rdpcap(args.pcap):
            handle_packet(pkt)
        print(f"\nDone. {packet_count} IP packets summarised.")
        return

    bpf = build_filter(args)
    print("Starting sniffer... press Ctrl+C to stop.")
    if bpf:
        print(f"Filter: {bpf}")
    if args.iface:
        print(f"Interface: {args.iface}")

    try:
        sniff(prn=handle_packet, store=False, filter=bpf,
              iface=args.iface, count=args.count)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\nPermission denied — live capture needs root. Try: sudo python3 sniffer.py",
              file=sys.stderr)
        sys.exit(1)
    finally:
        print(f"\nStopped. {packet_count} IP packets captured.")
        if log_file:
            log_file.close()


if __name__ == "__main__":
    main()
