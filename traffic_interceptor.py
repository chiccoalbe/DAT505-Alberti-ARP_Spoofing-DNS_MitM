#!/usr/bin/env python3
"""
traffic_interceptor.py

Parser that takes pcap ad extracts 

Usage:
  python3 pcap_parser.py /path/to/file.pcap

Outputs (in same dir as input pcap):
  urls.csv         - http_host,http_uri,src_ip,dst_ip,frame_time
  dns_queries.csv  - time,src_ip,qname,qtype,is_response,answers (pipe-separated)
  top_talkers.csv  - ip,packets,bytes
  proto_counts.csv - proto_number,proto_name,count
"""

import sys
import dpkt
import socket
import os
import csv
from datetime import datetime
from collections import defaultdict, Counter

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except Exception:
        return None

def parse_pcap(path):
    urls = []              # tuples: (time, src, dst, host, uri)
    dns_rows = []          # tuples: (time, src, qname, qtype, is_resp, answers)
    ip_packet_counts = defaultdict(int)
    ip_byte_counts = defaultdict(int)
    proto_counts = Counter()

    with open(path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            # try Ethernet
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue

            ip = eth.data
            # IPv4 or IPv6 handling for addresses
            if isinstance(ip, dpkt.ip.IP):
                src = inet_to_str(ip.src)
                dst = inet_to_str(ip.dst)
                ip_len = ip.len if hasattr(ip, 'len') else len(ip)
                proto = ip.p
            else:
                # IPv6
                src = socket.inet_ntop(socket.AF_INET6, ip.src)
                dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
                ip_len = getattr(ip, 'plen', 0)
                proto = getattr(ip, 'nh', None)

            if src:
                ip_packet_counts[src] += 1
                ip_byte_counts[src] += len(buf)
            if dst:
                ip_packet_counts[dst] += 0  # keep key presence
                ip_byte_counts[dst] += 0

            proto_counts[proto] += 1

            # TCP -> check for HTTP
            if proto == dpkt.ip.IP_PROTO_TCP:
                try:
                    tcp = ip.data
                except Exception:
                    continue
                # detect HTTP request (naive)
                if len(tcp.data) > 0:
                    # try parse as HTTP request
                    try:
                        req = dpkt.http.Request(tcp.data)
                        host = req.headers.get('host', '')
                        uri = req.uri
                        urls.append((ts, src, dst, host, uri))
                    except (dpkt.UnpackError, dpkt.NeedData):
                        # not a full HTTP request in this segment
                        pass
                    except Exception:
                        pass

            # UDP -> check for DNS
            if proto == dpkt.ip.IP_PROTO_UDP:
                try:
                    udp = ip.data
                    # DNS port 53 check
                    if getattr(udp, 'sport', None) == 53 or getattr(udp, 'dport', None) == 53:
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            is_resp = (dns.qr == dpkt.dns.DNS_R)
                            for q in dns.qd:
                                qname = q.name
                                qtype = q.type
                                answers = []
                                if is_resp:
                                    for a in dns.an:
                                        # Grab A/AAAA answers and other types
                                        if a.type == dpkt.dns.DNS_A:
                                            answers.append(socket.inet_ntoa(a.rdata))
                                        elif a.type == dpkt.dns.DNS_AAAA:
                                            try:
                                                answers.append(socket.inet_ntop(socket.AF_INET6, a.rdata))
                                            except Exception:
                                                pass
                                        else:
                                            # store textual repr
                                            answers.append(f"{a.name}:{a.type}")
                                dns_rows.append((ts, src, qname, qtype, is_resp, answers))
                        except (dpkt.UnpackError, IndexError):
                            pass
                except Exception:
                    pass

    return urls, dns_rows, ip_packet_counts, ip_byte_counts, proto_counts

def write_outputs(pcap_path, urls, dns_rows, pkt_counts, byte_counts, proto_counts):
    base = os.path.splitext(os.path.basename(pcap_path))[0]
    out_dir = os.path.dirname(pcap_path) or '.'

    # URLs
    urls_file = os.path.join(out_dir, f"{base}_urls.csv")
    with open(urls_file, 'w', newline='') as csvf:
        w = csv.writer(csvf)
        w.writerow(['time','src_ip','dst_ip','http_host','http_uri'])
        for ts, src, dst, host, uri in urls:
            t = datetime.utcfromtimestamp(ts).isoformat() + 'Z'
            w.writerow([t, src, dst, host, uri])

    # DNS
    dns_file = os.path.join(out_dir, f"{base}_dns_queries.csv")
    with open(dns_file, 'w', newline='') as csvf:
        w = csv.writer(csvf)
        w.writerow(['time','src_ip','qname','qtype','is_response','answers'])
        for ts, src, qname, qtype, is_resp, answers in dns_rows:
            t = datetime.utcfromtimestamp(ts).isoformat() + 'Z'
            ans_str = '|'.join(answers) if answers else ''
            w.writerow([t, src, qname, qtype, int(is_resp), ans_str])

    # Top talkers (by packets and bytes)
    top_file = os.path.join(out_dir, f"{base}_top_talkers.csv")
    with open(top_file, 'w', newline='') as csvf:
        w = csv.writer(csvf)
        w.writerow(['ip','packets','bytes'])
        # sort by packets desc
        for ip, pk in sorted(pkt_counts.items(), key=lambda x: x[1], reverse=True):
            b = byte_counts.get(ip, 0)
            w.writerow([ip, pk, b])

    # Protocol counts
    proto_file = os.path.join(out_dir, f"{base}_proto_counts.csv")
    with open(proto_file, 'w', newline='') as csvf:
        w = csv.writer(csvf)
        w.writerow(['proto_number','proto_name','count'])
        for proto, cnt in proto_counts.items():
            # map common protocol numbers
            name = {6:'TCP',17:'UDP',1:'ICMP',41:'IPv6',132:'SCTP'}.get(proto, '')
            w.writerow([proto, name, cnt])

    return urls_file, dns_file, top_file, proto_file

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 pcap_parser.py /path/to/pcap")
        sys.exit(1)
    pcap_path = sys.argv[1]
    if not os.path.exists(pcap_path):
        print("File not found:", pcap_path); sys.exit(1)

    print("[*] Parsing pcap:", pcap_path)
    urls, dns_rows, pkt_counts, byte_counts, proto_counts = parse_pcap(pcap_path)
    print(f"[*] Found {len(urls)} HTTP requests, {len(dns_rows)} DNS query rows")
    outs = write_outputs(pcap_path, urls, dns_rows, pkt_counts, byte_counts, proto_counts)
    print("[*] Wrote:")
    for o in outs:
        print("   ", o)

if __name__ == "__main__":
    main()
