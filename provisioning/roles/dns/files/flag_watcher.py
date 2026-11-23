#!/usr/bin/env python3
"""
DNS Lab flag watcher.

Passively observes real DNS traffic on this host for independent evidence
that a genuine, network-delivered DNS spoof actually happened, then reveals
the per-sandbox flag into the student's home directory.

This script is deployed and started by Ansible, as root, with a config file
whose path is given on the command line. The config content comes entirely
from provisioning (not from the student), so there is no attacker-controlled
input anywhere in this file.

Design intent: a student with only normal, non-root access to THIS machine
cannot fabricate the flag, because:
  - the per-sandbox secret lives under /root/.dns-lab, not readable without
    root, and there is no sudo on this machine (see the "user"/"dns"
    Ansible roles, which strip sudo entirely);
  - this script only copies the secret out once it has independently
    observed a DNS response packet that (a) physically arrived from the
    attacker machine's real IP address and (b) contains a record matching
    the shape of the intended attack (right qname/type/rdata), which can
    only be produced by actually sending a forged packet over the wire.
"""
import json
import os
import shutil
import sys
import time

from scapy.all import sniff, DNS, IP, UDP  # noqa: E402

CONFIG_PATH = sys.argv[1] if len(sys.argv) > 1 else "/etc/dns-lab/watcher.json"
LOG_PATH = "/var/log/dns-lab/watcher.log"


def log(msg):
    with open(LOG_PATH, "a") as f:
        f.write("%s: %s\n" % (time.ctime(), msg))


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def iter_resource_records(dns_layer):
    """Yield every RR in the Answer, Authority and Additional sections."""
    for count, chain in (
        (dns_layer.ancount, dns_layer.an),
        (dns_layer.nscount, dns_layer.ns),
        (dns_layer.arcount, dns_layer.ar),
    ):
        rr = chain
        seen = 0
        while rr is not None and seen < (count or 0):
            yield rr
            seen += 1
            rr = rr.payload if hasattr(rr, "payload") and rr.payload else None


def record_matches(rr, cfg):
    try:
        name = rr.rrname.decode(errors="ignore").rstrip(".").lower()
    except Exception:
        return False
    if cfg.get("qname_substr") and cfg["qname_substr"].lower() not in name:
        return False
    if cfg.get("need_rr_type"):
        rtype = rr.sprintf("%type%")
        if rtype != cfg["need_rr_type"]:
            return False
    if cfg.get("need_rdata_contains"):
        try:
            raw = rr.rdata
            rdata = raw.decode(errors="ignore") if isinstance(raw, bytes) else str(raw)
        except Exception:
            rdata = str(getattr(rr, "rdata", ""))
        if cfg["need_rdata_contains"].lower() not in rdata.lower():
            return False
    return True


def packet_is_valid_evidence(pkt, cfg):
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return False
    dns_layer = pkt[DNS]
    if dns_layer.qr != 1:
        return False  # must be a response, not a query
    if pkt[IP].src != cfg["attacker_ip"]:
        # Ground truth: the packet must have actually arrived over the wire
        # from the attacker machine's real IP. A locally-faked file edit on
        # this host can never satisfy this, regardless of privilege level.
        return False
    for rr in iter_resource_records(dns_layer):
        if record_matches(rr, cfg):
            return True
    return False


def reveal_flag(cfg):
    secret_path = cfg["secret_path"]
    out_path = cfg["reveal_path"]
    owner = cfg.get("reveal_owner", "seed")
    if os.path.exists(out_path):
        return
    shutil.copyfile(secret_path, out_path)
    os.chmod(out_path, 0o440)
    shutil.chown(out_path, user=owner, group=owner)
    log("evidence matched config=%s -> revealed %s" % (CONFIG_PATH, out_path))


def main():
    cfg = load_config()
    os.makedirs("/var/log/dns-lab", exist_ok=True)
    log("watcher started, iface=%s" % cfg.get("iface"))

    def handle(pkt):
        try:
            if packet_is_valid_evidence(pkt, cfg):
                reveal_flag(cfg)
                os._exit(0)  # done; systemd unit has Restart=no
        except Exception as exc:  # never crash-loop on a malformed packet
            log("error handling packet: %r" % exc)

    sniff(filter="udp port 53", prn=handle, store=False, iface=cfg.get("iface"))


if __name__ == "__main__":
    main()
