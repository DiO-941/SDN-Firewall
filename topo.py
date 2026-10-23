#!/usr/bin/env python3
"""Mininet topology: h1 (server) / h2 (legit client) / h3 (attacker) behind s1.

Usage:
  sudo python3 topo.py                              # controller on 127.0.0.1:6653
  sudo python3 topo.py --controller-ip 10.0.2.2     # controller on another machine
  sudo python3 topo.py --userspace                  # OVS userspace datapath
"""
import argparse

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel


def run(controller_ip, controller_port, userspace):
    net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=True)
    kw = dict(protocols="OpenFlow13", failMode="secure")  # no fallback to L2 learning
    if userspace:
        kw["datapath"] = "user"
    s1 = net.addSwitch("s1", **kw)
    h1 = net.addHost("h1", ip="10.0.0.1/24")   # protected server
    h2 = net.addHost("h2", ip="10.0.0.2/24")   # legitimate client
    h3 = net.addHost("h3", ip="10.0.0.3/24")   # attacker
    for h in (h1, h2, h3):
        net.addLink(h, s1)
    net.addController("c0", controller=RemoteController,
                      ip=controller_ip, port=controller_port)

    net.start()
    h1.cmd("python3 -m http.server 80 --bind 10.0.0.1 &> /tmp/h1_http.log &")
    print("*** Server h1 running HTTP on port 80 (cloaked by the firewall)")
    print("*** Try:  h3 nmap -sS -Pn -p 21,22,80,443,8080 10.0.0.1")
    print("***       h2 bash knock.sh 10.0.0.1")
    CLI(net)
    h1.cmd("kill %python3")
    net.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--controller-ip", default="127.0.0.1")
    ap.add_argument("--controller-port", type=int, default=6653)
    ap.add_argument("--userspace", action="store_true")
    args = ap.parse_args()
    setLogLevel("info")
    run(args.controller_ip, args.controller_port, args.userspace)
