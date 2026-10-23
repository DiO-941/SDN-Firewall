#!/bin/bash
# Usage (inside Mininet CLI):  h2 bash knock.sh 10.0.0.1
# Sequence must match KNOCK_SEQUENCE in knock_firewall.py: UDP 7000, TCP 8000, UDP 9000
SERVER=${1:-10.0.0.1}

echo "[*] Knock 1: UDP 7000"
echo knock | nc -u -w1 "$SERVER" 7000
echo "[*] Knock 2: TCP 8000"
nc -z -w1 "$SERVER" 8000 2>/dev/null     # SYN is sent; no reply expected
echo "[*] Knock 3: UDP 9000"
echo knock | nc -u -w1 "$SERVER" 9000

sleep 1
echo "[*] Requesting HTTP..."
curl -s -m 5 -o /dev/null -w "HTTP status: %{http_code}\n" "http://$SERVER:80/"
