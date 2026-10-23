# SDN Port-Knocking Firewall
A dynamic flow firewall built on software-defined networking. An os-ken controller (OpenFlow 1.3) manages an Open vSwitch bridge in Mininet, keeping a protected web server hidden until a client proves itself with a secret knock sequence.

**How it works**
- Default deny: unknown traffic goes to the controller. ARP is flooded so hosts can still resolve addresses.
- Port knocking: the sequence UDP 7000, TCP 8000, UDP 9000 within 5 seconds installs a temporary rule for TCP port 80 (client to server and the return path).
- Self-expiring access: the switch forwards permitted traffic itself and removes the rule after 30 idle seconds.
- Scan quarantine: four invalid probes within 10 seconds trigger a priority 200 drop rule for 60 seconds.

**Topology**

h1 (server, 10.0.0.1), h2 (client, 10.0.0.2) and h3 (attacker, 10.0.0.3) behind one switch, s1.

**Limitations**

- The knock sequence is static, so it is vulnerable to sniffing and replay from a spoofed IP.
- Single switch, single protected service.
- Tested in a Mininet lab, not on hardware.
