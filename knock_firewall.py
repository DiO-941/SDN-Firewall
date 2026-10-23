"""
SDN Dynamic Flow Firewall with Port-Knocking Gateway  (os-ken, OpenFlow 1.3)

Run:  osken-manager --verbose knock_firewall.py
"""
import time
from collections import defaultdict

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4, tcp, udp, ether_types, in_proto

# ----------------------------- CONFIGURATION -----------------------------
SERVER_IP = "10.0.0.1"
PROTECTED_PORT = 80                       # TCP service hidden behind the knock
KNOCK_SEQUENCE = [("udp", 7000), ("tcp", 8000), ("udp", 9000)]
KNOCK_WINDOW = 5.0                        # max seconds between knocks
INVALID_THRESHOLD = 4                     # invalid hits before quarantine
INVALID_DECAY = 10.0                      # invalid hits older than this are forgotten
QUARANTINE_TIME = 60                      # hard_timeout of DROP rule (s)
LEASE_IDLE = 30                           # idle_timeout of ALLOW rule (s)

PRIO_MISS, PRIO_ARP, PRIO_ALLOW, PRIO_DROP = 0, 10, 100, 200
COOKIE_ALLOW, COOKIE_DROP = 0xA110, 0xD209


class ClientState:
    def __init__(self):
        self.step = 0
        self.last_time = 0.0
        self.invalid = 0
        self.invalid_ts = 0.0


class KnockFirewall(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_state = defaultdict(ClientState)
        self.quarantined = {}             # ip -> expiry timestamp

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def add_flow(self, dp, priority, match, actions, idle=0, hard=0,
                 cookie=0, flags=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] \
            if actions else []            # empty instruction list == DROP
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match, instructions=inst,
            idle_timeout=idle, hard_timeout=hard, cookie=cookie, flags=flags))

    # ------------------------------------------------------------------
    # Phase 1: bootstrap (ARP bypass + table-miss -> controller)
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser

        # Rule 1: ARP -> flood (priority 10)
        self.add_flow(dp, PRIO_ARP,
                      parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP),
                      [parser.OFPActionOutput(ofp.OFPP_FLOOD)])

        # Rule 2: table-miss -> controller (priority 0)
        self.add_flow(dp, PRIO_MISS, parser.OFPMatch(),
                      [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                              ofp.OFPCML_NO_BUFFER)])
        self.logger.info("[BOOT] s%s ready: ARP flood + default-deny installed",
                         dp.id)

    # ------------------------------------------------------------------
    # Packet-In: decapsulate -> knock FSM / scan detection
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype != ether_types.ETH_TYPE_IP:
            return
        ip = pkt.get_protocol(ipv4.ipv4)
        # Only traffic aimed at the protected server is judged; everything
        # else that misses the table is silently dropped (default deny).
        if ip is None or ip.dst != SERVER_IP:
            return

        t, u = pkt.get_protocol(tcp.tcp), pkt.get_protocol(udp.udp)
        if t is not None:
            if not (t.bits & 0x02) or (t.bits & 0x10):   # only pure SYNs count
                return
            proto, dport = "tcp", t.dst_port
        elif u is not None:
            proto, dport = "udp", u.dst_port
        else:
            return                                       # ICMP etc: just drop

        src, now = ip.src, time.time()

        # Already quarantined? ignore (DROP flow normally catches these)
        if src in self.quarantined:
            if now < self.quarantined[src]:
                return
            del self.quarantined[src]

        self.process_knock(dp, src, proto, dport, now)

    # ------------------------------------------------------------------
    # Knock FSM (Phases 2 + 3)
    # ------------------------------------------------------------------
    def process_knock(self, dp, src, proto, dport, now):
        st = self.client_state[src]
        hit = (proto, dport)

        if now - st.invalid_ts > INVALID_DECAY:
            st.invalid = 0
        if st.step > 0 and now - st.last_time > KNOCK_WINDOW:
            self.logger.info("[KNOCK] %s window expired, reset", src)
            st.step = 0

        # Retransmit of the knock we just accepted -> ignore silently
        if st.step > 0 and hit == KNOCK_SEQUENCE[st.step - 1]:
            return

        if hit == KNOCK_SEQUENCE[st.step]:
            st.step += 1
            st.last_time = now
            self.logger.info("[KNOCK] %s step %d/%d OK (%s/%d)",
                             src, st.step, len(KNOCK_SEQUENCE), proto, dport)
            if st.step == len(KNOCK_SEQUENCE):
                self.grant_access(dp, src)
                st.step = 0
            return

        # Wrong packet: sequence breaks
        st.step = 0
        if hit == KNOCK_SEQUENCE[0]:          # could be a fresh first knock
            st.step, st.last_time = 1, now
            self.logger.info("[KNOCK] %s restarted at step 1", src)
            return

        st.invalid += 1
        st.invalid_ts = now
        self.logger.warning("[SCAN?] %s invalid hit %s/%d (%d/%d)", src, proto,
                            dport, st.invalid, INVALID_THRESHOLD)
        if st.invalid >= INVALID_THRESHOLD:
            self.quarantine(dp, src, now)

    # ------------------------------------------------------------------
    # Quarantine: priority 200 DROP, hard_timeout 60
    # ------------------------------------------------------------------
    def quarantine(self, dp, src, now):
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src)
        self.add_flow(dp, PRIO_DROP, match, [], hard=QUARANTINE_TIME,
                      cookie=COOKIE_DROP, flags=dp.ofproto.OFPFF_SEND_FLOW_REM)
        self.quarantined[src] = now + QUARANTINE_TIME
        self.client_state.pop(src, None)
        self.logger.error("[QUARANTINE] %s dropped for %ds", src, QUARANTINE_TIME)

    # ------------------------------------------------------------------
    # Access lease: priority 100 ALLOW (forward + reverse), idle_timeout 30
    # ------------------------------------------------------------------
    def grant_access(self, dp, src):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        normal = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        flags = ofp.OFPFF_SEND_FLOW_REM

        fwd = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src,
                              ipv4_dst=SERVER_IP, ip_proto=in_proto.IPPROTO_TCP,
                              tcp_dst=PROTECTED_PORT)
        # Return path (SYN-ACK, data) must be allowed too, or the server's
        # replies would hit table-miss.
        rev = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=SERVER_IP,
                              ipv4_dst=src, ip_proto=in_proto.IPPROTO_TCP,
                              tcp_src=PROTECTED_PORT)
        self.add_flow(dp, PRIO_ALLOW, fwd, normal, idle=LEASE_IDLE,
                      cookie=COOKIE_ALLOW, flags=flags)
        self.add_flow(dp, PRIO_ALLOW, rev, normal, idle=LEASE_IDLE,
                      cookie=COOKIE_ALLOW, flags=flags)
        self.logger.info("[GRANT] %s -> %s:%d lease %ds idle", src, SERVER_IP,
                         PROTECTED_PORT, LEASE_IDLE)

    # ------------------------------------------------------------------
    # Phase 4: log autonomous evictions
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        ofp = msg.datapath.ofproto
        reason = {ofp.OFPRR_IDLE_TIMEOUT: "idle timeout",
                  ofp.OFPRR_HARD_TIMEOUT: "hard timeout",
                  ofp.OFPRR_DELETE: "deleted"}.get(msg.reason, str(msg.reason))
        if msg.cookie == COOKIE_ALLOW:
            self.logger.info("[EXPIRE] lease removed (%s): %s", reason, msg.match)
        elif msg.cookie == COOKIE_DROP:
            ip = msg.match.get("ipv4_src")
            self.quarantined.pop(ip, None)
            self.logger.info("[RELEASE] %s quarantine ended (%s)", ip, reason)
