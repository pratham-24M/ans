from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, icmp, ether_types
from ryu.lib.packet.icmp import icmp as icmp_pkt
from ryu.lib import hub

class Lab1Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Lab1Controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # Pre‑defined router configurations [cite: 413, 419]
        self.router_ip_to_port = {"10.0.1.1": 1, "10.0.2.1": 2, "192.168.1.1": 3}
        self.port_to_mac = {1: "00:00:00:00:01:01", 2: "00:00:00:00:01:02", 3: "00:00:00:00:01:03"}
        self.arp_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        # Install table‑miss flow rule [cite: 377]
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER, datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_arp_reply(self, datapath, arp_pkt, in_port, target_port):
        """Send ARP reply for router's own IP."""
        parser = datapath.ofproto_parser
        own_mac = self.port_to_mac[target_port]
        own_ip = arp_pkt.dst_ip
        # Build Ethernet frame
        eth = ethernet.ethernet(dst=arp_pkt.src_mac, src=own_mac, ethertype=ether_types.ETH_TYPE_ARP)
        arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                            src_mac=own_mac,
                            src_ip=own_ip,
                            dst_mac=arp_pkt.src_mac,
                            dst_ip=arp_pkt.src_ip)
        pkt = packet.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(arp_reply)
        pkt.serialize()
        # Send PacketOut
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=pkt.data)
        datapath.send_msg(out)

    def send_arp_request(self, datapath, target_ip, out_port):
        """Send ARP request to resolve target IP."""
        parser = datapath.ofproto_parser
        own_ip = None
        for ip, port in self.router_ip_to_port.items():
            if port == out_port:
                own_ip = ip
                break
        if not own_ip:
            return
        own_mac = self.port_to_mac[out_port]
        # Build ARP request (broadcast)
        eth = ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff", src=own_mac, ethertype=ether_types.ETH_TYPE_ARP)
        arp_req = arp.arp(opcode=arp.ARP_REQUEST,
                          src_mac=own_mac,
                          src_ip=own_ip,
                          dst_mac="00:00:00:00:00:00",
                          dst_ip=target_ip)
        pkt = packet.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(arp_req)
        pkt.serialize()
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=pkt.data)
        datapath.send_msg(out)

    def send_icmp_reply(self, datapath, ip_pkt, icmp_pkt, eth, in_port):
        """Reply to ICMP echo request destined to router's own IP."""
        parser = datapath.ofproto_parser
        # Swap IP addresses
        src_ip = ip_pkt.dst
        dst_ip = ip_pkt.src
        # Build ICMP reply
        icmp_reply = icmp_pkt(type=icmp.ICMP_ECHO_REPLY,
                              code=icmp_pkt.code,
                              csum=0,
                              data=icmp_pkt.data)
        # Build IPv4 packet
        ipv4_reply = ipv4.ipv4(dst=dst_ip,
                               src=src_ip,
                               proto=ip_pkt.proto,
                               ttl=64,
                               total_length=ip_pkt.total_length)
        # Ethernet: src = router's port MAC, dst = original sender MAC
        eth_reply = ethernet.ethernet(dst=eth.src, src=self.port_to_mac[in_port], ethertype=ether_types.ETH_TYPE_IP)
        pkt = packet.Packet()
        pkt.add_protocol(eth_reply)
        pkt.add_protocol(ipv4_reply)
        pkt.add_protocol(icmp_reply)
        pkt.serialize()
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=pkt.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Switch Logic for s1 and s2 [cite: 375, 381]
        if datapath.id in [1, 2]:
            self.mac_to_port.setdefault(datapath.id, {})
            self.mac_to_port[datapath.id][eth.src] = in_port
            if eth.dst in self.mac_to_port[datapath.id]:
                out_port = self.mac_to_port[datapath.id][eth.dst]
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                # Add flow to minimize controller load [cite: 385, 389]
                match = datapath.ofproto_parser.OFPMatch(eth_dst=eth.dst)
                self.add_flow(datapath, 1, match, actions)
            else:
                out_port = datapath.ofproto.OFPP_FLOOD

            data = msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
            out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                       buffer_id=msg.buffer_id,
                                                       in_port=in_port,
                                                       actions=[datapath.ofproto_parser.OFPActionOutput(out_port)],
                                                       data=data)
            datapath.send_msg(out)

        # Router Logic for s3 (DPID 3) [cite: 405]
        elif datapath.id == 3:
            self.handle_router(datapath, pkt, eth, in_port, msg)

    def handle_router(self, datapath, pkt, eth, in_port, msg):
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        # --- ARP handling ---
        if arp_pkt:
            # Learn sender mapping
            self.arp_table[arp_pkt.src_ip] = eth.src
            # Reply to ARP requests for router's own IPs
            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip in self.router_ip_to_port:
                out_port = self.router_ip_to_port[arp_pkt.dst_ip]
                self.send_arp_reply(datapath, arp_pkt, in_port, out_port)
            return

        # --- IPv4 handling ---
        if not ipv4_pkt:
            return

        dst_ip = ipv4_pkt.dst
        src_ip = ipv4_pkt.src
        parser = datapath.ofproto_parser

        # 1) Handle ICMP echo requests destined to the router's own IP
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if dst_ip in self.router_ip_to_port.values():
            if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                self.send_icmp_reply(datapath, ipv4_pkt, icmp_pkt, eth, in_port)
            return

        # 2) Security policies
        # Block ICMP echo requests: ext -> internal AND internal -> ext
        if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
            # ext (192.168.1.2) to internal (10.0.x.x)
            if src_ip == "192.168.1.2" and dst_ip.startswith("10.0."):
                return
            # internal to ext
            if src_ip.startswith("10.0.") and dst_ip == "192.168.1.2":
                return

        # Block TCP/UDP between ext and ser
        if hasattr(ipv4_pkt, 'proto') and ipv4_pkt.proto in (6, 17):  # TCP or UDP
            if (src_ip == "192.168.1.2" and dst_ip == "10.0.2.2") or \
               (src_ip == "10.0.2.2" and dst_ip == "192.168.1.2"):
                return

        # 3) Determine output port based on destination IP prefix
        out_port = None
        if dst_ip.startswith("10.0.1"):
            out_port = 1
        elif dst_ip.startswith("10.0.2"):
            out_port = 2
        elif dst_ip.startswith("192.168.1"):
            out_port = 3
        else:
            return  # unknown destination

        # 4) Forward or resolve ARP
        if dst_ip in self.arp_table:
            # Build actions: decrement TTL, rewrite MACs, output
            actions = [
                parser.OFPActionDecNwTtl(),
                parser.OFPActionSetField(eth_src=self.port_to_mac[out_port]),
                parser.OFPActionSetField(eth_dst=self.arp_table[dst_ip]),
                parser.OFPActionOutput(out_port)
            ]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
            self.add_flow(datapath, 10, match, actions)
            # Forward this packet
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)
        else:
            # No MAC mapping: send ARP request
            self.send_arp_request(datapath, dst_ip, out_port)
