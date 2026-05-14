import copy
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, icmp, tcp, udp, ether_types

class Lab1Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Lab1Controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # Router mappings corresponding to run_network.py setup
        self.router_ip_to_port = {"10.0.1.1": 1, "10.0.2.1": 2, "192.168.1.1": 3}
        self.port_to_mac = {1: "00:00:00:00:01:01", 2: "00:00:00:00:01:02", 3: "00:00:00:00:01:03"}
        self.arp_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        # Table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER, datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Distinguish between switches (1, 2) and the router (3)
        if datapath.id in [1, 2]:
            self.handle_switch(datapath, pkt, eth, in_port, msg)
        elif datapath.id == 3:
            self.handle_router(datapath, pkt, eth, in_port, msg)

    def handle_switch(self, datapath, pkt, eth, in_port, msg):
        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][eth.src] = in_port

        if eth.dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][eth.dst]
        else:
            out_port = datapath.ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        if out_port != datapath.ofproto.OFPP_FLOOD:
            match = datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            if msg.buffer_id != datapath.ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def handle_router(self, datapath, pkt, eth, in_port, msg):
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        # 1. Handle ARP Packets
        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip in self.router_ip_to_port:
                self.send_arp_reply(datapath, arp_pkt, in_port)
            return

        # 2. Handle IPv4 Packets
        if ipv4_pkt:
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst

            # Lab Requirement: Hosts can ping THEIR OWN gateway, but not others
            if dst_ip in self.router_ip_to_port:
                if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                    expected_port = self.router_ip_to_port[dst_ip]
                    if in_port == expected_port:
                        self.send_icmp_reply(datapath, pkt, eth, ipv4_pkt, icmp_pkt, in_port)
                return

            # Lab Requirement: Security Policies
            if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                if src_ip == "192.168.1.2" and (dst_ip.startswith("10.0.1") or dst_ip.startswith("10.0.2")):
                    return # Block ext pings to internal network
            if tcp_pkt or udp_pkt:
                if (src_ip == "192.168.1.2" and dst_ip == "10.0.2.2") or (src_ip == "10.0.2.2" and dst_ip == "192.168.1.2"):
                    return # Block TCP/UDP between ext and ser

            # Routing Logic
            out_port = None
            if dst_ip.startswith("10.0.1"): out_port = 1
            elif dst_ip.startswith("10.0.2"): out_port = 2
            elif dst_ip.startswith("192.168.1"): out_port = 3

            if not out_port: return 

            router_mac = self.port_to_mac[out_port]

            if dst_ip in self.arp_table:
                dst_mac = self.arp_table[dst_ip]
                parser = datapath.ofproto_parser
                actions = [
                    parser.OFPActionSetField(eth_src=router_mac),
                    parser.OFPActionSetField(eth_dst=dst_mac),
                    parser.OFPActionDecNwTtl(), # RFC 1812 standard routing behavior
                    parser.OFPActionOutput(out_port)
                ]
                match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)
                self.add_flow(datapath, 10, match, actions)
                
                # Forward the initial packet
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)
            else:
                # Ask network for destination MAC
                self.send_arp_request(datapath, dst_ip, out_port)

    # Packet Generators
    def send_arp_reply(self, datapath, arp_req, in_port):
        router_mac = self.port_to_mac[in_port]
        eth = ethernet.ethernet(dst=arp_req.src_mac, src=router_mac, ethertype=ether_types.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REPLY, src_mac=router_mac, src_ip=arp_req.dst_ip,
                    dst_mac=arp_req.src_mac, dst_ip=arp_req.src_ip)
        self._send_generated_packet(datapath, eth, a, in_port)

    def send_arp_request(self, datapath, target_ip, out_port):
        router_mac = self.port_to_mac[out_port]
        router_ip = [ip for ip, port in self.router_ip_to_port.items() if port == out_port][0]
        eth = ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff", src=router_mac, ethertype=ether_types.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REQUEST, src_mac=router_mac, src_ip=router_ip,
                    dst_mac="00:00:00:00:00:00", dst_ip=target_ip)
        self._send_generated_packet(datapath, eth, a, out_port)

    def send_icmp_reply(self, datapath, pkt, eth, ipv4_pkt, icmp_req, in_port):
        router_mac = self.port_to_mac[in_port]
        eth_reply = ethernet.ethernet(dst=eth.src, src=router_mac, ethertype=ether_types.ETH_TYPE_IP)
        ipv4_reply = ipv4.ipv4(dst=ipv4_pkt.src, src=ipv4_pkt.dst, proto=ipv4_pkt.proto, ttl=64)
        icmp_reply = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=0, csum=0, data=icmp_req.data)
        
        p = packet.Packet()
        p.add_protocol(eth_reply)
        p.add_protocol(ipv4_reply)
        p.add_protocol(icmp_reply)
        p.serialize()
        
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=[datapath.ofproto_parser.OFPActionOutput(in_port)], data=p.data)
        datapath.send_msg(out)

    def _send_generated_packet(self, datapath, eth_header, payload, out_port):
        p = packet.Packet()
        p.add_protocol(eth_header)
        p.add_protocol(payload)
        p.serialize()
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=[datapath.ofproto_parser.OFPActionOutput(out_port)], data=p.data)
        datapath.send_msg(out)
