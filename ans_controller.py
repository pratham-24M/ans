from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, icmp, ether_types

class Lab1Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Lab1Controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # Pre-defined router configurations [cite: 413, 419]
        self.router_ip_to_port = {"10.0.1.1": 1, "10.0.2.1": 2, "192.168.1.1": 3}
        self.port_to_mac = {1: "00:00:00:00:01:01", 2: "00:00:00:00:01:02", 3: "00:00:00:00:01:03"}
        self.arp_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        # Install table-miss flow rule [cite: 377]
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER, datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return

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
            out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=[datapath.ofproto_parser.OFPActionOutput(out_port)], data=data)
            datapath.send_msg(out)

        # Router Logic for s3 (DPID 3) [cite: 405]
        elif datapath.id == 3:
            self.handle_router(datapath, pkt, eth, in_port, msg)

    def handle_router(self, datapath, pkt, eth, in_port, msg):
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = eth.src
            # Respond to ARP requests for router's own IPs [cite: 411, 418]
            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip in self.router_ip_to_port:
                self.send_arp_reply(datapath, arp_pkt, in_port)

        elif ipv4_pkt:
            # Security Policy: Block pings from ext to internal hosts [cite: 425, 426]
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                if ipv4_pkt.src == "192.168.1.2" and ipv4_pkt.dst.startswith("10.0."):
                    return # Drop packet

            # Routing logic [cite: 406, 408]
            dst_ip = ipv4_pkt.dst
            out_port = None
            if dst_ip.startswith("10.0.1"): out_port = 1
            elif dst_ip.startswith("10.0.2"): out_port = 2
            elif dst_ip.startswith("192.168.1"): out_port = 3

            if out_port and dst_ip in self.arp_table:
                # Update headers for routing [cite: 476]
                actions = [
                    datapath.ofproto_parser.OFPActionSetField(eth_src=self.port_to_mac[out_port]),
                    datapath.ofproto_parser.OFPActionSetField(eth_dst=self.arp_table[dst_ip]),
                    datapath.ofproto_parser.OFPActionOutput(out_port)
                ]
                match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)
                self.add_flow(datapath, 10, match, actions)
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)
            elif out_port:
                # Trigger ARP request if MAC unknown [cite: 476]
                self.send_arp_request(datapath, dst_ip, out_port)

    def send_arp_reply(self, datapath, arp_pkt, port):
        # Implementation for generating ARP Reply packet [cite: 476]
        pass # (Omitted for brevity, use standard Ryu packet construction)

    def send_arp_request(self, datapath, target_ip, out_port):
        # Implementation for generating ARP Request packet [cite: 476]
        pass