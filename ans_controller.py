#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, icmp, tcp, udp
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology import event
from ryu.topology.api import get_switch, get_link

class SwitchRouterController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SwitchRouterController, self).__init__(*args, **kwargs)
        
        self.mac_to_port = {}
        self.router_ports = [1, 2, 3] 
        
        self.port_to_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }
        
        self.port_to_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }
        
        self.subnet_to_port = {
            "10.0.1.0": 1,
            "10.0.2.0": 2,
            "192.168.1.0": 3
        }
        
        self.subnet_masks = {
            "10.0.1.0": "255.255.255.0",
            "10.0.2.0": "255.255.255.0",
            "192.168.1.0": "255.255.255.0"
        }
        
        self.arp_table = {}
        self.is_router = {}
        self.switches = {}
        
    def get_subnet(self, ip_str):
        ip_parts = ip_str.split('.')
        if ip_str.startswith('10.0.1'):
            return "10.0.1.0"
        elif ip_str.startswith('10.0.2'):
            return "10.0.2.0"
        elif ip_str.startswith('192.168.1'):
            return "192.168.1.0"
        return None
    
    def is_internal_ip(self, ip_str):
        return ip_str.startswith('10.0.1') or ip_str.startswith('10.0.2')
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.switches[datapath.id] = datapath
        
        if datapath.id == 3: 
            self.is_router[datapath.id] = True
        else:
            self.is_router[datapath.id] = False
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        
        if datapath.id in self.is_router and self.is_router[datapath.id]:
            self.handle_router_packet(datapath, pkt, eth_pkt, in_port, msg)
        else:
            self.handle_switch_packet(datapath, pkt, eth_pkt, in_port, dst_mac, src_mac, msg)
    
    def handle_switch_packet(self, datapath, pkt, eth_pkt, in_port, dst_mac, src_mac, msg):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
        
        if out_port != ofproto.OFPP_FLOOD and dst_mac in self.mac_to_port[dpid]:
            match = parser.OFPMatch(eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                return
        
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions)
        datapath.send_msg(out)
    
    def handle_router_packet(self, datapath, pkt, eth_pkt, in_port, msg):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.handle_arp(datapath, arp_pkt, in_port, msg)
            return
        
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.handle_ipv4(datapath, ip_pkt, in_port, msg, pkt)
            return
        
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions)
        datapath.send_msg(out)
    
    def handle_arp(self, datapath, arp_pkt, in_port, msg):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # FIX: The router MUST always learn the MAC address, even if the ARP is destined for it
        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
        target_ip = arp_pkt.dst_ip
        
        if target_ip in self.port_to_ip.values():
            # Only generate a reply if it's an explicit request
            if arp_pkt.opcode == arp.ARP_REQUEST:
                for port, ip in self.port_to_ip.items():
                    if ip == target_ip and port == in_port:
                        src_mac = self.port_to_mac[port]
                        
                        eth = ethernet.ethernet(dst=arp_pkt.src_mac,
                                               src=src_mac,
                                               ethertype=ether_types.ETH_TYPE_ARP)
                        # FIX: Ryu requires 'opcode' instead of 'op'
                        arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                                           src_mac=src_mac,
                                           src_ip=target_ip,
                                           dst_mac=arp_pkt.src_mac,
                                           dst_ip=arp_pkt.src_ip)
                        
                        pkt_out = packet.Packet()
                        pkt_out.add_protocol(eth)
                        pkt_out.add_protocol(arp_reply)
                        pkt_out.serialize()
                        
                        actions = [parser.OFPActionOutput(in_port)]
                        out = parser.OFPPacketOut(datapath=datapath,
                                                 buffer_id=ofproto.OFP_NO_BUFFER,
                                                 in_port=ofproto.OFPP_CONTROLLER,
                                                 actions=actions,
                                                 data=pkt_out.data)
                        datapath.send_msg(out)
                        break
            return
        else:
            self.route_packet(datapath, None, arp_pkt, in_port, msg, is_arp=True)
    
    def handle_ipv4(self, datapath, ip_pkt, in_port, msg, original_pkt):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        
        is_from_ext = src_ip == "192.168.1.2"
        is_dst_internal = self.is_internal_ip(dst_ip)
        
        icmp_pkt = original_pkt.get_protocol(icmp.icmp)
        tcp_pkt = original_pkt.get_protocol(tcp.tcp)
        udp_pkt = original_pkt.get_protocol(udp.udp)
        
        # FIX: Only block inbound ping requests. Blocking replies breaks outbound pings.
        if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST and is_from_ext and is_dst_internal:
            return
        
        # FIX: Explicitly target TCP/UDP protocols for isolation
        if tcp_pkt or udp_pkt:
            if (is_from_ext and dst_ip == "10.0.2.2") or (src_ip == "10.0.2.2" and dst_ip == "192.168.1.2"):
                return
        
        if dst_ip in self.port_to_ip.values():
            self.handle_packet_to_router(datapath, ip_pkt, icmp_pkt, in_port, msg, original_pkt)
            return
        
        self.route_packet(datapath, ip_pkt, None, in_port, msg, is_arp=False)
    
    def handle_packet_to_router(self, datapath, ip_pkt, icmp_pkt, in_port, msg, original_pkt):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        dst_ip = ip_pkt.dst
        src_ip = ip_pkt.src
        
        if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
            reply_port = None
            for port, ip in self.port_to_ip.items():
                if ip == dst_ip:
                    reply_port = port
                    break
            
            if reply_port:
                src_mac = self.port_to_mac[reply_port]
                dst_mac = self.arp_table.get(src_ip, "ff:ff:ff:ff:ff:ff")
                
                eth = ethernet.ethernet(dst=dst_mac,
                                       src=src_mac,
                                       ethertype=ether_types.ETH_TYPE_IP)
                
                # FIX: Ryu requires 'type_' instead of 'type'
                icmp_reply = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                      code=0,
                                      csum=0,
                                      data=icmp_pkt.data)
                
                ip_reply = ipv4.ipv4(dst=src_ip,
                                    src=dst_ip,
                                    proto=ip_pkt.proto,
                                    ttl=64)
                
                pkt_out = packet.Packet()
                pkt_out.add_protocol(eth)
                pkt_out.add_protocol(ip_reply)
                pkt_out.add_protocol(icmp_reply)
                pkt_out.serialize()
                
                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath,
                                         buffer_id=ofproto.OFP_NO_BUFFER,
                                         in_port=ofproto.OFPP_CONTROLLER,
                                         actions=actions,
                                         data=pkt_out.data)
                datapath.send_msg(out)
    
    def route_packet(self, datapath, ip_pkt, arp_pkt, in_port, msg, is_arp):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        if is_arp:
            target_ip = arp_pkt.dst_ip
            target_subnet = self.get_subnet(target_ip)
            
            if target_subnet and target_subnet in self.subnet_to_port:
                out_port = self.subnet_to_port[target_subnet]
                if target_ip not in self.arp_table:
                    actions = [parser.OFPActionOutput(out_port)]
                    out = parser.OFPPacketOut(datapath=datapath,
                                             buffer_id=msg.buffer_id,
                                             in_port=in_port,
                                             actions=actions)
                    datapath.send_msg(out)
        else:
            dst_ip = ip_pkt.dst
            src_ip = ip_pkt.src
            dst_subnet = self.get_subnet(dst_ip)
            
            if dst_subnet and dst_subnet in self.subnet_to_port:
                out_port = self.subnet_to_port[dst_subnet]
                router_ip = self.port_to_ip[out_port]
                router_mac = self.port_to_mac[out_port]
                
                dst_mac = self.arp_table.get(dst_ip)
                
                if dst_mac:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                           ipv4_dst=dst_ip)
                    actions = [parser.OFPActionSetField(eth_src=router_mac),
                              parser.OFPActionSetField(eth_dst=dst_mac),
                              parser.OFPActionOutput(out_port)]
                    
                    actions.append(parser.OFPActionSetField(ipv4_ttl=ip_pkt.ttl - 1))
                    
                    self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                    
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        actions = [parser.OFPActionOutput(out_port)]
                        out = parser.OFPPacketOut(datapath=datapath,
                                                 buffer_id=msg.buffer_id,
                                                 in_port=in_port,
                                                 actions=actions)
                        datapath.send_msg(out)
                    return
                else:
                    self.send_arp_request(datapath, dst_ip, out_port)
            
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=datapath,
                                     buffer_id=msg.buffer_id,
                                     in_port=in_port,
                                     actions=actions)
            datapath.send_msg(out)
    
    def send_arp_request(self, datapath, target_ip, out_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        router_ip = self.port_to_ip[out_port]
        router_mac = self.port_to_mac[out_port]
        
        eth = ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff",
                               src=router_mac,
                               ethertype=ether_types.ETH_TYPE_ARP)
        
        # FIX: Ryu requires 'opcode' instead of 'op'
        arp_req = arp.arp(opcode=arp.ARP_REQUEST,
                         src_mac=router_mac,
                         src_ip=router_ip,
                         dst_mac="00:00:00:00:00:00",
                         dst_ip=target_ip)
        
        pkt_out = packet.Packet()
        pkt_out.add_protocol(eth)
        pkt_out.add_protocol(arp_req)
        pkt_out.serialize()
        
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                 buffer_id=ofproto.OFP_NO_BUFFER,
                                 in_port=ofproto.OFPP_CONTROLLER,
                                 actions=actions,
                                 data=pkt_out.data)
        datapath.send_msg(out)