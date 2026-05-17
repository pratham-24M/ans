"""
 Copyright (c) 2026 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
SWITCH = {
    "1": 1,
    "2": 2,
    "3": 3
}

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

import ipaddress


class LearningSwitch(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # mac learning table
        self.mac_to_port = {}

        # router ips
        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }

        # router macs
        self.router_macs = {
            "10.0.1.1": "00:00:00:00:01:01",
            "10.0.2.1": "00:00:00:00:01:02",
            "192.168.1.1": "00:00:00:00:01:03"
        }

        # routing table
        self.routing_table = {
            "10.0.1.0/24": {
                "out_port": 1,
                "src_mac": "00:00:00:00:01:01"
            },

            "10.0.2.0/24": {
                "out_port": 2,
                "src_mac": "00:00:00:00:01:02"
            },

            "192.168.1.0/24": {
                "out_port": 3,
                "src_mac": "00:00:00:00:01:03"
            }
        }

        # arp cache
        self.arp_table = {}

        # packets waiting for arp reply
        self.pending_packets = {}

        self.router_dp = None
            
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if datapath.id == SWITCH["3"]:
            self.router_dp = datapath

        # default rule
        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(datapath, 0, match, actions)
        
    # clear stale entries when mininet restarts
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handle(self, ev):
        
        datapath = ev.datapath
        if ev.state == DEAD_DISPATCHER:
            dpid = datapath.id

            if dpid in self.mac_to_port:
                del self.mac_to_port[dpid]
                self.logger.info("switch %s disconnected - mac table cleared", dpid)

            if dpid == SWITCH["3"]:
                self.arp_table = {}
                self.pending_packets = {}
                self.router_dp = None
                self.logger.info("router disconnected - arp table and pending packets cleared")

    # add flow entry
    def add_flow(self, datapath, priority, match, actions):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)

        # ignore lldp
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # arp stuff
        arp_pkt = pkt.get_protocol(arp.arp)

        if arp_pkt:

            self.learn_arp(arp_pkt.src_ip, src)

            # got arp reply
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.send_waiting_packets(arp_pkt.src_ip)

            # arp request for router
            if arp_pkt.opcode == arp.ARP_REQUEST:

                target_ip = arp_pkt.dst_ip

                if target_ip in self.router_macs:

                    router_mac = self.router_macs[target_ip]

                    reply = packet.Packet()

                    reply.add_protocol(
                        ethernet.ethernet(
                            ethertype=ether_types.ETH_TYPE_ARP,
                            src=router_mac,
                            dst=src
                        )
                    )

                    reply.add_protocol(
                        arp.arp(
                            opcode=arp.ARP_REPLY,
                            src_mac=router_mac,
                            src_ip=target_ip,
                            dst_mac=src,
                            dst_ip=arp_pkt.src_ip
                        )
                    )

                    reply.serialize()

                    self.send_packet_out(
                        datapath,
                        ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER,
                        [parser.OFPActionOutput(in_port)],
                        reply.data
                    )

                    return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # switch logic
        if dpid in [SWITCH["1"], SWITCH["2"]]:

            out_port = self.mac_to_port[dpid].get(dst)

            if out_port == None:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src,
                eth_dst=dst
            )

            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, 1, match, actions)

            data = None

            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            self.send_packet_out(
                datapath,
                msg.buffer_id,
                in_port,
                actions,
                data
            )

            return

        # router logic
        if dpid == SWITCH["3"]:

            if ip_pkt == None:
                return

            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            self.learn_arp(src_ip, src)

            # Extract protocols for firewall/isolation rules
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

            # ext network isolation (Only drop ICMP to allow TCP/UDP connection tests)
            ext_net = ipaddress.ip_network("192.168.1.0/24")
            src_ext = ipaddress.ip_address(src_ip) in ext_net
            dst_ext = ipaddress.ip_address(dst_ip) in ext_net

            if src_ext != dst_ext and icmp_pkt != None:
                return

            # ping handling
            if icmp_pkt != None:

                if icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:

                    own_ip = self.port_to_own_ip.get(in_port)

                    # ping gateway
                    if dst_ip == own_ip:

                        router_mac = self.router_macs[dst_ip]

                        reply = packet.Packet()

                        reply.add_protocol(
                            ethernet.ethernet(
                                ethertype=ether_types.ETH_TYPE_IP,
                                src=router_mac,
                                dst=src
                            )
                        )

                        reply.add_protocol(
                            ipv4.ipv4(
                                src=dst_ip,
                                dst=src_ip,
                                proto=1
                            )
                        )

                        reply.add_protocol(
                            icmp.icmp(
                                type_=icmp.ICMP_ECHO_REPLY,
                                code=0,
                                csum=0,
                                data=icmp_pkt.data
                            )
                        )

                        reply.serialize()

                        self.send_packet_out(
                            datapath,
                            ofproto.OFP_NO_BUFFER,
                            ofproto.OFPP_CONTROLLER,
                            [parser.OFPActionOutput(in_port)],
                            reply.data
                        )

                        return

                    # Drop pings to other gateways
                    elif dst_ip in self.router_macs:
                        return

            # firewall (No TCP/UDP connection btw. ser & ext)
            SER_IP = "10.0.2.2"

            if tcp_pkt is not None or udp_pkt is not None:
                if (src_ext and dst_ip == SER_IP) or (dst_ext and src_ip == SER_IP):
                    self.logger.info("Packet drop");
                    return;

            # check routing table
            out_port = None
            srcMac = None

            for network, info in self.routing_table.items():

                if ipaddress.ip_address(dst_ip) in ipaddress.ip_network(network):

                    out_port = info["out_port"]
                    srcMac = info["src_mac"]

                    break

            if out_port == None:
                return

            # arp not known
            if dst_ip not in self.arp_table:

                if dst_ip not in self.pending_packets:

                    self.pending_packets[dst_ip] = []

                    self.send_arp_request(
                        datapath,
                        out_port,
                        self.port_to_own_ip[out_port],
                        dst_ip
                    )

                raw = None

                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    raw = msg.data

                if raw != None:
                    self.pending_packets[dst_ip].append((in_port, raw))

                return

            dstMac = self.arp_table[dst_ip]

            actions = [
                parser.OFPActionSetField(eth_src=srcMac),
                parser.OFPActionSetField(eth_dst=dstMac),
                parser.OFPActionDecNwTtl(),
                parser.OFPActionOutput(out_port)
            ]

            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=dst_ip
            )

            self.add_flow(datapath, 10, match, actions)

            data = None

            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            self.send_packet_out(
                datapath,
                msg.buffer_id,
                in_port,
                actions,
                data
            )

    # learn arp
    def learn_arp(self, ip, mac):

        if ip not in self.router_macs:

            if self.arp_table.get(ip) != mac:
                self.logger.info("learned arp %s: %s", ip, mac)

            self.arp_table[ip] = mac

    # send arp request
    def send_arp_request(self, datapath, out_port, src_ip, dst_ip):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        src_mac = self.router_macs[src_ip]

        pkt = packet.Packet()

        pkt.add_protocol(
            ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_ARP,
                src=src_mac,
                dst="ff:ff:ff:ff:ff:ff"
            )
        )

        pkt.add_protocol(
            arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac=src_mac,
                src_ip=src_ip,
                dst_mac="00:00:00:00:00:00",
                dst_ip=dst_ip
            )
        )

        pkt.serialize()

        self.send_packet_out(
            datapath,
            ofproto.OFP_NO_BUFFER,
            ofproto.OFPP_CONTROLLER,
            [parser.OFPActionOutput(out_port)],
            pkt.data
        )

        self.logger.info("sending arp for %s", dst_ip)

    # send buffered packets
    def send_waiting_packets(self, dst_ip):

        if dst_ip not in self.pending_packets:
            return

        if self.router_dp == None:
            return

        if dst_ip not in self.arp_table:
            return

        datapath = self.router_dp

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        out_port = None
        srcMac = None

        for network, info in self.routing_table.items():

            if ipaddress.ip_address(dst_ip) in ipaddress.ip_network(network):

                out_port = info["out_port"]
                srcMac = info["src_mac"]

                break

        dstMac = self.arp_table[dst_ip]

        actions = [
            parser.OFPActionSetField(eth_src=srcMac),
            parser.OFPActionSetField(eth_dst=dstMac),
            parser.OFPActionDecNwTtl(),
            parser.OFPActionOutput(out_port)
        ]

        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=dst_ip
        )

        self.add_flow(datapath, 10, match, actions)

        for saved_port, saved_data in self.pending_packets[dst_ip]:

            self.send_packet_out(
                datapath,
                ofproto.OFP_NO_BUFFER,
                saved_port,
                actions,
                saved_data
            )

        del self.pending_packets[dst_ip]

    def send_packet_out(self, datapath, buffer_id, in_port, actions, data):

        parser = datapath.ofproto_parser

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)
