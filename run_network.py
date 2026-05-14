#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
import os

class CompanyNetworkTopo(Topo):
    def build(self):
        # Add hosts with their IP addresses and default gateways
        h1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
        ser = self.addHost('ser', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
        ext = self.addHost('ext', ip='192.168.1.2/24', defaultRoute='via 192.168.1.1')
        
        # Add switches (OVS kernel switches)
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')  # Router as OVS
        
        # Add links with properties (15 Mbps, 10ms delay)
        # Hosts to switch s1
        self.addLink(h1, s1, bw=15, delay='10ms', use_htb=True)
        self.addLink(h2, s1, bw=15, delay='10ms', use_htb=True)
        
        # Host to switch s2
        self.addLink(ser, s2, bw=15, delay='10ms', use_htb=True)
        
        # FIX: Link creation order strictly dictates Mininet port assignment.
        # This order ensures s3 ports match the controller mapping (1->s1, 2->s2, 3->ext)
        self.addLink(s1, s3, bw=15, delay='10ms', use_htb=True)
        self.addLink(s2, s3, bw=15, delay='10ms', use_htb=True)
        self.addLink(ext, s3, bw=15, delay='10ms', use_htb=True)

def run_network():
    """Run the network with remote controller"""
    topo = CompanyNetworkTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)
    
    # Add remote controller (default: 127.0.0.1:6653)
    net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6653)
    
    net.start()
    
    # Set MAC and IPs for router ports (s3)
    s3 = net.get('s3')
    
    # FIX: Mininet OpenFlow interfaces start at index 1 (eth1, eth2, eth3)
    s3.cmd('ip link set s3-eth1 address 00:00:00:00:01:01')
    s3.cmd('ip link set s3-eth2 address 00:00:00:00:01:02')
    s3.cmd('ip link set s3-eth3 address 00:00:00:00:01:03')
    
    # Set IP addresses for router interfaces (s3)
    s3.cmd('ifconfig s3-eth1 10.0.1.1 netmask 255.255.255.0 up')
    s3.cmd('ifconfig s3-eth2 10.0.2.1 netmask 255.255.255.0 up')
    s3.cmd('ifconfig s3-eth3 192.168.1.1 netmask 255.255.255.0 up')
    
    # Enable IP forwarding on the router
    s3.cmd('sysctl -w net.ipv4.ip_forward=1')
    
    print("\n*** Network is running. Type 'pingall' to test connectivity.")
    CLI(net)
    
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    
    # Import RemoteController
    from mininet.node import RemoteController
    
    run_network()