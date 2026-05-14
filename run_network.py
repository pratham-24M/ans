#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel

class CompanyNetworkTopo(Topo):
    def build(self):
        # Configure hosts with default gateways [cite: 300, 316, 317]
        h1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
        ser = self.addHost('ser', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
        ext = self.addHost('ext', ip='192.168.1.2/24', defaultRoute='via 192.168.1.1')
        
        # Explicitly set DPIDs so the controller recognizes the router (s3) [cite: 398]
        s1 = self.addSwitch('s1', dpid='1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', dpid='2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', dpid='3', protocols='OpenFlow13') 

        # Add links. The order here defines the port numbers on s3 [cite: 327]
        self.addLink(h1, s1, bw=15, delay='10ms')
        self.addLink(h2, s1, bw=15, delay='10ms')
        self.addLink(ser, s2, bw=15, delay='10ms')

        # Port mapping for s3: Port 1 -> s1, Port 2 -> s2, Port 3 -> ext [cite: 413, 419]
        self.addLink(s1, s3, bw=15, delay='10ms') # s3 port 1
        self.addLink(s2, s3, bw=15, delay='10ms') # s3 port 2
        self.addLink(ext, s3, bw=15, delay='10ms') # s3 port 3

def run_network():
    topo = CompanyNetworkTopo()
    net = Mininet(topo=topo, link=TCLink, controller=RemoteController)
    net.start()
    
    s3 = net.get('s3')
    # Set the virtual MAC and IP addresses for the router interfaces [cite: 325, 411, 413, 419]
    s3.cmd('ip link set s3-eth1 address 00:00:00:00:01:01')
    s3.cmd('ip link set s3-eth2 address 00:00:00:00:01:02')
    s3.cmd('ip link set s3-eth3 address 00:00:00:00:01:03')
    
    s3.cmd('ifconfig s3-eth1 10.0.1.1 netmask 255.255.255.0 up')
    s3.cmd('ifconfig s3-eth2 10.0.2.1 netmask 255.255.255.0 up')
    s3.cmd('ifconfig s3-eth3 192.168.1.1 netmask 255.255.255.0 up')
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_network()