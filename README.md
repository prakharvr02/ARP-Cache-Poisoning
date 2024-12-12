# ARP Poisoning and Packet Sniffing Script

## Overview
This script performs **ARP poisoning** on a specified victim and gateway in a network, allowing the interception of packets between the two devices. Captured packets are saved in a `.pcap` file for further analysis.

It also restores ARP tables to their original state after the poisoning process is stopped, ensuring minimal disruption to the network.

## Features
- Performs ARP poisoning on a victim and gateway.
- Sniffs and saves packets related to the victim's IP in a `.pcap` file.
- Restores ARP tables after execution.

## Prerequisites
- **Python 3.x**
- **Scapy** library: Install it using:
  ```bash
  pip install scapy
