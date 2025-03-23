# Project Name: OrionPortProbe

Description:
OrionPortProbe is a sophisticated port scanner designed to explore open ports on target systems with speed and precision. 
It supports multiple scanning techniques, service detection, and an aesthetic command-line interface.


Features:

1. Multi-Scan Support: TCP Connect, SYN (Stealth), and UDP scans.

2. Service Detection: Fetch banners of open ports.

3. Threaded Scanning: Lightning-fast performance using concurrent threads.

4. User-Friendly: Colored output, progress tracking, and error handling.

5. Flexible Targeting: Scan single IPs, hostnames, or custom port ranges.

Usage:

# Install dependencies (Scapy for SYN scan)
pip install scapy

# Run with default settings (TCP scan)
sudo python3 orion_port_probe.py example.com -p 1-1000 -t 200

# SYN scan (requires root)
sudo python3 orion_port_probe.py 192.168.1.1 -s syn

# UDP scan
sudo python3 orion_port_probe.py target.com -s udp -p 53,67-69
