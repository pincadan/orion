import argparse
import socket
import concurrent.futures
from datetime import datetime
import sys
import ipaddress
from scapy.all import IP, TCP, UDP, sr1, ICMP
import os

# ANSI Color Codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

def banner():
    print(f"""{BLUE}
    ___  ____  ___  ___  ____  ___  _____  ____  ______  ____  
   / _ \/ _  \/ _ \/ _ \/ _  \/ _ \/ __  \/ __ \/ __  \/ _  \ 
  / , _/ |_| / |/ / , _/ |_| / , _/ / / / / / / / / / / |_| |
 /_/|_|\____/|___/_/|_|\____/_/|_/_/ /_/_/ /_/_/ /_/\____/  v1.0
{RESET}""")

def validate_ip(target):
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            sys.exit(f"{RED}Error: Invalid IP/Hostname{RESET}")

def tcp_scan(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return port, get_service(ip, port, timeout)
    except Exception:
        pass
    return None

def syn_scan(ip, port, timeout):
    if os.geteuid() != 0:
        sys.exit(f"{RED}SYN scan requires root privileges!{RESET}")
    packet = IP(dst=ip)/TCP(dport=port, flags="S")
    response = sr1(packet, timeout=timeout, verbose=0)
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        return port, "SYN-ACK Received"
    return None

def udp_scan(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"OrionProbe\x00", (ip, port))
            data, _ = s.recvfrom(1024)
            return port, "UDP Response"
    except (socket.timeout, socket.error):
        return None

def get_service(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.send(b"GET / HTTP/1.1\r\n\r\n")
            service = s.recv(1024).decode().strip()
            return service.split('\n')[0][:50]
    except Exception:
        return "Service unknown"

def scan_port(ip, port, scan_type, timeout):
    if scan_type == 'tcp':
        result = tcp_scan(ip, port, timeout)
    elif scan_type == 'syn':
        result = syn_scan(ip, port, timeout)
    elif scan_type == 'udp':
        result = udp_scan(ip, port, timeout)
    return result

def main():
    parser = argparse.ArgumentParser(description="OrionPortProbe - Network Port Scanner")
    parser.add_argument("target", help="Target IP or Hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 1-1000)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Threads")
    parser.add_argument("-T", "--timeout", type=float, default=1.0, help="Timeout (seconds)")
    parser.add_argument("-s", "--scan", choices=['tcp', 'syn', 'udp'], default='tcp', help="Scan type")
    args = parser.parse_args()

    banner()
    print(f"{YELLOW}Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")

    try:
        ip = validate_ip(args.target)
        start_port, end_port = map(int, args.ports.split('-'))
        ports = range(start_port, end_port + 1)
    except ValueError:
        sys.exit(f"{RED}Invalid port range!{RESET}")

    open_ports = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan_port, ip, port, args.scan, args.timeout): port for port in ports}
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        print(f"{GREEN}[+] Port {result[0]} open - {result[1]}{RESET}")
                except Exception as e:
                    print(f"{RED}Error scanning port {port}: {e}{RESET}")
    except KeyboardInterrupt:
        sys.exit(f"\n{RED}Scan aborted by user!{RESET}")

    print(f"\n{YELLOW}Scan completed. {len(open_ports)} ports open.{RESET}")

if __name__ == "__main__":
    main()