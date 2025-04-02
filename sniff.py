import scapy.all as scapy
import ipaddress
import os
import json
import re
import time
import threading
from collections import defaultdict

class MitreAttackData:
    def __init__(self):
        self.techniques = self.load_mitre_techniques()
        
    def load_mitre_techniques(self):
        """Load MITRE ATT&CK techniques from JSON file"""
        # Default techniques in case file doesn't exist
        default_techniques = {
            "T1046": "Network Service Scanning",
            "T1049": "System Network Connections Discovery",
            "T1055": "Process Injection",
            "T1057": "Process Discovery",
            "T1070": "Indicator Removal on Host",
            "T1071": "Application Layer Protocol",
            "T1072": "Software Deployment Tools",
            "T1082": "System Information Discovery",
            "T1083": "File and Directory Discovery",
            "T1090": "Proxy",
            "T1091": "Replication Through Removable Media",
            "T1095": "Non-Application Layer Protocol",
            "T1110": "Brute Force",
            "T1189": "Drive-by Compromise",
            "T1190": "Exploit Public-Facing Application",
            "T1566": "Phishing",
            "T1590": "Gather Victim Network Information"
        }
        
        try:
            if os.path.exists("mitre_techniques.json"):
                with open("mitre_techniques.json", 'r') as f:
                    techniques = json.load(f)
                print(f"Loaded {len(techniques)} MITRE ATT&CK techniques from mitre_techniques.json")
            else:
                techniques = default_techniques
                # Create the file with default values
                with open("mitre_techniques.json", 'w') as f:
                    json.dump(default_techniques, f, indent=2)
                print("Created new mitre_techniques.json file with default techniques")
        except Exception as e:
            print(f"Error loading MITRE techniques: {e}")
            techniques = default_techniques
        
        return techniques
        
    def load(self):
        return self.techniques
        
    def get_technique_name(self, technique_id):
        return self.techniques.get(technique_id, "Unknown Technique")

class NetworkMonitor:
    def __init__(self, interface="en0", whitelist_file="whitelist.txt", known_devices_file="known_devices.json"):
        self.interface = interface
        self.whitelist_file = whitelist_file
        self.known_devices_file = known_devices_file
        self.attck_data = MitreAttackData().load()
        self.known_devices = self.load_known_devices()
        self.scan_threshold = 10  # Number of unique ports in short time to trigger scan alert
        self.port_scan_tracker = defaultdict(list)
        self.dns_request_tracker = defaultdict(list)
        self.auth_failure_tracker = defaultdict(int)
        self.last_cleanup = time.time()
        self.whitelisted_ips = self.load_whitelisted_ips()
        self.scan_alert_cooldown = {}  # Track when we last alerted about an IP
        self.network_devices = {}  # Store discovered devices
        self.last_network_scan = 0  # Track when we last scanned the network
        
    def load_known_devices(self):
        # Default devices in case file doesn't exist
        default_devices = {
            "192.168.50.1": "a0:36:bc:61:85:20",  # Router
            "192.168.50.157": "9c:3e:53:8b:3f:60"  # Your MacBook's actual MAC
        }
        
        try:
            if os.path.exists(self.known_devices_file):
                with open(self.known_devices_file, 'r') as f:
                    devices = json.load(f)
                print(f"Loaded {len(devices)} devices from {self.known_devices_file}")
            else:
                devices = default_devices
                # Create the file with default values
                self.save_known_devices(devices)
                print(f"Created new known devices file: {self.known_devices_file}")
        except Exception as e:
            print(f"Error loading known devices: {e}")
            devices = default_devices
        
        # Standardize all MAC addresses to lowercase for comparison
        return {ip: mac.lower() for ip, mac in devices.items()}
    
    def save_known_devices(self, devices):
        """Save known devices to file"""
        try:
            with open(self.known_devices_file, 'w') as f:
                json.dump(devices, f, indent=4)
            print(f"Saved {len(devices)} devices to {self.known_devices_file}")
        except Exception as e:
            print(f"Error saving known devices: {e}")
    
    def add_known_device(self, ip, mac):
        """Add a new device to known devices"""
        self.known_devices[ip] = mac.lower()
        # Convert back to original case for saving to be more human-readable
        devices_to_save = {ip: mac for ip, mac in self.known_devices.items()}
        self.save_known_devices(devices_to_save)
    
    def load_whitelisted_ips(self):
        """Load whitelisted IPs from file"""
        # Default whitelist in case file doesn't exist
        default_whitelist = [
            "3.161.193.40",   # Identified scanner
            "34.107.199.61"   # Identified scanner
        ]
        
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r') as f:
                    whitelist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                print(f"Loaded {len(whitelist)} IPs from whitelist: {self.whitelist_file}")
            else:
                whitelist = default_whitelist
                # Create the file with default values
                self.save_whitelist(whitelist)
                print(f"Created new whitelist file: {self.whitelist_file}")
        except Exception as e:
            print(f"Error loading whitelist: {e}")
            whitelist = default_whitelist
            
        return whitelist
    
    def save_whitelist(self, whitelist):
        """Save whitelist to file"""
        try:
            with open(self.whitelist_file, 'w') as f:
                f.write("# Network Security Tool - Whitelisted IPs\n")
                f.write("# These IPs are allowed to perform scanning and will not trigger alerts\n")
                f.write("# One IP per line, lines starting with # are comments\n\n")
                for ip in whitelist:
                    f.write(f"{ip}\n")
            print(f"Saved {len(whitelist)} IPs to whitelist: {self.whitelist_file}")
        except Exception as e:
            print(f"Error saving whitelist: {e}")
    
    def add_to_whitelist(self, ip):
        """Add an IP to the whitelist"""
        if ip not in self.whitelisted_ips:
            self.whitelisted_ips.append(ip)
            self.save_whitelist(self.whitelisted_ips)
            print(f"Added {ip} to whitelist")
        
    def cleanup_trackers(self, current_time, expiry=60):
        """Clean up tracking data older than expiry seconds"""
        if current_time - self.last_cleanup > 30:  # Only cleanup every 30 seconds
            try:
                # Clean port scan tracker
                for ip in list(self.port_scan_tracker.keys()):
                    # Handle special keys for flood detection
                    if ip.startswith("icmp_flood_") or ip.startswith("syn_flood_"):
                        # For flood trackers that contain timestamps
                        self.port_scan_tracker[ip] = [
                            t for t in self.port_scan_tracker[ip] 
                            if isinstance(t, float) and current_time - t < expiry
                        ]
                    else:
                        # For regular trackers that contain tuples
                        self.port_scan_tracker[ip] = [
                            x for x in self.port_scan_tracker[ip] 
                            if isinstance(x, tuple) and len(x) >= 2 and isinstance(x[1], float) and current_time - x[1] < expiry
                        ]
                    
                    if not self.port_scan_tracker[ip]:
                        del self.port_scan_tracker[ip]
                
                # Clean DNS tracker
                for domain in list(self.dns_request_tracker.keys()):
                    self.dns_request_tracker[domain] = [
                        x for x in self.dns_request_tracker[domain] 
                        if isinstance(x, tuple) and len(x) >= 2 and isinstance(x[1], float) and current_time - x[1] < expiry
                    ]
                    if not self.dns_request_tracker[domain]:
                        del self.dns_request_tracker[domain]
                
                # Reset auth failure counters periodically
                if current_time - self.last_cleanup > 300:  # Reset every 5 minutes
                    self.auth_failure_tracker = defaultdict(int)
                
                # Clean up scan alert cooldown
                for ip in list(self.scan_alert_cooldown.keys()):
                    if current_time - self.scan_alert_cooldown[ip] > 300:  # 5 minutes cooldown
                        del self.scan_alert_cooldown[ip]
                
            except Exception as e:
                print(f"Error during tracker cleanup: {e}")
            
            self.last_cleanup = current_time
        
    def discover_network_devices(self):
        """Scan the network to discover all devices"""
        print("Scanning network for devices...")
        
        # Get local IP to determine network range
        local_ip = self.get_local_ip()
        if not local_ip:
            print("Could not determine local IP address")
            return
            
        # Determine network range (assuming /24 subnet)
        ip_parts = local_ip.split('.')
        network_prefix = '.'.join(ip_parts[0:3])
        network_range = f"{network_prefix}.0/24"
        
        try:
            # Create ARP request packets for all IPs in the range
            arp_request = scapy.ARP(pdst=network_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            # Send packets and receive responses
            answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
            
            # Process discovered devices
            discovered_devices = {}
            for sent, received in answered_list:
                ip = received.psrc
                mac = received.hwsrc.lower()
                discovered_devices[ip] = mac
                
                # Add to known devices if not already there
                if ip not in self.known_devices:
                    self.add_known_device(ip, mac)
                    
            self.network_devices = discovered_devices
            print(f"Discovered {len(discovered_devices)} devices on the network")
            
            # Print discovered devices
            print("IP Address\t\tMAC Address")
            print("-" * 40)
            for ip, mac in discovered_devices.items():
                print(f"{ip}\t\t{mac}")
                
        except Exception as e:
            print(f"Error during network scan: {e}")
            
        self.last_network_scan = time.time()
    
    def get_local_ip(self):
        """Get the local IP address of the interface"""
        try:
            # Create a temporary socket to determine local IP
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't need to be reachable, just used to determine interface IP
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            print(f"Error getting local IP: {e}")
            return None
    
    def periodic_network_scan(self):
        """Periodically scan the network for new devices"""
        while True:
            # Scan every 5 minutes
            if time.time() - self.last_network_scan > 300:
                self.discover_network_devices()
            time.sleep(60)  # Check every minute
    
    def start_sniffing(self):
        print(f"Starting packet sniffer on interface '{self.interface}'...")
        print("Monitoring for MITRE ATT&CK techniques:")
        for tid, name in self.attck_data.items():
            print(f"  - {tid}: {name}")
        print("------------------------------------------------------")
        print(f"Whitelisted IPs (allowed to scan): {', '.join(self.whitelisted_ips)}")
        print(f"Known devices: {len(self.known_devices)} registered")
        print("------------------------------------------------------")
        
        # Start network discovery in a separate thread
        discovery_thread = threading.Thread(target=self.periodic_network_scan, daemon=True)
        discovery_thread.start()
        
        # Initial network scan
        self.discover_network_devices()
        
        try:
            # Use store=False to process packets in real-time without storing them
            sniffed_packets = scapy.sniff(iface=self.interface, prn=self.analyze_packet, store=False)
        except Exception as e:
            print(f"Error while sniffing: {e}")
            
    def analyze_packet(self, packet):
        current_time = time.time()
        self.cleanup_trackers(current_time)
        
        # ARP Analysis (T1046, T1070)
        if packet.haslayer(scapy.ARP):
            self.analyze_arp_packet(packet)
            
        # DNS Analysis (T1071, T1189, T1566)
        elif packet.haslayer(scapy.DNSQR):
            self.analyze_dns_packet(packet)
            
        # TCP Analysis (T1046, T1049, T1071, T1090, T1110)
        elif packet.haslayer(scapy.TCP):
            self.analyze_tcp_packet(packet)
            
        # UDP Analysis (T1046, T1071)
        elif packet.haslayer(scapy.UDP):
            self.analyze_udp_packet(packet)
            
        # ICMP Analysis (T1049, T1095, T1590)
        elif packet.haslayer(scapy.ICMP):
            self.analyze_icmp_packet(packet)
    
    def analyze_arp_packet(self, packet):
        src_ip = packet[scapy.ARP].psrc
        dst_ip = packet[scapy.ARP].pdst
        src_mac = packet[scapy.ARP].hwsrc.lower()  # Convert to lowercase for comparison
        
        # Skip incomplete ARP entries and broadcast addresses
        if src_ip == "0.0.0.0" or dst_ip == "0.0.0.0" or src_mac == "00:00:00:00:00:00":
            return
            
        # Check for ARP spoofing (T1070) only if the source IP is in our known_devices
        if src_ip in self.known_devices and self.known_devices[src_ip] != src_mac:
            self.alert("T1070", f"ARP Spoofing Detected! Source IP: {src_ip}, Destination IP: {dst_ip}, " 
                              f"Claimed MAC: {src_mac}, Expected MAC: {self.known_devices[src_ip]}")
            # Also alert for potential Man-in-the-Middle (T1557)
            self.alert("T1557", f"Potential Man-in-the-Middle Attack via ARP Spoofing from {src_ip}")
        
        # Check for network scanning via ARP (T1046)
        if packet[scapy.ARP].op == 1:  # ARP request
            # Skip whitelisted IPs
            if src_ip in self.whitelisted_ips:
                return
                
            # Track ARP requests from the same source
            self.port_scan_tracker[src_ip].append(("ARP", time.time()))
            if len(self.port_scan_tracker[src_ip]) > 20:
                unique_targets = set([x[0] for x in self.port_scan_tracker[src_ip] if x[0] == "ARP"])
                if len(unique_targets) > 15:
                    # Check cooldown before alerting
                    if src_ip not in self.scan_alert_cooldown or time.time() - self.scan_alert_cooldown[src_ip] > 300:
                        self.alert("T1046", f"Network Scanning via ARP from {src_ip}")
                        self.scan_alert_cooldown[src_ip] = time.time()
                    self.port_scan_tracker[src_ip] = []  # Reset after alert
        
        # Check for ARP cache poisoning (T1557)
        if packet[scapy.ARP].op == 2:  # ARP reply
            # Check if this is an unsolicited ARP reply
            if dst_ip == "0.0.0.0" or dst_ip == "255.255.255.255":
                self.alert("T1557", f"Potential ARP Cache Poisoning from {src_ip} claiming to be {dst_ip}")
    
    def analyze_dns_packet(self, packet):
        if packet.haslayer(scapy.DNS):
            qname = packet[scapy.DNSQR].qname.decode('utf-8').lower()
            
            # Track DNS queries
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                self.dns_request_tracker[qname].append((src_ip, time.time()))
            
            # Check for C2 domains or suspicious DNS patterns (T1071)
            suspicious_patterns = [
                r'\.no-ip\.',
                r'\.dyndns\.',
                r'[a-zA-Z0-9]{20,}\.com',  # Very long random-looking subdomain
                r'\/.[a-f0-9]{32}\.'  # MD5 hash in domain
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, qname):
                    self.alert("T1071", f"Suspicious DNS Query: {qname}")
            
            # Check for phishing domains (T1566)
            phishing_keywords = ['login', 'secure', 'account', 'verify', 'paypal', 'amazon', 'microsoft']
            typosquatting_domains = ['amaz0n', 'g00gle', 'micros0ft', 'faceb00k']
            
            for keyword in phishing_keywords:
                if keyword in qname:
                    for typo in typosquatting_domains:
                        if typo in qname:
                            self.alert("T1566", f"Potential Phishing Domain Detected: {qname}")
            
            # Check for DNS exfiltration (T1048)
            if len(qname) > 50:  # Unusually long domain name
                parts = qname.split('.')
                for part in parts:
                    if len(part) > 30:  # Very long subdomain part
                        self.alert("T1048", f"Potential DNS Data Exfiltration: {qname}")
                        break
            
            # Check for domain generation algorithms (T1568)
            if re.match(r'^[a-z0-9]{10,20}\.(com|net|org|info)$', qname):
                self.alert("T1568", f"Potential DGA Domain: {qname}")
    
    def analyze_tcp_packet(self, packet):
        if not packet.haslayer(scapy.IP):
            return
            
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
        
        # Skip whitelisted IPs for port scanning detection
        if src_ip in self.whitelisted_ips:
            return
            
        # Port scanning detection (T1046)
        self.port_scan_tracker[src_ip].append((dst_port, time.time()))
        
        # Check for port scanning
        recent_ports = [p[0] for p in self.port_scan_tracker[src_ip] 
                      if time.time() - p[1] < 5]  # Ports in last 5 seconds
        
        if len(set(recent_ports)) > self.scan_threshold:
            # Check cooldown before alerting
            if src_ip not in self.scan_alert_cooldown or time.time() - self.scan_alert_cooldown[src_ip] > 300:
                self.alert("T1046", f"Port Scanning Detected from {src_ip}, {len(set(recent_ports))} unique ports")
                self.scan_alert_cooldown[src_ip] = time.time()
            self.port_scan_tracker[src_ip] = []  # Reset after alert
        
        # Common port-based detection
        
        # SSH Traffic (T1110, T1071)
        if dst_port == 22 or src_port == 22:
            # Look for authentication failures in SSH packets
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                if b"authentication failure" in payload or b"Failed password" in payload:
                    self.auth_failure_tracker[src_ip] += 1
                    if self.auth_failure_tracker[src_ip] > 5:
                        self.alert("T1110", f"SSH Brute Force Attempt from {src_ip}")
        
        # HTTP/HTTPS Traffic (T1071, T1190)
        elif dst_port == 80 or dst_port == 443 or src_port == 80 or src_port == 443:
            if packet.haslayer(scapy.Raw):
                payload = str(packet[scapy.Raw].load)
                
                # Check for web attacks
                if "SELECT" in payload and "FROM" in payload and ("UNION" in payload or "OR 1=1" in payload):
                    self.alert("T1190", f"SQL Injection Attempt Detected from {src_ip}")
                elif "/etc/passwd" in payload or "../../../" in payload:
                    self.alert("T1190", f"Directory Traversal Attack Detected from {src_ip}")
                elif "<script>" in payload or "eval(" in payload or "document.cookie" in payload:
                    self.alert("T1190", f"XSS Attack Detected from {src_ip}")
                
                # Check for command injection (T1059)
                if any(cmd in payload for cmd in [";ls", "|ls", ";cat", "|cat", ";rm", "|rm", ";wget", "|wget"]):
                    self.alert("T1059", f"Command Injection Attempt from {src_ip}")
                
                # Check for credential harvesting (T1213)
                if "password=" in payload or "passwd=" in payload or "credentials=" in payload:
                    self.alert("T1213", f"Potential Credential Harvesting from {src_ip}")
                
                # Check for supply chain attacks (T1195)
                if "package.json" in payload or "npm install" in payload or "pip install" in payload:
                    self.alert("T1195", f"Potential Supply Chain Attack Vector from {src_ip}")
        
        # RDP Traffic (T1021, T1133)
        elif dst_port == 3389 or src_port == 3389:
            if src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172."):
                self.alert("T1021", f"Internal RDP Connection from {src_ip} to {dst_ip}")
            else:
                self.alert("T1133", f"External Remote Access (RDP) from {src_ip} to {dst_ip}")
        
        # Database Traffic (T1190)
        elif dst_port in [1433, 3306, 5432]:  # SQL Server, MySQL, PostgreSQL
            if not (src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172.")):
                self.alert("T1190", f"External Database Connection Attempt to {dst_ip}:{dst_port}")
        
        # VNC Traffic (T1021)
        elif dst_port in [5900, 5901, 5902, 5903]:
            self.alert("T1021", f"VNC Remote Access from {src_ip} to {dst_ip}")
        
        # TeamViewer Traffic (T1219)
        elif dst_port == 5938:
            self.alert("T1219", f"TeamViewer Remote Access from {src_ip} to {dst_ip}")
        
        # Check for SYN flood (T1498)
        if packet[scapy.TCP].flags == 'S':
            self.port_scan_tracker[f"syn_flood_{src_ip}"].append((dst_port, time.time()))
            recent_syns = [p for p in self.port_scan_tracker[f"syn_flood_{src_ip}"] 
                          if time.time() - p[1] < 2]  # SYNs in last 2 seconds
            if len(recent_syns) > 30:  # Threshold for SYN flood
                self.alert("T1498", f"Potential SYN Flood Attack from {src_ip}")
                self.port_scan_tracker[f"syn_flood_{src_ip}"] = []  # Reset after alert
    
    def analyze_udp_packet(self, packet):
        if not packet.haslayer(scapy.IP):
            return
            
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        dst_port = packet[scapy.UDP].dport
        
        # Skip whitelisted IPs
        if src_ip in self.whitelisted_ips:
            return
            
        # DNS tunneling detection (T1071)
        if dst_port == 53:
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                # Look for unusually long DNS queries
                if len(payload) > 100:
                    self.alert("T1071", f"Potential DNS Tunneling from {src_ip}")
        
        # SNMP community string checks (T1046)
        elif dst_port == 161:
            if packet.haslayer(scapy.Raw):
                payload = str(packet[scapy.Raw].load)
                if "public" in payload or "private" in payload:
                    self.alert("T1046", f"SNMP Scanning with Default Community String from {src_ip}")
        
        # NTP amplification attack (T1498)
        elif dst_port == 123:
            if packet.haslayer(scapy.Raw) and len(packet[scapy.Raw].load) > 200:
                self.alert("T1498", f"Potential NTP Amplification Attack from {src_ip}")
        
        # SSDP/UPnP scanning (T1046)
        elif dst_port == 1900:
            self.alert("T1046", f"SSDP/UPnP Scanning from {src_ip}")
        
        # VoIP scanning/attacks (T1040)
        elif dst_port in [5060, 5061]:  # SIP ports
            self.alert("T1040", f"VoIP/SIP Traffic from {src_ip} to {dst_ip}")
    
    def analyze_icmp_packet(self, packet):
        if not packet.haslayer(scapy.IP):
            return
            
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        # Skip whitelisted IPs
        if src_ip in self.whitelisted_ips:
            return
            
        # ICMP Scanning detection (T1046, T1595)
        self.port_scan_tracker[src_ip].append(("ICMP", time.time()))
        
        icmp_count = len([x for x in self.port_scan_tracker[src_ip] if x[0] == "ICMP"])
        if icmp_count > 10:
            # Check cooldown before alerting
            if src_ip not in self.scan_alert_cooldown or time.time() - self.scan_alert_cooldown[src_ip] > 300:
                self.alert("T1046", f"ICMP Scanning from {src_ip}")
                self.scan_alert_cooldown[src_ip] = time.time()
            # Reset tracker for this IP
            self.port_scan_tracker[src_ip] = [x for x in self.port_scan_tracker[src_ip] if x[0] != "ICMP"]
        
        # ICMP Tunneling detection (T1095)
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            if len(payload) > 64:  # Normal ping is usually smaller
                self.alert("T1095", f"Potential ICMP Tunneling from {src_ip} to {dst_ip}")
        
        # ICMP flood detection (T1498) - Completely rewritten to avoid type errors
        try:
            # Use a separate tracker for ICMP flood detection
            flood_key = f"icmp_flood_{src_ip}"
            current_time = time.time()
            
            # Initialize if not exists
            if flood_key not in self.port_scan_tracker:
                self.port_scan_tracker[flood_key] = []
            
            # Add current timestamp
            self.port_scan_tracker[flood_key].append(current_time)
            
            # Filter recent timestamps (last second)
            recent_timestamps = [t for t in self.port_scan_tracker[flood_key] 
                               if isinstance(t, float) and current_time - t < 1]
            
            # Update the list with only recent timestamps
            self.port_scan_tracker[flood_key] = recent_timestamps
            
            # Check if threshold is exceeded
            if len(recent_timestamps) > 20:  # Threshold for ICMP flood
                self.alert("T1498", f"Potential ICMP Flood Attack from {src_ip}")
                self.port_scan_tracker[flood_key] = []  # Reset after alert
        except Exception as e:
            # Log the error but don't crash
            print(f"Error in ICMP flood detection: {e}")
    
    def alert(self, technique_id, message):
        technique_name = self.attck_data.get(technique_id, "Unknown Technique")
        print(f"[{technique_name} ({technique_id})] {message}")

# Initialize and run the monitor
if __name__ == "__main__":
    print("Enhanced Network Security Monitoring Tool")
    print("Using MITRE ATT&CK Framework for Threat Classification")
    print("------------------------------------------------------")
    
    # You can customize these file paths
    whitelist_file = "whitelist.txt"
    known_devices_file = "known_devices.json"
    
    # Try to automatically detect the network interface
    interface = None
    try:
        from scapy.arch import get_if_list
        interfaces = get_if_list()
        # Filter out loopback interfaces
        interfaces = [iface for iface in interfaces if not iface.startswith('lo')]
        if interfaces:
            interface = interfaces[0]  # Use the first available interface
            print(f"Automatically selected interface: {interface}")
            print(f"Available interfaces: {', '.join(interfaces)}")
    except Exception as e:
        print(f"Could not automatically detect interface: {e}")
        interface = "en0"  # Default fallback
    
    # Allow user to specify a different interface
    user_interface = input(f"Enter network interface to monitor (press Enter to use {interface}): ")
    if user_interface.strip():
        interface = user_interface.strip()
    
    monitor = NetworkMonitor(interface=interface, 
                           whitelist_file=whitelist_file,
                           known_devices_file=known_devices_file)
    
    monitor.start_sniffing()