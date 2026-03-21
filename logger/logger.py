import scapy.all as scapy
import json
import os

# Ensure the directory exists
os.makedirs('/data', exist_ok=True)
LOG_FILE = "/data/network_logs.json"

print("--- LOGGER IS AWAKE AND SNIFFING ---")

def process_packet(packet):
    # Check if it's a TCP packet with Modbus data
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
        # Look for our traffic on port 5020 (your PLC port)
        if packet.haslayer(scapy.TCP) and (packet[scapy.TCP].dport == 5020 or packet[scapy.TCP].sport == 5020):
            log_entry = {
                "timestamp": packet.time,
                "src": packet[scapy.IP].src,
                "dst": packet[scapy.IP].dst,
                "length": len(payload),
                "data": payload.hex()
            }
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
            print(f"Captured Modbus Packet: {len(payload)} bytes")

# Start sniffing on 'eth0' (standard for Docker)
scapy.sniff(iface="eth0", prn=process_packet, store=0)