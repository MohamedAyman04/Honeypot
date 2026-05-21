"""
Network Logger (Scapy-based)
============================
Captures Modbus (502) and S7comm (102) traffic on all available interfaces
and writes JSON log entries to /data/network_logs.json for the correlator.
"""
import scapy.all as scapy
import json
import os
import socket

os.makedirs('/data', exist_ok=True)
LOG_FILE = "/data/network_logs.json"

# Detect the main network interface (prefer eth0, fall back gracefully)
def get_iface():
    try:
        # Try to find the interface that has eth0 first
        ifaces = scapy.get_if_list()
        for candidate in ["eth0", "eth1", "ens3", "enp0s3"]:
            if candidate in ifaces:
                return candidate
        # Fall back to first non-loopback interface
        for iface in ifaces:
            if iface != "lo":
                return iface
    except Exception:
        pass
    return None

IFACE = get_iface()
print(f"--- LOGGER STARTING: sniffing on {IFACE} ---")

WATCHED_PORTS = {502, 102, 20000}   # Modbus, S7comm, DNP3

# Instantiate UnifiedLogger globally for probe forwarding
logger_instance = None
try:
    os.environ["INFLUX_URL"] = "http://127.0.0.1:8086"
    os.environ["STORY_LOGGER_URL"] = "http://127.0.0.1:8600"
    from unified_logger import UnifiedLogger
    logger_instance = UnifiedLogger(service="network_sniffer", layer="Level 2", log_dir="/data")
except Exception as e:
    print(f"Failed to initialize unified logger: {e}")

def process_packet(packet):
    if not packet.haslayer(scapy.Raw):
        return
    if not packet.haslayer(scapy.TCP) and not packet.haslayer(scapy.UDP):
        return

    layer = packet[scapy.TCP] if packet.haslayer(scapy.TCP) else packet[scapy.UDP]
    dport = layer.dport
    sport = layer.sport

    if dport not in WATCHED_PORTS and sport not in WATCHED_PORTS:
        return

    payload = packet[scapy.Raw].load
    proto   = "modbus" if (dport == 502 or sport == 502) else \
              "s7comm"  if (dport == 102  or sport == 102)  else "dnp3"

    log_entry = {
        "timestamp": float(packet.time),
        "src":       packet[scapy.IP].src if packet.haslayer(scapy.IP) else "?",
        "dst":       packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "?",
        "dport":     dport,
        "sport":     sport,
        "protocol":  proto,
        "length":    len(payload),
        "data":      payload.hex(),
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    print(f"[{proto.upper()}] {log_entry['src']} -> {log_entry['dst']} | {len(payload)} bytes")
    
    # Forward probes to unified_logger if it's a DNP3 or S7COMM probe
    if logger_instance:
        try:
            if proto == "dnp3" and (dport == 20000 or sport == 20000):
                logger_instance.log(
                    event_type="DNP3_PROBE",
                    source={"ip": log_entry["src"], "protocol": "DNP3"},
                    target={"ip": log_entry["dst"], "port": 20000, "host": "ics_dnp3", "service": "dnp3"},
                    payload={"raw_length": len(payload)}
                )
            elif proto == "s7comm" and (dport == 102 or sport == 102):
                logger_instance.log(
                    event_type="S7COMM_PROBE",
                    source={"ip": log_entry["src"], "protocol": "S7comm"},
                    target={"ip": log_entry["dst"], "port": 102, "host": "ics_s7_plc", "service": "s7comm"},
                    payload={"raw_length": len(payload)}
                )
        except Exception as e:
            print(f"Failed to forward to unified logger: {e}")

if IFACE:
    scapy.sniff(iface=IFACE, prn=process_packet, store=0)
else:
    # Fallback: sniff all interfaces if we couldn't determine one
    print("WARNING: Could not determine interface, sniffing all (may miss traffic)")
    scapy.sniff(prn=process_packet, store=0)