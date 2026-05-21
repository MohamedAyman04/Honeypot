"""
Cross-Layer Correlator  (v2 — MITRE ATT\u0026CK enrichment)
======================================================
Changes from v1:
  • Every InfluxDB point is now enriched with five additional indexed tags:
      mitre_tactic / mitre_technique_id / mitre_technique_name /
      kill_chain_stage / purdue_level / protocol
  • Enrichment is driven by shared/mitre_mapping.py — no hard-coded strings here.
  • All existing fields and tags are preserved — backward compatible.
"""

import sys
import os

# Allow the shared package to be found whether running inside or outside Docker
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


import scapy.all as scapy
from pymodbus.client import ModbusTcpClient
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import time
import struct

from shared.mitre_mapping import enrich_point
from unified_logger import UnifiedLogger

# ── Configuration ──────────────────────────────────────────────────────────────
PLC_IP        = os.environ.get('PLC_IP',         'plc_simulator')
INFLUX_URL    = os.environ.get('INFLUX_URL',     'http://ics_historian:8086')
INFLUX_TOKEN  = os.environ.get('INFLUX_TOKEN',   'supersecrettoken')
INFLUX_ORG    = os.environ.get('INFLUX_ORG',     'my_refinery')
INFLUX_BUCKET = os.environ.get('INFLUX_BUCKET',  'sensor_logs')

db_client  = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api  = db_client.write_api(write_options=SYNCHRONOUS)

unified_logger = UnifiedLogger(service="ics_correlator", layer="Level 2", log_dir="/data")

print("--- CROSS-LAYER CORRELATOR v2 (MITRE ATT\u0026CK enriched) STARTING ---")

def make_plc_client():
    return ModbusTcpClient(PLC_IP, port=502)

def read_physical_state() -> dict | None:
    client = make_plc_client()
    try:
        if client.connect():
            res = client.read_holding_registers(100, 4)
            if hasattr(res, 'registers') and not res.isError():
                return {
                    'pressure':    float(res.registers[0]),
                    'flow_rate':   float(res.registers[1]) / 10.0,
                    'temperature': float(res.registers[2]),
                    'pump_rpm':    float(res.registers[3]),
                }
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass
    return None

def parse_modbus_write(payload: bytes):
    """
    Extract function code and register info from a raw Modbus TCP payload.
    Modbus TCP ADU: Trans(2) + Proto(2) + Len(2) + UnitID(1) + FC(1) + Data(...)
    """
    if len(payload) < 8:
        return None
    func_code = payload[7]
    if func_code not in (5, 6, 15, 16):   # write function codes only
        return None, None, None
    if len(payload) < 12:
        return func_code, None, None
    reg_addr = struct.unpack('>H', payload[8:10])[0]
    reg_val  = struct.unpack('>H', payload[10:12])[0]
    return func_code, reg_addr, reg_val

def _classify_modbus(func_code: int, reg_addr: int | None) -> str:
    """
    Map Modbus function code + register address to an internal event_type
    understood by mitre_mapping.lookup().
    """
    if func_code in (5, 6, 15, 16):
        # Registers >= 200 are the forced-write / attack zone (project convention)
        if reg_addr is not None and reg_addr >= 200:
            return "forced_write"
        return "write_command"
    return "modbus_read"

def process_packet(packet):
    if not packet.haslayer(scapy.Raw) or not packet.haslayer(scapy.TCP):
        return
    layer = packet[scapy.TCP]
    src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "?"
    dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "?"
    payload = packet[scapy.Raw].load

    if layer.dport == 20000 or layer.sport == 20000:
        print(f"[CORRELATOR] DNP3 packet detected from {src_ip}")
        unified_logger.log(
            event_type="DNP3_PROBE",
            source={"ip": src_ip, "protocol": "DNP3"},
            target={"ip": dst_ip, "port": 20000, "host": "ics_dnp3", "service": "dnp3"},
            payload={"raw_length": len(payload)}
        )
        return

    if layer.dport == 102 or layer.sport == 102:
        print(f"[CORRELATOR] S7comm packet detected from {src_ip}")
        unified_logger.log(
            event_type="S7COMM_PROBE",
            source={"ip": src_ip, "protocol": "S7comm"},
            target={"ip": dst_ip, "port": 102, "host": "ics_s7_plc", "service": "s7comm"},
            payload={"raw_length": len(payload)}
        )
        return

    if layer.dport != 502 and layer.sport != 502:
        return

    if len(payload) >= 8:
        fc = payload[7]
        print(f"[DEBUG] Modbus packet {len(payload)} bytes, FC={fc}, payload={payload.hex()}")
    parsed  = parse_modbus_write(payload)
    if parsed is None:
        return
    func_code, reg_addr, reg_val = parsed
    if func_code is None:
        return

    event_type = _classify_modbus(func_code, reg_addr)

    print(f"[CORRELATOR] FC{func_code} {event_type}: Reg {reg_addr} = {reg_val}  from {src_ip}")

    state    = read_physical_state()
    pressure = float(state['pressure']) if state else 0.0
    flow     = float(state['flow_rate']) if state else 0.0

    try:
        point = (Point("correlation_logs")
                 .tag("event_type",  event_type)
                 .tag("source_ip",   src_ip)
                 .field("func_code",     func_code)
                 .field("register",      reg_addr if reg_addr is not None else -1)
                 .field("value",         reg_val  if reg_val  is not None else -1)
                 .field("phys_pressure", pressure)
                 .field("phys_flow",     flow)
                 .time(time.time_ns(), WritePrecision.NS))

        # ── ATT&CK enrichment (adds 6 indexed tags) ─────────────────────────────
        enrich_point(point, event_type)

        write_api.write(bucket=INFLUX_BUCKET, record=point)
        
        unified_logger.log(
            event_type="MODBUS_WRITE" if func_code in (5, 6, 15, 16) else "MODBUS_READ",
            source={
                "ip": src_ip,
                "protocol": "ModbusTCP"
            },
            target={
                "ip": dst_ip,
                "port": 502,
                "host": "plc_simulator",
                "service": "plc"
            },
            payload={
                "function_code": func_code,
                "register": reg_addr,
                "value": reg_val,
                "phys_pressure": pressure,
                "phys_flow": flow
            }
        )
        
        print(
            f"[CORRELATOR] Logged: Reg={reg_addr} Val={reg_val} "
            f"P={pressure:.1f} PSI  [{event_type}]"
        )
    except Exception as e:
        print(f"[CORRELATOR] InfluxDB error: {e}")

# ── Sniffing ──────────────────────────────────────────────────────────────
print("[CORRELATOR] Sniffing on ALL interfaces")
scapy.sniff(filter="tcp port 502 or tcp port 102 or tcp port 20000", prn=process_packet, store=0)
