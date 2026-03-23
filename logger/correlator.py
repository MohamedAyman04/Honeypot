"""
Cross-Layer Correlator
======================
Sniffs Modbus TCP (port 502) write commands using Scapy and correlates them
with live physical sensor readings from the PLC.  All events are written to
InfluxDB (correlation_logs measurement) for the ML engine to consume.
"""

import scapy.all as scapy
from pymodbus.client import ModbusTcpClient
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import os
import time
import struct

# ── Configuration ──────────────────────────────────────────────────────────────
PLC_IP        = os.environ.get('PLC_IP',         'plc_simulator')
INFLUX_URL    = os.environ.get('INFLUX_URL',     'http://ics_historian:8086')
INFLUX_TOKEN  = os.environ.get('INFLUX_TOKEN',   'supersecrettoken')
INFLUX_ORG    = os.environ.get('INFLUX_ORG',     'my_refinery')
INFLUX_BUCKET = os.environ.get('INFLUX_BUCKET',  'sensor_logs')

db_client  = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api  = db_client.write_api(write_options=SYNCHRONOUS)

print("--- CROSS-LAYER CORRELATOR STARTING ---")

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

def process_packet(packet):
    if not packet.haslayer(scapy.Raw) or not packet.haslayer(scapy.TCP):
        return
    layer = packet[scapy.TCP]
    if layer.dport != 502 and layer.sport != 502:
        return

    payload   = packet[scapy.Raw].load
    parsed    = parse_modbus_write(payload)
    if parsed is None:
        return
    func_code, reg_addr, reg_val = parsed
    if func_code is None:
        return

    src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "?"
    print(f"[CORRELATOR] FC{func_code} Write: Reg {reg_addr} = {reg_val}  from {src_ip}")

    state = read_physical_state()
    pressure = float(state['pressure']) if state else 0.0
    flow     = float(state['flow_rate']) if state else 0.0

    try:
        point = (Point("correlation_logs")
                 .tag("event_type",  "write_command")
                 .tag("source_ip",   src_ip)
                 .field("func_code",     func_code)
                 .field("register",      reg_addr   if reg_addr is not None else -1)
                 .field("value",         reg_val    if reg_val  is not None else -1)
                 .field("phys_pressure", pressure)
                 .field("phys_flow",     flow)
                 .time(time.time_ns(), WritePrecision.NS))
        write_api.write(bucket=INFLUX_BUCKET, record=point)
        print(f"[CORRELATOR] Logged: Reg={reg_addr} Val={reg_val} P={pressure:.1f} PSI")
    except Exception as e:
        print(f"[CORRELATOR] InfluxDB error: {e}")

# Detect available interface
def get_iface():
    try:
        ifaces = scapy.get_if_list()
        for candidate in ["eth0", "eth1", "ens3", "enp0s3"]:
            if candidate in ifaces:
                return candidate
        return next((i for i in ifaces if i != "lo"), None)
    except Exception:
        return None

IFACE = get_iface()
print(f"[CORRELATOR] Sniffing on {IFACE}")

if IFACE:
    scapy.sniff(iface=IFACE, filter="tcp port 502", prn=process_packet, store=0)
else:
    scapy.sniff(filter="tcp port 502", prn=process_packet, store=0)
