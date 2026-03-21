import scapy.all as scapy
from pymodbus.client import ModbusTcpClient
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import os
import time
import struct

# Config
PLC_IP = os.environ.get('PLC_IP', 'plc_simulator')
INFLUX_URL = "http://ics_historian:8086"
INFLUX_TOKEN = "supersecrettoken"
INFLUX_ORG = "my_refinery"
INFLUX_BUCKET = "sensor_logs"

# Init Clients
db_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = db_client.write_api(write_options=SYNCHRONOUS)
plc_client = ModbusTcpClient(PLC_IP, port=5020)

print("--- CROSS-LAYER CORRELATOR STARTING ---")

def get_modbus_data(payload):
    # Modbus TCP Header: Transaction ID (2), Protocol ID (2), Length (2), Unit ID (1) = 7 bytes
    # PDU: Function Code (1), Data (...)
    if len(payload) < 8:
        return None
    
    trans_id = struct.unpack(">H", payload[0:2])[0]
    func_code = payload[7]
    return trans_id, func_code, payload[8:]

def process_packet(packet):
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
        modbus = get_modbus_data(payload)
        if not modbus:
            return
            
        trans_id, func_code, data = modbus
        
        # Function Code 6: Write Single Register
        if func_code == 6:
            reg_addr = struct.unpack(">H", data[0:2])[0]
            reg_val = struct.unpack(">H", data[2:4])[0]
            
            print(f"[!] Write Command Captured: Reg {reg_addr} = {reg_val}")
            
            # Immediately query the PLC for the current physical state for correlation
            try:
                # Read sensors: Pressure (100), Flow (101)
                res = plc_client.read_holding_registers(100, 2)
                if not res.isError():
                    pressure = res.registers[0]
                    flow = res.registers[1] / 10.0
                    
                    point = Point("correlation_logs") \
                        .tag("event_type", "write_command") \
                        .field("register", reg_addr) \
                        .field("value", reg_val) \
                        .field("phys_pressure", float(pressure)) \
                        .field("phys_flow", float(flow)) \
                        .field("trans_id", trans_id) \
                        .time(time.time_ns(), WritePrecision.NS)
                    
                    write_api.write(bucket=INFLUX_BUCKET, record=point)
                    print(f"Logged Correlation: Write {reg_addr} @ Pressure {pressure}")
            except Exception as e:
                print(f"Correlation Error: {e}")

# Sniffing
scapy.sniff(iface="eth0", filter="tcp port 5020", prn=process_packet, store=0)
