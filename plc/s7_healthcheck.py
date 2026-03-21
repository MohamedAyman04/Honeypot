import socket
import sys

# Minimal TPKT + ISO 8073 COTP Connection Request (CR)
# This prevents the S7 server from logging "Connection closed by peer" errors
# by identifying as a valid (but minimal) protocol client.
TPKT_COTP_CR = bytes([
    0x03, 0x00, 0x00, 0x16,   # TPKT: version 3, length 22
    0x11,                     # COTP: length 17
    0xe0,                     # PDU type: Connection Request
    0x00, 0x00, 0x00, 0x01, 0x00,
    0xc1, 0x02, 0x01, 0x00,
    0xc2, 0x02, 0x01, 0x02,
    0xc0, 0x01, 0x09
])

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(('localhost', 102))
    s.sendall(TPKT_COTP_CR)
    # Give it a tiny bit of time to reach the server handler
    s.recv(1024)
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
