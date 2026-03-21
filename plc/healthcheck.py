import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(('localhost', 5020))
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)