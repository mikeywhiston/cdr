import socket, time
time.sleep(1.4)
c=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    c.connect("/shared/chan.sock"); c.recv(8)
except Exception: pass
c.close()
