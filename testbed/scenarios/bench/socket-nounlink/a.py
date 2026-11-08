import os, socket, time
p="/shared/chan.sock"
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(p); s.listen(1)
time.sleep(2.0)
try:
    c,_=s.accept(); c.sendall(b"hi"); c.close()
except Exception: pass
s.close()
