import os, time
p="/shared/chan.fifo"
try: os.unlink(p)
except FileNotFoundError: pass
os.mkfifo(p)
time.sleep(0.5)
fd=os.open(p, os.O_WRONLY)
os.write(fd, b"hello")
os.close(fd)
