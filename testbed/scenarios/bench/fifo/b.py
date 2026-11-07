import os, time
time.sleep(1.2)
fd=os.open("/shared/chan.fifo", os.O_RDONLY)
os.read(fd, 16)
os.close(fd)
