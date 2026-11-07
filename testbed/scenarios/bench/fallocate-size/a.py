import os, time
p="/shared/bigfile"
f=open(p,"wb"); f.truncate(1024*1024); f.close()
time.sleep(1.2)
os.truncate(p, 2*1024*1024)
