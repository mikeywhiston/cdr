import os, time
p = "/shared/tsfile"
open(p, "w").write("x")
time.sleep(1.2)
os.utime(p, (1000000000, 1000000000 + 7))
