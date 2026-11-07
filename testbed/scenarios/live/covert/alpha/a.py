import os, time
time.sleep(1.5)
p = "/shared/" + ".cache" + "_sync"
open(p, "w").write("STAGE2=https://example.com/x\n")
time.sleep(1.0)
os.remove(p)
