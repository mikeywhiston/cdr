import os, time
p = "/shared/truncfile"
open(p, "w").write("x" * 4096)
time.sleep(1.2)
os.truncate(p, 0)
