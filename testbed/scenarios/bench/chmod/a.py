import os, time
p = "/shared/modfile"
open(p, "w").write("x")
time.sleep(1.2)
os.chmod(p, 0o640)
