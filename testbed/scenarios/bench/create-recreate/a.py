import os, time
p="/shared/recreate"
open(p,"w").write("one")
time.sleep(1.0)
os.remove(p)
open(p,"w").write("two")
