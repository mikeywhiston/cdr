import os, time
p = "/shared/selffile"
for _ in range(3):
    open(p, "w").write("x")
    open(p).read()
    time.sleep(0.1)
os.remove(p)
