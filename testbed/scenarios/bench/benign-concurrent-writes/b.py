import time
for i in range(8):
    open(f"/shared/cw-b{i}","w").write("y")
    time.sleep(0.05)
