import time
for i in range(8):
    open(f"/shared/cw-a{i}","w").write("x")
    time.sleep(0.05)
