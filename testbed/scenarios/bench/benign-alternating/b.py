import time
time.sleep(1.2)
for i in range(5):
    open(f"/shared/alt-b{i}","w").write("y")
    time.sleep(0.1)
