import time
for i in range(5):
    open(f"/shared/alt-a{i}","w").write("x")
    time.sleep(0.1)
