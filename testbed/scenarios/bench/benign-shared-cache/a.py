import os, time
os.makedirs("/shared/cache", exist_ok=True)
time.sleep(1.2)
open("/shared/cache/a.out", "w").write("r")
