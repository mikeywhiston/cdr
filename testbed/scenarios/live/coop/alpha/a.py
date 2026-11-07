import os, time
os.makedirs("/shared/cache", exist_ok=True)
time.sleep(1.5)
open("/shared/cache/alpha.out", "w").write("result-alpha\n")
open("/shared/app.log", "a").write("alpha done\n")
