import os, time
os.makedirs("/shared/nest1/nest2", exist_ok=True)
time.sleep(1.2)
open("/shared/nest1/nest2/f","w").write("x")
