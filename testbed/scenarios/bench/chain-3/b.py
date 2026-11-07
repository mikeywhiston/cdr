import time
time.sleep(1.5)
open("/shared/chain1").read()
time.sleep(0.3)
open("/shared/chain2","w").write("b")
