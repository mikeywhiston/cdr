import time
time.sleep(1.2)
open("/shared/fan1","w").write("x")
open("/shared/fan2","w").write("y")
