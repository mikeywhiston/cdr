import os, time
open("/shared/scrubfile", "w").write("x")
time.sleep(2.0)
os.remove("/shared/scrubfile")
