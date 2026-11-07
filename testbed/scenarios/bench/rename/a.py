import os, time
open("/shared/tmpfile", "w").write("x")
time.sleep(1.2)
os.replace("/shared/tmpfile", "/shared/final")
