import time, glob
time.sleep(1.6)
for f in glob.glob("/shared/chan-file"):
    open(f).read()
