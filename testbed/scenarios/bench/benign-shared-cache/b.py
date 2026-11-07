import glob, time
time.sleep(1.6)
for p in glob.glob("/shared/cache/*"):
    open(p).read()
