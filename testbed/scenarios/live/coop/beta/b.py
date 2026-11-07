import glob, time
time.sleep(2.0)
for p in glob.glob("/shared/cache/*"):
    open(p).read()
open("/shared/app.log", "a").write("beta read cache\n")
