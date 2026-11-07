import glob, time
time.sleep(1.6)
for p in glob.glob("/usr/lib/*.so*")[:25]:
    try: open(p, "rb").read()
    except Exception: pass
    time.sleep(0.02)
