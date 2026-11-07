import glob, time
for p in glob.glob("/etc/*")[:25]:
    try: open(p, "rb").read()
    except Exception: pass
    time.sleep(0.02)
