import glob, time
time.sleep(1.3)
for p in glob.glob("/usr/share/**/*.txt", recursive=True)[:20]:
    try: open(p,"rb").read(4096)
    except Exception: pass
