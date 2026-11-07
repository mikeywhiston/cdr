import glob, time
for p in glob.glob("/usr/share/**/*.gz", recursive=True)[:20]:
    try: open(p,"rb").read(4096)
    except Exception: pass
