import glob, time
for _ in range(60):
    if any(".cache_sync" in p for p in glob.glob("/shared/.*")):
        print("RECEIVED")
        break
    time.sleep(0.1)
