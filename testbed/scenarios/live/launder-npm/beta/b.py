import glob, time
for _ in range(80):
    if any(".cache" in p for p in glob.glob("/shared/*")):
        print("RECEIVED")
        break
    time.sleep(0.1)
