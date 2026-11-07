import os, random, string, time, glob
base = "/tmp/rnd-b"
os.makedirs(base, exist_ok=True)
for _ in range(20):
    p = os.path.join(base, "".join(random.choices(string.ascii_lowercase, k=12)))
    open(p, "w").write("x")
    open(p).read()
    time.sleep(0.02)
for p in glob.glob(base + "/*"):
    os.remove(p)
