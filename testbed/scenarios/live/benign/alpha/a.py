import hashlib, time
h = hashlib.sha256()
for i in range(2000):
    h.update(b"alpha-%d" % i)
time.sleep(1.5)
print(h.hexdigest()[:16])
