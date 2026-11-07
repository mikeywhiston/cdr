import hashlib
h = hashlib.sha256()
for i in range(3000):
    h.update(b"b-%d" % i)
print(h.hexdigest()[:8])
