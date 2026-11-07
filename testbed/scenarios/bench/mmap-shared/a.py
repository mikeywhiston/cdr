import mmap, os, time
p = "/shared/mmapfile"
f = open(p, "w+b")
f.write(b"\0" * 64)
f.flush()
time.sleep(1.2)
m = mmap.mmap(f.fileno(), 64)
m[0:5] = b"HELLO"
m.flush()
time.sleep(1.0)
