import os, time
p = "/shared/xattrfile"
open(p, "w").write("x")
time.sleep(1.2)
os.setxattr(p, "user.stage", b"2")
