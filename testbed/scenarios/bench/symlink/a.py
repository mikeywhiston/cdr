import os, time
os.makedirs("/shared/symdir", exist_ok=True)
open("/shared/symdir/target", "w").write("x")
time.sleep(1.2)
try: os.unlink("/shared/link")
except FileNotFoundError: pass
os.symlink("/shared/symdir/target", "/shared/link")
