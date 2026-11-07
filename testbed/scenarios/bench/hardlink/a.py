import os, time
open("/shared/hard1","w").write("x")
time.sleep(1.2)
try: os.unlink("/shared/hard2")
except FileNotFoundError: pass
os.link("/shared/hard1","/shared/hard2")
