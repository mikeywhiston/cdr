import os, time
time.sleep(1.6)
os.getxattr("/shared/xattrfile", "user.stage")
