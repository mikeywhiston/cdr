import time
open("/shared/applog", "a").write("entry-a")
time.sleep(0.4)
open("/shared/applog", "a").write("entry-b")
