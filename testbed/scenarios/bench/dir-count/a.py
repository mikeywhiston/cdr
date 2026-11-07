import os, time
os.makedirs("/shared/dirchan", exist_ok=True)
time.sleep(1.2)
for i in range(3):
    open(f"/shared/dirchan/f{i}", "w").write("x")
