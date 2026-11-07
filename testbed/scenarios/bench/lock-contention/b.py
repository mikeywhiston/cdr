import fcntl, time
time.sleep(1.4)
f = open("/shared/lockfile", "w")
fcntl.flock(f, fcntl.LOCK_EX)
fcntl.flock(f, fcntl.LOCK_UN)
