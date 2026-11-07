import fcntl, time
f = open("/shared/lockfile", "w")
fcntl.flock(f, fcntl.LOCK_EX)
time.sleep(2.0)
fcntl.flock(f, fcntl.LOCK_UN)
