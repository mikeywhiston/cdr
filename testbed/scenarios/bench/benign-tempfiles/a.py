import tempfile, os
for _ in range(10):
    fd,p=tempfile.mkstemp(dir="/tmp")
    os.write(fd,b"x"); os.close(fd); os.unlink(p)
