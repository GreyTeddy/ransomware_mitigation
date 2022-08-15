
from time import time
from trickster import getPIDListFromName, suspendPIDforSeconds 

start = time()
name = "python.exe"
seconds = 2
pids = getPIDListFromName(name)
suspendPIDforSeconds(pids, seconds)
stop = time()

assert (stop - start) > seconds and (stop - start) < seconds + 1, "Weird amount of time running"