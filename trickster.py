import psutil
from time import sleep
import os
from threading import Thread


class trickster:
    pid_dict = {}

    def suspendProcess(self, pid):
        self.pid_dict[pid].suspend()
    
    def resumeProcess(self, pid):
        self.pid_dict[pid].resume()

    def killProcess(self, pid):
        self.pid_dict[pid].kill()
        del self.pid_dict[pid]
    
    def addPID(self, pid):
        self.pid_dict[pid] = psutil.Process(pid)

    def getPIDfromName(self, name):
        pids = []
        own_pid = os.getpid()  # get own pid so it does not get suspended
        for proc in psutil.process_iter():
            if name in proc.name() and own_pid != proc.pid:  # find pid with same name and also not self
                pids.append(proc.pid)
        return pids


    def getCPUUsage(self):
        return psutil.cpu_percent()

    def getCPUUsageForPID(self,pid):
        # as cpu_percent shows utilisation for all threads
        # divide for number of threads 
        return round(self.pid_dict[pid].cpu_percent()/ (psutil.cpu_count()),1)

    def addPIDfromName(self, name):
        for pid in self.getPIDfromName(name):
            self.addPID(pid)

    def suspendPIDforSeconds(self, pid: int, seconds: float):
        
        def suspend_then_run(pid,seconds):
            # show the time for sleeping
            print(f"Suspending {pid} pids for {seconds} s: ")
            self.suspendProcess(pid)
            sleep(seconds)
            self.resumeProcess(pid)
        t = Thread(target=suspend_then_run, args=(pid,seconds), kwargs=None)
        t.start()

    def getMemoryBytesUtilisationForPID(self,pid):
        """
        Get "Unique Set Size" of process in bytes
           USS is the memory used by the process
           that would be freed if the process was terminated
        """
        return self.pid_dict[pid].memory_full_info().uss

    def getMemoryPercentUtilisationForPID(self,pid):
        return self.pid_dict[pid].memory_percent(memtype="uss")

    def getOpenFiles(self,pid):
        return self.pid_dict[pid].open_files()

    def getParentPID(self,pid):
        return psutil.Process(self.pid_dict[pid].ppid())
     
    def getIOCountsForPID(self,pid):
        """
        read_count: read operations
        write_count: write operations
        read_bytes: bytes that have been read
        write_bytes: bytes that have been written
        other_count: operations other than read and write 
                        e.g. open
        other_bytes: bytes revolving around other operations 
                        e.g. open
        """
        return self.pid_dict[pid].io_counters()
    
    def getIOCounts(self):
        return psutil.disk_io_counters(perdisk=True)

import pprint
pp = pprint.PrettyPrinter(indent=4)
if __name__ == "__main__":
    name = "chrome.exe"
    pid = 14196
    pid = 11728
    seconds = 2
    trick = trickster()
    trick.addPID(pid)
    hello = set()
    try:
        while True:
            print("######################################")
            sleep(2)
    except KeyboardInterrupt:
        print(hello)

