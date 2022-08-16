import pprint
import psutil
from time import sleep
import os
from threading import Thread


class trickster:
    pid_dict = {}

    def suspendProcess(self, pid):
        self.pid_dict[pid]["proc"].suspend()

    def resumeProcess(self, pid):
        self.pid_dict[pid]["proc"].resume()

    def getProcess(self, pid):
        return psutil.Process(pid)

    def killProcess(self, pid):
        self.pid_dict[pid]["proc"].kill()
        del self.pid_dict[pid]["proc"]

    def addPID(self, pid):
        self.pid_dict[pid] = {
            "proc": psutil.Process(pid), "openedBefore":False}
        self.pid_dict[pid]["IOCounts"] = self.getIOCountsForPID(
            pid)

    def getPIDfromName(self, name):
        pids = []
        own_pid = os.getpid()  # get own pid so it does not get suspended
        for proc in psutil.process_iter():
            if name in proc.name() and own_pid != proc.pid:  # find pid with same name and also not self
                pids.append(proc.pid)
        return pids

    def getCPUUsage(self):
        return psutil.cpu_percent()

    def getCPUUsageForPID(self, pid):
        # as cpu_percent shows utilisation for all threads
        # divide for number of threads
        return round(self.pid_dict[pid]["proc"].cpu_percent() / (psutil.cpu_count()), 1)

    def addPIDfromName(self, name):
        for pid in self.getPIDfromName(name):
            self.addPID(pid)

    def suspendPIDforSeconds(self, pid: int, seconds: float):

        def suspend_then_run(pid, seconds):
            # show the time for sleeping
            print(f"Suspending {pid} pids for {seconds} s: ")
            self.suspendProcess(pid)
            sleep(seconds)
            self.resumeProcess(pid)
        t = Thread(target=suspend_then_run, args=(pid, seconds), kwargs=None)
        t.start()

    def getMemoryBytesUtilisationForPID(self, pid):
        """
        Get "Unique Set Size" of process in bytes
           USS is the memory used by the process
           that would be freed if the process was terminated
        """
        return self.pid_dict[pid]["proc"].memory_full_info().uss

    def getMemoryPercentUtilisationForPID(self, pid):
        return self.pid_dict[pid]["proc"].memory_percent(memtype="uss")

    def getOpenFiles(self, pid):
        return self.pid_dict[pid]["proc"].open_files()

    def getParentPID(self, pid):
        return psutil.Process(self.pid_dict[pid]["proc"].ppid())

    def getIOCountsForPID(self, pid):
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
        # try:
        return self.pid_dict[pid]["proc"].io_counters()
        # except KeyError:
        #     return {"read_count": 0,
        #             "write_count":  0,
        #             "read_bytes":  0,
        #             "write_bytes":  0,
        #             "other_count":  0,
        #             "other_bytes":  0, }

    def getIOCounts(self):
        return psutil.disk_io_counters(perdisk=True)

    def addAllPIDs(self):
        self.pid_disct = {}
        for proc in psutil.process_iter():
            self.pid_dict[proc.pid] = {
                "proc": proc, "openedBefore":False}
            self.pid_dict[proc.pid]["IOCounts"] = self.getIOCountsForPID(
                proc.pid)

    def addOldPIDs(self):
        self.pid_dict = {}
        for proc in psutil.process_iter():
            self.pid_dict[proc.pid] = {
                "proc": proc, "openedBefore":True}
            self.pid_dict[proc.pid]["IOCounts"] = self.getIOCountsForPID(
                proc.pid)


    def addNewPIDs(self):
        for proc in psutil.process_iter():
            try:
                if not self.pid_dict[proc.pid]["openedBefore"]:
                    # print(proc)
                    pass
            except KeyError:
                print("here")
                print(proc)
                self.addPID(proc.pid)

    def checkIOOccurenciesForPID(self):
        for pid in self.pid_dict:
            try:
                initial_io = self.pid_dict[pid]["IOCounts"]
                current_io = self.getIOCountsForPID(pid)

                read_count_difference = current_io.read_count - initial_io.read_count
            # print(read_count_difference)
                if read_count_difference > 1000:
                    print(self.getProcess(pid), read_count_difference)
            except psutil.NoSuchProcess:
                continue
            # print(read_count_difference)
            # exit()


def test_new_pid():
    trick = trickster()
    trick.addOldPIDs()
    while True:
        trick.addNewPIDs()
        sleep(2)

def test_io():
    trick = trickster()
    trick.addAllPIDs()
    try:
        while True:
            print("######################################")
            trick.checkIOOccurenciesForPID()
            sleep(2)
    except KeyboardInterrupt:
        print(hello)


def test_heh_exe():
    while True:
        print("######################################")
        trick = trickster()
        # for pid in trick.getPIDfromName("chrome.exe"):
        #     trick.addPID(pid)
        trick.addAllPIDs()
        # print(trick.getIOCounts())
        for pid in trick.pid_dict:
            try:
                if not trick.pid_dict[pid]["openedBefore"] and trick.getIOCountsForPID(pid).read_count > trick.pid_dict[pid]["IOCounts"].read_count + 10 and trick.getIOCountsForPID(pid).write_count > trick.pid_dict[pid]["IOCounts"].write_count + 20:
                    print("###")
                    print(trick.pid_dict[pid]["IOCounts"])
                    print(trick.getIOCountsForPID(pid),pid,trick.getProcess(pid).name())
                    # trick.suspendProcess(pid)
            except psutil.NoSuchProcess:
                continue
        sleep(0.05)


pp = pprint.PrettyPrinter(indent=4)
if __name__ == "__main__":
    test_new_pid()