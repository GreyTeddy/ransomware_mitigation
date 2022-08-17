import pprint
import psutil
import os
from threading import Thread
from time import sleep, time
from datetime import datetime
from collections import OrderedDict
import win32evtlog
import xmltodict

class trickster:
    pid_dict = {}
    white_list = set()
    PYTHON_PID = str(os.getpid())

    categories_id = {
        "process_created": 1,
        # "file_creation_time_changed": 2,
        # "process_terminated": 5,
        # "driver_loaded":6,
        # "image_loaded": 7,
        # "process_accessed": 10,
        # "file_created": 11,
        # "registry_object_added_or_deleted": 12,
        # "registry_value_set": 13,
        # "sysmon_config_state_changed": 16,
        # "file_delete_archive": 23,
        # "file_delete_logged": 24
    }
    categories_to_search = list(categories_id.keys())
    def suspendProcess(self, pid):
        self.pid_dict[pid]["proc"].suspend()

    def resumeProcess(self, pid):
        self.pid_dict[pid]["proc"].resume()

    def getProcess(self, pid):
        return psutil.Process(pid)

    def killProcess(self, pid):
        self.pid_dict[pid]["proc"].kill()
        del self.pid_dict[pid]["proc"]

    def addProcessFromPID(self, pid):
        pass

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
            self.addProcessFromPID(pid)

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

    def getNewIOCountsForPID(self, pid):
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
        new = {}
        initial = self.pid_dict[pid]["IOCountsInitial"]
        now = dict(self.pid_dict[pid]["proc"].io_counters()._asdict())
        for category in initial:
            new[category] = now[category] - initial[category]
        return new


        
    def getIOCounts(self):
        return psutil.disk_io_counters(perdisk=True)

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

    def searchEvent(self, LogName, EventId, count=20):
        EventLog = win32evtlog.EvtOpenLog(LogName, 1, None)

        totalRecords = win32evtlog.EvtGetLogInfo(
            EventLog, win32evtlog.EvtLogNumberOfLogRecords)[0]
        ResultSet = win32evtlog.EvtQuery(
            LogName, win32evtlog.EvtQueryReverseDirection, "*[System[(EventID=%d)]]" % EventId, None)

        EventList = []
        for evt in win32evtlog.EvtNext(ResultSet, count):
            res = xmltodict.parse(win32evtlog.EvtRender(evt, 1))

            EventData = {}
            for e in res['Event']['EventData']['Data']:
                if '#text' in e:
                    EventData[e['@Name']] = e['#text']

            EventList.append(EventData)

        return EventList

    def updateEvents(self, count, max_events=20,running_process_pid = set()):
        check_running = len(running_process_pid) > 0
        for category in self.categories_to_search:
            # get #count events for category
            Events = self.searchEvent(
                'Microsoft-Windows-Sysmon/Operational', self.categories_id[category], count)

            for i in Events:
                if "ProcessId" in i:
                    id_name = "ProcessId"
                elif "SourceProcessId" in i:
                    id_name = "SourceProcessId"
                else:
                    raise UserError #no pid found in events
                # elif "ImageLoaded" in i:
                #     id_name = "ImageLoaded"
                # if i[id_name] == self.PYTHON_PID or int(i[id_name]) not in self.pid_dict:
                #     print("hello")
                #     continue
                # if new PID
                if check_running and i[id_name] not in running_process_pid:
                    continue

                i[id_name] = int(i[id_name])
                if i[id_name] not in self.pid_dict:
                    # print(type(i[id_name]),i[id_name])
                    # print(i[id_name])
                    # print("here")
                    self.pid_dict[i[id_name]] = {}
                for new_category in self.categories_to_search:
                    if new_category not in self.pid_dict[i[id_name]]:
                        self.pid_dict[i[id_name]][new_category] = []

                # distinguish events by time
                self.pid_dict[i[id_name]][category].append(i)

                if len(self.pid_dict[i[id_name]][category]) > max_events:
                    self.pid_dict[i[id_name]][category].pop(0)
    
    def getCurrentPIDs(self,only_new = False,count=10,max_events=20):
        running_processes_pid = set()
        for proc in psutil.process_iter():
            try: # handle process dying while storing
                pid = proc.pid
                running_processes_pid.add(proc.pid)
                self.pid_dict[pid] = {"proc": proc}
                if "IOCounts" not in self.pid_dict[pid]:
                    self.pid_dict[pid]["IOCountsInitial"] = dict(self.getIOCountsForPID(pid)._asdict())
                self.pid_dict[pid]["IOCounts"] = self.getNewIOCountsForPID(pid)
                # pp.pprint(self.pid_dict[pid])
                # print(self.pid_dict[pid]["IOCountsInitial"])
            except psutil.NoSuchProcess:
                del self.pid_dict[pid]
        
        self.updateEvents(count, max_events=10)
        
        if only_new:
            pid_dict_pids = set(self.pid_dict.keys())
            for pid in pid_dict_pids:
                if pid not in running_processes_pid:
                    print(pid)
                    del self.pid_dict[pid]

        # print(self.pid_dict)
        # exit()

    def getCommandsRun(self):
        words_to_find = ["wbadmin","bcdedit","vssadmin","recoveryenabled","cmd","Win32_Shadowcopy","powershell"]
        commands = {}
        for pid in self.pid_dict:
            if "process_created" in self.pid_dict[pid]:
                for event in self.pid_dict[pid]["process_created"]:
                    event_parent = event["ParentProcessId"]
                    command = event["CommandLine"]
                    # print(command)
                    for word in words_to_find:
                        if command.find(word) != -1:
                            if command not in commands:
                                commands[command] = {"words":set(),"parents":{}}

                            commands[command]["words"].add(word)
                            if event_parent not in commands[command]["parents"]:
                                commands[command]["parents"][event_parent] = set()
                            commands[command]["parents"][event_parent].add(pid)
        return commands

    def printCommandsRun(self,count=20):
        while True:
            self.getCurrentPIDs(False,count)
            os.system("cls")
            print("##############################")
            
            commands = self.getCommandsRun()
            for command in commands:
                print(command)
                for parent in commands[command]["parents"]:
                    if parent not in self.pid_dict:
                        continue
                    print(parent)
                    # exit()
                    for child_id in commands[command]["parents"][parent]:
                        # print("\t",child_id)
                        if "IOCounts" in self.pid_dict[parent]:
                            print("\t\t",child_id)
                            print("\t\t",self.pid_dict[parent]["IOCounts"])
                print()
            sleep(1)

        
def test_file_creations():
    trick = trickster()
    # trick.addAllPIDs()
    THRESHOLD = 100
    COUNT = THRESHOLD
    SECONDS = 0.001
    while True:
        # os.system('cls')
        print('##############################')
        trick.getCurrentPIDs()
        trick.updateEvents(COUNT, 100)
        # pp.pprint(trick.pid_dict)
        # exit()
        print("actions in less than ", SECONDS, "seconds")
        pp.pprint(actions_done_in_less_than(SECONDS,THRESHOLD))
        trick.kill_if_too_many_actions(
            trick.actions_done_in_less_than(SECONDS, THRESHOLD))
        print(pid_dict.keys())
        sleep(1)


def test_process_creation():
    trick = trickster()
    COUNT = 100
    SECONDS = 0.001
    trick.printCommandsRun(COUNT)



def test_io():
    trick = trickster()
    trick.getCurrentPIDs()
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
        # trick.addAllPIDs()
        trick.getCurrentPIDs()
        # print(trick.getIOCounts())
        # for pid in trick.pid_dict:
        #     try:
        #         if not trick.pid_dict[pid]["openedBefore"] and trick.getIOCountsForPID(pid).read_count > trick.pid_dict[pid]["IOCounts"].read_count + 10 and trick.getIOCountsForPID(pid).write_count > trick.pid_dict[pid]["IOCounts"].write_count + 20:
        #             print("###")
        #             print(trick.pid_dict[pid]["IOCounts"])
        #             print(trick.getIOCountsForPID(pid),
        #                   pid, trick.getProcess(pid).name())
        #             # trick.suspendProcess(pid)
        #     except psutil.NoSuchProcess:
        #         continue
        sleep(0.05)


if __name__ == "__main__":
    # test_new_pid()
    pp = pprint.PrettyPrinter(indent=4)
    test_process_creation()
