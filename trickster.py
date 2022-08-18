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

    categories_id = {
        "process_created": 1,
        # "file_creation_time_changed": 2,
        # "process_terminated": 5,
        # "driver_loaded":6,
        # "image_loaded": 7,
        "process_accessed": 10,
        "file_created": 11,
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
        return self.pid_dict[pid]["proc"].io_counters()

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
        new = {}
        initial = self.pid_dict[pid]["IOCountsInitial"]
        now = dict(self.pid_dict[pid]["proc"].io_counters()._asdict())
        for category in initial:
            new[category] = now[category] - initial[category]
        return new


    def getIOCounts(self):
        return psutil.disk_io_counters(perdisk=True)

    def overIOOccurencies(self,number_of_actions,magnitude_of_difference_write_read):
        io_from_start = {}
        categories = ['read_count', 'write_count', 'read_bytes', 'write_bytes', 'other_count', 'other_bytes']
        for pid in self.pid_dict:
            if "IOCounts" in self.pid_dict[pid]:
                ## if the process does not exist anymore
                try:
                    current = self.getNewIOCountsForPID(pid)
                except psutil.NoSuchProcess:
                    continue

                for category in categories:
                    if current[category] > number_of_actions:
                        if pid not in io_from_start:
                            io_from_start[pid] = {}
                        io_from_start[pid][category] = current[category]
                        
                if pid not in io_from_start:
                    continue
                if categories[0] in io_from_start[pid] and categories[1] in io_from_start[pid]:
                    difference = io_from_start[pid][categories[1]] / io_from_start[pid][categories[0]]
                    if difference >= magnitude_of_difference_write_read:
                        io_from_start[pid]["write_read_magnitude"] = difference
                
                if categories[2] in io_from_start[pid] and categories[3] in io_from_start[pid]:
                    difference = io_from_start[pid][categories[2]] / io_from_start[pid][categories[3]]
                    if difference >= magnitude_of_difference_write_read:
                        io_from_start[pid]["byte_write_read_magnitude"] = difference

        return io_from_start

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

    def updateEvents(self, count, max_events=20):
        for category in self.categories_to_search:
            # get #count events for category
            Events = self.searchEvent(
                'Microsoft-Windows-Sysmon/Operational', self.categories_id[category], count)
            
            for event in Events:
                if "ProcessId" in event:
                    id_name = "ProcessId"
                    parent_name = "ParentProcessId"
                    current_directory = os.getcwd()+"\\"
                    python_id = os.getpid()
                    if "ParentImage" in event and event["ParentImage"] == 'C:\\Python310\\python.exe':
                        # print("parent image")
                        continue
                    if event[id_name] == python_id:
                        # print("parent:",i[parent_name])
                        # print("here") 
                        pass
                    if (parent_name in event and event[parent_name] == python_id):
                        # print("parent:",event[parent_name])
                        # print("here") 
                        continue
                elif "SourceProcessId" in event:
                    id_name = "SourceProcessId"
                elif "ImageLoaded" in event:
                    continue
                else:
                    raise UserError #no pid found in events
                
                # turn pid string to integer
                event[id_name] = int(event[id_name])

                if event[id_name] not in self.pid_dict:
                    self.pid_dict[event[id_name]] = {"events":{}}
                elif "events" not in self.pid_dict[event[id_name]]:
                    self.pid_dict[event[id_name]]["events"] = {}
                else:
                    pass

                if category not in self.pid_dict[event[id_name]]["events"]:
                    self.pid_dict[event[id_name]]["events"][category] = []
                
                self.pid_dict[event[id_name]]["events"][category].append(event)

                if len(self.pid_dict[event[id_name]]["events"][category]) > max_events:
                    self.pid_dict[event[id_name]]["events"][category].pop(0)

    def getEventForPID(self,pid,count=100, max_events=20):
        for category in self.categories_to_search:
            # get #count events for category
            Events = self.searchEvent(
                'Microsoft-Windows-Sysmon/Operational', self.categories_id[category], count)
            
            for i in Events:
                if "ProcessId" in i:
                        id_name = "ProcessId"
                elif "SourceProcessId" in i:
                    id_name = "SourceProcessId"
                elif "ImageLoaded" in i:
                    continue
            
                i[id_name] = int(i[id_name])

                print(i)
                print(type(i[id_name]))
                print(type(self.PYTHON_PID))
                print("event pid:",i[id_name])
                print("python pid:",self.PYTHON_PID)
                print(i["ParentCommandLine"])
                input()


    def getCurrentPIDs(self,count,max_events,only_new = False):
        self.pid_dict = {}
        running_processes_pid = set()
        for proc in psutil.process_iter():
            try: # handle process dying while storing
                pid = proc.pid
                running_processes_pid.add(proc.pid)
                
                if pid not in self.pid_dict:
                    self.pid_dict[pid] = {"proc": proc}
                if "IOCountsInitial" not in self.pid_dict[pid] and self.pid_dict[pid]:
                    self.pid_dict[pid] = {"proc": proc}
                    self.pid_dict[pid]["IOCountsInitial"] = dict(self.getIOCountsForPID(pid)._asdict())
                self.pid_dict[pid]["IOCounts"] = self.getNewIOCountsForPID(pid)
                # pp.pprint(self.pid_dict[pid])
                # print(self.pid_dict[pid]["IOCountsInitial"])
            except psutil.NoSuchProcess:
                del self.pid_dict[pid]
        
        self.updateEvents(count, max_events=50)
        
        if only_new:
            pid_dict_pids = set(self.pid_dict.keys())
            for pid in pid_dict_pids:
                if pid not in running_processes_pid:
                    # print(pid)
                    del self.pid_dict[pid]


    def checkDangerousProcessCreation(self):
        words_to_find = ["wbadmin","bcdedit","vssadmin","recoveryenabled","cmd","Win32_Shadowcopy","powershell"]
        words_to_find = ["wbadmin","bcdedit","vssadmin","recoveryenabled","Win32_Shadowcopy"]
        dangerous_commands = {}
        for pid in self.pid_dict:
            if "events" in self.pid_dict[pid] and "process_created" in self.pid_dict[pid]["events"]:
                for event in self.pid_dict[pid]["events"]["process_created"]:
                    event_parent = event["ParentProcessId"]
                    command = event["CommandLine"]
                    # print(command)
                    for word in words_to_find:
                        if command.find(word) != -1:
                            if command not in dangerous_commands:
                                dangerous_commands[command] = {"words":set(),"parents":{}}

                            dangerous_commands[command]["words"].add(word)
                            if event_parent not in dangerous_commands[command]["parents"]:
                                dangerous_commands[command]["parents"][event_parent] = set()
                            dangerous_commands[command]["parents"][event_parent].add(pid)
        return dangerous_commands

    def printDangerousProcessCheck(self,count=20):
        while True:
            self.getCurrentPIDs(count,max_events=10,only_new=False)
            os.system("cls")
            print("##############################")
            
            commands = self.checkDangerousProcessCreation()
            pp.pprint(commands)
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

    def eventsDistanceLessThan(self,seconds=1,number_of_actions=0):
        less_than_seconds_dict = {}
        ## handle events
        for pid in self.pid_dict:
            pid_in_mind = self.pid_dict[pid]
            if "events" in pid_in_mind:
                for category in pid_in_mind["events"]:
                    # if category not in 
                    less_than_seconds = 0
                    events = pid_in_mind["events"][category]
                    events_length = len(events)
                    if events_length > 1:
                        # stop = True
                        for events_index in range(1, events_length):
                            difference = (datetime.strptime(events[events_index]["UtcTime"], "%Y-%m-%d %H:%M:%S.%f") - datetime.strptime(events[events_index-1]["UtcTime"],
                                                                                                                                    "%Y-%m-%d %H:%M:%S.%f")).total_seconds()
                            if difference <= seconds:
                                less_than_seconds += 1
                    if less_than_seconds > 0:
                        if pid not in less_than_seconds_dict:
                            less_than_seconds_dict[pid] = {}
                        if less_than_seconds >= number_of_actions:
                            less_than_seconds_dict[pid][category] = less_than_seconds
                
                if pid in less_than_seconds_dict and len(less_than_seconds_dict[pid]) == 0:
                    del less_than_seconds_dict[pid]


        return less_than_seconds_dict

    def getDDL(self):
        import win32api
        import win32process
        import pywintypes

        pids_with_suspicious_dll = {}
        suspcious_dlls = ["bcrypt","crypt32","cryptbase","cryptsp"]
        while True:
            pids = win32process.EnumProcesses()
            for pid in pids:
                # pid = int(pid)
                try:
                    process = win32api.OpenProcess(0x0410, 0, pid)
                    try:
                        process_dlls = win32process.EnumProcessModules(process)
                        for dll in process_dlls:
                            win32process.GetModuleFileNameEx(process, dll)
                            dll_name = str(win32process.GetModuleFileNameEx(process, dll)).lower() 
                            ## -^^- takes the most time
                            for suspcious_dll in suspcious_dlls:
                                if suspcious_dll in dll_name:
                                    if pid not in pids_with_suspicious_dll:
                                        pids_with_suspicious_dll[pid] = {}
                                    if suspcious_dll not in pids_with_suspicious_dll[pid]:
                                        pids_with_suspicious_dll[pid][suspcious_dll] = []
                                    pids_with_suspicious_dll[pid][suspcious_dll].append(dll_name)
                            pass
                    finally:
                            win32api.CloseHandle(process)
                except pywintypes.error:
                        pass
            
        return pids_with_suspicious_dll
        
def test_dll_check():
    trick = trickster()
    trick.getCurrentPIDs(count=100, max_events=10)
    # pid = 17608S
    trick.getDDL()

def test_process_creation():
    trick = trickster()
    COUNT = 100
    SECONDS = 0.01
    trick.printDangerousProcessCheck(COUNT)


def test_too_many():
    NUMBER_OF_ACTIONS = 2
    COUNT = 100
    SECONDS = 0.003
    trick = trickster()
    trick.getCurrentPIDs(count=COUNT,max_events=10)
    while True:
        os.system('cls')
        trick.getCurrentPIDs(count=COUNT,max_events=10)
        pp.pprint(trick.eventsDistanceLessThan(seconds=SECONDS,number_of_actions=NUMBER_OF_ACTIONS))
        sleep(1)



def test_io():
    NUMBER_OF_ACTIONS = 10
    COUNT = 100
    SECONDS = 0.001
    trick = trickster()
    trick.getCurrentPIDs(count=COUNT,max_events=10)
    try:
        while True:
            print("######################################")
            pp.pprint(trick.overIOOccurencies(1,1))
            sleep(2)
    except KeyboardInterrupt:
        print(hello)


def test_heh_exe():
    while True:
        print("######################################")
        trick = trickster()
        trick.getCurrentPIDs()
        sleep(0.05)


if __name__ == "__main__":
    # test_new_pid()
    pp = pprint.PrettyPrinter(indent=4)
    test_dll_check()
