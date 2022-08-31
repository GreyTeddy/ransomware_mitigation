import pprint
import psutil
import os
from threading import Thread
from time import sleep, time
from datetime import datetime
from collections import OrderedDict
import xmltodict
import math
import win32con, win32api, win32evtlog

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

    honeypots = {}
    honeypot_folders = []
    main_drive = "C:"
    home_path = main_drive+os.environ["HOMEPATH"]
    # directory_paths = [home_path]
    directory_paths = [home_path]
    file_extensions = ["docx","pdf","txt","exe"]


    def createHoneyPotFiles(self):
        if self.home_path in self.directory_paths:
            for file in os.listdir(self.home_path):
                if file in ["Application Data","Cookies","Local Settings","My Documents","NetHood","PrintHood","Recent"]:
                    continue
                if os.path.isdir(self.home_path+"\\\\"+file):
                    # print(type(file))
                    self.directory_paths.append(self.home_path+"\\"+file)
            pp.pprint(self.directory_paths)
            pass
        # exit()
        for directory_path in self.directory_paths:
            # files on directory
            for file_extension in self.file_extensions:
                file_path = directory_path + "\\....trickster_honey."+ file_extension
                print(1,"\t\t",file_path)
                with open(file_path,"w") as file:
                    win32api.SetFileAttributes(file_path,win32con.FILE_ATTRIBUTE_HIDDEN)
                    file.write(f"Hello, from trickster!")
                    self.honeypots[file_path] = {"file_modified":int(os.path.getmtime(file_path))}
            
            # create folder
            folder_path = directory_path+"\\....trickster_honeycomb"
            os.makedirs(folder_path)
            win32api.SetFileAttributes(folder_path,win32con.FILE_ATTRIBUTE_HIDDEN)
            self.honeypot_folders.append(folder_path)

            # files inside honey folder inside directory
            for file_extension in self.file_extensions:
                print(2,"\t\t",file_path)
                file_path = directory_path + "\\....trickster_honeycomb\\....trickster_honey."+ file_extension
                with open(file_path,"w") as file:
                    win32api.SetFileAttributes(file_path,win32con.FILE_ATTRIBUTE_HIDDEN)
                    file.write(f"Hello, from trickster!")
                    self.honeypots[file_path] = {"file_modified":int(os.path.getmtime(file_path))}

    def getEntropy(self,file_content: str,file_size: int):
        # from 
        # https://stackoverflow.com/questions/59528143/compute-entropy-of-a-pickle-file
        byte_counters = {byte: 0 for byte in range(2 ** 8)}
        for byte in file_content:
            byte_counters[ord(byte)] += 1 
        probs = [byte_counter / file_size for byte_counter in byte_counters.values()]
        entropy = -sum(prob * math.log2(prob) for prob in probs if prob > 0)
        return entropy

    def getFileMetaDataChange(self,file_path: str):
        one = int(os.path.getmtime(file_path))
        two = self.honeypots[file_path]["file_modified"]
        return self.honeypots[file_path]["file_modified"] != int(os.path.getmtime(file_path))

    def checkHoneyPotFiles(self):
        # [file does not exist, file time has been modified ]
        for file_path in self.honeypots:
            if not os.path.exists(file_path):
                # if the file has changed or been deleted
                return [True,False,False]
            elif self.getFileMetaDataChange(file_path):
                # if the file has been modified
                return [False,True,False]
            
        return [False,False,False]


    def removeHoneyPotFiles(self):
        if len(self.honeypots) > 0:
            for file_path in self.honeypots:
                os.remove(file_path)
            for folder_path in self.honeypot_folders:
                os.rmdir(folder_path)
                    

def test_honeypot():
    trick = trickster()
    trick.createHoneyPotFiles()
    print("checking")
    print(trick.honeypots)
    try:
        while True:
            print("hello")
            print()
            if True in trick.checkHoneyPotFiles():
                print("found")
                raise KeyboardInterrupt
            # print("done")
            sleep(0.1)
    except KeyboardInterrupt:
        trick.removeHoneyPotFiles()
    # trick.removeHoneyPotFiles()


def test_dll_check():
    trick = trickster()
    trick.getCurrentPIDs(count=100, max_events=10)
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
    test_honeypot()
