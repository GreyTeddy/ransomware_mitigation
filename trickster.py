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
        # try:
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

                read_count_difference = current_io.read_count - initial_io["read_count"]
                if read_count_difference > 1000:
                    print(pid, read_count_difference)
            except (psutil.NoSuchProcess, KeyError):
                continue

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
        for category in self.categories_to_search:
            # get #count events for category
            Events = self.searchEvent(
                'Microsoft-Windows-Sysmon/Operational', self.categories_id[category], count)

            for i in Events:
                if "ProcessId" in i:
                    id_name = "ProcessId"
                elif "SourceProcessId" in i:
                    id_name = "SourceProcessId"
                elif i[id_name] == PYTHON_PID:
                    continue
                else:
                    raise UserError #no pid found in events
                
                # turn pid string to integer
                i[id_name] = int(i[id_name])

                if i[id_name] not in self.pid_dict:
                    self.pid_dict[i[id_name]] = {"events":{}}
                elif "events" not in self.pid_dict[i[id_name]]:
                    self.pid_dict[i[id_name]]["events"] = {}
                else:
                    pass

                if category not in self.pid_dict[i[id_name]]["events"]:
                    self.pid_dict[i[id_name]]["events"][category] = []
                
                self.pid_dict[i[id_name]]["events"][category].append(i)

                if len(self.pid_dict[i[id_name]]["events"][category]) > max_events:
                    self.pid_dict[i[id_name]]["events"][category].pop(0)

                # if category == "file_created" and len(self.pid_dict[i[id_name]]["events"][category]) > 1:
                #     print(self.pid_dict[i[id_name]]["events"][category])
    
    def getCurrentPIDs(self,only_new = False,count=10,max_events=20):
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

    def IOCountsDistanceLessThan(self):
        pass

def test_process_creation():
    trick = trickster()
    COUNT = 100
    SECONDS = 0.001
    trick.printCommandsRun(COUNT)


def test_too_many():
    NUMBER_OF_ACTIONS = 10
    COUNT = 100
    SECONDS = 0.001
    trick = trickster()
    trick.getCurrentPIDs(count=COUNT)
    while True:
        os.system('cls')
        trick.getCurrentPIDs(count=COUNT)
        pp.pprint(trick.eventsDistanceLessThan(seconds=SECONDS,number_of_actions=NUMBER_OF_ACTIONS))
        sleep(1)


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
    test_io()
