import pprint
import psutil
import os
import threading
from time import sleep, time
from datetime import datetime
from collections import OrderedDict
import xmltodict
import math
import win32con
import win32api
import win32evtlog
import win32process
import pywintypes

#########################################################################################
"""
Variables
"""
white_list = set()

# for iocounts
pid_initial_iocounts = {}
dangerous_io_counts_pids = {}
io_categories = ['read_count', 'write_count', 'read_bytes',
                 'write_bytes', 'other_count', 'other_bytes']

# for dlls
dangerous_dll_pids = {}

# for events
event_categories = {
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
dangerous_event_process_created = {}
dangerous_event_file_created = {}


# for honeypot
honeypots = {}
honeypot_folders = []
main_drive = "C:"
home_path = main_drive+os.environ["HOMEPATH"]
# directory_paths = [home_path]
directory_paths = ["."]
file_extensions = ["docx", "pdf", "txt", "exe"]
dangerous_honeypot_edits = {}
#########################################################################################
"""
Handling IOCounts
"""


def checkIOCounts(update_after_seconds, write_read_ratio_threshold, byte_write_read_ratio_threshold):
    while True:
        for proc in psutil.process_iter():
            try:
                pid = proc.pid
                if pid not in pid_initial_iocounts:
                    pid_initial_iocounts[pid] = proc.io_counters()._asdict()
                now = proc.io_counters()._asdict()
                current_io_counters = {category: now[category] - pid_initial_iocounts[pid]
                                       [category] for category in pid_initial_iocounts[pid]}
            except psutil.NoSuchProcess:
                pass

            # check write/read ratio
            if current_io_counters['read_count'] > 0:
                write_read_ratio = current_io_counters['write_count'] / \
                    current_io_counters['read_count']
            else:
                write_read_ratio = 0

            # check byte write/read ratio
            if current_io_counters['read_bytes'] > 0:
                byte_write_read_ratio = current_io_counters['write_bytes'] / \
                    current_io_counters['read_bytes']
            else:
                byte_write_read_ratio = 0

            over_limit = {}
            if write_read_ratio >= write_read_ratio_threshold:
                over_limit["write_read_ratio"] = write_read_ratio
            if byte_write_read_ratio >= byte_write_read_ratio_threshold:
                over_limit["byte_write_read_ratio"] = byte_write_read_ratio

            if len(over_limit) > 0:
                dangerous_io_counts_pids[pid] = over_limit

        sleep(update_after_seconds)


#########################################################################################
"""
Handling DDLs
"""


def populateDDL(update_after_seconds, suspcious_dlls={"bcrypt": "encryption"}):
    while True:
        suspcious_dlls_found = {}
        for proc in psutil.process_iter():
            pid = proc.pid
            try:
                process = win32api.OpenProcess(0x0410, 0, pid)
                try:
                    process_dlls = win32process.EnumProcessModules(process)
                    for dll in process_dlls:
                        win32process.GetModuleFileNameEx(process, dll)
                        dll_name = str(win32process.GetModuleFileNameEx(
                            process, dll))
                        # -^^- takes the most time
                        for suspcious_dll in suspcious_dlls:
                            if suspcious_dll in dll_name.lower():
                                if pid not in suspcious_dlls_found:
                                    suspcious_dlls_found[pid] = {}
                                if suspcious_dll not in suspcious_dlls_found[pid]:
                                    suspcious_dlls_found[pid][dll_name] = suspcious_dlls[suspcious_dll]
                        pass
                finally:
                    win32api.CloseHandle(process)
            except pywintypes.error:
                pass

        dangerous_dll_pids = suspcious_dlls_found
        sleep(update_after_seconds)


#########################################################################################
"""
Handling Events
"""


def searchEvent(LogName, EventId, count=20):
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


def findQuickFileCreationEvents(update_after_seconds, events_count, files_created_time_threshold):
    while True:
        Events = searchEvent(
            'Microsoft-Windows-Sysmon/Operational', event_categories["file_created"], events_count)

        file_create_events = {}
        for event in Events:
            event_pid = event["ProcessId"]
            if event_pid not in file_create_events:
                file_create_events[event_pid] = []
            file_create_events[event_pid].append(event)

        for event_pid in file_create_events:
            events = file_create_events[event_pid]
            events_length = len(file_create_events[event_pid])
            if events_length > 1:
                less_than_seconds = 0
                for events_index in range(1, events_length):
                    difference = (datetime.strptime(file_create_events[event_pid][events_index-1]["UtcTime"], "%Y-%m-%d %H:%M:%S.%f") - datetime.strptime(file_create_events[event_pid][events_index]["UtcTime"],
                                                                                                                                                          "%Y-%m-%d %H:%M:%S.%f")).total_seconds()

                    if difference <= files_created_time_threshold:
                        less_than_seconds += 1

                if less_than_seconds > 0:
                    if event_pid not in dangerous_event_file_created:
                        dangerous_event_file_created[event_pid] = less_than_seconds
                    # print(event_pid)
                    if "ParentProcessId" in event:
                        parent_pid = event["ParentProcessId"]
                        if parent_pid not in dangerous_event_file_created:
                            dangerous_event_file_created[parent_pid] = 0
                        dangerous_event_file_created[parent_pid] += less_than_seconds
                        # print(event["ParentProcessId"])
        sleep(update_after_seconds)


def findDangerousProcessCreatedEvents(update_after_seconds, events_count, keywords_to_find):
    while True:
        Events = searchEvent(
            'Microsoft-Windows-Sysmon/Operational', event_categories["process_created"], events_count)
        for event in Events:
            event_parent_pid = event["ParentProcessId"]
            python_ids = [os.getpid(), os.getppid()]
            event_pid = event["ProcessId"]
            # skip if its from this program
            if event_parent_pid in python_ids or event_pid in python_ids:
                continue

            command = event["CommandLine"]
            # check comand for keywords
            for keyword in keywords_to_find:
                if command.find(keyword) != -1:
                    if event_parent_pid not in dangerous_event_process_created:
                        dangerous_event_process_created[event_parent_pid] = {}
                    if command not in dangerous_pids[event_parent]:
                        dangerous_pids[event_parent_pid][command] = {
                            "keywords": set()}

                    event_parent[event_parent_pid][command]["keywords"].add(
                        keyword)
        sleep(update_after_seconds)


#########################################################################################
"""
The Honeypot
"""


def createHoneyPotFiles():
    if home_path in directory_paths:
        for file in os.listdir(home_path):
            if file in ["Application Data", "Cookies", "Local Settings", "My Documents", "NetHood", "PrintHood", "Recent"]:
                continue
            if os.path.isdir(home_path+"\\\\"+file):
                # print(type(file))
                directory_paths.append(home_path+"\\"+file)
        pp.pprint(directory_paths)
        pass
    # exit()
    for directory_path in directory_paths:
        # files on directory
        for file_extension in file_extensions:
            file_path = directory_path + "\\....trickster_honey." + file_extension
            print(1, "\t\t", file_path)
            with open(file_path, "w") as file:
                win32api.SetFileAttributes(
                    file_path, win32con.FILE_ATTRIBUTE_HIDDEN)
                file.write(f"Hello, from trickster!")
                honeypots[file_path] = {
                    "file_modified": int(os.path.getmtime(file_path))}

        # create folder
        folder_path = directory_path+"\\....trickster_honeycomb"
        honeypot_folders.append(folder_path)
        # os.makedirs(folder_path)
        try:
            os.makedirs(folder_path)
        except FileExistsError:
            removeHoneyPotFiles()
            createHoneyPotFiles()
        
        win32api.SetFileAttributes(folder_path, win32con.FILE_ATTRIBUTE_HIDDEN)

        # files inside honey folder inside directory
        for file_extension in file_extensions:
            print(2, "\t\t", file_path)
            file_path = directory_path + \
                "\\....trickster_honeycomb\\....trickster_honey." + file_extension
            with open(file_path, "w") as file:
                win32api.SetFileAttributes(
                    file_path, win32con.FILE_ATTRIBUTE_HIDDEN)
                file.write(f"Hello, from trickster!")
                honeypots[file_path] = {
                    "file_modified": int(os.path.getmtime(file_path))}

    # print("Honeypot files created!!#########################")


def getEntropy(file_content: str, file_size: int):
    # from
    # https://stackoverflow.com/questions/59528143/compute-entropy-of-a-pickle-file
    byte_counters = {byte: 0 for byte in range(2 ** 8)}
    for byte in file_content:
        byte_counters[ord(byte)] += 1
    probs = [byte_counter / file_size for byte_counter in byte_counters.values()]
    entropy = -sum(prob * math.log2(prob) for prob in probs if prob > 0)
    return entropy


def getFileMetaDataChange(file_path: str):
    one = int(os.path.getmtime(file_path))
    two = honeypots[file_path]["file_modified"]
    return honeypots[file_path]["file_modified"] != int(os.path.getmtime(file_path))


def checkHoneyPotFiles(update_after_seconds):
    while True:
        # [file does not exist, file time has been modified ]
        for file_path in honeypots:
            if not os.path.exists(file_path):
                # if the file has changed or been deleted
                print("does not exist:",file_path)
                dangerous_honeypot_edits[file_path] = [True, False]
            elif getFileMetaDataChange(file_path):
                # if the file has been modified
                print("file has changed:",file_path)
                dangerous_honeypot_edits[file_path] = [False, True]

        sleep(update_after_seconds)


def removeHoneyPotFiles():
    if len(honeypots) > 0:
        for file_path in honeypots:
            os.remove(file_path)
        for folder_path in honeypot_folders:
            for file in os.listdir(folder_path):
                os.remove(folder_path+"\\"+file)
            os.rmdir(folder_path)


def findProcessThatEditedFile():

    searchEvent(LogName, event_categories["file_created"])

#########################################################################################
"""
Running the application
"""


def printPIDDict(update_after_seconds):
    while True:
        print("###########################")
        # pp.pprint(pid_dict)
        pids = list(pid_dict.keys())
        for pid in pids:
            if "events" in pid_dict[pid]:
                print(pid_dict[pid])
        sleep(update_after_seconds)


def getThread(function, arguments):
    return threading.Thread(target=function, args=arguments)


def runWithTheads():
    ##########################################################
    # Variables
    events_count = 100
    update_after_seconds = 0.001

    suspcious_dlls = {"bcrypt": "encryption", "crypt32": "encryption",
                      "cryptbase": "encryption", "cryptsp": "encryption"}

    keywords_to_find = ["wbadmin", "bcdedit", "vssadmin"]

    write_read_ratio_threshold = 1.5
    byte_write_read_ratio_threshold = 1.5

    files_created_time_threshold = 0.001

    ## Sequential Functions
    createHoneyPotFiles()

    ##########################################################
    # Initialise Threads

    arguments = (update_after_seconds, write_read_ratio_threshold,
                 byte_write_read_ratio_threshold)
    checkIOCounts_thread = getThread(checkIOCounts, arguments)

    arguments = (update_after_seconds, suspcious_dlls)
    populateDDL_thread = getThread(populateDDL, arguments)

    arguments = (update_after_seconds, events_count, keywords_to_find)
    findDangerousProcessCreatedEvents_thread = getThread(
        findDangerousProcessCreatedEvents, arguments)

    arguments = (update_after_seconds, events_count,
                 files_created_time_threshold)
    findQuickFileCreationEvents_thread = getThread(
        findQuickFileCreationEvents, arguments)

    arguments = (update_after_seconds,)
    checkHoneyPotFiles_thread = getThread(checkHoneyPotFiles, arguments)

    # Start Threads
    checkIOCounts_thread.start()
    populateDDL_thread.start()
    findDangerousProcessCreatedEvents_thread.start()
    findQuickFileCreationEvents_thread.start()
    checkHoneyPotFiles_thread.start()

    try:
        while True:
            sleep(1)
    finally:
        removeHoneyPotFiles()
        exit()


if __name__ == "__main__":
    pp = pprint.PrettyPrinter(indent=1)
    try:
        runWithTheads()
    finally:
        print("hello")
    # pp.pprint(pid_dict)