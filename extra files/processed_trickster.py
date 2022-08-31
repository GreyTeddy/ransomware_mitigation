from multiprocessing import Queue
import Tkinter as tk
import pprint
import psutil
import os
import threading
import multiprocessing
from time import sleep, time
from datetime import datetime
import xmltodict
import math
import win32con
import win32api
import win32evtlog
# import win32process
# import pywintypes
import subprocess
from winappdbg import EventHandler, Debug, MixedBitsWarning, EventCallbackWarning
from winappdbg.win32 import PVOID, BOOL, DWORD, HANDLE
import warnings
warnings.filterwarnings("error")
#########################################################################################
"""
Variables
"""
# white_list = set()
old_pids = set()
suspended = set([1, 2, 3, 4, 5])
# for dlls
dangerous_dll_pids = {}

# for events
event_categories = {
    "process_created": "1",
    # "file_creation_time_changed": 2,
    # "process_terminated": 5,
    # "driver_loaded":6,
    # "image_loaded": 7,
    # "process_accessed": 10,
    "file_created": "11",
    # "registry_object_added_or_deleted": 12,
    # "registry_value_set": 13,
    # "sysmon_config_state_changed": 16,
    # "file_delete_archive": 23,
    # "file_delete_logged": 24
}
dangerous_event_process_created = {}
dangerous_event_file_created = {}
dangerous_event_file_deleted = {}


# for honeypot
honeypots = {}
honeypot_folders = []
main_drive = "C:"
home_path = main_drive+str(os.environ["HOMEPATH"])
directory_paths = [main_drive, home_path]
# directory_paths = ["."]
# directory_paths = [".", home_path]

file_extensions = ["docx", "pdf", "txt", "exe"]
dangerous_honeypot_edits = {}


keywords_to_find = ["wbadmin", "bcdedit", "vssadmin", "Win32_Shadowcopy"
                    "taskkill.exe /f /im", "shadowcopy delete", "icacls"]


in_debugging = set()

in_debugging_event = threading.Event()
#########################################################################################
"""
Handling Events
"""


#########################################################################################
"""
Handling Events
"""

# https://stackoverflow.com/questions/55701662/how-to-read-event-logs-under-applications-and-services-logs-in-python
def searchEvent(LogName, EventId, count=20):
    EventLog = win32evtlog.EvtOpenLog(LogName, 1, None)
    totalRecords = win32evtlog.EvtGetLogInfo(
        EventLog, win32evtlog.EvtLogNumberOfLogRecords)[0]
    # print(EventId)
    ResultSet = win32evtlog.EvtQuery(
        LogName, win32evtlog.EvtQueryReverseDirection, "*[System[(EventID=" + EventId + ")]]", None)
    EventList = []
    for evt in win32evtlog.EvtNext(ResultSet, count):
        res = xmltodict.parse(win32evtlog.EvtRender(evt, 1))
        # print(res)
        EventData = {}
        for e in res['Event']['EventData']['Data']:
            if '#text' in e:
                EventData[e['@Name']] = e['#text']

        EventList.append(EventData)
    return EventList


def findQuickFileCreationEvents(pid_to_suspend_queue):
    # print("checking events for quick file creation")
    update_after_seconds = 0.001
    events_count = 10
    files_created_time_threshold = 0.000
    python_pid = str(os.getpid())
    # print("python_pid", python_pid)
    while True:
        # start = time()
        Events = searchEvent(
            'Microsoft-Windows-Sysmon/Operational', event_categories["file_created"], count=events_count)

        file_create_events = {}
        for event in Events:
            event_pid = event["ProcessId"]
            if event_pid == python_pid:
                continue
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
                    # print()
                    if difference <= files_created_time_threshold:
                        less_than_seconds += 1

                if less_than_seconds > 5:
                    # debugPIDThread(int(event_pid))
                    try:
                        # psutil.Process(int(event_pid)).suspend()
                        pid_to_suspend_queue.put(
                            [int(event_pid), "quick_file_creation"])
                    except psutil.NoSuchProcess:
                        pass
                    # if "ParentProcessId" in event:
                    #     debugPIDThread(int(event["ParentProcessId"]))
        # stop = time()
        # print("quick file creation: " + str(stop-start))
        sleep(update_after_seconds)


def findDangerousProcessCreatedEvents(pid_to_suspend_queue, keywords_to_find):
    # print("checking for these keywords", keywords_to_find)
    update_after_seconds = 0.001
    events_count = 2
    LogName = "Microsoft-Windows-Sysmon/Operational"
    EventLog = win32evtlog.EvtOpenLog(LogName, 1, None)
    while True:
        # start = time()
        ResultSet = win32evtlog.EvtQuery(
            LogName, win32evtlog.EvtQueryReverseDirection, "*[System[(EventID=" + event_categories['process_created'] + ")]]", None)
        for evt in win32evtlog.EvtNext(ResultSet, events_count):
            res = win32evtlog.EvtRender(evt, 1)
            for keyword in keywords_to_find:
                start_index = res.find(keyword)
                if start_index != -1:
                    start_index = res.find("ProcessId'>") + 11
                    stop_index = res.find("<", start_index)
                    pid = int(res[start_index:stop_index])
                    pid_to_suspend_queue.put(
                        [pid, "Dangerous Process:" + keyword + " found"])
                    print(pid, "dangerous process " + keyword)
                    start_index = res.find("ParentProcessId'>") + 17
                    stop_index = res.find("<", start_index)
                    parent_pid = int(res[start_index:stop_index])
                    pid_to_suspend_queue.put(
                        [parent_pid, "Dangerous Parent Process:" + keyword + "found"])
                    print("parent ", parent_pid,
                          "dangerous parent process with keyword:" + keyword)
                    # return
        # stop = time()
        # print("dangerous process: " + str(stop-start))
        sleep(update_after_seconds)


#########################################################################################
"""
The Honeypot
"""


def setAuditInfoToHoneyPots():

    # set object access audit to true
    audit_pol = subprocess.call(
        ["powershell", "-Command", 'auditpol /set /category:"Object Access" /failure:enable /success:enable'])
    # print(audit_pol)

    # create a temporary folder
    os.mkdir("temporary_folder")

    # assign audit to the temporery folder
    target_file = "temporary_folder"
    audit_user = "Everyone"
    audit_rules = "CreateFiles, DeleteSubdirectoriesAndFiles, WriteAttributes, Delete"
    inherit_type = "ContainerInherit,ObjectInherit"
    audit_type = "Success,Failure"
    set_variable_command = '$AuditUser = "%s";$AuditRules = "%s";$InheritType = "%s";$AuditType = "%s"' % (
        audit_user, audit_rules, inherit_type, audit_type)
    get_audit_command = '$AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule($AuditUser,$AuditRules,$InheritType,"None",$AuditType)'
    get_target_file = "$TargetFile = '%s'" % (target_file)
    set_audit_command = '$ACL = Get-Acl $TargetFile;$ACL.SetAuditRule($AccessRule);Write-Host "Processing >",$TargetFile;$ACL | Set-Acl $TargetFile'
    command = set_variable_command + ";" + get_audit_command + \
        ";"+get_target_file + ";" + set_audit_command
    result = subprocess.call(
        ["powershell", "-Command", command])

    command = ""
    for file_path in honeypots:
        command += 'Get-Acl temporary_folder -Audit | Set-Acl ' + file_path + " ; "
    result = subprocess.call(
        ["powershell", "-Command", command])
    # if result.stderr == "":
    print("audit setup complete")
    # return None

    os.rmdir(".\\temporary_folder")
    print("finished audit setup")


def createHoneyPotFiles():
    if home_path in directory_paths:
        for file in ["Documents", "Downloads", "Desktop"]:
            # if file in ["Application Data", "Cookies", "Local Settings", "My Documents", "NetHood", "PrintHood", "Recent"]:
            #     continue
            if os.path.isdir(home_path+"\\\\"+file):
                # print(type(file))
                directory_paths.append(home_path+"\\"+file)
        pp.pprint(directory_paths)
        pass
    # exit()
    for directory_path in directory_paths:
        # files on directory
        for file_extension in file_extensions:
            file_path = directory_path + "\\!!!!trickster_honey." + file_extension
            print(1, "\t\t", file_path)
            with open(file_path, "w+") as file:
                win32api.SetFileAttributes(
                    file_path, win32con.FILE_ATTRIBUTE_HIDDEN)
                file.write("Hello, from trickster!")
                honeypots[file_path] = {
                    "file_modified": int(os.path.getmtime(file_path))}

        # create folder
        folder_path = directory_path+"\\!!!!trickster_honeycomb"
        honeypot_folders.append(folder_path)
        # os.makedirs(folder_path)
        try:
            os.makedirs(folder_path)
        except:
            removeHoneyPotFiles()
            createHoneyPotFiles()

        win32api.SetFileAttributes(folder_path, win32con.FILE_ATTRIBUTE_HIDDEN)

        # files inside honey folder inside directory
        for file_extension in file_extensions:
            print(2, "\t\t", file_path)
            file_path = directory_path + \
                "\\!!!!trickster_honeycomb\\!!!!trickster_honey." + file_extension
            with open(file_path, "w") as file:
                win32api.SetFileAttributes(
                    file_path, win32con.FILE_ATTRIBUTE_HIDDEN)
                file.write("Hello, from trickster!")
                honeypots[file_path] = {
                    "file_modified": int(os.path.getmtime(file_path))}

    print("Honeypot files created!!#########################")


def getFileMetaDataChange(file_path, honeypots):
    try:  # if file gets deleted in the process
        one = int(os.path.getmtime(file_path))
        two = honeypots[file_path]["file_modified"]
        return honeypots[file_path]["file_modified"] != int(os.path.getmtime(file_path))
    except WindowsError:
        return False


def checkHoneyPotFiles(pid_to_suspend_queue, old_pids, honeypots):
    # print("hellloooo")
    update_after_seconds = 0.001
    old_pids[os.getpid()] = "Checking Process"

    while True:
        # start = time()
        # print(honeypots)
        for file_path in honeypots.keys():
            # print("hello")
            if not os.path.exists(file_path) or getFileMetaDataChange(file_path, honeypots):
                # temp = set(psutil.pids())
                # old_pids = old_pids.intersection(temp)
                new_pids = set(psutil.pids()) - set(old_pids.keys())
                # print(set(psutil.pids()))
                # print()
                # print(set(old_pids.keys()))
                # print()
                # print(new_pids)
                # exit()
                for pid in new_pids:
                    # print("pid debug: ",pid)
                    # pid_to_suspend_queue(pid, pid_to_suspend_queue)
                    # suspendAndCreateWindowThread(pid)
                    # print(new_pids)
                    pid_to_suspend_queue.put([pid, "honeypot file check"])
                    break
        # stop = time()
        # print("honeypot check:" + str(stop-start))
        sleep(update_after_seconds)


def removeHoneyPotFiles():
    if len(honeypots) > 0:
        print("removing honeypots")
        for file_path in honeypots:
            os.remove(file_path)
        for folder_path in honeypot_folders:
            # for file in os.listdir(folder_path):
            #     os.remove(folder_path+"\\"+file)
            os.rmdir(folder_path)


def checkAuditForHoneypot(pid_to_suspend_queue):
    update_after_seconds = 0.001
    # Clear security log for clean slate
    clear_security_log = subprocess.call(
        ["powershell", "-Command", 'Clear-EventLog -LogName Security'])
    event_count = 5
    while True:
        # start = time()
        LogName = "Security"
        EventId = "4656"
        ResultSet = win32evtlog.EvtQuery(
            LogName, win32evtlog.EvtQueryReverseDirection, "*[System[(EventID="+EventId+")]]", None)
        for evt in win32evtlog.EvtNext(ResultSet, event_count):
            test = win32evtlog.EvtRender(evt, 1)
            start_index = test.find("ObjectName") + 12
            stop_index = test.find("<", start_index)
            object_name = test[start_index:stop_index]
            if "trickster" in object_name:
                test = test[stop_index:]
                start_index = test.find("ProcessId'>") + 11
                stop_index = test.find("<", start_index)
                pid = int(test[start_index:stop_index], base=16)
                pid_to_suspend_queue.put([pid, "Honeypot file edited"])
                try:
                    parrent_pid = psutil.Process(pid).ppid()
                except psutil.NoSuchProcess:
                    # print("parent not found for",pid)
                    continue  # skip parent pid if it not running anymore
                pid_to_suspend_queue.put([parrent_pid, "Honeypot file edited"])

            pass
        # stop = time()
        # print("honeypot audit:" + str(stop-start))
        pass


        sleep(update_after_seconds)


#########################################################################################
# Debug checks
class MyEventHandler(EventHandler):

    def __init__(self, pid_to_suspend_queue):
        self.pid_to_suspend_queue = pid_to_suspend_queue

    # print("event loaded")
    # print("keywords_to_find",keywords_to_find)
    apiHooks = {
        'kernel32.dll': [
            ('CreateProcessA', (PVOID, PVOID, PVOID, PVOID,
             BOOL, DWORD, PVOID, PVOID, PVOID, PVOID)),
            ('CreateProcessW', (PVOID, PVOID, PVOID, PVOID,
                                BOOL, DWORD, PVOID, PVOID, PVOID, PVOID)),
            ('CreateFileA', (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE)),
            ('CreateFileW', (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE)),
        ],
    }

    def pre_CreateProcessA(self, event, ra, lpApplicationName, lpCommandLine,
                           lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                           lpStartupInfo, lpProcessInformation):
        command = return_string_ansi(lpCommandLine)
        print("A command: "+command)
        for keyword in keywords_to_find:
            if keyword in command:
                self.pid_to_suspend_queue.put([
                    int(event.get_pid()), "Dangerous Process Command: "+command])

        print(return_string_ansi(lpCommandLine))

    def pre_CreateProcessW(self, event, ra, lpApplicationName, lpCommandLine,
                           lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                           lpStartupInfo, lpProcessInformation):
        command = return_string_unicode(lpCommandLine)
        print("W command: "+command)
        for keyword in keywords_to_find:
            if keyword in command:
                print("hello")
                self.pid_to_suspend_queue.put([
                    int(event.get_pid()), "Dangerous Process Command: "+command])
        print(return_string_unicode(lpCommandLine))

    def return_string_ansi(self, event,  pointer):
        return event.get_process().peek_string(pointer)

    def return_string_unicode(self, event, pointer):
        return event.get_process().peek_string(pointer, fUnicode=True)

    def pre_CreateFileA(self, event, ra, lpFileName, dwDesiredAccess,
                        dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                        dwFlagsAndAttributes, hTemplateFile):
        print("file opened/created A",
              self.return_string_ansi(event, lpFileName))
        if "trickster" in self.return_string_ansi(event, lpFileName):
            print(int(event.get_pid()), self.return_string_ansi(event, lpFileName))
            self.pid_to_suspend_queue.put([
                int(event.get_pid()), "Attempted to open/edit honeypot file"])

    def pre_CreateFileW(self, event, ra, lpFileName, dwDesiredAccess,
                        dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                        dwFlagsAndAttributes, hTemplateFile):
        print("file created/opened W", int(event.get_pid()),
              self.return_string_unicode(event, lpFileName), self.return_string_ansi(event, lpFileName), lpFileName)
        if "trickster" in self.return_string_unicode(event, lpFileName):
            print(int(event.get_pid()),
                  self.return_string_unicode(event, lpFileName))
            self.pid_to_suspend_queue.put([
                int(event.get_pid()), "Attempted to open/edit honeypot file"])

    def return_string_ansi(self, event,  pointer):
        return event.get_process().peek_string(pointer)

    def return_string_unicode(self, event, pointer):
        return event.get_process().peek_string(pointer, fUnicode=True)

    def load_dll(self, event):
        module = event.get_module()
        if module.match_name("kernel32.dll"):
            pid = int(event.get_pid())
            address = module.resolve("WriteFile")
            signature = (HANDLE, PVOID, DWORD, PVOID, PVOID)
            event.debug.hook_function(
                pid, address, self.writeFileCheck, signature=signature)
            address = module.resolve("WriteFileEx")
            # event.debug.hook_function(
            #     pid, address, self.writeFileCheck, signature=signature)

    # This function will be called when the hooked function is entered.
    def writeFileCheck(self, event, ra, hFile, lpFlpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):
        # Get the format string.
        entropy = self.getEntropy(self.return_string_ansi(event, lpFlpBuffer))
        # print("entropy: " + str(entropy),
        #       self.return_string_ansi(event, lpFlpBuffer))
        # print(entropy)
        # print()
        if entropy > 1.0:
            # print("entropyyyyyyyyyyyyyyy")
            # print(pid_to_suspend_queue)
            # print(self.pid_to_suspend_queue)
            self.pid_to_suspend_queue.put([
                int(event.get_pid()), "Writing with high entropy"])

    def getEntropy(self, buffer_content):
        # from
        # https://stackoverflow.com/questions/59528143/compute-entropy-of-a-pickle-file
        buffer_size = len(buffer_content)
        byte_counters = {byte: 0 for byte in range(2 ** 8)}
        for byte in buffer_content:
            byte_counters[ord(byte)] += 1.0
        probs = [byte_counter /
                 buffer_size for byte_counter in byte_counters.values()]
        entropy = -sum(prob * math.log(prob, 2) for prob in probs if prob > 0)
        return entropy


def setupDebug(pid_with_reason, pid_to_suspend_queue):
    with Debug(MyEventHandler(pid_to_suspend_queue)) as debug:
        try:
            # print("before attaching: "+str(pid))
            debug.attach(pid_with_reason[0])
            # print("attached: "+str(pid))
            debug.loop()
        except WindowsError:
            print("already debugging or no longer exists")
            return
        except (MixedBitsWarning):
            print("32bit detected")
            print(pid_with_reason)
            pid_to_suspend_queue.put([pid_with_reason[0], "32bit executable, likely dangerous"])
            return
        # except (EventCallbackWarning) as e:
        #     print(e)
        #     print("hello man")
        #     print(pid_with_reason)
        #     pid_to_suspend_queue.put([pid_with_reason[0], "debugger failed"])
        #     return
        pass

#########################################################################################
# handle dangerous pid


def suspendAndCreateWindow(pid_and_reason, white_list):
    try:
        process = psutil.Process(pid_and_reason[0])
        if process.name() in ["explorer.exe", "winlogon.exe", "python.exe"]:
            return
        print("hello")
        if not process.status() == "stopped":
            process.suspend()
            print("process " + str(pid_and_reason[0]) + "suspended")
            # suspended.add(pid_and_reason[0])
            # exit()
    except psutil.NoSuchProcess:
        print("no such process")
        return

    # print("this pid is going to make a window", pid)
    # print(pid_and_reason[0], suspended)
    window = tk.Tk()
    window.title("PID: "+str(pid_and_reason[0])+", Name: " +
                 process.name() + " Reason: " + pid_and_reason[1])
    # set window width and height
    text = tk.Text(window, height=8)
    text.pack()
    text.insert("1.0", "PID: "+str(pid_and_reason[0])+", Name: " +
                process.name() + " Reason: " + pid_and_reason[1])

    def resume_and_whitelist():
        try:
            process.resume()
        except psutil.NoSuchProcess:
            pass
        white_list[pid_and_reason[0]] = pid_and_reason[1]
        window.destroy()

    def close_and_exit():
        try:
            process.terminate()
        except psutil.NoSuchProcess:
            pass
        window.destroy()

    btn1 = tk.Button(window, text='Resume', bd='5',
                     command=resume_and_whitelist).pack()
    btn2 = tk.Button(window, text='Quit', bd='5',
                     command=close_and_exit).pack()
    window.geometry("400x200")
    # print("before the loop")
    window.mainloop()


#########################################################################################
"""
Running the application
"""


def checkWhiteList():
    update_after_seconds = 5
    while True:
        white_list_check = set(white_list)
        running_pids = psutil.pids()
        for pid in white_list_check:
            if int(pid) not in running_pids:
                white_list.remove(pid)
        sleep(update_after_seconds)


def getThread(function, arguments):
    return threading.Thread(target=function, args=arguments)


def checkingProcess(honeypots):
    ##########################################################
    # Variables
    # multi process accesible dictionary of whitelisted pids
    white_list = multiprocessing.Manager().dict({0: "System Process"})
    # multi process accesible dictionary of pids before checking
    old_pids = multiprocessing.Manager().dict()
    old = len(psutil.pids())
    print("number of processes before", len(psutil.pids()))
    for pid in psutil.pids():
        old_pids[pid] = "Old Process"

    pid_to_suspend_queue = Queue()  # multi process accesible queue for pids to suspend
    windowed_pids = set()  # set of already created pid windows
    debug_pids = set()
    debug = []
    windows = []  # store all the window processes

    ##########################################################
    # Processing
    checkHoneyPotFiles_process = multiprocessing.Process(
        target=checkHoneyPotFiles, args=(pid_to_suspend_queue, old_pids, honeypots))
    checkHoneyPotFiles_process.daemon = True
    checkHoneyPotFiles_process.start()

    findQuickFileCreationEvents_process = multiprocessing.Process(
        target=findQuickFileCreationEvents, args=(pid_to_suspend_queue,))
    findQuickFileCreationEvents_process.daemon = True
    findQuickFileCreationEvents_process.start()

    findDangerousProcessCreatedEvents_process = threading.Thread(
        target=findDangerousProcessCreatedEvents, args=(pid_to_suspend_queue, keywords_to_find))
    findDangerousProcessCreatedEvents_process.daemon = True
    findDangerousProcessCreatedEvents_process.start()

    checkAuditForHoneypot_processing = threading.Thread(
        target=checkAuditForHoneypot, args=(pid_to_suspend_queue,))
    checkAuditForHoneypot_processing.daemon = True
    checkAuditForHoneypot_processing.start()

    print("checking started")
    # try:
    new = len(psutil.pids())
    # print("number of processes after", len(psutil.pids()))
    # print("difference outside")
    while True:
        pid_and_reason = pid_to_suspend_queue.get()  # wait for a suspicious pid
        pid = int(pid_and_reason[0])
        if pid in old_pids.keys(): # if it is an id witnessed before the checking initialisation
            pass
        elif pid_and_reason[1] in ["quick_file_creation","honeypot file check"]:
            if pid not in debug_pids:
                print("this pid is going to be debuged", pid)
                # print(pid)
                # input()
                debug_pids.add(pid)
                # print("debug_pids",debug_pids)
                debug.append(multiprocessing.Process(
                    target=setupDebug, args=(pid_and_reason, pid_to_suspend_queue)))
                debug[-1].daemon = True
                debug[-1].start()

        elif pid not in windowed_pids and pid not in white_list.keys():
            # print("here")
            print("pid_and_reason", pid_and_reason)
            windowed_pids.add(pid)
            windows.append(multiprocessing.Process(
                target=suspendAndCreateWindow, args=(pid_and_reason, white_list)))
            windows[-1].daemon = True
            windows[-1].start()


if __name__ == "__main__":
    pp = pprint.PrettyPrinter(indent=1)
    createHoneyPotFiles()
    honeypots = multiprocessing.Manager().dict(honeypots)
    setAuditInfoToHoneyPots()
    # print(honeypots)
    try:
        checkingProcess(honeypots)
    finally:
        print("goodbye,")
        removeHoneyPotFiles()
    # pp.pprint(pid_dict)

    # removeHoneyPotFiles()
    pass
