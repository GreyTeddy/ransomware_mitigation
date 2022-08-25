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
# import win32process
# import pywintypes
import subprocess
from winappdbg import EventHandler
from winappdbg.win32 import PVOID, BOOL, DWORD, HANDLE

import tkinter

#########################################################################################
"""
Variables
"""
white_list = set()

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
directory_paths = [home_path]
# directory_paths = ["."]
# directory_paths = [".",home_path]

file_extensions = ["docx", "pdf", "txt", "exe"]
dangerous_honeypot_edits = {}


keywords_to_find = ["wbadmin", "bcdedit", "vssadmin", "delete",
                    "taskkill.exe /f /im", "wmic shadowcopy delete", "icacls . /grant Everyone"]


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
        EventData = {}
        for e in res['Event']['EventData']['Data']:
            if '#text' in e:
                EventData[e['@Name']] = e['#text']

        EventList.append(EventData)
    return EventList


def findQuickFileCreationEvents():
    update_after_seconds = 0.001
    events_count = 3
    files_created_time_threshold = 3
    while True:
        start = time()
        Events = searchEvent(
            'Microsoft-Windows-Sysmon/Operational', event_categories["file_created"], count=events_count)

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

                if less_than_seconds > 1:
                    debugPIDThread(int(event_pid))
                    if "ParentProcessId" in event:
                        debugPIDThread(int(event["ParentProcessId"]))
        stop = time()
        print("quick file creation" + str(stop-start))
        sleep(update_after_seconds)


def findDangerousProcessCreatedEvents():
    update_after_seconds = 0.001
    events_count = 2
    LogName = "Microsoft-Windows-Sysmon/Operational"
    EventLog = win32evtlog.EvtOpenLog(LogName, 1, None)
    while True:
        start = time()
        ResultSet = win32evtlog.EvtQuery(
            LogName, win32evtlog.EvtQueryReverseDirection, "*[System[(EventID="+ event_categories['process_created'] + ")]]", None)
        for evt in win32evtlog.EvtNext(ResultSet, events_count):
            res = win32evtlog.EvtRender(evt, 1)
            for keyword in keywords_to_find:
                start_index = res.find(keyword)
                if start_index != -1:
                    print("found", keyword)
                    pp.pprint(res)
                    start_index = res.find("ProcessId'>") + 11
                    stop_index = res.find("<", start_index)
                    pid = int(res[start_index:stop_index], base=16)
                    suspendAndCreateWindow(pid, reason="Dangerous Process:" + keyword + "found")
                    start_index = res.find("ParentProcessId'>") + 17
                    stop_index = res.find("<", start_index)
                    parent_pid = int(res[start_index:stop_index], base=16)
                    suspendAndCreateWindow(parent_pid, reason="Dangerous Process:" + keyword + "found")
                    # return
        stop = time()
        print("dangerous process: " + str(stop-start))
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
    set_variable_command = '$AuditUser = "%s";$AuditRules = "%s";$InheritType = "%s";$AuditType = "%s"' % (audit_user, audit_rules, inherit_type, audit_type )
    get_audit_command = '$AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule($AuditUser,$AuditRules,$InheritType,"None",$AuditType)'
    get_target_file = "$TargetFile = '%s'" % (target_file)
    set_audit_command = '$ACL = Get-Acl $TargetFile;$ACL.SetAuditRule($AccessRule);Write-Host "Processing >",$TargetFile;$ACL | Set-Acl $TargetFile'
    command = set_variable_command + ";" + get_audit_command + \
        ";"+get_target_file + ";" + set_audit_command
    result = subprocess.call(
        ["powershell", "-Command", command])

    for file_path in honeypots:
        command = 'Get-Acl temporary_folder -Audit | Set-Acl ' + file_path
        result = subprocess.call(
            ["powershell", "-Command", command])
        # if result.stderr == "":
        print(file_path, "set to be audited")
        # return None

    os.rmdir(".\\temporary_folder")


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
                file.write("Hello, from trickster!")
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
                file.write("Hello, from trickster!")
                honeypots[file_path] = {
                    "file_modified": int(os.path.getmtime(file_path))}

    print("Honeypot files created!!#########################")


def getFileMetaDataChange(file_path):
    one = int(os.path.getmtime(file_path))
    two = honeypots[file_path]["file_modified"]
    return honeypots[file_path]["file_modified"] != int(os.path.getmtime(file_path))


def checkHoneyPotFiles():
    update_after_seconds = 0.001
    while True:
        start = time()
        # [file does not exist, file time has been modified ]
        for file_path in honeypots:
            if not os.path.exists(file_path) or getFileMetaDataChange(file_path):
                for pid in new_pid:
                    debugPIDThread(pid)
        stop = time()
        print("honeypot check:" + str(stop-start))
        sleep(update_after_seconds)


def removeHoneyPotFiles():
    if len(honeypots) > 0:
        for file_path in honeypots:
            os.remove(file_path)
        for folder_path in honeypot_folders:
            for file in os.listdir(folder_path):
                os.remove(folder_path+"\\"+file)
            os.rmdir(folder_path)


def checkAuditForHoneypot():
    update_after_seconds = 0.001
    # Clear security log for clean slate
    clear_security_log = subprocess.call(
        ["powershell", "-Command", 'Clear-EventLog -LogName Security'])
    event_count = 5
    while True:
        start = time()
        LogName = "Security"
        EventId = "4656"
        # EventLog = win32evtlog.EvtOpenLog(LogName, 1, None)
        # print("*[System[(EventID={"+EventId+"})]]")
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
                suspendAndCreateWindow(pid, reason="Honeypot file edited")
                parrent_pid = psutil.Process(pid).ppid()
                suspendAndCreateWindow(parrent_pid, reason="Honeypot file edited")
            pass
        pass

        stop = time()
        print("honeypot audit:" + str(stop-start))

        sleep(update_after_seconds)


#########################################################################################
# Debug checks
class MyEventHandler(EventHandler):
    print("event loaded")
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
        for keyword in keywords_to_find:
            if keyword in command:
                suspendAndCreateWindow(event.get_pid(), reason = "Dangerous Process Command: "+command)

        print(return_string_ansi(lpCommandLine))

    def pre_CreateProcessW(self, event, ra, lpApplicationName, lpCommandLine,
                           lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                           lpStartupInfo, lpProcessInformation):
        command = return_string_unicode(lpCommandLine)
        for keyword in keywords_to_find:
            if keyword in command:
                suspendAndCreateWindow(event.get_pid(), reason = "Dangerous Process Command: "+command)
        print(return_string_unicode(lpCommandLine))

    def return_string_ansi(self, event,  pointer):
        return event.get_process().peek_string(pointer)

    def return_string_unicode(self, event, pointer):
        return event.get_process().peek_string(pointer, fUnicode=True)

    def pre_CreateFileA(self, event, ra, lpFileName, dwDesiredAccess,
                        dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                        dwFlagsAndAttributes, hTemplateFile):
        if "trickster" in self.return_string_ansi(event, lpFileName):
            print("file opened/created", self.return_string_ansi(event, lpFileName))
            print(event.get_pid(), self.return_string_ansi(event, lpFileName))
            suspendAndCreateWindow(event.get_pid(), reason= "Attempted to open/edit honeypot file")

    def pre_CreateFileW(self, event, ra, lpFileName, dwDesiredAccess,
                        dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                        dwFlagsAndAttributes, hTemplateFile):
        print("file created/opened", self.return_string_unicode(event, lpFileName))
        if "trickster" in self.return_string_unicode(event, lpFileName):
            print(event.get_pid(), self.return_string_unicode(event, lpFileName))
            suspendAndCreateWindow(event.get_pid(), reason= "Attempted to open/edit honeypot file")

    def return_string_ansi(self, event,  pointer):
        return event.get_process().peek_string(pointer)

    def return_string_unicode(self, event, pointer):
        return event.get_process().peek_string(pointer, fUnicode=True)

    def load_dll(self, event):
        module = event.get_module()
        if module.match_name("kernel32.dll"):
            pid = event.get_pid()
            address = module.resolve("WriteFile")
            signature = (HANDLE, PVOID, DWORD, PVOID, PVOID)
            event.debug.hook_function(
                pid, address, self.writeFileCheck, signature=signature)
            address = module.resolve("WriteFileEx")
            event.debug.hook_function(
                pid, address, self.writeFileCheck, signature=signature)

    # This function will be called when the hooked function is entered.
    def writeFileCheck(self, event, ra, hFile, lpFlpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):
        # Get the format string.
        entropy = self.getEntropy(self.return_string_ansi(event, lpFlpBuffer))
        print("entropy" + str(entropy))
        if entropy > 4.5:
            suspendAndCreateWindow(event.get_pid(), reason="Writing with high entropy")

    def getEntropy(self, buffer_content):
        # from
        # https://stackoverflow.com/questions/59528143/compute-entropy-of-a-pickle-file
        buffer_size = len(buffer_content)
        byte_counters = {byte: 0 for byte in range(2 ** 16)}
        for byte in buffer_content:
            byte_counters[ord(byte)] += 1.0
        probs = [byte_counter /
                 buffer_size for byte_counter in byte_counters.values()]
        entropy = -sum(prob * math.log(prob, 2) for prob in probs if prob > 0)
        return entropy


def setupDebug(pid):
    with Debug(MyEventHandler()) as debug:
        debug.attach(pid)
        debug.loop()
        pass

#########################################################################################
##### handle dangerous pid

def debugPIDThread(pid):
    ### create a thread for debugging
    # check if process is not already in debugging
    # nad check if process still exists
    if pid not in in_debugging and pid not in white_list and psutil.pid_exists(pid):
        in_debugging.add(pid)
        threading.Thread(target=setupDebug,args=(pid,))


def suspendAndCreateWindow(pid, reason = "No Reason Given"):
    #### suspend process and create window 
    # deal with try catch 
    # so no need to check if pid exists 
    try:
        process = psutil.Process(pid)
        if not process.status() == "stopped":
            process.suspend()
            print("process "+ str(process.pid()) + "suspended")
    except psutil.NoSuchProcess:
        return

    window.title("PID: "+str(pid)+", Name: "+process.name()+ " Reason: " + reason)
    # set window width and height
    def resume_and_whitelist():
        process.resume()
        white_list.add(str(pid))
        window.destroy()
    def close_and_exit():
        process.terminate()
        window.destroy()

    btn1 = tk.Button(window, text = 'Resume', bd = '5',
                command = resume_and_whitelist).pack()
    btn2 = tk.Button(window, text = 'Quit', bd = '5',
                command = close_and_exit).pack()
    window.geometry("400x200")
    window.mainloop()


    # create window for user to select road of action
    
    


#########################################################################################
"""
Running the application
"""


def getThread(function, arguments):
    return threading.Thread(target=function, args=arguments)


def runWithTheads():
    ##########################################################
    # Threading

    checkHoneyPotFiles_thread = threading.Thread(target=checkHoneyPotFiles)
    checkHoneyPotFiles_thread.daemon = True
    findQuickFileCreationEvents_thread = threading.Thread(target=findQuickFileCreationEvents)
    findQuickFileCreationEvents_thread.daemon = True
    findDangerousProcessCreatedEvents_thread = threading.Thread(target=findDangerousProcessCreatedEvents)
    findDangerousProcessCreatedEvents_thread.daemon = True
    checkAuditForHoneypot_thread = threading.Thread(target=checkAuditForHoneypot)
    checkAuditForHoneypot_thread.daemon = True

    findQuickFileCreationEvents_thread.start()
    checkHoneyPotFiles_thread.start()
    findDangerousProcessCreatedEvents_thread.start()
    checkAuditForHoneypot_thread.start()

    try:
        while True:
            sleep(1)
    finally:
        # removeHoneyPotFiles()
        exit()


if __name__ == "__main__":
    pp = pprint.PrettyPrinter(indent=1)
    try:
        runWithTheads()
    finally:
        print("hello")
    # pp.pprint(pid_dict)

    # removeHoneyPotFiles()
    pass
