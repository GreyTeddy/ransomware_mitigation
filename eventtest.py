from time import sleep
from collections import OrderedDict
import os
import win32evtlog
import xmltodict

import psutil

import pprint
pp = pprint.PrettyPrinter(indent=4)

# https://stackoverflow.com/questions/55701662/how-to-read-event-logs-under-applications-and-services-logs-in-python


def SearchEvents(LogName, EventId, count=20):
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


categories_id = {
    "process_created": 1,
    "file_creation_time_changed": 2,
    "process_terminated": 5,
    "image_loaded": 7,
    "file_created": 11,
    "process_accessed": 10,
    "registry_object_added_or_deleted": 12,
    "registry_value_set": 13,
    "sysmon_config_state_changed": 16,
    "file_delete_archive": 23,
    "file_delete_logged": 24
}

pid_dict = {}

categories_to_search = ["process_created", "file_created", "file_created"]
# categories_to_search = list(categories_id.keys())

def update_events(count):
    for category in categories_to_search:
        # get #count events for category
        Events = SearchEvents(
            'Microsoft-Windows-Sysmon/Operational', categories_id[category], count)

        for i in Events:
            if "ProcessId" in i:
                id_name = "ProcessId"
            else:
                id_name = "SourceProcessId"
            
            # if new PID
            if not i[id_name] in pid_dict:
                pid_dict[i[id_name]] = {}
                for new_category in categories_to_search:
                    pid_dict[i[id_name]][new_category] = OrderedDict()

            # distinguish events by time
            pid_dict[i[id_name]][category][i["UtcTime"]] = i

            if len(pid_dict[i[id_name]][category]) > 20:
                pid_dict[i[id_name]][category].popitem()

    # 
    while len(pid_dict[i[id_name]]) > 50:
        pid_dict[i[id_name]].popitem()
    

def frequency_of_actions():
    for pid in pid_dict:
        print(pid)
        for category in pid_dict[pid]:
            same_minute_seconds = {}
            print("\t", category)

            for time in pid_dict[pid][category].keys():
                split_time = time.split(":")
                if split_time[1] not in same_minute_seconds:
                    same_minute_seconds[split_time[1]] = []
                
                same_minute_seconds[split_time[1]].append(float(split_time[2]))
                print("\t\t",split_time)
                print("\t\t",same_minute_seconds)
            # for time in pid_dict[pid][category]:
            #     # if len(pid_dict[pid][category]) > 10:
            #     print("\t\t",time.split(":"))
    # exit()

COUNT = 2
while True:
    os.system('cls')
    print('##############################')
    update_events(COUNT)
    frequency_of_actions()
    # print(pid_dict.keys())
    all_processes = []
    for proc in psutil.process_iter():
        all_processes.append(proc.pid)
    

    # print(all_processes)
    # print(pid_dict.keys())

    for proc in all_processes:
        if proc in pid_dict.keys():
            print(proc)
    sleep(2)

# pp.pprint(pid_dict[i["ProcessId"]]["process_created"])
