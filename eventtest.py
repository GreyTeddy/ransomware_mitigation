from time import sleep, time
from datetime import datetime
from collections import OrderedDict
import os
import win32evtlog
import xmltodict

import psutil

import pprint
pp = pprint.PrettyPrinter(indent=4)

# https://stackoverflow.com/questions/55701662/how-to-read-event-logs-under-applications-and-services-logs-in-python


def search_event(LogName, EventId, count=20):
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


def update_events(count,max_events=20):
    for category in categories_to_search:
        # get #count events for category
        Events = search_event(
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

            if len(pid_dict[i[id_name]][category]) > max_events:
                pid_dict[i[id_name]][category].popitem()

    while len(pid_dict[i[id_name]]) > 20:
        pid_dict[i[id_name]].popitem()


def actions_done_in_less_than(seconds = 1):
    less_than_seconds_dict = {}
    for pid in get_running_pids():
        for category in pid_dict[pid]:
            less_than_seconds = 0
            event_time = list(pid_dict[pid][category].keys())
            event_time_length = len(event_time)
            if event_time_length > 1:
                for event_time_index in range(1,event_time_length):
                    difference = (datetime.strptime(event_time[event_time_index],"%Y-%m-%d %H:%M:%S.%f") - datetime.strptime(event_time[event_time_index-1],
                                                    "%Y-%m-%d %H:%M:%S.%f")).total_seconds()
                    if difference < seconds:
                        less_than_seconds += 1
                    # exit()
            if less_than_seconds > 0:
                # print(pid)
                # print("\t",category)
                # print("\t\t",event_time)
                # print("\t\t",less_than_seconds)
                # pp.pprint(pid_dict[pid][category])
                if pid not in less_than_seconds_dict:
                    less_than_seconds_dict[pid] = {}
                less_than_seconds_dict[pid][category] = less_than_seconds
                

                # exit()
    pp.pprint(less_than_seconds_dict)
        # exit()


def get_running_pids():
    all_processes = []
    for proc in psutil.process_iter():
        all_processes.append(proc.pid)
    still_running = []
    for proc in all_processes:
        proc = str(proc)
        if proc in pid_dict.keys():
            still_running.append(proc)
    return still_running


COUNT = 200
SECONDS = 0.05
while True:
    os.system('cls')
    print('##############################')
    update_events(COUNT,100)
    print("actions in less than ",SECONDS,"seconds")
    actions_done_in_less_than(SECONDS)
    # print(pid_dict.keys())

    sleep(2)

# pp.pprint(pid_dict[i["ProcessId"]]["process_created"])
