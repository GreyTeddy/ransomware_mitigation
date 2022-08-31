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
    # "process_created": 1,
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

pid_dict = {}
white_list = set()
PYTHON_PID = str(os.getpid())
# categories_to_search = ["process_created", "file_created",
                        # "file_created", "registry_value_set","file_creation_time_changed"]
categories_to_search = list(categories_id.keys())


def update_events(count, max_events=20):
    for category in categories_to_search:
        # get #count events for category
        Events = search_event(
            'Microsoft-Windows-Sysmon/Operational', categories_id[category], count)

        for i in Events:
            if "ProcessId" in i:
                id_name = "ProcessId"
            elif "SourceProcessId" in i:
                id_name = "SourceProcessId"
            elif "ImageLoaded" in i:
                id_name = "ImageLoaded"
            if i[id_name] == PYTHON_PID:
                continue
            # if new PID
            if not i[id_name] in pid_dict:
                pid_dict[i[id_name]] = {}
                for new_category in categories_to_search:
                    pid_dict[i[id_name]][new_category] = []

            # distinguish events by time
            pid_dict[i[id_name]][category].append(i)

            if len(pid_dict[i[id_name]][category]) > max_events:
                pid_dict[i[id_name]][category].pop(0)


def actions_done_in_less_than(seconds=1,threshold=0):
    less_than_seconds_dict = {}
    for pid in get_running_pids():
    # for pid in pid_dict:
        for category in pid_dict[pid]:
            less_than_seconds = 0
            event_time = pid_dict[pid][category]
            event_time_length = len(event_time)
            if event_time_length > 1:
                for event_time_index in range(1, event_time_length):
                    # print(event_time[event_time_index]["UtcTime"])
                    difference = (datetime.strptime(event_time[event_time_index]["UtcTime"], "%Y-%m-%d %H:%M:%S.%f") - datetime.strptime(event_time[event_time_index-1]["UtcTime"],
                                                                                                                              "%Y-%m-%d %H:%M:%S.%f")).total_seconds()
                    if difference <= seconds:
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
                if less_than_seconds >= threshold:
                    less_than_seconds_dict[pid][category] = less_than_seconds
                    # print(event_time[event_time_index],event_time[event_time_index-1])

        if pid in less_than_seconds_dict and len(less_than_seconds_dict[pid]) == 0:
            del less_than_seconds_dict[pid]
                # exit()
    # pp.pprint(less_than_seconds_dict)
    return less_than_seconds_dict
    # exit()


def kill_if_too_many_actions(less_than_dictionary):
    # pp.pprint(less_than_dictionary)

    for pid in less_than_dictionary:
        for category in  less_than_dictionary[pid]:
            # pp.pprint(less_than_dictionary)
            # print("here")
            if category == "file_created":
                pp.pprint(less_than_dictionary)
                pp.pprint(pid_dict[pid][category])
                process = psutil.Process(int(pid))
                import tkinter
                window = tkinter.Tk()
                # set window title
                window.title("Suspended: "+str(pid)+" "+str(process.name()))
                # set window width and height
                def resume_and_continue():
                    process.resume()
                    white_list.add(str(pid))
                    window.destroy()
                
                def close_and_exit():
                    process.terminate()
                    del pid_dict[pid]
                    window.destroy()

                btn1 = tkinter.Button(window, text = 'Resume', bd = '5',
                          command = resume_and_continue).pack()
                btn2 = tkinter.Button(window, text = 'Quit', bd = '5',
                          command = close_and_exit).pack()
                window.geometry("500x200")
                process.suspend()
                window.mainloop()
                # exit()
                # exit()
                # print("here as well")
                

def get_running_pids():
    all_processes = []
    for proc in psutil.process_iter():
        all_processes.append(proc.pid)
    still_running = []
    for proc in all_processes:
        proc = str(proc)
        if proc in pid_dict.keys() and proc not in white_list:
            still_running.append(proc)
    return still_running


THRESHOLD = 10
COUNT = THRESHOLD
SECONDS = 0.001
while True:
    # os.system('cls')
    print('##############################')
    update_events(COUNT, 100)
    print("actions in less than ", SECONDS, "seconds")
    # pp.pprint(actions_done_in_less_than(SECONDS,THRESHOLD))
    kill_if_too_many_actions(actions_done_in_less_than(SECONDS,THRESHOLD))
    # print(pid_dict.keys())

    sleep(0.01)

# pp.pprint(pid_dict[i["ProcessId"]]["process_created"])
