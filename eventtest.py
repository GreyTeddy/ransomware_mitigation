import win32evtlog
import xmltodict

import pprint
pp = pprint.PrettyPrinter(indent=4)

def SearchEvents(LogName, EventId, count=10):
    EventLog = win32evtlog.EvtOpenLog(LogName, 1, None)
    ResultSet = win32evtlog.EvtQuery(LogName, win32evtlog.EvtQueryReverseDirection, "*", None)
    
    EventList = []
    for evt in win32evtlog.EvtNext(ResultSet, count):
        xml_content = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
        print(xml_content)
        exit()
        # res = xmltodict.parse(win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml))
        pp.pprint(res)
        exit()
        EventData = {}
        for e in res:
            pp.pprint(res[e])
            print()
            exit()
            EventData[e['@Name']] = e['#text']

        EventList.append(EventData)

    return EventList



Events = SearchEvents('Microsoft-Windows-Sysmon/Operational', 10,1)
for i in Events:
    print(i)
    print("#############################################")
    break
print(len(Events))
