# Ransomware Mitigation
This is a Python implementation of the checking functionality proposed for the detection of ransomware activity, with the purpose of encrypting files and taking appart services that provide recovery.

The checking is carried out 

- Through parsing information of Windows Event Logs from [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) and [Security Auditing](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview), 
- with the aid of [honeypot](https://en.wikipedia.org/wiki/Honeypot_(computing)) files placed in strategical places to tackle depth first and breadth first search
- and the implementation of multiprocessing for quick and independing 

When a processed is deemed malicious, the process is suspended and a window is created notifying the user of the activity done by the process and the user is then able to choose whether to terminate the process or resume, in case it is a false positive.



## Analysis

This repository also includes analysis done through the scraping of analysis of ransomware attribute with MITRE's ATT&CK technique [T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/), and through the analysis of the reports of ransomware samplies of those families through [JoeSandbox](https://www.joesandbox.com/).

## To Test
#### Beware: Use a secure sandboxed environment when testing any malicious code!
- Use Python 2.7
- Install Sysmon
- Install the modules required for python
    ```
        pip install  -r requirements.txt
    ```
- Run the implementation
    ```
        python processed_trickster.py
    ```
_This is a software implementation for the Thesis for the MSc Computing (Software Engineering) course at Imperial College London._
