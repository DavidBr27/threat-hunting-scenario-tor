<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/DavidBr27/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "davidcyberrange" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-03-21T05:24:05.2143324Z`. These events began at `2025-03-21T04:49:52.1710233Z`.

**Query used to locate events:**

```kql
DeviceFileEvents 
| where DeviceName == "test-vm-david" 
| where FileName contains "tor" 
| where InitiatingProcessAccountName == "davidcyberrange" 
| where TimeGenerated >= todatetime('2025-03-21T04:49:52.1710233Z') 
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = 
InitiatingProcessAccountName 
```

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/98239cac-0584-43bc-8322-7b01229a79d4">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-03-21T05:06:04.1276921Z`, an "davidcyberrange" on the "test-vm-david" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "test-vm-david"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7.exe"
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/76d56569-0306-4fb5-95c3-17003038ed52">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "davidcyberrange" actually opened the TOR browser. There was evidence that they did open it at `2025-03-21T05:07:14.6480093Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "test-vm-david"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, FolderPath, SHA256
| order by TimeGenerated desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/d984540d-1ec0-4fe2-a876-a44bd4d135f7">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-03-21T05:07:43.5428556Z`, an user "davidcyberrange" on the "test-vm-david" device successfully established a connection to the remote IP address `136.243.154.74` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\davidcyberrange\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "test-vm-david"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by TimeGenerated
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/43effc11-e3d6-49ec-a4e5-0434b2f6382e">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-03-21T04:49:52Z`
- **Event:** The user "davidcyberrange" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\davidcyberrange\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-03-21T05:06:04Z`
- **Event:** The user "davidcyberrange" executed the file `tor-browser-windows-x86_64-portable-14.0.7.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.7.exe /S`
- **File Path:** `C:\Users\davidcyberrange\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-03-21T05:07:14Z`
- **Event:** User "davidcyberrange" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\davidcyberrange\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-03-21T05:07:43Z`
- **Event:** A network connection to IP `136.243.154.74` on port `9001` by user "davidcyberrange" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\davidcyberrange\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamp:**
  - `2025-03-21T05:07:45Z` - Connected to `91.186.218.181` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-03-21T04:49:52Z`
- **Event:** The user "davidcyberrange" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** ` C:\Users\davidcyberrange\Desktop\tor-shopping-list.txt`

---

## Summary

The user "davidcyberrange" on the "test-vm-david" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `test-vm-david` by the user `davidcyberrange`. The device was isolated, and the user's direct manager was notified.

---
