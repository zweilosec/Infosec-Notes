---
description: Introduction to Windows built-in commands and utilities
---

# **Windows Utilities**

These utilities can be combined in batch scripts or used interactively to automate and streamline system  management tasks. Most of these utilities are either built into the cmd shell, or are executables shipped with Windows that can mainly be found in `C:\Windows\System32\`. 

## **File and Directory Management**

Windows provides several utilities for managing files and directories directly from the command line. These commands allow users to create, delete, copy, move, and rename files and folders, as well as navigate and view the contents of the filesystem. 

| Utility    | Description                                         | Example Commands                                 | Built-in or Executable   |
|------------|-----------------------------------------------------|--------------------------------------------------|-------------------------|
| `cd`       | Change the current directory                        | `cd C:\Users\tester\Documents` – Navigate to the Documents folder for user `tester`.                   | Built-in                |
| `dir`      | List files and directories in the current location  | `dir /s /b` – List all files in the current directory and subdirectories in bare format.                | Built-in                |
| `mkdir`    | Create a new directory                              | `mkdir C:\NewFolder` – Create a folder named `NewFolder`.                                               | Built-in                |
| `rmdir`    | Remove a directory (optionally with contents)       | `rmdir /s /q C:\OldFolder` – Remove `OldFolder` and its contents without confirmation.                  | Built-in                |
| `copy`     | Copy files from one location to another             | `copy file.txt D:\Backup\` – Copy `file.txt` to the `Backup` folder.                                   | Built-in                |
| `xcopy`    | Copy files and directories, including subdirectories| `xcopy C:\Source D:\Dest /E /H /C /I` – Copy all files and subfolders from `Source` to `Dest`, including hidden and empty ones. | Executable (`xcopy.exe`)|
| `robocopy` | Advanced file and directory copy utility            | `robocopy C:\Source D:\Dest /MIR /Z /R:3` – Mirror `Source` to `Dest` with restartable mode and 3 retries. | Executable (`robocopy.exe`)|
| `move`     | Move or rename files and directories                | `move file.txt D:\Backup\` – Move `file.txt` to the `Backup` folder.                                   | Built-in                |
| `del`      | Delete one or more files                            | `del /F /Q file.txt` – Force delete `file.txt` without confirmation.                                   | Built-in                |
| `ren`      | Rename a file or directory                          | `ren oldname.txt newname.txt` – Rename `oldname.txt` to `newname.txt`.                                | Built-in                |
| `attrib`   | View or change file and directory attributes        | `attrib +H secret.txt` – Hide `secret.txt` by setting the Hidden attribute.                            | Executable (`attrib.exe`)|
| `tree`     | Display a graphical directory structure             | `tree C:\Projects /F` – Show the folder structure of `C:\Projects` including files.                    | Executable (`tree.com`) |
| `fsutil`   | Advanced file and volume management (admin only)    | `fsutil fsinfo drives` – List all drives on the system.                                                | Executable (`fsutil.exe`)|
| `type`     | Display the contents of a text file                 | `type file.txt` – Show the contents of `file.txt` in the terminal.                                     | Built-in                |
| `more`     | View file contents one screen at a time             | `type file.txt \| more` – Display `file.txt` one page at a time.                                       | Executable (`more.com`) |
| `fc`       | Compare the contents of two files                   | `fc file1.txt file2.txt` – Show differences between `file1.txt` and `file2.txt`.                       | Executable (`fc.exe`)   |
| `find`     | Search for text within a file                       | `find "keyword" file.txt` – Search for lines containing "keyword" in `file.txt`.                       | Executable (`find.exe`) |
| `findstr`  | Search for strings using patterns/regex             | `findstr /i "pattern" file.txt` – Search for "pattern" (case-insensitive) in `file.txt`.               | Executable (`findstr.exe`) |

### **Use Cases**

- **Bulk File Renaming:**  
  Use `for` loops in batch scripts to rename multiple files based on a pattern.  
  Example:  
  ```bat
  for %f in (*.txt) do ren "%f" "archived_%f"
  ```
  This prepends "archived_" to all `.txt` files in the current directory.

- **Automated Backup:**  
  Schedule a nightly backup of important folders using `robocopy` with logging.  
  Example:  
  ```bat
  robocopy C:\Projects D:\Backups\Projects /MIR /LOG:C:\BackupLogs\projects.log
  ```
  This mirrors the Projects folder and logs the operation.

- **Finding Large Files:**  
  Identify files over a certain size for cleanup using `forfiles`.  
  Example:  
  ```bat
  forfiles /S /M *.* /C "cmd /c if @fsize GTR 104857600 echo @path"
  ```
  This lists files larger than 100 MB.

- **Quick File Content Search:**  
  Search for a keyword in all `.log` files in a directory tree.  
  Example:  
  ```bat
  findstr /s /i "ERROR" *.log
  ```
  This finds all lines containing "ERROR" in `.log` files, case-insensitive.

- **Batch File Attribute Modification:**  
  Remove the read-only attribute from all files in a folder.  
  Example:  
  ```bat
  attrib -r *.* /s
  ```
  This clears the read-only flag recursively.

- **Generating Directory Listings:**  
  Create a text file listing all files and folders for documentation or auditing.  
  Example:  
  ```bat
  dir /s /b > directory_listing.txt
  ```
  This outputs a bare format recursive listing to a file.

- **Synchronizing Folders Across Drives:**  
  Use `xcopy` to copy only updated files between two directories.  
  Example:  
  ```bat
  xcopy C:\Source D:\Dest /D /E /H /Y
  ```
  This copies only newer files, including subfolders and hidden files.

- **Monitoring File Changes:**  
  Use `fsutil` to monitor NTFS USN journal for file changes (advanced).  
  Example:  
  ```bat
  fsutil usn readjournal C:
  ```
  This displays recent changes tracked by the NTFS journal.


## **System Information**

There are also several utilities for gathering detailed information about the system, hardware, and operating environment. These tools are useful for quickly gathering system diagnostics for troubleshooting, auditing, and inventory purposes.

| Utility         | Description                                                      | Example Commands                                                                                                   | Built-in or Executable         |
|-----------------|------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|-------------------------------|
| `systeminfo`    | Displays detailed system configuration, including OS version, hardware specs, memory, network adapters, and installed updates. | `systeminfo` – Show a summary of OS, hardware, and network info.                                                                  | Executable (`systeminfo.exe`) |
| `wmic`          | Windows Management Instrumentation Command-line: Query system information, hardware, processes, and more. | `wmic OS get Caption,Version,BuildNumber` – Display OS name and version.<br>`wmic cpu get name` – Show CPU model name.            | Executable (`wmic.exe`)       |
| `hostname`      | Displays the computer's network name.                            | `hostname` – Print the system's network hostname.                                                                                 | Executable (`hostname.exe`)   |
| `ver`           | Shows the Windows version.                                       | `ver` – Display the Windows version string.                                                                                       | Built-in                      |
| `set`           | Lists all environment variables and their values.                | `set` – List all environment variables and their current values.                                                                  | Built-in                      |
| `echo %PROCESSOR_ARCHITECTURE%` | Displays the processor architecture (e.g., x86, AMD64). | `echo %PROCESSOR_ARCHITECTURE%` – Print the CPU architecture (e.g., AMD64 for 64-bit).                                           | Built-in                      |
| `tasklist`      | Lists all running processes with their PID and memory usage.     | `tasklist /v` – Show detailed info (including memory and user) for all running processes.                                         | Executable (`tasklist.exe`)   |
| `driverquery`   | Lists all installed device drivers and their properties.         | `driverquery` – List all drivers, their status, and associated files.                                                             | Executable (`driverquery.exe`)|
| `msinfo32`      | Opens the System Information GUI tool for comprehensive details. | `msinfo32` – Launch the System Information GUI for a full hardware and software summary.                                          | Executable (`msinfo32.exe`)   |
| `whoami`        | Displays the current logged-in user and domain.                  | `whoami /all` – Show the current user, domain, and detailed security information (groups, privileges, etc.).                      | Executable (`whoami.exe`)     |

### **Common Use Cases:**
- **Display current user and privileges:** `whoami /priv`
- **Show only detailed OS info and installed hotfixes:** `systeminfo | findstr /B /C:"OS" /C:"Hotfix"`
- **List all logical drives:** `wmic logicaldisk get name`
- **Get BIOS version:** `wmic bios get smbiosbiosversion`
- **Show network adapter configuration:** `wmic nicconfig get description,ipaddress`
- **Display available memory:** `systeminfo | findstr /C:"Available Physical Memory"`
- **List running services:** `sc query`
- **Show current domain:** `echo %USERDOMAIN%`

## **Process and Task Management**

Other utilities include programs for viewing, managing, and controlling running processes and tasks directly from the command line. These tools are essential for monitoring system activity, troubleshooting issues, and automating administrative tasks.

| Utility         | Description                                                      | Example Commands                                         | Built-in or Executable         |
|-----------------|------------------------------------------------------------------|----------------------------------------------------------|-------------------------------|
| `tasklist`      | Lists all running processes with their PID, session name, and memory usage. | `tasklist /v` – Show detailed info for all processes.    | Executable (`tasklist.exe`)   |
| `taskkill`      | Terminates running processes by PID or image name.               | `taskkill /PID 1234 /F` – Force kill process with PID 1234.<br>`taskkill /IM notepad.exe /F` – Kill all Notepad processes. | Executable (`taskkill.exe`)   |
| `start`         | Launches a program, command, or script in a new window or background. | `start notepad.exe` – Open Notepad.<br>`start /b script.bat` – Run batch script in background. | Built-in                      |
| `wmic process`  | Queries and manages processes using Windows Management Instrumentation. | `wmic process list brief` – List processes.<br>`wmic process where name="notepad.exe" call terminate` – Kill Notepad. | Executable (`wmic.exe`)       |
| `tskill`        | Terminates a process by name or PID (legacy, less granular than `taskkill`). | `tskill notepad` – Kill all Notepad processes.           | Executable (`tskill.exe`)     |
| `pslist`        | Lists detailed process information (Sysinternals tool, not built-in). | `pslist` – List all processes.<br>`pslist -d` – Show thread and CPU details. | Executable (`pslist.exe`)     |
| `pskill`        | Terminates processes locally or remotely (Sysinternals tool).    | `pskill notepad` – Kill all Notepad processes.           | Executable (`pskill.exe`)     |

### **Common Use Cases:**
- **View running processes:** `tasklist`
- **Get detailed process info:** `tasklist /v` or `wmic process list full`
- **Kill a process by PID:** `taskkill /PID <PID> /F`
- **Kill a process by name:** `taskkill /IM <processname> /F`
- **Start a program in background:** `start /b <program>`

**Note:** For advanced process monitoring and management, consider using Sysinternals tools like [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) and [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec).

## **Networking Utilities**

There are also a range of command-line utilities for troubleshooting, configuring, and monitoring network connections. These tools are essential for diagnosing connectivity issues, viewing network statistics, and managing network resources.

| Utility         | Description                                                      | Example Commands                                                                 | Built-in or Executable         |
|-----------------|------------------------------------------------------------------|----------------------------------------------------------------------------------|-------------------------------|
| `ipconfig`      | Displays network adapter configuration, IP addresses, DNS, and more. | `ipconfig /all` – Show detailed network configuration.<br>`ipconfig /release` – Release DHCP lease.<br>`ipconfig /renew` – Renew DHCP lease. | Executable (`ipconfig.exe`)   |
| `netstat`       | Shows active network connections, listening ports, and routing tables. | `netstat -ano` – List all connections with PID.<br>`netstat -r` – Display routing table.<br>`netstat -e` – Show Ethernet statistics. | Executable (`netstat.exe`)    |
| `ping`          | Tests connectivity to a remote host by sending ICMP echo requests. | `ping 8.8.8.8` – Ping Google DNS.<br>`ping -t hostname` – Ping continuously.      | Executable (`ping.exe`)       |
| `tracert`       | Traces the route packets take to a destination host.             | `tracert www.microsoft.com` – Trace route to Microsoft.                          | Executable (`tracert.exe`)    |
| `nslookup`      | Queries DNS servers for domain name or IP address information.   | `nslookup example.com` – Get IP for a domain.<br>`nslookup` – Enter interactive mode. | Executable (`nslookup.exe`)   |
| `arp`           | Displays and modifies the ARP cache (IP-to-MAC address mapping). | `arp -a` – Show ARP table.<br>`arp -d *` – Clear ARP cache.                      | Executable (`arp.exe`)        |
| `route`         | Views and modifies the local IP routing table.                   | `route print` – Show routing table.<br>`route add 10.0.0.0 mask 255.0.0.0 192.168.1.1` – Add a route. | Executable (`route.exe`)      |
| `net use`       | Connects to, removes, and displays shared network resources.     | `net use Z: \\server\share` – Map a network drive.<br>`net use Z: /delete` – Remove mapped drive. | Executable (`net.exe`)        |
| `net share`     | Creates, deletes, and manages shared folders.                    | `net share myshare=C:\Data` – Share a folder.<br>`net share myshare /delete` – Remove share. | Executable (`net.exe`)        |
| `net view`      | Lists computers and shared resources on the network.             | `net view` – List computers.<br>`net view \\server` – List shares on a server.   | Executable (`net.exe`)        |
| `nbtstat`       | Displays NetBIOS over TCP/IP statistics and name tables.         | `nbtstat -n` – Show local NetBIOS names.<br>`nbtstat -A <ip>` – Query remote NetBIOS info. | Executable (`nbtstat.exe`)    |
| `hostname`      | Displays the local computer's network name.                      | `hostname` – Show the system's hostname.                                         | Executable (`hostname.exe`)   |

### **Common Use Cases:**
- **Check IP configuration:** `ipconfig /all`
- **Test network connectivity:** `ping <hostname or IP>`
- **View open network connections:** `netstat -ano`
- **Trace network path:** `tracert <destination>`
- **Query DNS records:** `nslookup <domain>`
- **Map/unmap network drives:** `net use Z: \\server\share` / `net use Z: /delete`
- **List network shares:** `net share` or `net view \\server`

**Note:** For advanced network monitoring and troubleshooting, consider using Sysinternals tools like [TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) or third-party utilities such as Wireshark.


## The 'Net' Commands

The Windows **`net`** commands are a set of command-line tools that allow administrators and users to perform a variety of tasks related to system configurations, network services, and security. The main executable, **`net.exe`**, is typically located in the `C:\Windows\System32\` directory. On modern Windows systems, `net.exe` may also invoke **`net1.exe`** (also in `System32`) for certain operations, especially when running in environments where legacy compatibility or specific command parsing is required. This fallback helps ensure consistent behavior across different Windows versions and scenarios.

##### Common Use Cases for `net` Commands

The many use cases make knowing the `net` commands essential for system administrators and power users managing Windows environments.

- **User and Group Management**
  - Create, modify, or delete local user accounts (`net user`)
  - Add or remove users from local groups (`net localgroup`)
  - Reset user passwords or unlock accounts

- **Network Resource Management**
  - Map or disconnect network drives (`net use`)
  - List available network shares and computers (`net view`)
  - Create or remove shared folders (`net share`)
  - Manage and monitor open files on a server (`net file`)

- **Service Control**
  - Start or stop Windows services (`net start`, `net stop`)
  - List all running services

- **Session and Connection Management**
  - View or disconnect active sessions on a server (`net session`)
  - Monitor who is connected to a shared resource

- **Account and Security Policy Management**
  - Set password and logon policies (`net accounts`)
  - Enforce password complexity or expiration rules

- **Network Diagnostics and Statistics**
  - View network statistics for the workstation or server (`net statistics`)
  - Check print jobs on network printers (`net print`)

- **Time Synchronization**
  - Synchronize the system clock with a network time server (`net time`)
  - Check system uptime `net statistics workstation`

- **Domain and Group Management (on domain-joined systems)**
  - Manage global groups in Active Directory (`net group`)
  - Execute user or group commands on a domain controller (`/domain` flag)

Here’s a **brief overview** of some of the key `net` commands:

| Command | Description | Example Use Case | Common Options |
|---------|------------|------------------|----------------|
| **net user** | Manages user accounts on a computer. You can add, remove, and modify users. | `net user tester /add` – Adds a new user named `tester`. | `/delete` – Remove a user, `/domain` – Execute on a domain controller. |
| **net localgroup** | Manages local groups on the computer. You can add, remove, and list members. | `net localgroup Administrators tester /add` – Adds `tester` to the Administrators group. | `/delete` – Remove a group, `/add` – Create a new group. |
| **net share** | Creates, deletes, and manages shared resources on the network. | `net share myshare=C:\MyFolder /grant:tester,full` – Creates a share named `myshare` with full access for user `tester`. | `/delete` – Stop sharing a resource, `/grant` – Assign access permissions. |
| **net start / stop** | Starts or stops network services. | `net start "Web Client"` – Starts the Web Client service. | Specify service names to start or stop. |
| **net session** | Displays all current sessions or disconnects them. | `net session \\RemotePC /delete` – Disconnects the session with `RemotePC`. | `/delete` – End a session. |
| **net use** | Connects, disconnects, and displays shared network resources. | `net use Z: \\Server\Share` – Maps the network share at `\\Server\Share` to the `Z:` drive. | `/delete` – Disconnect a network drive, `/persistent` – Make the connection persistent across reboots. |
| **net view** | Displays a list of computers or network resources. | `net view \\Server` – Shows shared resources on the server named `Server`. | `/domain` – List domains or computers in a domain. |
| **net accounts** | Displays or modifies password and logon policies for user accounts. | `net accounts /maxpwage:90` – Set maximum password age to 90 days. | `/forcelogoff` – Force logoff after inactivity, `/minpwlen` – Set minimum password length. |
| **net statistics** | Displays statistics for network services like Workstation or Server. | `net statistics workstation` – View workstation statistics. | Specify `workstation` or `server` for different stats. |
| **net print** | Displays or manages print jobs on a network printer. | `net print \\Server\Printer` – View print jobs on a shared printer. | `/delete` – Remove a print job. |
| **net file** | Displays open files on a network and allows closing them. | `net file` – View open files. | `/close` – Close an open file. |
| **net group** | Manages global groups on a domain. | `net group "IT Admins" /add` – Creates a new global group named "IT Admins". | `/delete` – Remove a group, `/add` – Create a new group. |
| **net time** | Synchronizes the system clock with a network time server. | `net time \\Server /set /yes` – Sync time with `Server`. | `/querysntp` – Query the SNTP time server. |

## Graphical Utilities

Windows includes many graphical utilities that expose system configuration, diagnostics, and security‑relevant information. These can be useful to know which interfaces reveal high‑value system data, without delving into the command line. 

| Utility | Path / Command | What It Shows | Red Team–Relevant Insight (Defensive Framing) |
|--------|----------------|---------------|-----------------------------------------------|
| **System Information** | `msinfo32` | Hardware, drivers, startup items | Highlights where to look for weak drivers, outdated firmware, or misconfigured startup entries—useful for understanding exposure points. |
| **Task Manager** | `taskmgr` | Processes, startup apps, services | Shows how security-related and malicious processes would appear. |
| **Resource Monitor** | `resmon` | Per‑process CPU, disk, and network activity | Reveals how noisy or anomalous activity looks in a GUI, helping assess operational stealth. |
| **Event Viewer** | `eventvwr.msc` | System and security logs | Shows which actions generate obvious logs, helping teams understand detection paths and improve log hygiene. |
| **Local Security Policy** | `secpol.msc` | Password, audit, and privilege policies | Exposes where weak configurations create opportunity, and where strong policies limit attacker movement. |
| **Group Policy Editor** | `gpedit.msc` | System and user policies | Helps identify which enforced policies restrict common attack paths and where misconfigurations create openings. |
| **Services Manager** | `services.msc` | Installed services and startup types | Hunt for security products, vulnerable services, and where to look for persistence mechanisms. |
| **Task Scheduler** | `taskschd.msc` | Scheduled tasks and triggers | Shows how scheduled persistence appears to administrators. |
| **Computer Management** | `compmgmt.msc` | Users, groups, disks, logs | Centralizes many surfaces defenders review, helping red teamers understand how quickly anomalies can be found. |
| **Performance Monitor** | `perfmon` | Long‑term performance metrics | Highlights how sustained resource usage becomes visible over time, informing operational discipline. |
| **Windows Firewall (Advanced)** | `wf.msc` | Inbound/outbound rules | Shows which network paths are allowed or blocked, helping assess realistic lateral movement constraints. |
| **Network & Sharing Center** | Control Panel | Network adapters and sharing settings | Reveals how unusual adapters, bridges, or sharing configurations can lead to further attack paths. |
| **Credential Manager** | Control Panel | Stored credentials | Shows where credential artifacts accumulate and how easily they can be reviewed or removed. |
| **Local Users & Groups** | `lusrmgr.msc` | Accounts and group memberships | Demonstrates how unauthorized accounts or privilege changes stand out in GUI audits. |
| **Disk Management** | `diskmgmt.msc` | Partitions and volumes | Shows how hidden or unexpected partitions would appear to administrators. |

## Sysinternals

If you don't know about Mark Russinovich's amazing tools then you should go and check them out. There are many, many use cases for these tools: from enumeration, persistence, threat-hunting, to ordinary system administration. While they are not built into the operating system (though they should be!), these tools are maintained and offered directly from Microsoft at [https://docs.microsoft.com/en-us/sysinternals/](https://docs.microsoft.com/en-us/sysinternals/).

Red-teamers and penetration testers can leverage Sysinternals tools for enumeration, privilege escalation, and lateral movement. This table includes a few of the Sysinternals tools useful for offensive security:

| Tool | Description | Example Use Case | Cyber Kill Chain Phase |
|------|------------|------------------|------------------------|
| **PsExec** | Executes processes remotely on another system. | Used for lateral movement by executing commands on remote hosts. | **Lateral Movement** |
| **AccessChk** | Checks user permissions for files, registry keys, and objects. | Identify privilege escalation opportunities by analyzing access control settings. | **Privilege Escalation** |
| **ProcMon (Process Monitor)** | Captures real-time system activity, including file, registry, and network events. | Monitor security controls and detect potential weaknesses in endpoint defenses. | **Exploitation** |
| **TCPView** | Monitors active TCP/UDP connections in real time. | Identify open ports and active connections for reconnaissance. | **Reconnaissance** |
| **Autoruns & Autorunsc** | Displays all auto-start programs, services, and registry entries. | Find persistence mechanisms used by malware or adversaries. | **Persistence** |
| **Handle** | Lists open handles to files, registry keys, and other system objects. | Investigate (i.e. unlock) locked files that may contain sensitive data or credentials. | **Credential Access** |
| **ListDLLs** | Displays loaded DLLs for running processes. | Identify DLL injection opportunities for stealthy code execution (i.e. Running malware) | **Defense Evasion** |
| **SigCheck** | Verifies digital signatures of files. | Detect unsigned or tampered executables that may be malicious. | **Execution** |
| **Strings** | Extracts readable text from binary files. | Analyze malware binaries for embedded commands or indicators of compromise. | **Reconnaissance** |
| **PsSuspend** | Suspends processes without terminating them. | Disable security tools temporarily during red-team operations. | **Defense Evasion** |

- A full list of the current tools can be found [here](https://learn.microsoft.com/en-us/sysinternals/downloads/).
- Sysinternals tools can be linked to directly and run in-memory from [https://live.sysinternals.com/](https://live.sysinternals.com/)
    - This command maps the current full list of Sysinternals tools to the first available drive letter as a network share, ready for use!
    ```powershell
    net use * //live.sysinternals.com
    ```
