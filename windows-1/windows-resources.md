# Useful resources for Windows

## Windows Forensic Artifacts

| Resource | Best for | Why useful |
|---|---|---|
| https://github.com/Psmths/windows-forensic-artifacts/ | | |

## Process Identification

The resources in this section can be very useful for identifying processes on a Windows machine.


## Services

The resources in this section can be very useful for identifying services on a Windows machine.

| Resource | Best for | Why useful |
|---|---|---|
| [Windows Default Services (GitHub)](https://github.com/mentebinaria/win-default-services) | Services | Baseline of legitimate Windows services across Windows versions. |
| [Microsoft Service Documentation](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services) | | |


## Scheduled Tasks
| Resource | Best for | Why useful |
|---|---|---|
| [Windows Default Scheduled Tasks (GitHub)](https://github.com/mentebinaria/win-default-scheduled-tasks) | Scheduled tasks | Catalog of default tasks per Windows version; excellent for spotting malicious additions. |
| [Microsoft Task Scheduler Reference](https://learn.microsoft.com/windows/win32/taskschd) | Scheduled tasks | Official schema + documentation for legitimate system tasks. |

## Malware Triage

| **Resource** | **Useful For** | **Why It’s Useful** |
| --- | --- | --- |
| [Winbindex](https://winbindex.m417z.com) | Processes, DLLs | Lets you look up official Microsoft‑signed Windows binaries, versions, hashes, and metadata. Great for verifying legitimacy. |
| [File.net](https://www.file.net) | Processes | Large catalog of common Windows processes with descriptions and legitimacy indicators. |
| [ProcessLibrary.com](https://www.processlibrary.com) | Processes | Community database of Windows processes; helpful for quick “is this normal?” checks. |
| [Should I Block It?](https://www.shouldiblockit.com) | Processes | Reputation‑based process lookup with behavioral notes and prevalence. |
| [WinTasks Online](https://www.liutilities.com/processlibrary) | Processes | Older but still useful catalog of Windows processes and services. |
| [SystemLookup](https://www.systemlookup.com/) | Startup entries | Older-looking, but surprisingly useful for researching startup entries and suspicious filenames |
| [Hybrid Analysis](https://www.hybrid-analysis.com) | Binaries | Search any binary name or hash to see sandbox behavior, signatures, and prevalence. |
| [Any.Run](https://any.run) | Binaries, malware behavior | Interactive sandbox results; searching a process name shows how malware families use it. |
| [VirusTotal](https://www.virustotal.com) | Binaries | Hash reputation, signer info, prevalence, and sandbox behavior. |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de) | Malware families | Helps map suspicious binaries to known malware families. |
| [Windows Default Processes (GitHub)](https://github.com/mentebinaria/win-default-processes) | Processes | Community‑maintained list of default Windows processes across versions. |
| [LOLBAS (Living Off The Land Binaries)](https://github.com/LOLBAS-Project/LOLBAS) | Processes, binaries | Catalog of legitimate Windows binaries often abused by malware; helps determine if a binary is normal *and* if its usage is suspicious. |
| [GTFOBins (Windows subset)](https://gtfobins.github.io) | Processes | Shows which legitimate binaries can be abused for privilege escalation or persistence. |
| [Windows Event Log Baselines (GitHub)](https://github.com/0x6d69636b/windows-event-log-baselines) | Event logs | Baseline of normal Windows event logs; deviations often correlate with abnormal processes/services. |
|  [wikidll.com](https://wikidll.com) | dlls | Lists some native dlls on Windows - may be incomplete (Use an add blocker!) |

# Windows Malware Triage Flowchart (Lookup‑Only)

Below is a **triage flowchart** you can use when investigating a suspicious Windows process, service, scheduled task, or binary - **without running anything on the machine**.

---

## **1. Identify the Item**
**What are you triaging?**  
- A **process name**  
- A **service**  
- A **scheduled task**  
- A **DLL or EXE binary**  

Extract:
- File name  
- Full path  
- Hash (if available)  
- Publisher (if known)

---

## **2. Check if it’s a Default Windows Component**
Use baseline catalogs:

### **Processes**
- **Winbindex** — official Microsoft binaries  
- **Windows Default Processes** — GitHub baseline  

### **Services**
- **Windows Default Services** — GitHub  
- **Microsoft Services Reference**  

### **Scheduled Tasks**
- **Windows Default Scheduled Tasks** — GitHub  
- **Microsoft Task Scheduler Docs**  

If it **appears in a baseline**, mark it as *likely legitimate* unless:
- Path is wrong  
- Publisher mismatch  
- Version mismatch  
- Unexpected command-line arguments  

---

## **3. Check Reputation & Prevalence**
Use reputation databases:

- **VirusTotal**  
- **Hybrid Analysis**  
- **Any.Run**  
- **Malpedia**  

Look for:
- Known malware associations  
- Low prevalence  
- Suspicious behavior in sandbox reports  
- Unsigned or mismatched signatures  

---

## **4. Check Community Process Databases**
If still unknown:

- **File.net**  
- **ProcessLibrary**  
- **Should I Block It**  
- **WinTasks Online**  

These help determine:
- Whether the name is commonly abused  
- Whether the file is normally present on Windows  
- Whether the path matches legitimate usage  

---

## **5. Check for LOLBAS / Abuse Potential**
If the binary is legitimate but suspicious:

- **LOLBAS**  
- **GTFOBins**  

Determine:
- Is this binary normally present?  
- Is it being used in a way attackers commonly abuse?  

Examples:
- `bitsadmin.exe`  
- `mshta.exe`  
- `regsvr32.exe`  
- `rundll32.exe`  

---

## **6. Check for Abnormal Behavior Patterns**
Use behavior catalogs:

- **Atomic Red Team**  
- **Windows Event Log Baselines**  

Look for:
- Unexpected parent processes  
- Suspicious command-line flags  
- Abnormal execution frequency  
- Unusual triggers (scheduled tasks)  

---

## **7. Final Decision**
### **Legitimate**
- Appears in Windows baselines  
- Signed by Microsoft or trusted vendor  
- Normal path  
- Normal command-line  
- Normal behavior  

### **Suspicious**
- Not in baselines  
- Wrong path  
- Unsigned or mismatched signature  
- Abnormal command-line  
- Known malware associations  
- LOLBAS abuse pattern  

### **Malicious**
- Known malware hash  
- Sandbox behavior matches malware  
- Persistence via abnormal service/task  
- Drops additional payloads  
- Network C2 behavior  

---

TODO: finish this!

-----

{% hint style="danger" %}
Not much here yet...More needed! Please feel free to contribute any resources you find useful at [my GitHub page](https://github.com/zweilosec/Infosec-Notes).
{% endhint %}
