# Useful resources for Windows

## 

| Resource | Best for | Why useful |
|---|---|---|
| https://github.com/Psmths/windows-forensic-artifacts/ | | |

## Process Identification

The resources in this section can be very useful for identifying suspicious processes and services on a Windows machine.

| Resource | Best for | Why useful |
|---|---|---|
| [Winbindex](https://winbindex.m417z.com/) | Windows binaries | Excellent for determining whether a Windows executable is legitimate and which Windows versions contain it |
| [File.net](https://www.file.net/) | EXEs/DLLs/processes | Good quick lookup for filename, expected path, vendor, description and community information |
| [ProcessLibrary](https://www.processlibrary.com/) | Processes/DLLs | Large process/DLL database; May help find persistence |
| [SystemLookup](https://www.systemlookup.com/) | Startup entries | Older-looking, but surprisingly useful for researching startup entries and suspicious filenames |
| [LOLBAS](https://lolbas-project.github.io/) | Windows built-ins | Extremely useful for determining whether a binary is a legitimate Microsoft utility that can perform unusual/suspicious actions |
| [Microsoft Learn – Windows Internals/Sysinternals](https://learn.microsoft.com/en-us/sysinternals/) | Windows internals | Primary-source information about what Microsoft's own processes and utilities actually do |
| [Virustotal](https://www.virustotal.com/) | EXEs/DLLs/processes | Filehash lookup service. Identify whether an executable is known good/bad |


## Services
| Resource | Best for | Why useful |
|---|---|---|
| https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services | | |


| **[Resource](ca://s?q=Tell_me_more_about_this_resource)** | **Useful For** | **Why It’s Useful** |
| --- | --- | --- |
| **Winbindex** — [https://winbindex.m417z.com](https://winbindex.m417z.com) | Processes, DLLs | Lets you look up official Microsoft‑signed Windows binaries, versions, hashes, and metadata. Great for verifying legitimacy. |
| **File.net** — [https://www.file.net](https://www.file.net) | Processes | Large catalog of common Windows processes with descriptions and legitimacy indicators. |
| **ProcessLibrary.com** — [https://www.processlibrary.com](https://www.processlibrary.com) | Processes | Community database of Windows processes; helpful for quick “is this normal?” checks. |
| **Should I Block It?** — [https://www.shouldiblockit.com](https://www.shouldiblockit.com) | Processes | Reputation‑based process lookup with behavioral notes and prevalence. |
| **WinTasks Online** — ``https://www.liutilities.com/processlibrary`` [(liutilities.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fwww.liutilities.com%2Fprocesslibrary") | Processes | Older but still useful catalog of Windows processes and services. |
| **Hybrid Analysis** — [https://www.hybrid-analysis.com](https://www.hybrid-analysis.com) | Binaries | Search any binary name or hash to see sandbox behavior, signatures, and prevalence. |
| **Any.Run** — [https://any.run](https://any.run) | Binaries, malware behavior | Interactive sandbox results; searching a process name shows how malware families use it. |
| **VirusTotal** — [https://www.virustotal.com](https://www.virustotal.com) | Binaries | Hash reputation, signer info, prevalence, and sandbox behavior. |
| **Malpedia** — ``https://malpedia.caad.fkie.fraunhofer.de`` [(malpedia.caad.fkie.fraunhofer.de in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fmalpedia.caad.fkie.fraunhofer.de%2F") | Malware families | Helps map suspicious binaries to known malware families. |
| **Microsoft Windows Services Reference** — ``https://learn.microsoft.com/windows/win32/services`` [(learn.microsoft.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Flearn.microsoft.com%2Fwindows%2Fwin32%2Fservices") | Services | Official documentation describing legitimate Windows services and expected behavior. |
| **Microsoft Task Scheduler Reference** — ``https://learn.microsoft.com/windows/win32/taskschd`` [(learn.microsoft.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Flearn.microsoft.com%2Fwindows%2Fwin32%2Ftaskschd") | Scheduled tasks | Official schema + documentation for legitimate system tasks. |
| **Windows Default Processes (GitHub)** — ``https://github.com/mentebinaria/win-default-processes`` [(github.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fgithub.com%2Fmentebinaria%2Fwin-default-processes") | Processes | Community‑maintained list of default Windows processes across versions. |
| **Windows Default Services (GitHub)** — ``https://github.com/mentebinaria/win-default-services`` [(github.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fgithub.com%2Fmentebinaria%2Fwin-default-services") | Services | Baseline of legitimate Windows services across Windows versions. |
| **Windows Default Scheduled Tasks (GitHub)** — ``https://github.com/mentebinaria/win-default-scheduled-tasks`` [(github.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fgithub.com%2Fmentebinaria%2Fwin-default-scheduled-tasks") | Scheduled tasks | Catalog of default tasks per Windows version; excellent for spotting malicious additions. |
| **LOLBAS (Living Off The Land Binaries)** — ``https://github.com/LOLBAS-Project/LOLBAS`` [(github.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fgithub.com%2FLOLBAS-Project%2FLOLBAS") | Processes, binaries | Catalog of legitimate Windows binaries often abused by malware; helps determine if a binary is normal *and* if its usage is suspicious. |
| **GTFOBins (Windows subset)** — [https://gtfobins.github.io](https://gtfobins.github.io) | Processes | Shows which legitimate binaries can be abused for privilege escalation or persistence. |
| **Windows Event Log Baselines (GitHub)** — ``https://github.com/0x6d69636b/windows-event-log-baselines`` [(github.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fgithub.com%2F0x6d69636b%2Fwindows-event-log-baselines") | Event logs | Baseline of normal Windows event logs; deviations often correlate with abnormal processes/services. |


Here’s a **clean, visual, lookup‑focused triage flowchart** you can use when investigating a suspicious Windows process, service, scheduled task, or binary — **without running anything on the machine**.

I’m giving you a **flowchart-style decision tree**, optimized for fast malware triage.  
Every step includes **Guided Links** so you can jump deeper into any part of the workflow.

---

# 🔍 Windows Malware Triage Flowchart (Lookup‑Only)

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

# UNIX : TODO: move to unix page!

| **[Resource](ca://s?q=Tell_me_more_about_this_Unix_resource)** | **Distros** | **Useful For** | **Why It’s Useful** |
| --- | --- | --- | --- |
| **Debian Package Tracker** — [https://tracker.debian.org](https://tracker.debian.org) | Debian/Ubuntu | Packages, maintainers, versions | Lets you verify whether a binary belongs to a legitimate Debian package and check its expected files. |
| **Ubuntu Packages** — [https://packages.ubuntu.com](https://packages.ubuntu.com) | Ubuntu | Packages, file lists | Shows which package a file should belong to and its expected path. |
| **Red Hat Package Browser** — [https://access.redhat.com/downloads](https://access.redhat.com/downloads) | RHEL/CentOS | Packages, changelogs | Official RPM package metadata; helps confirm legitimate system binaries. |
| **CentOS Vault** — [https://vault.centos.org](https://vault.centos.org) | CentOS | Historical packages | Useful for older systems where malware hides in outdated packages. |
| **RPMFind** — [https://rpmfind.net](https://rpmfind.net) | RHEL/CentOS | RPM package lookup | Helps identify which package a suspicious file *should* belong to. |
| **Solaris Man Pages** — ``https://docs.oracle.com/cd/E86824_01/html/E54764/index.html`` [(docs.oracle.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fdocs.oracle.com%2Fcd%2FE86824_01%2Fhtml%2FE54764%2Findex.html") | Solaris | System binaries | Official documentation for Solaris commands and daemons. |
| **Solaris Package Index** — [https://pkg.oracle.com](https://pkg.oracle.com) | Solaris | IPS packages | Lets you verify legitimate Solaris package contents. |
| **Unix StackExchange** — [https://unix.stackexchange.com](https://unix.stackexchange.com) | All | Behavior, process explanations | High‑quality explanations of obscure daemons and system processes. |
| **ServerFault** — [https://serverfault.com](https://serverfault.com) | All | Sysadmin behavior | Good for identifying whether a daemon or cron job is normal in enterprise setups. |
| **GTFOBins** — [https://gtfobins.github.io](https://gtfobins.github.io) | All | Abuse potential | Catalog of legitimate Unix binaries commonly abused for privilege escalation. |
| **MITRE ATT&CK (Linux)** — ``https://attack.mitre.org/matrices/enterprise/linux/`` [(attack.mitre.org in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fattack.mitre.org%2Fmatrices%2Fenterprise%2Flinux%2F") | All | Suspicious behavior | Helps identify abnormal process behavior patterns. |
| **Linux Malware Repository (LMD)** — ``https://github.com/rfxn/linux-malware-detect`` [(github.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fgithub.com%2Frfxn%2Flinux-malware-detect") | All | Known malware | Contains signatures and names of known Linux malware families. |
| **Malpedia (Linux families)** — ``https://malpedia.caad.fkie.fraunhofer.de`` [(malpedia.caad.fkie.fraunhofer.de in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fmalpedia.caad.fkie.fraunhofer.de%2F") | All | Malware families | Helps map suspicious binaries to known Linux malware. |
| **VirusTotal** — [https://www.virustotal.com](https://www.virustotal.com) | All | Hash reputation | Critical for unknown ELF binaries. |
| **Any.Run (Linux sandbox)** — [https://any.run](https://any.run) | All | Behavioral analysis | Lets you search for ELF binaries and see sandbox behavior. |
| **Linux Standard Base (LSB)** — [https://refspecs.linuxfoundation.org/lsb.shtml](https://refspecs.linuxfoundation.org/lsb.shtml) | All | Expected system binaries | Defines standard system paths and binaries across distros. |
| **Filesystem Hierarchy Standard (FHS)** — [https://refspecs.linuxfoundation.org/fhs.shtml](https://refspecs.linuxfoundation.org/fhs.shtml) | All | Expected file locations | Helps determine whether a binary is in a suspicious path. |


Below is a **Unix/Linux triage resource table** (lookup‑only, no tools that require execution) followed by a **cross‑platform triage flowchart** tailored for **Debian/Ubuntu**, **CentOS/Red Hat**, and **Solaris**.  
Everything is structured for malware triage where you **cannot run commands on the target system** and must rely on external references.

---

# 🧩 **Unix/Linux “Is It Normal?” Lookup Resources Table**

| **Resource** | **Distros** | **Useful For** | **Why It’s Useful** |
|-----------------------------|------------|----------------|----------------------|
| **Debian Package Tracker** — [https://tracker.debian.org](https://tracker.debian.org) | Debian/Ubuntu | Packages, maintainers, versions | Lets you verify whether a binary belongs to a legitimate Debian package and check its expected files. |
| **Ubuntu Packages** — [https://packages.ubuntu.com](https://packages.ubuntu.com) | Ubuntu | Packages, file lists | Shows which package a file should belong to and its expected path. |
| **Red Hat Package Browser** — [https://access.redhat.com/downloads](https://access.redhat.com/downloads) | RHEL/CentOS | Packages, changelogs | Official RPM package metadata; helps confirm legitimate system binaries. |
| **CentOS Vault** — [https://vault.centos.org](https://vault.centos.org) | CentOS | Historical packages | Useful for older systems where malware hides in outdated packages. |
| **RPMFind** — [https://rpmfind.net](https://rpmfind.net) | RHEL/CentOS | RPM package lookup | Helps identify which package a suspicious file *should* belong to. |
| **Solaris Man Pages** — `https://docs.oracle.com/cd/E86824_01/html/E54764/index.html` [(docs.oracle.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fdocs.oracle.com%2Fcd%2FE86824_01%2Fhtml%2FE54764%2Findex.html") | Solaris | System binaries | Official documentation for Solaris commands and daemons. |
| **Solaris Package Index** — [https://pkg.oracle.com](https://pkg.oracle.com) | Solaris | IPS packages | Lets you verify legitimate Solaris package contents. |
| **Unix StackExchange** — [https://unix.stackexchange.com](https://unix.stackexchange.com) | All | Behavior, process explanations | High‑quality explanations of obscure daemons and system processes. |
| **ServerFault** — [https://serverfault.com](https://serverfault.com) | All | Sysadmin behavior | Good for identifying whether a daemon or cron job is normal in enterprise setups. |
| **GTFOBins** — [https://gtfobins.github.io](https://gtfobins.github.io) | All | Abuse potential | Catalog of legitimate Unix binaries commonly abused for privilege escalation. |
| **MITRE ATT&CK (Linux)** — `https://attack.mitre.org/matrices/enterprise/linux/` [(attack.mitre.org in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fattack.mitre.org%2Fmatrices%2Fenterprise%2Flinux%2F") | All | Suspicious behavior | Helps identify abnormal process behavior patterns. |
| **Linux Malware Repository (LMD)** — `https://github.com/rfxn/linux-malware-detect` [(github.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fgithub.com%2Frfxn%2Flinux-malware-detect") | All | Known malware | Contains signatures and names of known Linux malware families. |
| **Malpedia (Linux families)** — `https://malpedia.caad.fkie.fraunhofer.de` [(malpedia.caad.fkie.fraunhofer.de in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fmalpedia.caad.fkie.fraunhofer.de%2F") | All | Malware families | Helps map suspicious binaries to known Linux malware. |
| **VirusTotal** — [https://www.virustotal.com](https://www.virustotal.com) | All | Hash reputation | Critical for unknown ELF binaries. |
| **Any.Run (Linux sandbox)** — [https://any.run](https://any.run) | All | Behavioral analysis | Lets you search for ELF binaries and see sandbox behavior. |
| **Linux Standard Base (LSB)** — [https://refspecs.linuxfoundation.org/lsb.shtml](https://refspecs.linuxfoundation.org/lsb.shtml) | All | Expected system binaries | Defines standard system paths and binaries across distros. |
| **Filesystem Hierarchy Standard (FHS)** — [https://refspecs.linuxfoundation.org/fhs.shtml](https://refspecs.linuxfoundation.org/fhs.shtml) | All | Expected file locations | Helps determine whether a binary is in a suspicious path. |

---

# 🔍 **Unix/Linux Malware Triage Flowchart (Lookup‑Only)**

This flowchart mirrors the Windows version but is tailored to Unix systems.

---

## **1. Identify the Item**
What are you triaging?

- A **process name**  
- A **daemon/service**  
- A **cron job**  
- A **ELF binary**  

Collect:
- File name  
- Full path  
- Package ownership (if known)  
- Hash  
- Interpreter (bash, python, perl, etc.)

---

## **2. Check if it’s a Default System Component**
### **Debian/Ubuntu**
- **Debian Package Tracker**  
- **Ubuntu Packages**  

### **CentOS/Red Hat**
- **Red Hat Package Browser**  
- **RPMFind**  

### **Solaris**
- **Solaris Man Pages**  
- **Solaris Package Index**  

If the binary is part of a legitimate package:
- Check expected file paths  
- Check expected permissions  
- Check expected version  

If it’s **not** part of any package → suspicious.

---

## **3. Check Reputation & Prevalence**
Use external reputation databases:

- **VirusTotal**  
- **Any.Run**  
- **Malpedia**  
- **Linux Malware Detect signatures**  

Look for:
- Known malware associations  
- Low prevalence  
- Suspicious ELF sections  
- Obfuscated scripts  

---

## **4. Check Community Knowledge**
If still unknown:

- **Unix StackExchange**  
- **ServerFault**  

Search for:
- Daemon names  
- Cron job names  
- Script names  
- Systemd unit names  

If nobody recognizes it → suspicious.

---

## **5. Check for Abuse Potential**
Use exploitation catalogs:

- **GTFOBins**  

Determine:
- Is the binary normally present?  
- Is it being used in a way attackers commonly abuse?  

Examples:
- `curl` used for C2  
- `bash -c` with encoded payloads  
- `python` used for reverse shells  
- `socat` used for tunneling  

---

## **6. Check for Abnormal Behavior Patterns**
Use behavior references:

- **MITRE ATT&CK Linux**  

Look for:
- Unexpected parent processes  
- Cron jobs running binaries in `/tmp` or `/var/tmp`  
- Systemd units pointing to non‑package files  
- Scripts in `/etc/init.d` not belonging to any package  
- ELF binaries in user home directories  

---

## **7. Final Decision**
### **Legitimate**
- Part of a known package  
- Expected path  
- Expected permissions  
- Normal behavior  

### **Suspicious**
- Not part of any package  
- Wrong path (e.g., `/usr/local/bin/ssh`)  
- Cron jobs pointing to temp directories  
- Unusual interpreters (e.g., Perl on a system that doesn’t use it)  

### **Malicious**
- Known malware hash  
- Reverse shell behavior  
- Persistence via cron/systemd  
- ELF packed or obfuscated  
- Network C2 behavior  

---



-----

{% hint style="danger" %}
Not much here yet...More needed! Please feel free to contribute any resources you find useful at [my GitHub page](https://github.com/zweilosec/Infosec-Notes).
{% endhint %}
