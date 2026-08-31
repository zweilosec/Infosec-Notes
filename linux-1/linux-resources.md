# UNIX Resources

## Malware Triage 

Below is a **Unix/Linux triage resource table** (lookup‑only, no tools that require execution) followed by a **cross‑platform triage flowchart** tailored for **Debian/Ubuntu**, **CentOS/Red Hat**, and **Solaris**.  
Everything is structured for malware triage where you **cannot run commands on the target system** and must rely on external references.

| **Resource** | **Distros** | **Useful For** | **Why It’s Useful** |
| --- | --- | --- | --- |
| [Debian Package Tracker](https://tracker.debian.org) | Debian/Ubuntu | Packages, maintainers, versions | Lets you verify whether a binary belongs to a legitimate Debian package and check its expected files. |
| [Ubuntu Packages](https://packages.ubuntu.com) | Ubuntu | Packages, file lists | Shows which package a file should belong to and its expected path. |
| [Red Hat Package Browser](https://access.redhat.com/downloads) | RHEL/CentOS | Packages, changelogs | Official RPM package metadata; helps confirm legitimate system binaries. |
| [CentOS Vault](https://vault.centos.org) | CentOS | Historical packages | Useful for older systems where malware hides in outdated packages. |
| [RPMFind](https://rpmfind.net) | RHEL/CentOS | RPM package lookup | Helps identify which package a suspicious file *should* belong to. |
| [Solaris Man Pages](https://docs.oracle.com/cd/E86824_01/html/E54764/index.html) | Solaris | System binaries | Official documentation for Solaris commands and daemons. |
| [Solaris Package Index](https://pkg.oracle.com) | Solaris | IPS packages | Lets you verify legitimate Solaris package contents. |
| [Unix StackExchange](https://unix.stackexchange.com) | All | Behavior, process explanations | High‑quality explanations of obscure daemons and system processes. |
| [ServerFault](https://serverfault.com) | All | Sysadmin behavior | Good for identifying whether a daemon or cron job is normal in enterprise setups. |
| [GTFOBins](https://gtfobins.github.io) | All | Abuse potential | Catalog of legitimate Unix binaries commonly abused for privilege escalation. |
| [MITRE ATT&CK (Linux)](https://attack.mitre.org/matrices/enterprise/linux/) | All | Suspicious behavior | Helps identify abnormal process behavior patterns. |
| [Linux Malware Repository (LMD)](https://github.com/rfxn/linux-malware-detect) | All | Known malware | Contains signatures and names of known Linux malware families. |
| [Malpedia (Linux families)](https://malpedia.caad.fkie.fraunhofer.de) | All | Malware families | Helps map suspicious binaries to known Linux malware. |
| [VirusTotal](https://www.virustotal.com) | All | Hash reputation | Critical for unknown ELF binaries. |
| [Any.Run (Linux sandbox)](https://any.run) | All | Behavioral analysis | Lets you search for ELF binaries and see sandbox behavior. |
| [Linux Standard Base (LSB)](https://refspecs.linuxfoundation.org/lsb.shtml) | All | Expected system binaries | Defines standard system paths and binaries across distros. |
| [Filesystem Hierarchy Standard (FHS)](https://refspecs.linuxfoundation.org/fhs.shtml) | All | Expected file locations | Helps determine whether a binary is in a suspicious path. |




### **Unix/Linux Malware Triage Flowchart (Lookup‑Only)**

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
