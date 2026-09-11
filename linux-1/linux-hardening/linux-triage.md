# Malware Triage 

Below is a **Unix/Linux triage resource table** followed by a **triage flowchart** tailored for **Debian/Ubuntu**, **CentOS/Red Hat**, and **Solaris**.  

## Useful resources

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

## Unix/Linux Malware Triage Flowchart

Below is a high-level overview of the steps to take when triaging unknown software found on a Unix system.

---

### **1. Identify the Item**
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

### **2. Check if it’s a Default System Component**
#### **Debian/Ubuntu**
- **Debian Package Tracker**  
- **Ubuntu Packages**  

#### **CentOS/Red Hat**
- **Red Hat Package Browser**  
- **RPMFind**  

#### **Solaris**
- **Solaris Man Pages**  
- **Solaris Package Index**  

If the binary is part of a legitimate package:
- Check expected file paths  
- Check expected permissions  
- Check expected version  

If it’s **not** part of any package → suspicious. (see persistence hunt function below!)

---

### **3. Check Reputation & Prevalence**
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

### **4. Check Community Knowledge**
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

### **5. Check for Abuse Potential**
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

### **6. Check for Abnormal Behavior Patterns**
Use behavior references:

- **MITRE ATT&CK Linux**  

Look for:
- Unexpected parent processes  
- Cron jobs running binaries in `/tmp` or `/var/tmp`  
- Systemd units pointing to non‑package files  
- Scripts in `/etc/init.d` not belonging to any package  
- ELF binaries in user home directories  

---

### **7. Final Decision**
#### **Legitimate**
- Part of a known package  
- Expected path  
- Expected permissions  
- Normal behavior  

#### **Suspicious**
- Not part of any package  
- Wrong path (e.g., `/usr/local/bin/ssh`)  
- Cron jobs pointing to temp directories  
- Unusual interpreters (e.g., Perl on a system that doesn’t use it)  

#### **Malicious**
- Known malware hash  
- Reverse shell behavior  
- Persistence via cron/systemd  
- ELF packed or obfuscated  
- Network C2 behavior  

---

## Unix suspicious process/service hunt commands

Unix malware triage pivot commands. Use when you have already found a process/service/file that is suspicious

```bash
# Check the current status of a systemd service. Useful to see if a service is active, failed, or loaded
systemctl status <service-name> 2>/dev/null

# List the services that depend on the given service. 
systemctl list-dependencies --reverse <service-name> 2>/dev/null

# Show detailed unit file information for a service. This helps determine how and when the service is intended to start.
systemctl show <service-name> 2>/dev/null | grep -E 'WantedBy|RequiredBy|FragmentPath|UnitFileState'

# Find symbolic links pointing to a specific service unit file within systemd directories.
# Useful to trace back from a known endpoint (the link) to its source configuration file.
find /etc/systemd/system -type l -lname '<service>' -ls 2>/dev/null

# Recursively search for a name across all systemd unit directories.
# This is a broad sweep to ensure the malware or its indicators aren't hidden in unusual unit files.
grep -Rni "<name>" /etc/systemd/system /lib/systemd/system /usr/lib/systemd 2>/dev/null

# Recursively search for a name across common traditional init/startup scripts.
# This checks for persistence mechanisms in older or complementary startup environments (e.g., /etc/init.d).
grep -Rni "<name>" /etc/init.d /etc/rc.d /etc/init/.conf /etc/xinetd.d 2>/dev/null

# Recursively search for a name across common cron job locations. Useful for finding scheduled task persistence.
grep -Rni "<name>" /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/anacrontab 2>/dev/null

# Recursively search for a name in user profile configuration files.
# This checks for persistence via shell profiles (e.g., .bashrc, .profile) or global environment settings.
grep -Rni "<name>" /etc/profile /etc/profile.d /root /home 2>/dev/null
```

## Unix persistence hunting function

This function is a Linux persistence‑hunting script. Paste this function into your shell, and voila! Many of the common peristence locations will be searched for anything that is not an installed package for the system you are on. 

It scans common persistence locations (cron, systemd, shell profiles, at‑jobs, etc.), extracts every referenced file path, and reports any executable or Python file not belonging to an installed package, which is a potential indicator of malicious persistence.

DO NOT rely solely on this as a source of truth, or use it to replace doing your checks manually! It can, however, be a time-saving measure to point you in the right direction to start.

```bash
persistenum() { PKG_MGR_CMD='';hash yum &>/dev/null && PKG_MGR_CMD='rpm -qf';hash dpkg &>/dev/null && PKG_MGR_CMD='dpkg -S';if test -z "$PKG_MGR_CMD"; then echo "\[\*\] Could not find package manager to use for verification";return 1;fi;shopt -s nullglob;for match in $( egrep -o '(/\\w+.).+\\b' /etc/crontab /etc/anacrontab /etc/cron.\*/\* /var/spool/cron/crontab/\* /var/spool/anacron/\* /var/spool/at/spool/\* /home/\*/{.profile,.bashrc,.bash_profile,.bash_login} /root/{.profile,.bashrc,.bash_profile,.bash_login} /usr/lib/systemd/scripts/\* /usr/lib/systemd/system/\* /etc/init.d/\* 2>/dev/null ); do location=$(echo "$match" | cut -f1 -d:);fname=$(echo "$match" | cut -f2- -d:);test -f "${fname}" || continue;test -h "${fname}" && continue;if readelf -h "${fname}" &>/dev/null; then $PKG_MGR_CMD "${fname}" &>/dev/null || printf "%s:\\t%s\\n" "${location}" "${fname}";continue;fi;filetype="$( file -bi $fname )";if test "${filetype:0:13}" == "text/x-python"; then $PKG_MGR_CMD "${fname}" &>/dev/null || printf "%s:\\t%s\\n" "${location}" "${fname}"; continue;fi;done; };persistenum
```

Below is an updated version that changes up the script search to include any scripts, not just python.  These have both seen limited testing, so please let me know your results and if tweaks need to be made to make them better!

```bash
persistenum() { PKG_MGR_CMD='';hash yum &>/dev/null&&PKG_MGR_CMD='rpm -qf';hash dpkg &>/dev/null&&PKG_MGR_CMD='dpkg -S';test -z "$PKG_MGR_CMD"&&echo "[*] Could not find package manager to use for verification"&&return 1;shopt -s nullglob;for match in $(egrep -o '(/\w+.).+\b' /etc/crontab /etc/anacrontab /etc/cron.*/* /var/spool/cron/crontab/* /var/spool/anacron/* /var/spool/at/spool/* /home/*/{.profile,.bashrc,.bash_profile,.bash_login} /root/{.profile,.bashrc,.bash_profile,.bash_login} /usr/lib/systemd/scripts/* /usr/lib/systemd/system/* /etc/init.d/* 2>/dev/null);do location=$(echo "$match"|cut -f1 -d:);fname=$(echo "$match"|cut -f2- -d:);test -f "$fname"||continue;test -h "$fname"&&continue;readelf -h "$fname" &>/dev/null&&($PKG_MGR_CMD "$fname" &>/dev/null||printf "%s:\t%s\n" "$location" "$fname")&&continue;if echo "$(file -bi "$fname")"|grep -qi script||head -n1 "$fname"|grep -Eq '^#!';then $PKG_MGR_CMD "$fname" &>/dev/null||printf "%s:\t%s\n" "$location" "$fname";fi;done; };persistenum
```

-----

{% hint style="danger" %}
Not much here yet...More needed! Please feel free to contribute any resources you find useful at [my GitHub page](https://github.com/zweilosec/Infosec-Notes).
{% endhint %}
