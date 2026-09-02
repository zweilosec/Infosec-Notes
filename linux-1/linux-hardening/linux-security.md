# Unix Security Enumeration

When you land on a Unix system, your first job is to map the defender’s visibility surface. The tools above represent the most common telemetry sources you’ll encounter. Your enumeration should answer:

- Where will my commands be logged?  
- Which services are monitored or alerting?  
- Are logs forwarded off‑host?  
- Is file integrity monitoring active?  
- Is kernel‑level auditing enabled?  
- Is network activity being captured or analyzed?

Once you understand the monitoring stack, you can adjust your operational tempo, tooling, and persistence strategy accordingly.


## Mapping the Defender’s Eyes: Monitoring & Logging on Unix Systems

Modern Unix systems are a patchwork of legacy logging daemons, kernel‑level audit frameworks, and enterprise observability stacks. For red teams, understanding this landscape isn’t optional, it’s the difference between an operation that quietly succeeds and one that leaves a forensic trail bright enough to be seen from orbit. This write‑up breaks down the common monitoring and logging components you’ll encounter, how to enumerate them, and what each one means for your OPSEC.


## The Syslog Family: The Old Guard Still Watching

### syslog / rsyslog / syslog‑ng
These daemons form the backbone of traditional Unix logging. Even on systems with newer frameworks, syslog often acts as the final aggregation point before logs are shipped off‑host.

Syslog configs reveal exactly what the defenders consider important. A quick look at `/etc/rsyslog.conf` or `/etc/rsyslog.d/` often exposes:

- Whether authentication logs are forwarded to a SIEM  
- Custom rules for sudo, SSH, or privilege escalation  
- Remote log collectors (your activity may be visible off‑host within seconds)

### What gets logged
- SSH authentication events  
- sudo/su privilege escalation  
- PAM messages  
- Cron jobs  
- System service logs  
- Kernel messages (depending on config)

### Where logs appear
- `/var/log/auth.log` (Debian/Ubuntu)
- `/var/log/secure` (RHEL/CentOS)
- `/var/log/messages`
- `/var/log/syslog`

### Enumeration tips:  
Check for `@@` or `@` entries—these indicate TCP/UDP forwarding. If logs leave the box, stealth expectations must adjust accordingly.

### Enumeration Commands

```bash
# Main config
cat /etc/rsyslog.conf

# Additional rules
ls -al /etc/rsyslog.d/
cat /etc/rsyslog.d/*.conf

# Remote log forwarding (SIEM ingestion)
grep -R "@@" /etc/rsyslog.conf /etc/rsyslog.d/
grep -R "@ " /etc/rsyslog.conf /etc/rsyslog.d/

# syslog-ng presence
syslog-ng --version 2>/dev/null
cat /etc/syslog-ng/syslog-ng.conf 2>/dev/null
```

## systemd‑journal: The Binary Black Box

### journald
On systemd‑based systems, journald captures logs before they ever reach syslog. It stores them in a binary format and can be configured to retain logs indefinitely.

`journalctl` reveals what services are noisy, what’s monitored, and whether logs persist across reboots. Persistent journals (`Storage=persistent`) mean defenders have a longer forensic window.

### What gets logged
- All systemd service logs  
- Authentication events  
- Kernel logs  
- sudo/su session events  
- Cron activity  
- Anything logged via systemd units

### Enumeration tips:  
- `journalctl --list-boots` shows how far back logs go  
- `journalctl -u <service>` exposes service‑specific monitoring  
- `/etc/systemd/journald.conf` tells you whether logs are forwarded or rate‑limited  

### Enumeration Commands

```bash
# Check journald configuration
cat /etc/systemd/journald.conf

# Check if logs persist across reboots
grep Storage /etc/systemd/journald.conf

# List boots (forensic retention)
journalctl --list-boots

# Check logs for specific services
journalctl -u ssh
journalctl -u sudo
journalctl -u cron

# Check forwarding to syslog
grep ForwardToSyslog /etc/systemd/journald.conf

# Persistent logs?
grep Storage /etc/systemd/journald.conf
```

## Authentication & Access Visibility: Where Your Footprints Live

### PAM (Pluggable Authentication Modules)
PAM (Pluggable Authentication Modules) is the core authentication framework. It logs every login attempt, success or failure, and session open/close.

#### Enumeration tips:  
Inspect `/etc/pam.d/` for modules like:

- `pam_tally2` (failed login counters)  
- `pam_faillock` (lockout policies)  
- `pam_exec` (custom scripts triggered on login: dangerous for stealth)

#### Enumeration Commands

```bash
# Enumerate PAM configs
ls -al /etc/pam.d/
grep -R "pam_tally" /etc/pam.d/
grep -R "pam_faillock" /etc/pam.d/
grep -R "pam_exec" /etc/pam.d/
```

### auth.log / secure log
These files track SSH logins, sudo usage, PAM events, and anything authentication‑related.
 
Every failed login attempt, every sudo invocation, every PAM‑triggered event is recorded here. Reviewing these logs helps you understand what your activity will look like to defenders.

#### Example Commands

```bash
# View authentication logs
tail -n 50 /var/log/auth.log 2>/dev/null
tail -n 50 /var/log/secure 2>/dev/null

# Search for your own activity
grep -i "sudo" /var/log/auth.log
grep -i "session opened" /var/log/auth.log
```

### wtmp / btmp / last / lastb
Binary login history databases. These files persist login traces even if syslog is disabled. `lastb` is especially useful for spotting brute‑force detection thresholds.

#### Example Commands

```bash
# Successful logins
last

# Failed logins
lastb

# Raw files
ls -al /var/log/wtmp /var/log/btmp
```

### SSH Login Example: What Gets Logged

These are examples, not all entries are shown!

- auth.log / secure
  ```
  sshd[PID]: Accepted publickey for user from <IP>
  sshd[PID]: pam_unix(sshd:session): session opened for <user>
  ```

- PAM logs
  ```
  pam_unix(sshd:auth): authentication success
  pam_lastlog(sshd:session): Checking for failed logins
  ```

## auditd: The Kernel-Level Tripwire

### auditd
Auditd is one of the most dangerous logging systems for red teams. It can track syscalls, file access, privilege escalation, and execution of specific binaries.

Audit rules often target:

- `/usr/bin/sudo`  
- `/usr/bin/passwd`  
- `/usr/bin/chmod`  
- `/usr/bin/chown`  
- Sensitive directories like `/etc/` or `/var/log/`

If auditd is configured aggressively, even seemingly harmless actions can generate forensic artifacts.

#### Enumeration tips:  
- `auditctl -l` shows active rules  
- `/etc/audit/audit.rules` reveals monitored binaries and syscalls  
- Watch for rules containing `-w` (watch) and `-a` (syscall auditing)

#### Example Commands

```bash
# Check if auditd is running
systemctl status auditd

# List active audit rules
auditctl -l

# Review persistent rules
cat /etc/audit/audit.rules
cat /etc/audit/rules.d/*.rules

# Check for monitored binaries
grep -R "/usr/bin" /etc/audit/audit.rules /etc/audit/rules.d/
```

## Process & Command Monitoring: The Silent Historians

### Shell History

Shell history files are local, user‑specific command logs that record the commands typed in interactive shells. They are not typically real‑time logs, instead, they are written when the shell session exits cleanly, meaning commands may not appear immediately while you’re active.

#### Common History Files
- Bash: ~/.bash_history
- Zsh: ~/.zsh_history
- Ksh: ~/.ksh_history
- Fish: ~/.local/share/fish/fish_history

#### When They Are Written
- On shell exit
- When the shell flushes history manually (`history -a`)
- When configured to append in real time (`PROMPT_COMMAND='history -a'`)

#### Key Environment Variables Affecting History
- HISTFILE - where history is stored
- HISTSIZE - number of commands kept in memory
- HISTFILESIZE - number of commands stored on disk
- HISTCONTROL - ignores duplicates or commands starting with spaces
- HISTIGNORE - patterns to skip logging

Make sure to always read out the contents of these files as they can contain a wealth of knowledge about the system you are on.

### auditd Logs

The auditd log is the output of the Linux Audit Framework: a kernel‑level monitoring system designed to capture security‑relevant events with forensic precision. Unlike syslog or shell history, auditd records activity at the syscall level, meaning it can log *exactly what was executed, by whom, with what arguments, and which files were touched*.

#### What auditd logs
- Command execution (`EXECVE`)  
  Full command + arguments, including sensitive ones.
- File access (`PATH`)  
  Reads/writes to critical files like `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`.
- Authentication events  
  `USER_AUTH`, `USER_LOGIN`, `USER_ACCT`.
- Privilege escalation  
  sudo, su, setuid binaries, capability changes.
- System configuration changes  
  Modifications to monitored directories or binaries.
- Network‑related syscalls (if rules are configured)

#### Where logs live
- `/var/log/audit/audit.log`

#### Why it matters to red teams
Auditd is one of the most dangerous visibility surfaces because:

- It logs exact commands, not just the fact that a command ran.
- It logs file paths accessed, even if the command itself is quiet.
- It logs privilege escalation attempts with full detail.
- It logs binary execution, even if shell history is disabled.
- It can be configured to log everything, including syscalls for persistence techniques.

Even stealthy actions like reading `/etc/shadow`, spawning a shell, or modifying cron jobs can produce audit entries.

#### Example auditd entry (for running a command)  

```bash
type=EXECVE msg=audit(1693590000.123:420): argc=2 a0="cat" a1="/etc/shadow"
type=PATH msg=audit(1693590000.123:420): item=0 name="/etc/shadow" inode=12345
type=SYSCALL msg=audit(1693590000.123:420): arch=c000003e syscall=59 success=yes pid=1337 uid=1000 ...
```

These entries can contain:

- The exact command (`cat /etc/shadow`)
- The file accessed
- The audit event sequence number (e.g. 420 above)
- The timestamp (Unix epoch time format)
- The process ID
- The user ID

Multiple records (EXECVE, PATH, SYSCALL, CWD) will share the same event ID (420), allowing defenders to reconstruct the entire action.

```bash
ausearch -a 420
```

This will show all records tied to event ID 420:

- EXECVE (command + args)
- SYSCALL (PID, UID, GID, syscall)
- PATH (files accessed)
- CWD (current working directory)

#### Enumeration commands

```bash
# Check auditd status
systemctl status auditd

# View active rules
auditctl -l

# Inspect persistent rules
cat /etc/audit/audit.rules
cat /etc/audit/rules.d/*.rules

# Search for specific events
ausearch -m EXECVE
ausearch -m USER_AUTH
ausearch -m USER_CMD
```

### psacct / acct
Command accounting logs *every command executed* on the system. If enabled, this is catastrophic for stealth. Every shell command becomes part of a forensic timeline.

#### Enumeration tips:  
Presence of `/var/account/pacct` or a running `acct` service is a red flag.

```bash
# Check if acct is installed
systemctl status acct 2>/dev/null

# Check accounting file
ls -al /var/account/pacct

# View recent command accounting entries
lastcomm | head
```

### atop
Atop can log historical process activity, including CPU, memory, and disk usage.

If defenders use atop logging, high‑resource payloads or unusual process behavior may stand out.

## Network Visibility: Packet Trails & Firewall Eyes

### iptables / nftables logging
Firewall rules can log dropped packets, suspicious traffic, or specific ports.

Why red teams care:  
LOG rules can reveal:

- Port scans  
- Lateral movement attempts  
- Unexpected outbound connections  

#### Example Commands

```bash
# Check iptables rules for LOG actions
iptables -L -n -v | grep LOG

# nftables logging
nft list ruleset | grep log
```

### fail2ban
Fail2ban monitors logs for suspicious authentication patterns.

#### Enumeration tips:  
Inspect `/etc/fail2ban/jail.conf` and `/etc/fail2ban/jail.d/` to see:

- Which services are protected  
- Ban thresholds  
- Whether your brute‑force attempts will trigger alerts

```bash
# Check fail2ban status
systemctl status fail2ban

# Enumerate jails
fail2ban-client status

# View jail configs
ls -al /etc/fail2ban/jail.d/
cat /etc/fail2ban/jail.conf
```

### Packet Capture Tools

Packet capturing tools such as tcpdump, wireshark, etc can capture your login sessions, tool uploads, and further network actions.

```bash
# Check for running packet captures
ps aux | grep -E "tcpdump|tshark|dumpcap|wireshark"

# Check common pcap directories
ls -al /var/log/pcap/ 2>/dev/null
```

## Application-Level Logging: Web, Database, and Service Trails

### Apache / Nginx
Access and error logs reveal:

- Reconnaissance  
- Exploitation attempts  
- Web shell activity  
- Proxy behavior  

```bash
# Apache logs
ls -al /var/log/apache2/
tail -n 50 /var/log/apache2/access.log
tail -n 50 /var/log/apache2/error.log

# Nginx logs
ls -al /var/log/nginx/
tail -n 50 /var/log/nginx/access.log
tail -n 50 /var/log/nginx/error.log
```

### MySQL / PostgreSQL
Database logs may include:

- Authentication failures  
- Slow queries  
- Audit plugin output  

Why red teams care:  
Database audit plugins can log every query—critical when performing SQL injection or lateral movement through DB credentials.

```bash
# MySQL logs
grep -R "log" /etc/mysql/
ls -al /var/log/mysql/

# PostgreSQL logs
grep -R "log" /etc/postgresql/
ls -al /var/log/postgresql/
```

## Antimalware Tools (AV, rootkit hunters, file monitoring, etc)

### ClamAV

ClamAV is a widely deployed open‑source antivirus engine used on Unix systems for malware detection, email scanning, and filesystem scanning. While not as intrusive as commercial EDR products, ClamAV still creates forensic artifacts, scheduled scans, and signature updates that matter during red‑team operations.

ClamAV provides:

- On-demand scanning (`clamscan`, `clamdscan`)
- Daemon-based scanning (`clamd`)
- Signature updates (`freshclam`)
- Email gateway scanning (via MTA integration)
- Filesystem scanning via cron jobs or systemd timers

ClamAV does not provide kernel-level telemetry or real-time behavioral monitoring like EDRs.

#### ClamAV Logs & Artifacts

ClamAV logs typically live in:

- `/var/log/clamav/clamav.log`
- `/var/log/clamav/freshclam.log`
- `/var/log/clamav/clamd.log`
- `/var/log/syslog` or `/var/log/messages` (if syslog integration is enabled)

#### What gets logged
- Scan start/stop times  
- Files scanned  
- Files flagged as infected  
- Signature update events  
- Errors or permission issues  
- Daemon startup/shutdown  
- Freshclam update failures (common on misconfigured systems)

#### Example log entries

```
ClamAV scan started at Wed Sep 2 12:00:00
Scanning /home/user/payload.bin
payload.bin: Infected with Win.Trojan.Generic
ClamAV scan completed: 1 infected files
```

Updates through freshclam

```
freshclam: Downloaded daily.cvd
freshclam: Database updated (version 26845)
```

#### Check ClamAV engine version & signature versions

```bash
# Engine version
clamscan --version

# Signature database versions
clamd --version 2>/dev/null | grep version

# Check signature files directly
ls -al /var/lib/clamav/
```

#### Check last signature update time

```bash
grep -i "Database updated" /var/log/clamav/freshclam.log | tail -n 10
```

Or check file timestamps:

```bash
ls -al --full-time /var/lib/clamav/*.cvd
```

Look for:

- `main.cvd`
- `daily.cvd`
- `bytecode.cvd`

Their timestamps reveal last update time.

#### clamd configuration

```bash
cat /etc/clamav/clamd.conf 2>/dev/null
```

Key fields:

- `LogFile`
- `LogTime`
- `ScanMail`
- `ScanArchive`
- `ExcludePath`
- `MaxFileSize`
- `AllowSupplementaryGroups`

#### freshclam configuration

```bash
cat /etc/clamav/freshclam.conf 2>/dev/null
```

Settings to look out for:

- Update frequency  
- Mirror servers  
- Logging settings  
- Notification settings  

#### ClamAV services and processes

```bash
# Check if clamd is running
systemctl status clamd 2>/dev/null
systemctl status clamav-daemon 2>/dev/null

# Check freshclam auto-update service
systemctl status clamav-freshclam 2>/dev/null

# Running processes
ps aux | grep -E "clamd|clamscan|freshclam"
```

#### Scheduled scans (cron or systemd timers)


```bash
grep -R clam /etc/cron* /var/spool/cron/
```

#### Systemd timers

```bash
systemctl list-timers | grep -i clam
```

Common scheduled tasks:

- Daily filesystem scans  
- Daily signature updates  
- Email gateway scanning  

#### ClamAV logs

```bash
ls -al /var/log/clamav/
tail -n 50 /var/log/clamav/clamav.log
tail -n 50 /var/log/clamav/freshclam.log
tail -n 50 /var/log/clamav/clamd.log
```

### Rootkit & Host Integrity Tools: rkhunter, chkrootkit, etc

Beyond ClamAV, many Unix systems deploy lightweight, open‑source host integrity and rootkit detection tools. These tools don’t behave like full EDRs, but they do generate logs, alerts, and forensic artifacts that matter during red‑team operations.

The most common tools you’ll encounter:

- rkhunter (Rootkit Hunter)  
- chkrootkit  
- Lynis (security auditing)  
- unhide (process hiding detection)

These tools typically run via cron or systemd timers and scan for:

- Rootkits  
- Suspicious binaries  
- Hidden processes  
- Modified system files  
- Unexpected network listeners  
- Kernel module anomalies  

#### rkhunter (Rootkit Hunter)

rkhunter is one of the most widely deployed open‑source rootkit scanners. It checks for known rootkits, suspicious file permissions, hidden directories, and modified binaries.

##### What rkhunter does
- Compares system binaries against known-good hashes  
- Checks for hidden processes  
- Scans for suspicious kernel modules  
- Detects common rootkits (e.g., LRK, Xz, Phalanx, etc.)  
- Checks for unexpected network ports  
- Validates file permissions and ownership  
- Monitors `/etc/passwd`, `/etc/group`, `/etc/shadow` integrity  

##### Where logs live
- `/var/log/rkhunter.log`
- `/var/log/rkhunter/rkhunter.log`
- `/var/log/syslog` (if syslog integration enabled)

##### What defenders see
- Alerts about modified binaries  
- Warnings about unexpected suid/sgid files  
- Suspicious network listeners  
- Hidden processes  
- Rootkit signature matches  
- File integrity warnings  

Even benign red‑team tools (linpeas, enumeration scripts, custom binaries) can trigger warnings.

##### Check if rkhunter is installed

```bash
rkhunter --versioncheck 2>/dev/null
rkhunter --version 2>/dev/null
```

##### rkhunter configuration

```bash
cat /etc/rkhunter.conf 2>/dev/null
grep -R "ALLOW" /etc/rkhunter.conf
grep -R "SCRIPTWHITELIST" /etc/rkhunter.conf
```

Key fields:

- `ALLOW_SSH_ROOT_USER`  
- `ALLOW_SUID`  
- `ALLOWDEVFILE`  
- `SCRIPTWHITELIST`  
- `UPDATE_MIRRORS`  

##### rkhunter last run time

```bash
grep -i "Start" /var/log/rkhunter.log | tail -n 5
grep -i "End" /var/log/rkhunter.log | tail -n 5
```

Or check cron/systemd:

```bash
grep -R rkhunter /etc/cron* /var/spool/cron/
systemctl list-timers | grep -i rkhunter
```

##### rkhunter logs

```bash
tail -n 50 /var/log/rkhunter.log
grep -i warning /var/log/rkhunter.log
grep -i "infected" /var/log/rkhunter.log
```

##### rkhunter database versions

```bash
rkhunter --update --versioncheck
ls -al /var/lib/rkhunter/db/
```

#### chkrootkit

chkrootkit is another common rootkit scanner. It’s older and less comprehensive than rkhunter, but still widely deployed. It can:

- Scan for known rootkits  
- Check for hidden processes  
- Look for suspicious network activity  
- Detect modified system binaries  
- Check for signs of kernel-level compromise  

##### Where logs live
chkrootkit usually logs to:

- `/var/log/chkrootkit.log`
- `/var/log/syslog` (if run via cron)

##### What defenders see
- Rootkit signature matches  
- Suspicious file modifications  
- Unexpected network listeners  
- Hidden processes  

chkrootkit is prone to false positives, but defenders often investigate them anyway.

##### Enumeration commands

```bash
# Check if installed
chkrootkit -V 2>/dev/null

# Check last run time
grep -R chkrootkit /etc/cron* /var/spool/cron/
systemctl list-timers | grep -i chkrootkit

# Check logs
tail -n 50 /var/log/chkrootkit.log 2>/dev/null
grep -i "INFECTED" /var/log/chkrootkit.log

# Run a safe enumeration (no scan)
chkrootkit -l
```

#### Lynis (Security Auditing Tool)

Lynis is a host auditing tool used for compliance and security posture checks. It’s not strictly antimalware, but it detects many red‑team artifacts.

- Audits system configuration  
- Checks file permissions  
- Scans for suspicious binaries  
- Reviews authentication configuration  
- Checks for rootkit indicators  
- Evaluates kernel hardening  
- Reviews cron jobs, timers, and services  

##### Where logs live
- `/var/log/lynis.log`
- `/var/log/lynis-report.dat`

##### What defenders see
- Warnings about insecure configurations  
- Suspicious binaries  
- Unexpected suid/sgid files  
- Weak SSH settings  
- Modified system files  
- Cron persistence indicators  

##### Lynis Enumeration Commands

```bash
# Check if installed
lynis show version 2>/dev/null


# Check last audit
tail -n 50 /var/log/lynis.log
grep -i warning /var/log/lynis.log


# Check Lynis report
cat /var/log/lynis-report.dat


# Check cron/systemd
grep -R lynis /etc/cron* /var/spool/cron/
systemctl list-timers | grep -i lynis
```

#### unhide (Hidden Process Detection)

unhide detects hidden processes and hidden TCP/UDP ports.

- Compares `/proc` process list against kernel process list  
- Detects hidden processes (rootkits often hide themselves)  
- Checks for hidden network listeners  

##### Where logs live
Usually only stdout unless run via cron.

##### Enumeration Commands

```bash
unhide --version 2>/dev/null

# Check if installed
which unhide

# Check cron/systemd
grep -R unhide /etc/cron* /var/spool/cron/
systemctl list-timers | grep -i unhide
```

#### File Integrity Monitoring: Persistence Detection Engines

#### AIDE
AIDE builds a database of file hashes and alerts on changes.

##### What gets logged
- Changes to `/etc/passwd`, `/etc/shadow`
- Cron modifications
- SSH key installation
- System file tampering
 
Persistence techniques involving file modification (cron jobs, systemd units, SSH keys) may be detected.

```bash
# Check AIDE config
cat /etc/aide/aide.conf

# Check for scheduled AIDE runs
grep -R aide /etc/cron* /var/spool/cron/
```

#### OSSEC / Wazuh
Host‑based intrusion detection systems with log analysis, file integrity monitoring, and active response.

##### Enumeration tips:  
Look at `/var/ossec/etc/ossec.conf` to see:

- Monitored directories  
- Active response modules (auto‑blocking)  
- Log forwarding behavior  

```bash
# Check OSSEC/Wazuh config
cat /var/ossec/etc/ossec.conf

# Check agent status
systemctl status wazuh-agent 2>/dev/null
systemctl status ossec 2>/dev/null
```

#### Other Common Monitoring Tools

##### Debsums (Debian-based systems)  
Checks integrity of installed packages.

```bash
debsums -s
```

#### Tripwire (less common now)  
File integrity monitoring.

```bash
tripwire --check
```

#### OpenVAS/Greenbone (network vulnerability scanning)  
Not host-based, but often installed locally.

```bash
ps aux | grep openvas
```

## Modern Observability Stacks: Enterprise Eyes Everywhere

### Prometheus
Prometheus scrapes metrics from exporters like `node_exporter` and `process_exporter`.

Why red teams care:  
Exporters can reveal:

- Suspicious processes  
- Resource spikes  
- Unexpected network activity  
- Lateral movement indicators  
- Full-text log indexing  

```bash
# Check Prometheus config
cat /etc/prometheus/prometheus.yml

# Check exporters
ps aux | grep exporter
```

### Grafana Loki
Loki aggregates logs with labels that often expose:

- Usernames  
- Service identifiers  

```bash
# Check Loki config
cat /etc/loki/local-config.yaml 2>/dev/null
cat /etc/loki/config.yaml 2>/dev/null
```

### Elastic Stack (ELK)
Logstash pipelines and Elasticsearch indices often represent the defender’s primary SIEM.

Enumeration tips:  
Presence of ELK usually means:

- High log retention  
- Full‑text search  
- Real‑time alerting  

```bash
# Check Logstash pipelines
ls -al /etc/logstash/conf.d/
cat /etc/logstash/conf.d/*.conf

# Check Elasticsearch presence
ps aux | grep elastic
```

### Graylog
Another enterprise log aggregation platform. Config files reveal input streams and alerting rules.

```bash
# Graylog server config
cat /etc/graylog/server/server.conf
```

## Monitoring Suites

### Nagios / Icinga

```bash
# Nagios configs
ls -al /etc/nagios/
grep -R "check_" /etc/nagios/

# Icinga configs
ls -al /etc/icinga/
grep -R "command" /etc/icinga/
```

### Zabbix

```bash
# Zabbix agent config
cat /etc/zabbix/zabbix_agentd.conf

# Check active/passive mode
grep -E "Server|ServerActive" /etc/zabbix/zabbix_agentd.conf
```

### Netdata

```bash
# Netdata config
ls -al /etc/netdata/
cat /etc/netdata/netdata.conf

# Check collectors
ls -al /etc/netdata/collectors/
```