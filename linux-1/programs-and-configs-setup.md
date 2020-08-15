---
description: >-
  A collection of useful programs and configurations for getting your home box
  set up for pre-engagement use. I think I want to rename this page to something
  else...can't think of a good title right now
---

# Programs & Configs Setup

## System update

The first thing to do after the first boot is to update the system. In most Debian-based flavors of Linux, you achieve this by executing the commands below:

```text
sudo apt update && sudo apt upgrade -y
```

## Check the installed packages

List all packages installed on your Linux OS and remove the unnecessary ones. Besides installing updates, the next best way to harden a system is to remove or disable applications and services that are vulnerable to attack or are not needed. Here’s an example of how to list the packages installed on Kali Linux: `apt-cache pkgnames`

Remember that disabling unnecessary services will reduce the attack surface, so it is important to remove the following legacy services if you found them installed on the Linux server:

* Telnet server
* RSH server
* NIS server
* TFTP server
* TALK server
* Any other running services that are not needed

## Check for open ports

Identifying open connections to the internet is critical to understanding your attack surface. In Kali Linux, use the following commands to identify open ports:

```text
netstat
ss
lsof -i

...add more info
```

## Secure SSH

First of all, if you do not need SSH, disable it. However, if you want to use it, then you need to ensure the configurations of SSH are secure.

1. Browse to `/etc/ssh` and open the `sshd_config` file using your favorite text editor.
2. Change the default port number 22 to something else, e.g. 2299. \(Caution: this could interfere with some tools which expect SSH to run on port 22\).
3. Make sure that root cannot login remotely through SSH by modifying the following line in `sshd_config`.

    `PermitRootLogin no`

4. Allow only specific users:

    `AllowUsers <username>`

5. Add a banner to discourage attackers from continuing further with:

    `Banner /etc/banner` 

6. Check the manual for SSH to understand all the configurations in `/etc/ssh/sshd_config`. Some other examples of recommended configuration options are:

   ```text
   AuthorizedKeysFile /etc/ssh/authorized-keys/%u #removes this file from user's folder and puts its in more secure /etc folder
   Protocol2
   IgnoreRhosts to yes
   HostbasedAuthentication no
   PermitEmptyPasswords no
   X11Forwarding no
   MaxAuthTries 5
   Ciphers aes128-ctr,aes192-ctr,aes256-ctr
   HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss
   KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256
   MACs hmac-sha2-256,hmac-sha2-512,hmac-sha1
   ClientAliveInterval 900 
   ClientAliveCountMax 0
   UsePAM yes
   ```

7. Finally, set the permissions on the sshd\_config file so that only root users can change its contents:
   * `chown root:root /etc/ssh/sshd_config`
   * `chmod 600 /etc/ssh/sshd_config`

## Lock the boot directory

The boot directory contains important files related to the Linux kernel, so you need to make sure that this directory is locked down to read-only permissions by following the next simple steps. 1. First, open the “fstab” file: `vim /etc/fstab` 2. Then, add the following below the last line: `LABEL=/boot /boot ext2 defaults,ro 1 2` 3. When you finish editing the file, you need to set the owner by executing the following command: `chown root:root /etc/fstab` 4. Next, set permissions for securing the boot settings:

* Set the owner and group of `/etc/grub.conf` to the root user: `chown root:root /etc/grub.conf`
* Set permission on the `/etc/grub.conf` file to read and write for root only: `chmod og-rwx /etc/grub.conf`
* Require authentication for single-user mode:
  * `sed -i "/SINGLE/s/sushell/sulogin/" /etc/sysconfig/init`
  * `sed -i "/PROMPT/s/yes/no/" /etc/sysconfig/init`

## Monitoring and Logging

[https://kali.training/topic/monitoring-and-logging/](https://kali.training/topic/monitoring-and-logging/) TODO: add more info tripwire [https://kali.training/topic/exercise-7-3-securing-the-kali-file-system/](https://kali.training/topic/exercise-7-3-securing-the-kali-file-system/) checksecurity chkrootkit/rkhunter

### Monitoring Logs with `logcheck`

TODO:Rewrite this...brevity and clarity

The logcheck program monitors log files every hour by default and sends unusual log messages in emails to the administrator for further analysis. The list of monitored files is stored in /etc/logcheck/logcheck.logfiles. The default values work fine if the /etc/rsyslog.conf file has not been completely overhauled. logcheck can report in various levels of detail: paranoid, server, and workstation. paranoid is very verbose and should probably be restricted to specific servers such as firewalls. server is the default mode and is recommended for most servers. workstation is obviously designed for workstations and is extremely terse, filtering out more messages than the other options. In all three cases, logcheck should probably be customized to exclude some extra messages \(depending on installed services\), unless you really want to receive hourly batches of long uninteresting emails. Since the message selection mechanism is rather complex, /usr/share/doc/logcheck-database/README.logcheck-database.gz is a required—if challenging—read. The applied rules can be split into several types: those that qualify a message as a cracking attempt \(stored in a file in the /etc/logcheck/cracking.d/directory\); ignored cracking attempts \(/etc/logcheck/cracking.ignore.d/\); those classifying a message as a security alert \(/etc/logcheck/violations.d/\); ignored security alerts \(/etc/logcheck/violations.ignore.d/\); finally, those applying to the remaining messages \(considered as system events\). ignore.d files are used to \(obviously\) ignore messages. For example, a message tagged as a cracking attempt or a security alert \(following a rule stored in a /etc/logcheck/violations.d/myfile file\) can only be ignored by a rule in a /etc/logcheck/violations.ignore.d/myfile or /etc/logcheck/violations.ignore.d/myfile-extension file. A system event is always signaled unless a rule in one of the /etc/logcheck/ignore.d.{paranoid,server,workstation}/ directories states the event should be ignored. Of course, the only directories taken into account are those corresponding to verbosity levels equal or greater than the selected operation mode.

## Enable SELinux

Security Enhanced Linux is a Kernel security mechanism for supporting access control security policy. The SELinux has three configuration modes:

* Disabled: Turned-off
* Permissive: Prints warnings
* Enforcing: Policy is enforced

  Using a text editor, open the config file `/etc/selinux/config` and make sure that the policy is enforced by changing the line `SELINUX=enforcing`.

  ```text
  add example of config file - image?
  ```

## Permissions and verifications

Prepare yourself mentally because this is going to be a long list. But, permissions is one of the most important and critical tasks to achieve the security goal on a Linux host. Set User/Group Owner and Permissions to `root` on `/etc/anacrontab`, `/etc/crontab` and `/etc/cron.*` by executing the following commands: \(as `root`\)

```text
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
```

Set the permissions and owner on `/var/spool/cron` for the `root` crontab.

```text
chown root:root <crontabfile>
chmod og-rwx <crontabfile>
```

Set permissions and owner on `/etc/passwd` file \(this file must be readable by all users\).

```text
chmod 644 /etc/passwd
chown root:root /etc/passwd
```

Set permissions and owner on the `/etc/group` file \(this file must be readable by all users\).

```text
chmod 644 /etc/group
chown root:root /etc/group
```

Set permissions and owner on the `/etc/shadow` file.

```text
chmod 600 /etc/shadow
chown root:root /etc/shadow
```

Set permissions and owner on the `/etc/gshadow` file.

```text
chmod 600 /etc/gshadow
chown root:root /etc/gshadow
```

## Misc

Use strong passwords Set up `fail2ban`, which will make it much harder to brute-force passwords over the network by filtering IP addresses that exceed a limit of failed login attempts. `apt install fail2ban` VPN NAT Firewall Rules `iptables` and `ip6tables` or GUI `fwbuilder` \([https://kali.training/topic/firewall-or-packet-filtering/](https://kali.training/topic/firewall-or-packet-filtering/)\) Check for default credentials in `README.Debian` files of each respective installed package, as well as `docs.kali.org` and `tools.kali.or`g to see if isntalled services need special care to be secured.

## Useful Programs & Configs Setup

### TMUX

tmux can keep alive sessions if you lose ssh sessions etc, can split panes and more:

```text
tmux new -s <session_name> 
ctrl-b = prefix key (enables addnl commands) 
+[%] vertical pane  
+["] horizontal pane 
+[alt-space] switch pane between horizontal or vertical
+[arrow_keys] move between panes 
+[z] zoom in/out on pane 
+[?] help for tmux 
+[t] timer
```

tmux plugins:

* tmux logging plugin \(get this!!\) can save log of tmux windows
* [better mouse mode](https://github.com/NHDaly/tmux-better-mouse-mode)

### Tmux

Config from [ippsec](https://www.youtube.com/watch?v=Lqehvpe_djs).

```text
#set prefix
set -g prefix C-a
bind C-a send-prefix
unbind C-b

set -g history-limit 100000
set -g allow-rename off

bind-key j command-prompt -p "Join pane from:" "join-pane -s '%%'"
bind-key s command-prompt -p "Send pane to:" "joian-pane -t '%%'"

set-window-option -g mode-keys vi

run-shell /opt/tmux-logging/logging.tmux
```

First press the prefix `ctrl + b`\(default, Ippsec changes it to Ctrl+a\) then release the buttons and press the combination you want.

Create new named session: `tmux new -s [Name]`

Create new window: `prefix + c`

Rename window: `prefix + ,`

Change panes: `prefix + #`

List windows: `prefix + w`

Vertical split: `prefix + %`

Horizontal split: `prefix + "`

Join panes: `prefix + s #`

Zoom in/out to panes: `prefix + z`

Make sub-terminal its own window: `prefix + !`

Enter vim mode: `prefix + ]` -&gt; Search with `?` in vi mode then press `space` to start copying. Press `prefix + ]` to paste

Kill session by tag:`tmux kill-session -t X`

Kill pane: `prefix + &`

### iptables based wireless access point

Here’s a cool and interesting use of iptables. You can turn any computer with a wireless interface into a wireless access point with hostapd. This solution comes from [https://seravo.fi/2014/create-wireless-access-point-hostapd](https://seravo.fi/2014/create-wireless-access-point-hostapd):

```text
iptables -t nat -F
iptables -F
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
echo '1' > /proc/sys/net/ipv4/ip_forward
(DNS, dhcp still required)
```

## References

* [https://forums.kali.org/showthread.php?28027-Hardening-Kali-Linux-Tips-and-Tricks](https://forums.kali.org/showthread.php?28027-Hardening-Kali-Linux-Tips-and-Tricks)
* [https://kali.training/lessons/7-securing-and-monitoring-kali/](https://kali.training/lessons/7-securing-and-monitoring-kali/)
* [https://www.tecmint.com/linux-server-hardening-security-tips/](https://www.tecmint.com/linux-server-hardening-security-tips/)  - TODO: pull more info from this source
* [https://www.ssh.com/ssh/sshd\_config/](https://www.ssh.com/ssh/sshd_config/)
* [https://www.pluralsight.com/blog/it-ops/linux-hardening-secure-server-checklist](https://www.pluralsight.com/blog/it-ops/linux-hardening-secure-server-checklist)

