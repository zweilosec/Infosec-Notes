# Enumeration

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

Be aware sometimes these commands require elevated privileges to be run, or may be blocked by GPO.

[https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) = My favorite Windows enumeration script, automates most common enumeration methods

## User Enumeration

### Get current user information:

{% tabs %}
{% tab title="PowerShell" %}
`[Security.Principal.WindowsIdentity]::GetCurrent()` Not very good output by default, need to manipulate the object a bit to get the desired information
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
`net user %username%` \#Me `net users` \#All local users `net localgroup` \#Groups `net localgroup Administrators` \#Who is inside Administrators group 
{% endtab %}
{% endtabs %}

### Using WMI Query Language \(WQL\)

WQL is an entire subject on its own.  If you want to know the full extent of the capabilities of this powerful query language, type `Get-Help WQL` in a PowerShell prompt.  Below are a few examples of queries to pull lists of users from both local machines and from the domain.

```text
The following WQL query returns only local user accounts from a domain
joined computer.

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

`systeminfo | findstr /B /C:"OS Name" /C:"OS Version"` 

`[System.Environment]::OSVersion.Version`

### Get basic Windows information

Also lists the patches that have been installed. `systeminfo` `Get-ComputerInfo`

### Get installed patches

`wmic qfe get Caption,Description,HotFixID,InstalledOn` 

`Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} Get-Hotfix -description "Security update"` \#List only "Security Updates"

### Drivers

#### Get a list of installed drivers

`driverquery` 

`Get-WindowsDriver -Online -All -Online` Specifies that the action is to be taken on the operating system that is currently running on the local computer.

#### Default log path

`%WINDIR%\Logs\Dism\dism.log`

#### Make back up of all installed drivers

`Export-WindowsDriver -Online -Destination "C:\Backup\Path\"`

### List Environment Variables

`set` 

`Get-ChildItem env:`

### Check Audit \(logging\) Settings

These settings show what is being logged, this can be useful information for evasion and persistence `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit`

#### Windows Event Forwarding

\(where are the logs sent\) `reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager`

### AV

Check if there is any antivirus intalled: `WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get DisplayName | fl`

### Clipboard

Get the contents of the clipboard `Get-Clipboard`

## Software, Services, and Processes

### Software

#### List the installed software

`dir /a "C:\Program Files"` 

`dir /a "C:\Program Files (x86)"` 

`reg query HKEY_LOCAL_MACHINE\SOFTWARE`

`Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)'` 

`Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE`

### Services

Get a list of services: 

`net start` 

`wmic service list brief` 

`sc query` 

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

Lists all the service information for each process with `tasklist /svc`. Valid when the `/fo <format>` parameter is set to table \(default format\). Can be run remotely with `/s <name or IP address>` and credentialed with `/u <username>` and `/p <password>`. `/v` = verbose

With usernames of process owner `Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize`

Without usernames `Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id`

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

`netstat -ano`

[https://github.com/carlospolop/hacktricks/blob/master/windows/basic-cmd-for-pentesters.md\#network](https://github.com/carlospolop/hacktricks/blob/master/windows/basic-cmd-for-pentesters.md#network) \(\*check for more network enumeration info here\)

### AutoRuns

Check which files are executed when the computer is started. Components that are executed when a user logins can be exploited to execute malicious code when the administrator logins. \(cmd.exe\)

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

\(powershell\)

```text
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

#### SysInternals AutoRuns

For a comprehensive list of auto-executed files you can use AutoRuns from SysInternals [https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns): `autorunsc.exe -m -nobanner -a * -ct /accepteula`

## References

* [https://docs.microsoft.com/en-us/sysinternals/](https://docs.microsoft.com/en-us/sysinternals/)
* [https://docs.microsoft.com/en-us/powershell/](https://docs.microsoft.com/en-us/powershell/)

