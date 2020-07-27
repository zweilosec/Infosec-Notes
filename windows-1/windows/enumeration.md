# Enumeration

Be aware sometimes these commands require elevated privileges to be run, or may be blocked by GPO.

(./winpeas.exe)[https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS] #My favorite Windows enumeration script, automates most common enumeration methods 

# User Enumeration
### Get list of current user information:  
`whoami /all` Includes: Username, SID, Groups \(including their descriptions!\), and user privileges.
`Get-WmiObject -class Win32_UserAccount [-filter "LocalAccount=True"]` #filter does not work on my work computer...but without it dumps all accounts on the whole domain!

(cmd.exe)
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

(Powershell)
Get-WmiObject -Class Win32_UserAccount

## LAPS

LAPS allows you to manage the local Administrator password (which is randomised, unique, and changed regularly) on domain-joined computers. These passwords are centrally stored in Active Directory and restricted to authorised users using ACLs. Passwords are protected in transit from the client to the server using Kerberos v5 and AES.
`reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled`
When using LAPS, 2 new attributes appear in the computer objects of the domain: ms-msc-AdmPwd and ms-mcs-AdmPwdExpirationTime. These attributes contains the plain-text admin password and the expiration time. Then, in a domain environment, it could be interesting to check which users can read these attributes...


# OS Information
## Get OS Version information
`systeminfo | findstr /B /C:"OS Name" /C:"OS Version"`
`[System.Environment]::OSVersion.Version`

## Get basic Windows information 
Also lists the patches that have been installed. 
`systeminfo`
`Get-ComputerInfo`

## Get installed patches
`wmic qfe get Caption,Description,HotFixID,InstalledOn` 
`Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid}`
`Get-Hotfix`
  `-description "Security update"` #List only "Security Updates"

## Drivers
### Get a list of installed drivers
`driverquery`
`Get-WindowsDriver -Online -All`
`-Online` Specifies that the action is to be taken on the operating system that is currently running on the local computer.

### Default log path
`%WINDIR%\Logs\Dism\dism.log`
### Make back up of all installed drivers
`Export-WindowsDriver -Online -Destination "C:\Backup\Path\"`

## List Environment Variables
`set`
`Get-ChildItem env:`

## Check Audit (logging) Settings
These settings show what is being logged, this can be useful information for evasion and persistence
`reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit`

### Windows Event Forwarding 
(where are the logs sent)
`reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager`

## AV
Check if there is any antivirus intalled:
`WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get DisplayName | fl`

## Clipboard
Get the contents of the clipboard
`Get-Clipboard`


# Software, Services, and Processes
## Software

### List the installed software
`dir /a "C:\Program Files"`
`dir /a "C:\Program Files (x86)"`
`reg query HKEY_LOCAL_MACHINE\SOFTWARE`

`Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)'`
`Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE`
## Services
Get a list of services:
`net start`
`wmic service list brief`
`sc query`
`Get-Process`
### Get detailed information for a specific service
`sc qc <service_name>` 
To use this command in PowerShell you need to specify `sc.exe` instead of `sc`.  In PowerShell `sc` is an alias for `Set-Content` and will not give the expected output.

`Get-Service`

### Enable a disabled service
If you are having this error (for example with SSDPSRV):
> System error 1058 has occurred. 
> The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.
You can enable it using:
```
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
Note: In Windows XP SP1, the service upnphost depends on SSDPSRV to work

### Enable a disabled service
If you are having this error (for example with SSDPSRV):
> System error 1058 has occurred. 
> The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.
You can enable it using:
```
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
Note: In Windows XP SP1, the service upnphost depends on SSDPSRV to work


## Get running processes
Lists all the service information for each process with `tasklist /svc`. Valid when the `/fo <format>` parameter is set to table (default format). Can be run remotely with `/s <name or IP address>` and credentialed with `/u <username>` and `/p <password>`. `/v` = verbose

With usernames of process owner
`Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize`

Without usernames
`Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id`

### Check permissions of the process binaries
```
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z" 
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```
### Check permissions of the folders of the process binaries (useful for dll injection)
```
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v 
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users 
todos %username%" && echo.
)
```
## Get current network connections
`netstat -ano` 

https://github.com/carlospolop/hacktricks/blob/master/windows/basic-cmd-for-pentesters.md#network (*check for more network enumeration info here)

## AutoRuns
Check which files are executed when the computer is started. Components that are executed when a user logins can be exploited to execute malicious code when the administrator logins.
(cmd.exe)
```
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
(powershell)
```
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
### SysInternals AutoRuns

For a comprehensive list of auto-executed files you can use AutoRuns from SysInternals https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns:
`autorunsc.exe -m -nobanner -a * -ct /accepteula`


# References

- https://docs.microsoft.com/en-us/sysinternals/
- https://docs.microsoft.com/en-us/powershell/
