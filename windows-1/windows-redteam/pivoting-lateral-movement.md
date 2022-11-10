# Pivoting/Lateral Movement

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

Not much here yet...please feel free to contribute at [https://www.github.com/zweilosec](https://github.com/zweilosec)

## WinRM

### Using winrs

```batch
winrs -r:$ip -u:$domain\$user -p:$passwd $cmd
```

To use this command you need to specify a remote IP, the remote user (with domain), the user's password, and the command to be run

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/winrs

### Using PowerShell

Test if WinRM is running on the remote system

```powershell
Test-WSMan -ComputerName $computername
```

Test if the port is open

```powershell
Test-NetConnection -ComputerName $computername -CommonTCPPort WINRM
```

Run a command on the system (using current credentials as SSO)

```powershell
Invoke-Command -ComputerName $computername -Port 5985 -ScriptBlock { $cmd }
```

Run a command on the system by specifying credentials

{% code overflow="wrap" lineNumbers="true" %}
```powershell
$passwd = ConvertTo-SecureString '$passwd' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('$user', $passwd)
Invoke-Command -ComputerName $computername -Port 5985 -ScriptBlock { $cmd } -Credential $cred -Authentication Negotiate
```
{% endcode %}

If you have a GUI logon such as through RDP you can simplify the credential request by using `Get-Credential`. This way you do not need to type the password into the cmdline, which is likely being logged.

## Forward ports using built-in firewall

### Using netsh

To set up a port forwarder using `netsh` run the below commands as an administrator.

{% code overflow="wrap" lineNumbers="true" %}
```batch
netsh interface portproxy add v4tov4 listenport=$lport connectport=$rport connectaddress=$ip
```
{% endcode %}

Substitute **`$lport`**, **`$rport`**, and **`$ip`** with the local port, remote port, and IP to forward to, respectively.

## SMB Shares

You can use the command `net use` to start a session on a remote computer

```batch
net use \\$target
```

Typing the command without specifying credentials will use SSO with your current user's credentials. To connect as a specific user, use the below command

```batch
net use \\$target $password /u:$user
```

If remote sessions are alllowed you should see "Command completed successfully."

If you don't specify a share, as above, it will access the first available share on the remote system (typically IPC$). Since this likely won't have access to the file system directly, you will need to specify a share to connect to. Use the command `net view` to list out the available shares.

```batch
PS c:/> net view \\$target /all
Shared resources at \\COMPUTER
Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\                             Default share
ADMIN$       C:\WINDOWS                      Remote Admin
Users        C:\Users
The command completed successfully.
```

Next, pick a share you want to connect to and specify it in the command to connect.

```batch
net use * \\$target\$share $passwd /u:$user
```

The `*` indicates that you want the remote share mounted locally. It will choose the first available drive letter and mount the share to it. You can also specify a letter instead (e.g. `net use z:`)

Note: sometimes you need to specify the hostname or domain with the username in order for the login to work properly.

```batch
net use * \\$target\$share $passwd /u:$host_or_domain\$user
```

Warning: Windows machines only allow a single SMB session with a target machine at a time. You will need to drop the first session in order to open a new one.

```batch
net use \\$target /del /y
```

Or quickly drop all SMB sessions with the below command.

```batch
net use * /del /y
```

### Service Controller (sc.exe)

If you have an active administrator SMB session with a remote computer you can use `sc.exe` to query, configure, start, or stop services on that computer.  This can enable you to use other methods on that machine without having to get a shell (or allow shell access by enabling WinRM, for example). &#x20;

To run `sc.exe` against a remote machine use the syntax below

```
sc.exe \\$target
```

With this you can do any other `sc.exe` command, such as listing the state of all installed services.  Make sure to note the space after `state=` in the command below.

```
sc.exe \\$target query state= all
```

This gives detailed information about each service installed on the system such as state (STOPPED, RUNNING, etc.), type, service name, and display name.  The service name is needed to interact with a specific service.  With this you can start, stop, or change startup type of a service.

```
#start a service
sc.exe \\$target start $service_name

#stop a service
sc.exe \\$target stop $service_name
```

To start a service, you might need to know its current startup type.  Unfortunately, the command above does not list this, so you need to query the specific service individually.

```
sc.exe \\$target qc $service_name
```

This gives additional information such as the `START_TYPE` and `BINARY_PATH_NAME`.  The main reason you need to know the `START_TYPE` is that when the startup type is `DISABLED` you must change it to `DEMAND` ("Manual" in the GUI) before you can start the service.  Change the `START_TYPE` of a service using the command below.

```
sc.exe config \\$target $service_name start= demand
```

The different startup types are boot, system, auto, demand, disabled, and delayed-auto.

### at/schtasks

The `at.exe` and `schtasks.exe` programs are another set of built-in Windows commands that can be run on a remote system once an administrator SMB session has been created (such as with `net use` above). &#x20;

{% hint style="info" %}
You will also need to use `sc.exe` to ensure the Scheduler service is running!

```
sc.exe \\$target query schedule
```

If the service is not running, start it, then optionally set it to automatically startup as well (see [previous section](pivoting-lateral-movement.md#service-controller-sc.exe)).
{% endhint %}



{% hint style="info" %}
You will also likely need to know the current time on the system you are scheduling the task on, as it might not be the same as your current system.

```powershell
net time \\$target
```
{% endhint %}

#### at.exe

{% hint style="warning" %}
This command may not work on your target system anymore, as it has been deprecated by Microsoft. On my Windows 10 22H2 machine I received the message:

```
The AT command has been deprecated. Please use schtasks.exe instead.

The request is not supported.
```
{% endhint %}

The syntax for scheduling a command to run with `at.exe` is as below

```powershell
at.exe \\$target $time $command
```

The time must be in the format `HH:MM A` where `A` represents AM and `P` in its place would represent PM.  Some versions of Windows support 24-hour time, but not all.  It is better to use AM/PM as all versions support this. &#x20;

To check the status of the new service just run the command by itself against the remote machine.

```
at.exe //$target
```

This will show all tasks scheduled through the `at.exe` command, but not `schtasks`. &#x20;

#### schtasks.exe

The basic syntax for `schtasks.exe` is much more customizable that `at.exe`.

{% code overflow="wrap" lineNumbers="true" %}
```powershell
schtasks.exe /create /tn $task_name /s $target /u $user /p $password /sc $frequency /st $start_time /tr $command
```
{% endcode %}

* `/st`: As with `at.exe` there is a specific formation the start time needs to follow, or the command will fail.  In this case the start time must be in the format `HH:MM:SS`. &#x20;
* `/sc`: The frequency can be set to repeat the command according to a number of values:&#x20;
  * **MINUTE** - Specifies the number of minutes before the task should run.
  * **HOURLY** - Specifies the number of hours before the task should run.
  * **DAILY** - Specifies the number of days before the task should run.
  * **WEEKLY** Specifies the number of weeks before the task should run.
  * **MONTHLY** - Specifies the number of months before the task should run.
  * **ONCE** - Specifies that that task runs once at a specified date and time.
  * **ONSTART** - Specifies that the task runs every time the system starts. You can specify a start date, or run the task the next time the system starts.
  * **ONLOGON** - Specifies that the task runs whenever a user (any user) logs on. You can specify a date, or run the task the next time the user logs on.
  * **ONIDLE** - Specifies that the task runs whenever the system is idle for a specified period of time. You can specify a date, or run the task the next time the system is idle.

If you want to run the command as SYSTEM rather than with a specific user's credentials replace the `/u` and `/p` options with `/ru SYSTEM`. &#x20;

For many more advanced options check out [Microsoft's documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create).

To check the status of tasks scheduled with both `at.exe` and `schtasks` use this command:

```powershell
schtasks.exe /query /s $target
```

## PSEXEC

Signed Microsoft binary, part of the Sysinternals toolkit.  Connects to the remote system through SMB, then creates a service on the remote system which runs the command specified. Some AV/EDR products automatically flag this as malicious now. Basic syntax is below:

```powershell
psexec.exe \\$target "$command"
```

You can also specify more than one target by separating them by a comma or replacing the target with a text file with `@target_file`. Some other advanced options:

| Option | Definition                                                                      |
| ------ | ------------------------------------------------------------------------------- |
| `-c`   | Copy specified executable to remote system before execution, will not overwrite |
| `-d`   | Disconnected mode. Does not channelize stdin/stdout. Use with nc listeners      |
| `-f`   | Force overwrite of copied executable                                            |
| `-h`   | Run with elevated privileges                                                    |
| `-u`   | Username                                                                        |
| `-p`   | Password                                                                        |
| `-s`   | Run as SYSTEM                                                                   |
| `-i`   | Run interactively (i.e. with cmd.exe or PowerShell)                             |

Make sure to add the option `-accepteula` the first time you run PsExec against a system. Otherwise, your command will not run, and the user will see a prompt to accept the license agreement.
