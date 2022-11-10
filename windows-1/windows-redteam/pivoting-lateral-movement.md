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
