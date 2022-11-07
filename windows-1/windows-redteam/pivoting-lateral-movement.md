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

```powershell
$passwd = ConvertTo-SecureString '$passwd' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('$user', $passwd)
Invoke-Command -ComputerName $computername -Port 5985 -ScriptBlock { $cmd } -Credential $cred -Authentication Negotiate
```

If you have a GUI logon such as through RDP you can simplify the credential request by using `Get-Credential`. This way you do not need to type the password into the cmdline, which is likely being logged.

## Forward ports using built-in firewall

### Using netsh

To set up a port forwarder using `netsh` run the below commands as an administrator.

```batch
netsh interface portproxy add v4tov4 listenport=$lport connectport=$rport connectaddress=$ip
```

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
