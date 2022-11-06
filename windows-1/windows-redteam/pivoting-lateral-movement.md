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
