# Getting Access

{% hint style="success" %}
**Hack Responsibly.**

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

## Lateral Movement

### PowerShell Remoting

```powershell
#Enable Powershell Remoting on current Machine (Needs Admin Access)
Enable-PSRemoting

#Entering or Starting a new PSSession (Needs Admin Access)
$sess = New-PSSession -ComputerName $ComputerName>
Enter-PSSession -ComputerName $ComputerName 
#-OR-
Enter-PSSession -Sessions $SessionName
```

### Remote Code Execution with PS Credentials

```powershell
$SecPassword = ConvertTo-SecureString '$Password' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('$DomainName\$User', $SecPassword)
Invoke-Command -ComputerName $ComputerName -Credential $Cred -ScriptBlock {whoami /all}
```

### Import a PowerShell module and execute its functions remotely

```powershell
#Execute the command and start a session
Invoke-Command -Credential $cred -ComputerName $ComputerName -FilePath $PSModule_FilePath -Session $sess 

#Interact with the session
Enter-PSSession -Session $sess
```

### Executing Remote Stateful commands

```powershell
#Create a new session
$sess = New-PSSession -ComputerName $ComputerName

#Execute command on the session
Invoke-Command -Session $sess -ScriptBlock {$ps = Get-Process}

#Check the result of the command to confirm we have an interactive session
Invoke-Command -Session $sess -ScriptBlock {$ps}
```

### Useful Tools

* [Powercat](https://github.com/besimorhino/powercat) netcat written in powershell, and provides tunneling, relay and portforward capabilities.
* [SCShell](https://github.com/Mr-Un1k0d3r/SCShell) fileless lateral movement tool that relies on ChangeServiceConfigA to run command
* [Evil-Winrm](https://github.com/Hackplayers/evil-winrm) the ultimate WinRM shell for hacking/pentesting
* [RunasCs](https://github.com/antonioCoco/RunasCs) Csharp and open version of windows builtin runas.exe

