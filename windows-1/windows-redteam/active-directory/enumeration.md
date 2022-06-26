# Enumeration

{% hint style="success" %}
**Hack Responsibly.**

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

## Without Active Directory module installed

#### Get Current Domain Info

```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

#### Get Domain Trusts

```
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
```

#### Get Forest Info

```
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
```

#### Get Forest Trust Relationships

```
([System.DirectoryServices.ActiveDirectory.Forest]::GetForest((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', 'forest-of-interest.local')))).GetAllTrustRelationships()
```

### Enumerate Domain Users

#### Get User-related Environment Variables (cmd.exe)

```
set u
```

#### List all Usernames

```powershell
([adsisearcher]"(&(objectClass=User)(samaccountname=*))").FindAll().Properties.samaccountname
```

#### List Administrators

```powershell
([adsisearcher]"(&(objectClass=User)(admincount=1))").FindAll().Properties.samaccountname
```

#### List all Info about specific user

{% tabs %}
{% tab title="PowerShell" %}
```powershell
([adsisearcher]"(&(objectClass=User)(samaccountname=$UserName))").FindAll().Properties
```
{% endtab %}

{% tab title="cmd.exe" %}
```
nltest /user:"zweilos"
```
{% endtab %}
{% endtabs %}

#### View All Users with Description Field Set

```powershell
([adsisearcher]"(&(objectClass=group)(samaccountname=*))").FindAll().Properties | % { Write-Host $_.samaccountname : $_.description }
```

## Using Active Directory PowerShell module



#### View all Active Directory commands

```powershell
Get-Command -Module ActiveDirectory
```

#### Display Basic Domain Information

```powershell
Get-ADDomain
```

**Get Domain SID**

```powershell
Get-DomainSID
```

**Enumerate other Domains:**&#x20;

```powershell
Get-ADDomain -Identity $DomainName
```

**List Domain Controllers**

```powershell
Get-ADDomainController
Get-ADDomainController -Identity $DomainName
```

#### Get all Domain Controllers by Hostname and Operating **System**

```powershell
Get-ADDomainController -filter * | select hostname, operatingsystem
```

**Enumerate Domain Computers:**

```powershell
Get-ADComputer -Filter * -Properties *
Get-ADGroup -Filter *
```

**Enumerate Domain Trust:**

```powershell
Get-ADTrust -Filter *
Get-ADTrust -Identity $DomainName
```

**Enumerate Forest Trust:**

```powershell
Get-ADForest
Get-ADForest -Identity $ForestName

#List Domains in a Forest
(Get-ADForest).Domains
```

**Enumerate Local AppLocker Effective Policy:**

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

#### Get all Fine Grained Password Policies

```powershell
Get-ADFineGrainedPasswordPolicy -filter *
```

#### Get Domain Default Password Policy

Gets the password policy from the logged in domain

```powershell
Get-ADDefaultDomainPasswordPolicy
```

#### Backup Active Directory System State Remotely

This will back up the domain controllers system state data. Change DC-Name to your server name and change the Backup-Path. The backup path can be a local disk or a UNC path

```powershell
Invoke-Command -ComputerName $DC_Name -scriptblock {wbadmin start systemstateback up -backupTarget:"Backup-Path" -quiet}
```

### AD User Enumeration

**Get User and List All Properties (attributes)**

For the variable `$username` use the `samAccountName` of the account

```powershell
Get-ADUser $username -Properties *
```

**Get User and list only specific properties**

```powershell
Get-ADUser $username -Properties * | Select name, department, title
```

#### Find a specific string in a certain user's attribute

```powershell
Get-ADUser -Filter 'Description -like "*pass*"' -Properties Description | select Name, Description
```

#### Get All Active Directory Users in Domain

```powershell
Get-ADUser -Filter *
```

#### Get All Users From a Specific OU

OU = Full distinguished path of the OU

```powershell
Get-ADUser -SearchBase “OU=Domain Users,dc=test,dc=local” -Filter *
```

#### Get AD Users by Name

This command will find all users that have the word bob in the name.

```powershell
Get-Aduser -Filter {name -like "*bob*"}
```

#### Get All Disable User Accounts

```powershell
Search-ADAccount -AccountDisabled | select name
```

#### Disable User Account

```powershell
Disable-ADAccount -Identity $UserName
```

#### Enable User Account

```powershell
Enable-ADAccount -Identity $UserName
```

#### Get All Accounts with Password Set to Never Expire

```powershell
Get-Aduser -filter * -properties Name, PasswordNeverExpires | where {$_.passwordNeverExpires -eq "true" } | Select-Object DistinguishedName,Name,Enabled
```

#### Find All Locked User Accounts

```powershell
Search-ADAccount -LockedOut
```

#### Unlock User Account

```powershell
Unlock-ADAccount –Identity $UserName
```

#### List all Disabled User Accounts

```powershell
Search-ADAccount -AccountDisabled
```

#### Force Password Change at Next Login

```powershell
Set-ADUser -Identity $UserName -ChangePasswordAtLogon $true
```

#### Move a Single User to a New OU

You will need the distinguishedName of the user and the target OU

```powershell
Move-ADObject -Identity "CN=bob,OU=Users,DC=ad,DC=test,DC=local" -TargetPath "OU=HR,OU=Users,DC=ad,DC=ad,DC=com"
```

#### Move Users from one OU to another using a CSV file

Create a csv with a `name` field containing a list of the users `SamAccountName`'s. Then just change the target OU path to move the users.

```powershell
# Specify target OU. 
$TargetOU = "OU=HR,OU=Users,DC=ad,DC=test,DC=local"

# Read user SAMAccountNames from csv file (field labeled "Name"). 
Import-Csv -Path $csvFile | ForEach-Object { 

  # Retrieve the distinguishedName of the User. 
  $UserDN = (Get-ADUser -Identity $_.Name).distinguishedName 

  # Move user to target OU. 
  Move-ADObject -Identity $UserDN -TargetPath $TargetOU 
}
```

### AD Group Commands

#### Get All members of a Security group

```powershell
Get-ADGroupMember -identity $GroupName
```

#### Get All Security Groups

This will list all security groups in a domain

```powershell
Get-ADGroup -filter *
```

#### Add User to Group

```powershell
Add-ADGroupMember -Identity $GroupName -Members $user1, $user2
```

#### Export Users From a Group

This will export group members to a CSV, change group-name to the group you want to export.

```powershell
Get-ADGroupMember -identity $GroupName | select name | Export-csv -Path $OutCsv -NoTypeInformation
```

#### Get Group by keyword

```powershell
Get-AdGroup -filter * | Where-Object {$_.name -like "*$GroupName*"}
```

#### Import a List of Users to a Group

```powershell
$members = Import-CSV $csvFile | Select-Object -ExpandProperty samaccountname | Add-ADGroupMember -Identity $GroupName -Members $members
```

### AD Computer Commands

#### List All Computers

```powershell
Get-AdComputer -filter *
```

#### List All Computers by Name

```powershell
Get-ADComputer -filter * | select name
```

#### Get All Computers from a specific OU

```powershell
Get-ADComputer -SearchBase "OU=$DistinguishedName" -Filter *
```

#### Get a Count of All Computers in Domain

```powershell
Get-ADComputer -filter * | measure
```

#### Get all Windows 10 Computers

```powershell
Get-ADComputer -filter {OperatingSystem -Like '*Windows 10*'} -property * | select name, operatingsystem
```

#### Get a Count of All computers by Operating System

This will provide a count of all computers and group them by the operating system. A great command to give you a quick inventory of computers in AD.

```powershell
Get-ADComputer -Filter "name -like '*'" -Properties operatingSystem | group -Property operatingSystem | Select Name,Count
```

#### Delete a single Computer

```powershell
Remove-ADComputer -Identity "$ComputerName"
```

#### Delete a List of Computer Accounts

Add the hostnames to a text file and run the command below.

```powershell
Get-Content -Path $ComputerList | Remove-ADComputer
```

#### Delete Computers From an OU

```powershell
Get-ADComputer -SearchBase "OU=$DistinguishedName" -Filter * | Remote-ADComputer
```

## Using [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon)

* **Get Current Domain:** `Get-NetDomain`
* **Enumerate other Domains:** `Get-NetDomain -Domain $DomainName`
* **Get Domain SID:** `Get-DomainSID`
*   **Get Domain Policy:**

    ```powershell
    Get-DomainPolicy

    #Will show us the policy configurations of the Domain about system access or kerberos
    (Get-DomainPolicy)."system access"
    (Get-DomainPolicy)."kerberos policy"
    ```
*   **Get Domain Controllers:**

    ```powershell
    Get-NetDomainController
    Get-NetDomainController -Domain $DomainName
    ```
*   **Enumerate Domain Users:**

    ```powershell
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
*   **Enumerate Domain Computers:**

    ```powershell
    Get-NetComputer -FullData
    Get-DomainGroup

    #Enumerate Live machines 
    Get-NetComputer -Ping
    ```
*   **Enumerate Groups and Group Members:**

    ```powershell
    Get-NetGroupMember -GroupName "$GroupName" -Domain $DomainName

    #Enumerate the members of a specified group of the domain
    Get-DomainGroup -Identity $GroupName | Select-Object -ExpandProperty Member

    #Returns all GPOs in a domain that modify local group memberships through Restricted Groups or Group Policy Preferences
    Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName
    ```
*   **Enumerate Shares**

    ```powershell
    #Enumerate Domain Shares
    Find-DomainShare

    #Enumerate Domain Shares the current user has access
    Find-DomainShare -CheckShareAccess
    ```
*   **Enumerate Group Policies:**

    ```powershell
    Get-NetGPO

    # Shows active Policy on specified machine
    Get-NetGPO -ComputerName $ComputerName
    Get-NetGPOGroup

    #Get users that are part of a Machine's local Admin group
    Find-GPOComputerAdmin -ComputerName $ComputerName
    ```
*   **Enumerate OUs:**

    ```powershell
    Get-NetOU -FullData 
    Get-NetGPO -GPOname $GPO_GUID
    ```
*   **Enumerate ACLs:**

    ```powershell
    # Returns the ACLs associated with the specified account
    Get-ObjectAcl -SamAccountName $AccountName -ResolveGUIDs
    Get-ObjectAcl -ADSprefix 'CN=Administrator, CN=Users' -Verbose

    #Search for interesting ACEs
    Invoke-ACLScanner -ResolveGUIDs

    #Check the ACLs associated with a specified path (e.g smb share)
    Get-PathAcl -Path $Share_Path
    ```
*   **Enumerate Domain Trust:**

    ```powershell
    Get-NetDomainTrust
    Get-NetDomainTrust -Domain $DomainName
    ```
*   **Enumerate Forest Trust:**

    ```powershell
    Get-NetForestDomain
    Get-NetForestDomain Forest $ForestName

    #Domains of Forest Enumeration
    Get-NetForestDomain
    Get-NetForestDomain Forest $ForestName

    #Map the Trust of the Forest
    Get-NetForestTrust
    Get-NetDomainTrust -Forest $ForestName
    ```
*   **User Hunting:**

    ```powershell
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

## Using BloodHound

```powershell
#Using .exe ingestor
.\SharpHound.exe --CollectionMethod All --LDAPUser $UserName --LDAPPass $Password --JSONFolder $OutFile_Path

#Using powershell module ingestor
.\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All  -LDAPUser $UserName -LDAPPass $Password -OutputDirectory $OutFile_Path
```

## Group Policy

#### Get all GPO related commands

```powershell
Get-Command -Module grouppolicy
```

#### Get all GPOs by status

```powershell
Get-GPO -all | select DisplayName, gpostatus
```

#### Backup all GPOs in the Domain

```powershell
Backup-Gpo -All -Path E:GPObackup
```

## Enumeration using nltest and .Net

### Get Domain Information

```
nltest /DCLIST:DomainName
nltest /DCNAME:DomainName
nltest /DSGETDC:DomainName
```

### Get Current Domain Info

```
nltest /dsgetdc:test.local

set l
```

### View Domain Forest Info

```
nltest /domain_trusts
```

### View Domain Trust Information

{% tabs %}
{% tab title="PowerShell" %}
```powershell
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

([System.DirectoryServices.ActiveDirectory.Forest]::GetForest((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', 'forest-name.local')))).GetAllTrustRelationships()
```
{% endtab %}

{% tab title="cmd.exe" %}
```
nltest /domain_trusts

nltest [server:<fqdn_foreign_domain>] /domain_trusts /all_trusts /v

nltest /dsgetfti:<domain>

nltest /server:<ip_dc> /domain_trusts /all_trusts
```
{% endtab %}
{% endtabs %}

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

### Get domain name and DC the user authenticated to

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

## Other useful AD enumeration tools

* [LDAPDomainDump](https://github.com/dirkjanm/ldapdomaindump) Information dumper via LDAP, Gathers the AD schema details.
* [adidnsdump](https://github.com/dirkjanm/adidnsdump) Integrated DNS dumping by any authenticated user
* [ACLight](https://github.com/cyberark/ACLight) Advanced Discovery of Privileged Accounts
* [ADRecon](https://github.com/sense-of-security/ADRecon) Detailed Active Directory Recon Tool
* [ADExplorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) easily navigate an AD database, save snapshots of an AD database for off-line viewing.
