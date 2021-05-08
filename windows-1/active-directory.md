# Active Directory

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
