# Cracking the Hashes

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Password Hashes

### Identifying Hashes

```bash
MD5 = 32 hex characters
SHA-1 = 40 hex characters
SHA-256 = 64 hex characters
SHA-512 = 128 hex characters
```

Find the type of hash:

```text
hash-identifier
```

* Find hash type at [https://hashkiller.co.uk](https://hashkiller.co.uk)

Running `john` with no parameters will attempt to tell you the hash type:

```text
john $hash_list
```

### Hash Cracking

#### Hashcat basic syntax:

```text
hashcat -m $hash_type -a $mode -o $out_file $hash_file $pass_list
```

#### John the Ripper basic syntax:

```text
john --wordlist=$pass_list --format $hash_format $hash_list
```

#### Convert hashes from `/etc/shadow`to a crackable format \(then use john to crack\):

```text
unshadow $etc_password $etc_shadow > $unshadowed_outfile
```

#### Generating wordlists

```text
crunch

#hashcat can make a huge variety of different passwords using many 
#different mangling rules or masks

hashcat --outfile > $hash_file 
```

#### Online rainbow tables:

* https://crackstation.net/
* http://www.cmd5.org/
* https://hashkiller.co.uk/md5-decrypter.aspx
* https://www.onlinehashcrack.com/
* http://rainbowtables.it64.com/
* http://www.md5online.org

## Hashcat Cheatsheet <a id="hashcat-cheatsheet"></a>

Hashcat Cheatsheet for OSCP [https://hashcat.net/wiki/doku.php?id=hashcat](https://hashcat.net/wiki/doku.php?id=hashcat)​

### Identify Hashes <a id="identify-hashes"></a>

`hash-identifier`

Example Hashes: [https://hashcat.net/wiki/doku.php?id=example\_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)​

#### MOAR POWAR!

I have found that I can squeeze some more power out of my hash cracking by adding these parameters:

```text
--force -O -w 4 --opencl-device-types 1,2
```

These will force Hashcat to use the CUDA GPU interface which is buggy but provides more performance \(–force\) , will Optimize for 32 characters or less passwords \(-O\) and will set the workload to "Insane" \(-w 4\) which is supposed to make your computer effectively unusable during the cracking process. Finally "--opencl-device-types 1,2 " will force HashCat to use BOTH the GPU and the CPU to handle the cracking.

### Using a dictionary <a id="using-hashcat-and-a-dictionary"></a>

Hashcat example: cracking Linux md5crypt passwords \(identified by $1$\) using a wordlist:

`hashcat --force -m 500 -a 0 -o $out_cracked_passes $hash_file $pass_list`

Hashcat example cracking WordPress passwords using a wordlist: `hashcat --force -m 400 -a 0 -o $out_cracked_passes $hash_file $pass_list`

Sample Hashes [http://openwall.info/wiki/john/sample-hashes](http://openwall.info/wiki/john/sample-hashes)​

### One Rule to Rule Them All <a id="hashcat-one-rule-to-rule-them-all"></a>

@NotSoSecure has built a custom rule that combines many of the most popular Hashcat rules: [https://www.notsosecure.com/one-rule-to-rule-them-all/](https://www.notsosecure.com/one-rule-to-rule-them-all/) 

The rule can be downloaded from GitHub: [https://github.com/NotSoSecure/password\_cracking\_rules](https://github.com/NotSoSecure/password_cracking_rules)​

Put the `OneRuleToRuleThemAll.rule` file into the `/usr/share/hashcat/rules/` folder and run it:

```text
hashcat -D1,2 -O --force -m300 --status -w3 -o $out_cracked_passes -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule $hash $pass_list
```

### Using Hashcat for brute-forcing <a id="using-hashcat-bruteforcing"></a>

Predefined character sets:

```text
?l = abcdefghijklmnopqrstuvwxyz
?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
?d = 0123456789
?s = «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
?a = ?l?u?d?s
?b = 0x00 - 0xff
```

?u?l?d is the same as: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789

Brute-force all passwords of length 1-8 with these possible characters: A-Z a-z 0-9 `hashcat -m 500 $hash_file -a 3 --increment -1 ?l?d?u ?1?1?1?1?1?1?1?1`

### Cracking Linux Hashes from `/etc/shadow` file <a id="cracking-linux-hashes-etc-shadow-file"></a>

| ID | Description | Type |
| :--- | :--- | :--- |
| 500 | md5crypt $1$, MD5\(Unix\) | Operating-Systems |
| 200 | bcrypt $2\*$, Blowfish\(Unix\) | Operating-Systems |
| 400 | sha256crypt $5$, SHA256\(Unix\) | Operating-Systems |
| 1800 | sha512crypt $6$, SHA512\(Unix\) | Operating-Systems |

### Cracking Windows Hashes <a id="cracking-windows-hashes"></a>

| ID | Description | Type |
| :--- | :--- | :--- |
| 3000 | LM | Operating-Systems |
| 1000 | NTLM | Operating-Systems |

### Cracking Common Application Hashes <a id="cracking-common-application-hashes"></a>

| ID | Description | Type |
| :--- | :--- | :--- |
| 900 | MD4 | Raw Hash |
| 0 | MD5 | Raw Hash |
| 5100 | Half MD5 | Raw Hash |
| 100 | SHA1 | Raw Hash |
| 10800 | SHA-384 | Raw Hash |
| 1400 | SHA-256 | Raw Hash |
| 1700 | SHA-512 | Raw Hash |

### Cracking Common File Password Protections <a id="cracking-common-file-password-protections"></a>

| ID | Description | Type |
| :--- | :--- | :--- |
| 11600 | 7-Zip | Archives |
| 12500 | RAR3-hp | Archives |
| 13000 | RAR5 | Archives |
| 13200 | AxCrypt | Archives |
| 13300 | AxCrypt in-memory SHA1 | Archives |
| 13600 | WinZip | Archives |
| 9700 | MS Office &lt;= 2003 $0/$1, MD5 + RC4 | Documents |
| 9710 | MS Office &lt;= 2003 $0/$1, MD5 + RC4, collider \#1 | Documents |
| 9720 | MS Office &lt;= 2003 $0/$1, MD5 + RC4, collider \#2 | Documents |
| 9800 | MS Office &lt;= 2003 $3/$4, SHA1 + RC4 | Documents |
| 9810 | MS Office &lt;= 2003 $3, SHA1 + RC4, collider \#1 | Documents |
| 9820 | MS Office &lt;= 2003 $3, SHA1 + RC4, collider \#2 | Documents |
| 9400 | MS Office 2007 | Documents |
| 9500 | MS Office 2010 | Documents |
| 9600 | MS Office 2013 | Documents |
| 10400 | PDF 1.1 - 1.3 \(Acrobat 2 - 4\) | Documents |
| 10410 | PDF 1.1 - 1.3 \(Acrobat 2 - 4\), collider \#1 | Documents |
| 10420 | PDF 1.1 - 1.3 \(Acrobat 2 - 4\), collider \#2 | Documents |
| 10500 | PDF 1.4 - 1.6 \(Acrobat 5 - 8\) | Documents |
| 10600 | PDF 1.7 Level 3 \(Acrobat 9\) | Documents |
| 10700 | PDF 1.7 Level 8 \(Acrobat 10 - 11\) | Documents |
| 16200 | Apple Secure Notes | Documents |

### Cracking Commmon Database Hash Formats <a id="cracking-commmon-database-hash-formats"></a>

| ID | Description | Type | Example Hash |
| :--- | :--- | :--- | :--- |
| 12 | PostgreSQL | Database Server | a6343a68d964ca596d9752250d54bb8a:postgres |
| 131 | MSSQL \(2000\) | Database Server | 0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578 |
| 132 | MSSQL \(2005\) | Database Server | 0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe |
| 1731 | MSSQL \(2012, 2014\) | Database Server | 0x02000102030434ea1b17802fd95ea6316bd61d2c94622ca3812793e8fb1672487b5c904a45a31b2ab4a78890d563d2fcf5663e46fe797d71550494be50cf4915d3f4d55ec375 |
| 200 | MySQL323 | Database Server | 7196759210defdc0 |
| 300 | MySQL4.1/MySQL5 | Database Server | fcf7c1b8749cf99d88e5f34271d636178fb5d130 |
| 3100 | Oracle H: Type \(Oracle 7+\) | Database Server | 7A963A529D2E3229:3682427524 |
| 112 | Oracle S: Type \(Oracle 11+\) | Database Server | ac5f1e62d21fd0529428b84d42e8955b04966703:38445748184477378130 |
| 12300 | Oracle T: Type \(Oracle 12+\) | Database Server | 78281A9C0CF626BD05EFC4F41B515B61D6C4D95A250CD4A605CA0EF97168D670EBCB5673B6F5A2FB9CC4E0C0101E659C0C4E3B9B3BEDA846CD15508E88685A2334141655046766111066420254008225 |
| 8000 | Sybase ASE | Database Server | 0xc00778168388631428230545ed2c976790af96768afa0806fe6c0da3b28f3e132137eac56f9bad027ea2 |

### Cracking NTLM hashes <a id="cracking-ntlm-hashes"></a>

After grabbing or dumping the `NTDS.dit` and `SYSTEM` registry hive or dumping LSASS memory from a Windows machine:

| Path | Description |
| :--- | :--- |
| C:\Windows\NTDS\ntds.dit | Active Directory database |
| C:\Windows\System32\config\SYSTEM | Registry hive containing the key used to encrypt hashes |

Using `Impacket` to dump the hashes:

```text
impacket-secretsdump -system SYSTEM -ntds ntds.dit -hashes lmhash:nthash LOCAL -outputfile ntlm-extract
```

You can crack the NTLM hash dump usign the following hashcat syntax:

```text
hashcat -m 1000 -a 0 -w 4 --force --opencl-device-types 1,2 -O $hash_file $pass_list -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule
```

### Cracking KRB5TGS Hashes - "Kerberoasting"  <a id="cracking-hashes-from-kerboroasting-krb-5-tgs"></a>

A service principal name \(SPN\) is a unique identifier of a service instance. SPNs are used by Kerberos authentication to associate a service instance with a service logon account. This allows a client application to request that the service authenticate an account even if the client does not have the account name.  These SPNs cat be collected by using a username list and Impacket's example scripts. After gathering a list of valid usernames that have the property ‘Do not require Kerberos pre-authentication’ set \(UF\_DONT\_REQUIRE\_PREAUTH\), you can get the SPN hash for cracking, replay, or creating of Kerberos tickets using the example below.

```bash
python GetNPUsers.py -dc-ip $DC_IP $DOMAIN/ -usersfile $users_list -format hashcat -outputfile $out_hash_list
```



```bash
python GetUserSPNs.py -request -dc-ip $DC_IP $DOMAIN/$valid_user
```

Hashcat supports multiple versions of the KRB5TGS hash which can easily be identified by the number between the dollar signs in the hash itself.

* 13100 - Type 23 - $krb5tgs$23$
* 19600 - Type 17 - $krb5tgs$17$
* 19700 - Type 18 - $krb5tgs$18$

KRB5TGS Type 23 - Crackstation humans only word list with OneRuleToRuleThemAll mutations rule list.

```text
hashcat64 -m 13100 -a 0 -w 4 --force --opencl-device-types 1,2 -O d:\krb5tgs.hash d:\WORDLISTS\realhuman_phill.txt -r OneRuleToRuleThemAll.rule	
```

### To crack Linux hashes with John you must first `unshadow` them <a id="to-crack-linux-hashes-you-must-first-unshadow-them"></a>

```bash
unshadow $passwd $shadow > unshadowed.txt
```

### Crack a zip password <a id="crack-a-zip-password"></a>

`zip2john Zipfile.zip | cut -d ':' -f 2 > hashes.txt` `hashcat -a 0 -m 13600 hashes.txt /usr/share/wordlists/rockyou.txt`

Hashcat appears to have issues with some zip hash formats generated from zip2john. You can fix this by editing the zip hash contents to align with the example zip hash format found on the hash cat example page: `$zip2$*0*3*0*b5d2b7bf57ad5e86a55c400509c672bd*d218*0**ca3d736d03a34165cfa9*$/zip2$`

John seems to accept a wider range of zip formats for cracking.

John the ripper: `john --wordlist=/usr/share/wordlists/rockyou.txt <hash_file>`

[Jumbo John](https://github.com/magnumripper/JohnTheRipper) = Better than original `john`

[Hashes.org](https://hashes.org/): large database of pre-cracked hashes

Many password lists to download at [skullsecurity](https://wiki.skullsecurity.org/Passwords)

21.1GB wordlist of passwords! \(Smaller samples available too\) [https://md5decrypt.net/en/Password-cracking-wordlist-download/](https://md5decrypt.net/en/Password-cracking-wordlist-download/)

Hash formats list for [hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)

#### Brute-force crack password with known format:

```bash
hashcat -m <1600 (hashtype)> <hash.txt> --force -a 3 -1 <char_set> ?1?1?1?1?1?1?1?1 -O
[?1 = use 1 char from '1' set] 5KFB6
```

#### Create wordlist of 'words' with known character-set & length:

```bash
crunch <8 (min_length)> <8 (max_length)> <aefhrt (char_set)> > wordlist.txt
```

#### Generate password for insertion directly into `/etc/passwd` \(assumes write privilege to that file\):

```bash
openssl passwd -l [or 1?] -salt <any_salt_value> <password> 
<username>:<generated_pass>:0:0:root:/root:/bin/bash #enter into /etc/passwd like this
```

## Custom Code Examples

### Decrypt LDAP Passwords

[https://dotnetfiddle.net/2RDoWz](https://dotnetfiddle.net/2RDoWz)

```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
					
public class Program
{
	public static void Main()
	{
	  //Change these three variables to decode your own; need a key and IV to decode!
		string ciphertext = "BQO5l5Kj9MdErXx6Q6AGOw==";
		string key = "c4scadek3y654321";
		string iv = "1tdyjCbY1Ix49842";
		
		string plaintext = string.Empty;
		plaintext = DecryptString(ciphertext, key, iv);
		Console.WriteLine(plaintext);
	}
	
	public static string DecryptString(string EncryptedString, string Key, string iv)
    {
      byte[] buffer = Convert.FromBase64String(EncryptedString);
      Aes aes = Aes.Create();
      ((SymmetricAlgorithm) aes).KeySize = 128;
      ((SymmetricAlgorithm) aes).BlockSize = 128;
      ((SymmetricAlgorithm) aes).IV = Encoding.UTF8.GetBytes(iv);
      ((SymmetricAlgorithm) aes).Mode = CipherMode.CBC;
      ((SymmetricAlgorithm) aes).Key = Encoding.UTF8.GetBytes(Key);
      using (MemoryStream memoryStream = new MemoryStream(buffer))
      {
        using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, ((SymmetricAlgorithm) aes).CreateDecryptor(), CryptoStreamMode.Read))
        {
          byte[] numArray = new byte[checked (buffer.Length - 1 + 1)]; //not sure why this has -1+1 here, example works without it though...
          cryptoStream.Read(numArray, 0, numArray.Length);
          return Encoding.UTF8.GetString(numArray);
        }
      }
    }
}
```

Decodes to: `w3lc0meFr31nd`



If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!

