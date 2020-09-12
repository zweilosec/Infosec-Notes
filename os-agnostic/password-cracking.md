# Password Cracking

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Headings:

This page is getting to be long, so here are shortcuts to the major sections.  I may break these into separate pages later.

* [Getting the hashes](password-cracking.md#getting-the-hashes)
* [Wordlist manipulation](password-cracking.md#wordlist-manipulation)
* [Password cracking](password-cracking.md#password-cracking)

## Getting the Hashes

### Extract md5 hashes

`# egrep -oE '(^|[^a-fA-F0-9])[a-fA-F0-9]{32}([^a-fA-F0-9]|$)' *.txt | egrep -o '[a-fA-F0-9]{32}' > md5-hashes.txt`

An alternative could be with sed

`# sed -rn 's/.*[^a-fA-F0-9]([a-fA-F0-9]{32})[^a-fA-F0-9].*/1/p' *.txt > md5-hashes`

> **Note:** The above regexes can be used for SHA1, SHA256 and other unsalted hashes represented in hex. The only thing you have to do is change the '{32}' to the corresponding length for your desired hash-type.

### Extract valid MySQL-Old hashes

`# grep -e "[0-7][0-9a-f]{7}[0-7][0-9a-f]{7}" *.txt > mysql-old-hashes.txt`

### Extract blowfish hashes

`# grep -e "$2a\$\08\$(.){75}" *.txt > blowfish-hashes.txt`

### Extract Joomla hashes

`# egrep -o "([0-9a-zA-Z]{32}):(w{16,32})" *.txt > joomla.txt`

### Extract VBulletin hashes

`# egrep -o "([0-9a-zA-Z]{32}):(S{3,32})" *.txt > vbulletin.txt`

### Extraxt phpBB3-MD5

`# egrep -o '$H$S{31}' *.txt > phpBB3-md5.txt`

### Extract Wordpress-MD5

`# egrep -o '$P$S{31}' *.txt > wordpress-md5.txt`

### Extract Drupal 7

`# egrep -o '$S$S{52}' *.txt > drupal-7.txt`

### Extract old Unix-md5

`# egrep -o '$1$w{8}S{22}' *.txt > md5-unix-old.txt`

### Extract md5-apr1

`# egrep -o '$apr1$w{8}S{22}' *.txt > md5-apr1.txt`

### Extract sha512crypt, SHA512\(Unix\)

`# egrep -o '$6$w{8}S{86}' *.txt > sha512crypt.txt`

### Extract e-mails from text files

`# grep -E -o "\b[a-zA-Z0-9.#?$*_-]+@[a-zA-Z0-9.#?$*_-]+.[a-zA-Z0-9.-]+\b" *.txt > e-mails.txt`

### Extract HTTP URLs from text files

`# grep http | grep -shoP 'http.*?[" >]' *.txt > http-urls.txt`

For extracting HTTPS, FTP and other URL format use `# grep -E '(((https|ftp|gopher)|mailto)[.:][^ >" ]*|www.[-a-z0-9.]+)[^ .,; >">):]' *.txt > urls.txt`

> **Note:** if grep returns "Binary file \(standard input\) matches" use the following approaches `# tr '[\000-\011\013-\037177-377]' '.' < *.log | grep -E "Your_Regex"` OR `# cat -v *.log | egrep -o "Your_Regex"`

### Extract Floating point numbers

`# grep -E -o "^[-+]?[0-9]*.?[0-9]+([eE][-+]?[0-9]+)?$" *.txt > floats.txt`

### Extract credit card data

Visa `# grep -E -o "4[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > visa.txt`

MasterCard `# grep -E -o "5[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > mastercard.txt`

American Express `# grep -E -o "\b3[47][0-9]{13}\b" *.txt > american-express.txt`

Diners Club `# grep -E -o "\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b" *.txt > diners.txt`

Discover `# grep -E -o "6011[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > discover.txt`

JCB `# grep -E -o "\b(?:2131|1800|35d{3})d{11}\b" *.txt > jcb.txt`

AMEX `# grep -E -o "3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}" *.txt > amex.txt`

### Extract Social Security Number \(SSN\)

`# grep -E -o "[0-9]{3}[ -]?[0-9]{2}[ -]?[0-9]{4}" *.txt > ssn.txt`

### Extract Indiana Driver License Number

`# grep -E -o "[0-9]{4}[ -]?[0-9]{2}[ -]?[0-9]{4}" *.txt > indiana-dln.txt`

### Extract US Passport Cards

`# grep -E -o "C0[0-9]{7}" *.txt > us-pass-card.txt`

### Extract US Passport Number

`# grep -E -o "[23][0-9]{8}" *.txt > us-pass-num.txt`

### Extract US Phone Numberss

`# grep -Po 'd{3}[s-_]?d{3}[s-_]?d{4}' *.txt > us-phones.txt`

### Extract ISBN Numbers

`# egrep -a -o "\bISBN(?:-1[03])?:? (?=[0-9X]{10}$|(?=(?:[0-9]+[- ]){3})[- 0-9X]{13}$|97[89][0-9]{10}$|(?=(?:[0-9]+[- ]){4})[- 0-9]{17}$)(?:97[89][- ]?)?[0-9]{1,5}[- ]?[0-9]+[- ]?[0-9]+[- ]?[0-9X]\b" *.txt > isbn.txt`

## Wordlist Manipulation

### Remove the space character with sed

`# sed -i 's/ //g' file.txt` OR `# egrep -v "^[[:space:]]*$" file.txt`

### Remove the last space character with sed

`# sed -i s/.$// file.txt`

### Sorting Wordlists by Length

`# awk '{print length, $0}' rockyou.txt | sort -n | cut -d " " -f2- > rockyou_length-list.txt`

### Convert uppercase to lowercase and the opposite

```text
# tr [A-Z] [a-z] < file.txt > lower-case.txt
# tr [a-z] [A-Z] < file.txt > upper-case.txt
```

### Remove blank lines with sed

`# sed -i '/^$/d' List.txt`

### Remove defined character with sed

`# sed -i "s/'//" file.txt`

### Delete a string with sed

`# echo 'This is a foo test' | sed -e 's/<foo>//g'`

### Replace characters with tr

`# tr '@' '#' < emails.txt` OR `# sed 's/@/#' file.txt`

### Print specific columns with awk

`# awk -F "," '{print $3}' infile.csv > outfile.csv` OR `# cut -d "," -f 3 infile.csv > outfile.csv`

> **Note:** if you want to isolate all columns after column 3 use `# cut -d "," -f 3- infile.csv > outfile.csv`

### Generate Random Passwords with /dev/urandom

```text
# tr -dc 'a-zA-Z0-9._!@#$%^&*()' < /dev/urandom | fold -w 8 | head -n 500000 > wordlist.txt
# tr -dc 'a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?=' < /dev/urandom | fold -w 12 | head -n 4
# base64 /dev/urandom | tr -d '[^:alnum:]' | cut -c1-10 | head -2
# tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 10 | head -n 4
# tr -dc 'a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?=' < /dev/urandom | fold -w 12 | head -n 4 | grep -i '[!@#$%^&*()_+{}|:<>?=]'
# tr -dc '[:print:]' < /dev/urandom | fold -w 10| head -n 10
# tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n2
```

### Remove Parenthesis with tr

`# tr -d '()' < in_file > out_file`

### Generate wordlists from your file names

`# ls -A | sed 's/regexp/& /g'`

### Process text files when cat is unable to handle strange characters

`# sed 's/([[:alnum:]]*)[[:space:]]*(.)(..*)/12/' *.txt`

### Generate length based wordlists with awk

`# awk 'length == 10' file.txt > 10-length.txt`

### Merge two different txt files

`# paste -d' ' file1.txt file2.txt > new-file.txt`

### Faster sorting

`# export alias sort='sort --parallel=<number_of_cpu_cores> -S <amount_of_memory>G ' && export LC_ALL='C' && cat file.txt | sort -u > new-file.txt`

### Mac to unix

`# tr '\015' '\012' < in_file > out_file`

### Dos to Unix

`# dos2unix file.txt`

### Unix to Dos

`# unix2dos file.txt`

### Remove from one file what is in another file

`# grep -F -v -f file1.txt -w file2.txt > file3.txt`

### Isolate specific line numbers with sed

`# sed -n '1,100p' test.file > file.out`

### Create Wordlists from PDF files

`# pdftotext file.pdf file.txt`

### Find the line number of a string inside a file

`# awk '{ print NR, $0 }' file.txt | grep "string-to-grep"`

## Password Cracking

https://github.com/frizb/

An amazing index of brute-force commands

```text
https://book.hacktricks.xyz/brute-force
```

## Hydra <a id="hydra"></a>

Below are a few scriptable examples of common protocols to brute force logins.

| Command | Description |
| :--- | :--- |
| `hydra -P $pass_list -v $ip snmp -v` | Brute force against SNMP |
| `hydra -t 1 -l $user -P $pass_list -v $ip ftp` | FTP with  known user using password list |
| `hydra -v -V -u -L $users_list -P $pass_list -t 1 -u $ip ssh` | SSH using list of users and passwords |
| `hydra -v -V -u -L $users_list -p $pass -t 1 -u $ip ssh` | SSH with a known password and a username list |
| `hydra $ip -s $port ssh -l $user -P $pass_list` | SSH with known username on non-standard port |
| `hydra -l $user -P $pass_list -f $ip pop3 -v` | POP3 Brute Force |
| `hydra -L $users_list -P $pass_list $ip http-get $login_page` | HTTP GET with user and pass list |
| `hydra -t 1 -v -f -l $user -P $pass_list rdp://$ip` | Windows Remote Desktop with pass list |
| `hydra -t 1 -V -f -l $user -P $pass_list $ip smb` | SMB brute force with known user and pass list |
| `hydra -l $user -P $pass_list $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'` | WordPress brute force an admin login |
| `hydra -v -L $users_list -p $pass $ip http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'` | WordPress enumerate users |
| `wpscan --url $url -U $user -P $pass_list` | Use wpscan to brute force password with known user |

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

  ```text
  https://crackstation.net/http://www.cmd5.org/https://hashkiller.co.uk/md5-decrypter.aspxhttps://www.onlinehashcrack.com/http://rainbowtables.it64.com/http://www.md5online.org/
  ```

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
hashcat --force -m300 --status -w3 -o $out_cracked_passes -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule $hash $pass_list
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

### Cracking Hashes from Kerboroasting - KRB5TGS <a id="cracking-hashes-from-kerboroasting-krb-5-tgs"></a>

A service principal name \(SPN\) is a unique identifier of a service instance. SPNs are used by Kerberos authentication to associate a service instance with a service logon account. This allows a client application to request that the service authenticate an account even if the client does not have the account name. KRB5TGS - Kerberoasting Service Accounts that use SPN Once you have identified a Kerberoastable service account \(Bloodhound? Powershell Empire? - likely a MS SQL Server Service Account\), any AD user can request a krb5tgs hash from it which can be used to crack the password.

Based on my benchmarking, KRB5TGS cracking is 28 times slower than NTLM.

Hashcat supports multiple versions of the KRB5TGS hash which can easily be identified by the number between the dollar signs in the hash itself.

* 13100 - Type 23 - $krb5tgs$23$
* 19600 - Type 17 - $krb5tgs$17$
* 19700 - Type 18 - $krb5tgs$18$

KRB5TGS Type 23 - Crackstation humans only word list with OneRuleToRuleThemAll mutations rule list.

```text
hashcat64 -m 13100 -a 0 -w 4 --force --opencl-device-types 1,2 -O d:\krb5tgs.hash d:\WORDLISTS\realhuman_phill.txt -r OneRuleToRuleThemAll.rule	
```

_Benchmark using a Nvidia 2060 GTX:_ Speed: 250 MH/s Elapsed Time: 9 Minutes

### To crack linux hashes you must first unshadow them <a id="to-crack-linux-hashes-you-must-first-unshadow-them"></a>

`unshadow passwd-file.txt shadow-file.txt`

`unshadow passwd-file.txt shadow-file.txt > unshadowed.txt`

### Crack a zip password <a id="crack-a-zip-password"></a>

`zip2john Zipfile.zip | cut -d ':' -f 2 > hashes.txt` `hashcat -a 0 -m 13600 hashes.txt /usr/share/wordlists/rockyou.txt`

Hashcat appears to have issues with some zip hash formats generated from zip2john. You can fix this by editing the zip hash contents to align with the example zip hash format found on the hash cat 5KFB6 example page: `$zip2$*0*3*0*b5d2b7bf57ad5e86a55c400509c672bd*d218*0**ca3d736d03a34165cfa9*$/zip2$`

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

### 

## Faster filtering with the silver searcher

https://github.com/ggreer/the\_silver\_searcher

For faster searching, use all the above grep regular expressions with the command `ag`.

## Resources

* [https://www.unix-ninja.com/p/A\_cheat-sheet\_for\_password\_crackers](https://www.unix-ninja.com/p/A_cheat-sheet_for_password_crackers)
* [https://guide.offsecnewbie.com/password-cracking](https://guide.offsecnewbie.com/password-cracking)

