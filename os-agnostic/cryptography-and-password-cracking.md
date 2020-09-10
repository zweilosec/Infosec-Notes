# Cryptography & Password Cracking

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Encryption/Decryption

[CyberChef](https://gchq.github.io/CyberChef/): Website for encryption/decryption of many different types at same time

good cipher tools: [http://rumkin.com/](http://rumkin.com/)

one time pad: `pt - ct = key`

decrypt rsa private key: `openssl rsautl -decrypt -inkey <key_file> < <pass.crypt (hex file?encrypted contents of pub key?)>`

* [Ippsec:HacktheBox - Charon](https://www.youtube.com/watch?v=_csbKuOlmdE)

`hydra -e nsr` - additional checks, "n" for null password, "s" try login as pass, "r" try the reverse login as pass

## Password Cracking

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

## WordList Manipulation

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

### Generate Random Passwords with urandom

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

### Generate wordlists from your file-names

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

## Faster filtering with the silver searcher

https://github.com/ggreer/the\_silver\_searcher

For faster searching, use all the above grep regular expressions with the command `ag`.

## Cryptography

{% embed url="https://pequalsnp-team.github.io/cheatsheet/crypto-101" %}

## Ciphers

[https://www.boxentriq.com/code-breaking](https://www.boxentriq.com/code-breaking) &lt;-- useful site which can help identify type of cipher. 

[https://www.dcode.fr](https://www.dcode.fr) &lt;-- one of the best sites I have found with many decoders for many types of ciphers.

[Cyber Chef](https://gchq.github.io/CyberChef/) &lt;-- very useful for chained ciphers which require different steps to solve. Can decrypt certificates.

### Fernet

Fernet \(symmetric encryption\) - **looks like base64** but decodes to garbage, in two parts. First part \(32 bytes\) is the key. Uses 128-bit AES in CBC mode and PKCS7 padding, with HMAC using SHA256 for authentication. IV is created from `os.random()`.

Decode fernet @ [https://asecuritysite.com/encryption/ferdecode](https://asecuritysite.com/encryption/ferdecode) &lt;-- Will also give the IV and timestamp \(could be useful!\) more info about this @ [https://cryptography.io/en/latest/fernet](https://cryptography.io/en/latest/fernet)

```python
from cryptography.fernet import Fernet

key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(b"this is my key")
print('the key is ' + key + '/nThe cipher text is ' + token)
==========decrypt
from cryptography.fernet import Fernet
key = 'input key here'
f = Fernet(key)
token = 'cipher text here'
print(f.decrypt(token))
```

### Malbolge

Esoteric inferno encryption. Used in some CTF challenges. Malbolge programming language - **text from base64 looks like random text**, but complete garbage \(much of it unprintable.\) . Read for at [https://en.wikipedia.org/wiki/Malbolge](https://en.wikipedia.org/wiki/Malbolge) and [https://www.tutorialspoint.com/execute\_malbolge\_online.php](https://www.tutorialspoint.com/execute_malbolge_online.php)

## Test for Plaintext Output from a \(Python\) Script

```python
#checks the output from crypto and sees if at least 60% is ascii letters and returns true for possible plaintext
def is_plaintext(ptext):
    num_letters = sum(map(lambda x : 1 if x in string.ascii_letters else 0, ptext))
    if num_letters / len(ptext) >= .6:
      return True
```

## Digital Certificates

X.509

[https://8gwifi.org/PemParserFunctions.jsp](https://8gwifi.org/PemParserFunctions.jsp) -- extract information from various digital certificates

