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

### Password Cracking

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

