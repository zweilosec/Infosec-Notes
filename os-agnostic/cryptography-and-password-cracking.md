# Cryptography & Password Cracking

## Encryption/Decryption

[CyberChef](https://gchq.github.io/CyberChef/): Website for encryption/decryption of many different types at same time

good cipher tools: [http://rumkin.com/](http://rumkin.com/)

one time pad: `pt - ct = key`

decrypt rsa private key: `openssl rsautl -decrypt -inkey <key_file> < <pass.crypt (hex file?encrypted contents of pub key?)>`

* [Ippsec:HacktheBox - Charon](https://www.youtube.com/watch?v=_csbKuOlmdE)

`hydra -e nsr` - additional checks, "n" for null password, "s" try login as pass, "r" try the reverse login as pass

### Password Cracking

[Jumbo John](https://github.com/magnumripper/JohnTheRipper) = Better than original `john`

[Hashes.org](https://hashes.org/): large database of pre-cracked hashes

Many password lists to download at [skullsecurity](https://wiki.skullsecurity.org/Passwords)

21.1GB wordlist of passwords! \(Smaller samples available too\) [https://md5decrypt.net/en/Password-cracking-wordlist-download/](https://md5decrypt.net/en/Password-cracking-wordlist-download/)

Hash formats list for [hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)

#### Brute-force crack password with known format:

```bash
hashcat -m <1600 (hashtype)> <hash.txt> --force -a 3 -1 <char_set> ?1?1?1?1?1?1?1?1 -O
[?1 = use 1 char from '1' set]
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

### Test for Plaintext Output from a \(Python\) Script

```text
#checks the output from crypto and sees if at least 60% is ascii letters and returns true for possible plaintext
def is_plaintext(ptext):
    num_letters = sum(map(lambda x : 1 if x in string.ascii_letters else 0, ptext))
    if num_letters / len(ptext) >= .6:
      return True
```
