---
description: >-
  Misc notes that still need to be sorted through and sent to their proper
  homes.
---

# Unsorted

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Markdown

```text
{% hint style="warning" %} Warning box. Looks nice! {% endhint %}
```

{% hint style="danger" %}
Text between these will show up in a warning box. Looks nice! 

_Can click on the icon to change it to something appropriate \( Changes style, I think. Gitbook only?\)._
{% endhint %}

[https://8gwifi.org/PemParserFunctions.jsp](https://8gwifi.org/PemParserFunctions.jsp) &lt;--extract information from various digital certificates

locate all files that symlink to this\_file: `find -L / -samefile path/to/<this_file>`

PHP [https://www.php.net/manual/en/features.commandline.webserver.php](https://www.php.net/manual/en/features.commandline.webserver.php) When starting php -S on a mac \(in my case macOS Sierra\) to host a local server, I had trouble with connecting from legacy Java. As it turned out, if you started the php server with `php -S localhost:80` the server will be started with ipv6 support only! To access it via ipv4, you need to change the start up command like so: `php -S 127.0.0.1:80` which starts server in ipv4 mode only.

It’s not mentioned directly, and may not be obvious, but you can also use this to create a virtual host. This, of course, requires the help of your hosts file. Here are the steps:

```text
1    /etc/hosts
    127.0.0.1    www.example.com
2    cd [root folder]
    php -S www.example.com:8000
3    Browser:
    http://www.example.com:8000/index.php
```

In order to set project specific configuration options, simply add a php.ini file to your project, and then run the built-in server with this flag: `php -S localhost:8000 -c php.ini`

Example \#6 Accessing the CLI Web Server From Remote Machines You can make the web server accessible on port 8000 to any interface with: `$ php -S 0.0.0.0:8000`

Example \#2 Starting with a specific document root directory

```text
$ cd ~/public_html
$ php -S localhost:8000 -t foo/
Listening on localhost:8000
Document root is /home/me/public_html/foo
```

SSH Keys

```text
AWS will NOT accept this file.
You have to strip off the -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY----- from the file. Save it and import and it should work in AWS.
```

and if you need to convert this format to ssh-rsa AAAAB3NzaC1y.... run : `ssh-keygen -f PublicKey.pub -i -mPKCS8`

For those interested in the details - you can see what's inside the public key file \(generated as explained above\), by doing this:- \`\`\`openssl rsa -noout -text -inform PEM -in key.pub -pubin or for the private key file, this:- openssl rsa -noout -text -in key.private which outputs as text on the console the actual components of the key \(modulus, exponents, primes, ...\)

````` extract public key from private key:```openssl rsa -in privkey.pem -pubout -out key.pub\`

Powershell wget [http://blog.stackexchange.com/](http://blog.stackexchange.com/) -OutFile out.html wget is an alias for Invoke-WebRequest

Windows enumeration: whoami /all net use z: \\ tasklist /v \(verbose\) netstat -an Get-WmiObject -class Win32\_UserAccount \[-filter "LocalAccount=True"\]

./winpeas.exe cmd

aquatone ?? - pulls up series of websites and takes screenshots

Ciphers [https://www.boxentriq.com/code-breaking](https://www.boxentriq.com/code-breaking) &lt;-- useful site which can help identiry type of cipher. [https://www.dcode.fr](https://www.dcode.fr) &lt;-- one of the best sites I have found with many decoders for many types of ciphers. github Cyber Chef &lt;-- very useful for chained ciphers which require different steps to solve, can be limited. can decrypt certificates Fernet \(symmetric encryption\) - looks like base64 but decodes to garbage, in two parts. first part \(32 bytes\) is the key. Uses 128-bit AES in CBC mode and PKCS7 padding, with HMAC using SHA256 for authentication. IV is created from os.random\(\).

> decode fernet @ [https://asecuritysite.com/encryption/ferdecode](https://asecuritysite.com/encryption/ferdecode) &lt;-- Will also give the IV and timestamp \(could be useful!\) more info about this @ [https://cryptography.io/en/latest/fernet](https://cryptography.io/en/latest/fernet) python from cryptography.fernet import Fernet key = Fernet.generate\_key\(\) f = Fernet\(key\) token = f.encrypt\(b"this is my key"\) print\('the key is ' + key + '/nThe cipher text is ' + token\) ==========decrypt from cryptography.fernet import Fernet key = 'input key here' f = Fernet\(key\) token = 'cipher text here' print\(f.decrypt\(token\)\)

esoteric inferno encryption Malbolge programming language &lt;--text from base64 looks like random text, but not complete garbage \(!unprintable\) ^[https://en.wikipedia.org/wiki/Malbolge](https://en.wikipedia.org/wiki/Malbolge) // [https://www.tutorialspoint.com/execute\_malbolge\_online.php](https://www.tutorialspoint.com/execute_malbolge_online.php)

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

## 

