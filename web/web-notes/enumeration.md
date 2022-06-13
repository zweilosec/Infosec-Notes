# Enumeration

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

## HTTP Enumeration

### dirsearch 

[https://github.com/maurosoria/dirsearch](https://github.com/maurosoria/dirsearch)

```text
python3 dirsearch.py -e php,html,js -u https://target -w /path/to/wordlist
```

### gobuster:

```text
gobuster -w /usr/share/wordlists/dirb/common.txt -u $ip
```

### DirBuster - Http folder enumeration - can take a dictionary file

### Dirb

* Directory brute force finding using a dictionary file

```text
dirb http://$ip/ wordlist.dict

dirb <<http://vm/>>
```

* Dirb against a proxy

```text
dirb http://$ip/ -p $ip:$port
```

### Nikto

```text
nikto -h $ip
```

* Proxy Enumeration \(useful for open proxies\)

```text
nikto -useproxy http://$ip:3128 -h $ip
```

### Nmap HTTP Enumeration

```text
nmap --script=http-enum -p80 -n $ip/24
```

* Nmap Check the server methods

```text
nmap --script http-methods --script-args http-methods.url-path='/test' $ip
```

### Uniscan

 directory finder:

```text
uniscan -qweds -u <<http://vm/>>
```

### Wfuzz - The web brute forcer

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

### Misc

* Get Options available from web server

```text
  curl -vX OPTIONS vm/test
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

## 

