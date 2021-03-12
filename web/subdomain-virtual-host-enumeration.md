# Subdomain/Virtual Host Enumeration

## Wordlists

* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056\#file-all-txt](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056#file-all-txt)

## OWASP `amass`

* [https://github.com/OWASP/Amass](https://github.com/OWASP/Amass)
* [https://medium.com/@hakluke/haklukes-guide-to-amass-how-to-use-amass-more-effectively-for-bug-bounties-7c37570b83f7](https://medium.com/@hakluke/haklukes-guide-to-amass-how-to-use-amass-more-effectively-for-bug-bounties-7c37570b83f7)

The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.

**Information Gathering Techniques:**

| Technique | Data Sources |
| :--- | :--- |
| DNS | Brute forcing, Reverse DNS sweeping, NSEC zone walking, Zone transfers, FQDN alterations/permutations, FQDN Similarity-based Guessing |
| Scraping | Ask, Baidu, Bing, BuiltWith, DNSDumpster, HackerOne, IPv4Info, RapidDNS, Riddler, SiteDossier, Yahoo |
| Certificates | Active pulls \(optional\), Censys, CertSpotter, Crtsh, FacebookCT, GoogleCT |
| APIs | AlienVault, Anubis, BinaryEdge, BGPView, BufferOver, C99, CIRCL, Cloudflare, CommonCrawl, DNSDB, GitHub, HackerTarget, Mnemonic, NetworksDB, PassiveTotal, Pastebin, RADb, ReconDev, Robtex, SecurityTrails, ShadowServer, Shodan, SonarSearch, Spyse, Sublist3rAPI, TeamCymru, ThreatBook, ThreatCrowd, ThreatMiner, Twitter, Umbrella, URLScan, VirusTotal, WhoisXML, ZETAlytics, ZoomEye |
| Web Archives | ArchiveIt, ArchiveToday, Wayback |

#### The 5 Subcommands

Amass comes with 5 different subcommands. They are `intel`, `enum`, `track`, `viz` and `db`. Their purposes are shown below, copy pasta straight from the amass docs for your convenience.

* `amass intel` — Discover targets for enumerations
* `amass enum` — Perform enumerations and network mapping
* `amass viz` — Visualize enumeration results
* `amass track` — Track differences between enumerations
* `amass db` — Manipulate the Amass graph database

#### SSL Certificate Grabbing

If you feed IP addresses to Amass and give it the `-active` flag, it pulls the SSL certificate from every IP address within the IP range and then spits back the domain that the SSL cert is associated with.

#### Basic examples:

```bash
amass enum -passive -d $domain -o $out_txt

# Active enumeration uses DNS resolution - can take a long time
amass enum -active -brute -w $wordlist -d $domain -o $out_txt

# Amass get company ASN and scan
# might want to verify ASNs manually before automating to reduce errors
amass intel -org $org_name -max-dns-queries 2500 > asn.txt
cat asn.txt | awk -F, '{print $1}' ORS=',' | sed 's/,$//' | xargs -P3 -I@ -d ',' amass intel -asn @ -max-dns-queries 2500''

# Use SSL certificate grabbing to enumerate domains
amass intel -active -cidr $ip/$cidr
```

#### Tracking

Every scan that you do with `amass` is automatically stored on the computer that you ran it on.  If you run the same scan again, `amass` will track any changes that have taken place since your last scan. The most obvious way to use this feature is to discover which subdomains have appeared since your last scan. For example, if you run `amass enum -d $domain` one month, then run it again on the same domain again the following month, you can run `amass track -d $domain` and it will tell you anything that has changed between the two runs.

## gobuster

* [https://github.com/OJ/gobuster](https://github.com/OJ/gobuster)

TODO: Add examples, link to relevant Hack the Box writeups

#### Available Modes

* **`dir`** - the classic directory brute-forcing mode
* **`dns`** - DNS subdomain brute-forcing mode
* **`s3`** - Enumerate open S3 buckets and look for existence and bucket listings
* **`vhost`** - virtual host brute-forcing mode \(not the same as DNS!\)

#### Wordlists via STDIN

Wordlists can be piped into `gobuster` via stdin by providing a `-` to the `-w` option:

```text
hashcat -a 3 --stdout ?l | gobuster dir -u https://mysite.com -w -
```

Note: If the `-w` option is specified at the same time as piping from STDIN, an error will be shown and the program will terminate.

#### Patterns

You can supply pattern files that will be applied to every word from the wordlist. Just place the string `{GOBUSTER}` in it and this will be replaced with the word. This feature is also handy in s3 mode to pre- or postfix certain patterns.

{% hint style="warning" %}
**Caution:** Using a big pattern file can cause a lot of request as every pattern is applied to every word in the wordlist.
{% endhint %}

#### Example file:

```text
{GOBUSTER}Partial
{GOBUSTER}Service
PRE{GOBUSTER}POST
{GOBUSTER}-prod
{GOBUSTER}-dev
```

## Burp

While navigating through target website with Burp try each of these in order of increasing noisiness:

1. Without passive scanner
2. Set forms to auto submit
3. Change Scope in Advanced settings, any protocol and one relevant keyword
4. Select all sitemap, Engagement Tools -&gt; Analyze target

## dnsrecon

* [https://github.com/darkoperator/dnsrecon](https://github.com/darkoperator/dnsrecon)

```bash
dnsrecon -d $domain -D $wordlist -t brt
```

## fierce

* [https://github.com/mschwager/fierce](https://github.com/mschwager/fierce)

```bash
fierce --domain $domain
```

## Misc

TODO: Test each tool, get links, and add usage examples

```bash
assetfinder example.com

subfinder -d example.com  -recursive -silent -t 200 -v -o  example.com.subs
subfinder -d target.com -silent | httpx -follow-redirects -status-code -vhost -threads 300 -silent | sort -u | grep “[200]” | cut -d [ -f1 > resolved.txt

knockpy domain.com

# https://github.com/nsonaniya2010/SubDomainizer
python3 SubDomainizer.py -u https://url.com

python3 domained.py -d example.com --quick

# Subdomains from Wayback Machine
gau -subs example.com | cut -d / -f 3 | sort -u

# AltDNS - Subdomains of subdomains XD
altdns -i subdomains.txt -o data_output -w words.txt -r -s results_output.txt

# One-liner to find (sub)domains related to a keyword on pastebin through google
# https://github.com/gwen001/pentest-tools/blob/master/google-search.py
google-search.py -t "site:http://pastebin.com $keyword" -b -d -s 0 -e 5 | sed "s/\.com\//\.com\/raw\//" | xargs curl -s | egrep -ho "[a-zA-Z0-9_\.\-]+kword[a-zA-Z0-9_\.\-]+" | sort -fu

dnsrecon -d example.com -D subdomains-top1mil-5000.txt -t brt

# Wildcard subdomain
dig a *.domain.com = dig a asdasdasd132123123213.domain.com # this is a wildcard subdomain

# Subdomain enumeration from GitHub
# https://github.com/gwen001/github-search
python3 github-subdomains.py -t "GITHUB-TOKEN" -d example.com

# Get url from JS files
# https://github.com/Threezh1/JSFinder
python JSFinder.py -u http://www.target.com

# https://github.com/Screetsec/Sudomy
./sudomy -d example.com

# https://github.com/cihanmehmet/sub.sh
bash ./sub.sh -a example.com
```



## Validate discovered subdomains

### [Aquatone](https://github.com/michenriksen/aquatone)

Use `aquatone` to validate subdomains by taking screenshots and generating a report of findings.  Best used with Chromium browser.  Creates the following files and folders in the current directory:

* **aquatone\_report.html**: An HTML report to open in a browser that displays all the collected screenshots and response headers clustered by similarity.
* **aquatone\_urls.txt**: A file containing all responsive URLs. Useful for feeding into other tools.
* **aquatone\_session.json**: A file containing statistics and page data. Useful for automation.
* **headers/**: A folder with files containing raw response headers from processed targets
* **html/**: A folder with files containing the raw response bodies from processed targets. If you are processing a large amount of hosts, and don't need this for further analysis, you can disable this with the `-save-body=false` flag to save some disk space.
* **screenshots/**: A folder with PNG screenshots of the processed targets

```bash
cat targets.txt | aquatone
```

#### Specify output directory

Can send output to a specified directory with the `-out $directory` argument.

#### Specify ports to scan

By default, `aquatone` will scan target hosts with a small list of commonly used HTTP ports: 80, 443, 8000, 8080 and 8443. You can change this to your own list of ports with the `-ports` flag:

```text
cat targets.txt | aquatone -ports 80,443,3000,3001
```

`aquatone` also supports aliases of built-in port lists to make it easier for you:

* **small**: 80, 443
* **medium**: 80, 443, 8000, 8080, 8443 \(same as default\)
* **large**: 80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 8000, 8001, 8008, 8080, 8083, 8443, 8834, 8888
* **xlarge**: 80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9981, 12443, 16080, 18091, 18092, 20720, 28017

```text
cat targets.txt | aquatone -ports large
```

#### Import results from **Nmap or Masscan**

`aquatone` can make a report on hosts scanned with the [Nmap](https://nmap.org/) or [Masscan](https://github.com/robertdavidgraham/masscan) port scanners. Simply feed `aquatone` the XML output and give it the `-nmap` flag to tell it to parse the input as `Nmap/Masscan` XML:

```text
nmap $ip -oX scan
cat scan.xml | aquatone -nmap
```

