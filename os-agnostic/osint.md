# OSINT

## OSINT Multitool

{% embed url="https://osintframework.com/" caption="Mind map of many many OSINT tools and websites" %}

## Google Account Enumeration

{% embed url="https://medium.com/week-in-osint/getting-a-grasp-on-googleids-77a8ab707e43" %}

This writeup from Sector035 gives a detailed walk through of how to get a wealth of information from a Google account such as a @gmail.com email address.  

{% hint style="danger" %}
Some of the steps for doing this require you to actually sign in to a Google account, and to add the target as a contact.  A burner account or sock puppet are recommended if you are doing this for a real engagement.
{% endhint %}

[https://developers.google.com/identity/sign-in/web/people](https://developers.google.com/identity/sign-in/web/people) [https://developers.google.com/people/api/rest/v1/people/get](https://developers.google.com/people/api/rest/v1/people/get)

## Multipurpose

* https://shodan.io/
* https://www.zoomeye.org/
* https://leakix.net/
* https://www.yougetsignal.com/
* https://intelx.io/
* https://pentest-tools.com/
* [https://osintframework.com/](https://osintframework.com/)

[RiskIQ’s Community Edition](https://www.riskiq.com/products/community-edition/) - 

> Threat Hunter
>
> * Access the most comprehensive internet data sets available to track adversaries across the internet
> * Pivot across passive DNS, WHOIS, SSL certificates, web trackers, and more
> * Enrich internal controls and logs to uncover, understand, and respond to external threats
> * Monitor threat infrastructure for changes or new, similar artifacts
>
> Threat Defender
>
> * Understand your Digital Footprint® and how you’re exposed from the outside in
> * Discover unknown assets, exposures, and vulnerabilities
> * Get alerts when your brand or trademarked terms appear in new domains and WHOIS contact information
> * View digital assets details such as domain attributes, IP address, and registrant details

 [https://censys.io/](https://censys.io/) - Attack surface enumeration

> Discover every asset in your attack surface, known or unknown.

## Domain/IP Recon

* https://domainbigdata.com/
* https://viewdns.info/
* http://bgp.he.net/
* https://rapiddns.io/
* https://dnsdumpster.com/
* https://www.whoxy.com/
*  [http://whois.domaintools.com/](http://whois.domaintools.com/)

 [https://www.robtex.com/](https://www.robtex.com/) - Good for geo-location of IP origin

> Robtex is used for various kinds of research of IP numbers, Domain names, etc
>
> Robtex uses various sources to gather public information about IP numbers, domain names, host names, Autonomous systems, routes etc. It then indexes the data in a big database and provide free access to the data.

[https://opendata.rapid7.com/sonar.fdns\_v2/](https://opendata.rapid7.com/sonar.fdns_v2/)

> Project Sonar produces a [Forward DNS](https://scans.io/study/sonar.fdns_v2) dataset every week or so. This data is created by extracting domain names from a number of sources and then sending an `ANY` query for each domain. The sources used to build the list of domains include:
>
> * Reverse DNS \(PTR\) Records
> * Common Name and SubjectAltName fields from SSL Certificates
> * HTML elements and Location headers seen in HTTP responses
> * Zone files from COM, INFO, ORG, NET, BIZ, INFO and other TLDs
> * Zone files from gTLDs
>
> The data format is a gzip-compressed JSON file, where each line of the file is a JSON document with attributes for the record name, type, value and time of resolution.

## Mail server blacklist enumerator

* http://multirbl.valli.org/

## Dark web exposure

* https://immuniweb.com/radar/

## New acquisitions

* https://crunchbase.com/

## Email

* https://hunter.io/
  * Email Domain enumeration
* [https://emkei.cz/](https://emkei.cz/)
  * Fake email sender

## Social Media

### Social media search engine

* [https://kribrum.io/](https://kribrum.io/)
  * This page is in Russian!

### Accounts registered by email

* [emailrep.io ](https://emailrep.io/)

### Enumerate usernames

* [https://whatsmyname.app/](https://whatsmyname.app/)

### Twitter

* [https://tinfoleak.com/](https://tinfoleak.com/)

### Instagram

* [https://www.searchmy.bio/](https://www.searchmy.bio/)

### Facebook

### Skype

* [https://mostwantedhf.info/](https://mostwantedhf.info/)

### Forums

* [https://boardreader.com/](https://boardreader.com/)

### Pastebin

* [https://psbdmp.ws/](https://psbdmp.ws/)

## Advanced Search

### Search with results grouped by topic

* [https://search.carrot2.org/](https://search.carrot2.org/)

### Search by Region/ Augmented keyword search

* [https://swisscows.com/](https://swisscows.com/)

### Source code search engines

* [https://publicwww.com/](https://publicwww.com/)
  * Can search by language or feature
* [https://searchcode.com/](https://searchcode.com/)
  * Search public repositories
* [https://www.shhgit.com/](https://www.shhgit.com/)
  * Searches for "secrets" inside git code repos
  * FOSS version at [https://github.com/eth0izzle/shhgit](https://github.com/eth0izzle/shhgit)

## Credential Leak Sites

{% embed url="https://haveibeenpwned.com" %}

Run by Troy Hunt, haveibeenpwned.com is one of the best for checking whether an email address has been involved in a credential breach.  

{% hint style="danger" %}
Not all of these sites below are trustworthy.  Do not enter any credentials that are in use, or you plan to use into any searches!
{% endhint %}

* https://link-base.org/index.php
* http://xjypo5vzgmo7jca6b322dnqbsdnp3amd24ybx26x5nxbusccjkm4pwid.onion/
* http://pwndb2am4tzkvold.onion
* https://weleakinfo.to/
* https://www.dehashed.com/search?query=
* https://rslookup.com
* https://leakcheck.net
* https://snusbase.com
* https://leakpeek.com
* https://breachchecker.com
* https://leak-lookup.com
* https://weleakinfo.to
* https://leakcheck.io
* http://scylla.sh
* http://scatteredsecrets.com
* https://joe.black/leakengine.html
* https://services.normshield.com/data-breach
* https://leakedsource.ru/main/ 
* https://leaked.site/ 
* https://ghostproject.fr/ 
* https://haveibeensold.app/
* https://vigilante.pw/
* https://nuclearleaks.com/
* https://hashes.org/
* https://leak.sx/
* https://leakcorp.com/login
* https://private-base.info/
* https://4iq.com/
* https://intelx.io
* https://leakprobe.net



If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!

