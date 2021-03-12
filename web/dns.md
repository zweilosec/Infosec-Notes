# DNS

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Hosts File

Description here

{% tabs %}
{% tab title="Linux" %}
`/etc/hosts`

```text
example here
```
{% endtab %}

{% tab title="Windows" %}
`C:\Windows\System32\drivers\etc\hosts`

```text
example here
```
{% endtab %}
{% endtabs %}

## DNS Enumeration

DNS offers a variety of information about public \(and sometimes private!\) organization servers, such as IP addresses, server names, and server functionality.

### zonetransfer.me

zonetransfer.me \([https://digi.ninja/projects/zonetransferme.php](https://digi.ninja/projects/zonetransferme.php)\)

A public training site for testing and learning about DNS.  Uses the following two name servers:

* nsztm1.digi.ninja
* nsztm2.digi.ninja

You can test everything from simple `dig` queries to DNS zone transfers.

### Interacting with a DNS Server

```text
host -t ns zonetransfer.me
# -t : type , ns: dns

host -t mx zonetransfer.me           
# mx : mail server
```

* Also you can use `nslookup`

```text
nslookup zonetransfer.me
```

* `dig` also can be used

```text
dig zonetransfer.me
```

### Automating lookups

we have some initial data from the zonetransfer.me domain, we can continue to use additional DNS queries to discover more host names and IP addresses belonging to megacorpone.com.

```text
host zonetransfer.me
# we will found that it has an IP

host idontexist.zonetransfer.me
# this is not found
```

### Forward Lookup Brute Force

Taking the previous concept a step further, we can automate the Forward DNS Lookup of common host names using the host command and a Bash script.

```text
echo www > list.txt
echo ftp >> list.txt
echo mail >> list.txt
echo owa >> list.txt
echo proxy >> list.txt
echo router >> list.txt
echo api >> list.txt
for ip in $(cat list.txt);do host $ip.$domain;done
```

### Reverse Lookup Brute Force

If the DNS administrator of megacorpone.com configured PTR records for the domain, we might find out some more domain names that were missed during the forward lookup brute-force phase.

```text
for ip in $(seq 155 190);do host 50.7.67.$ip;done | grep -v "not found"
# grep -v :: --invert-match
```

### **DNS Zone Transfers**

* A zone transfer is similar to a database replication act between related DNS servers.
* This process includes the copying of the zone file from a master DNS server to a slave server.
* The zone file contains a list of all the DNS names configured for that zone. Zone transfers should usually be limited to authorized slave DNS servers.

```text
host -l megacorpone.com ns1.megacorpone.com   # ns1 refused us our zone transfer request
# -l :: list all hosts in a domain

host -l megacorpone.com ns2.megacorpone.com
# The result is a full dump of the zone file for the megacorpone.com domain,
# providing us a convenient list of IPs and DNS names for the megacorpone.com domain.
```

```text
host -t axfr zonetransfer.me nsztm1.digi.ninja
```

```text
dig axfr nsztm1.digi.ninja zonetransfer.me
```

* Now Lets automate the process:
  * To get the name servers for a given domain in a clean format, we can issue the following command.

    ```text
    host -t ns zonetransfer.me | cut -d " " -f 4
    # -d :: --delimiter=DELIM ;
    # -f ::  --fields=LIST select only these fields on each line;
    ```

  * Taking this a step further, we could write the following simple Bash script to automate the procedure of discovering and attempting a zone transfer on each DNS server found.

    ```text
    # /bin/bash
    # Simple Zone Transfer Bash Script
    # $1 is the first argument given after the bash script
    # Check if argument was given, if not, print usage
    if  [-z "$1" ]; then
    echo "[-] Simple Zone transfer script"
    echo "[-] Usage : $0 $domain_name "
    exit 0
    fi

    # if argument was given, identify the DNS servers for the domain
    for server in $(host ­-t ns $1 | cut ­-d" " ­-f4);do
    # For each of these servers, attempt a zone transfer
    host -l $1 $server | grep "has address"
    done
    ```

    Running this script on zonetransfer.me should automatically identify both name servers and attempt a zone transfer on each of them

    ```text
    > chmod 755 dns-­-axfr.sh
    > ./dns-­-axfr.sh zonetransfer.me
    ```

## Tools

### **DNSRecon**

```text
dnsrecon -d zonetransfer.me -t axfr
# -d :: domain
# -t :: type of Enumeration to perform
# axfr :: test all ns servers for zone transfer
```

### **DNSEnum**

```text
dnsenum zonetransfer.me
```

### **fierce**

{% hint style="info" %}
**NOTE:** the one included in Kali is outdated and may not work, so try using the new version from [fierce](https://github.com/mschwager/fierce)
{% endhint %}

```text
pip3 install fierce
fierce --domain zonetransfer.me
```

### DIG

```bash
dig zonetransfer.me + short
dig zonetransfer.me MX
dig zonetransfer.me NS
dig zonetransfer.me SOA
dig zonetransfer.me ANY +noall +answer
dig -x zonetransfer.me
dig zonetransfer.me mx +noall +answer zonetransfer.me ns +noall +answer

# DNS Zone Transfer
dig -t AXFR zonetransfer.me
dig axfr @10.11.1.111 zonetransfer.me

# For Ipv4
dig -4 zonetransfer.me

# For IPv6
dig -6 zonetransfer.me
```

### DNSEnum

```bash
# dnsenum
dnsenum 10.11.1.111
```

## Misc

DNS reverse lookup recon: `dnsrecon -r <ip/subnet[127.0.0.0/24]> -n <ip_to_check>`

DNS zone transfer: `dig axfr <hostname> @<ip>` or `host -l <domain> <nameserver>`

add DNS server - Linux: `/etc/resolv.conf {nameserver <ip>}`

Network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques: [https://github.com/OWASP/Amass](https://github.com/OWASP/Amass)

* NMAP DNS Hostnames Lookup

```text
nmap -F --dns-server
```

* Host Lookup

```text
host -t ns zonetransfer.me
```

* Reverse Lookup Brute Force - find domains in the same range

```text
for ip in $(seq 155 190);do host 50.7.67.$ip;done |grep -v "not found"
```

* Perform DNS IP Lookup

```text
dig a domain-name-here.com @nameserver
```

* Perform MX Record Lookup

```text
dig mx domain-name-here.com @nameserver
```

* Perform Zone Transfer with DIG

```text
dig axfr domain-name-here.com @nameserver
```

### DNS Zone Transfers

* Windows DNS zone transfer

```text
nslookup -> set type=any -> ls -d zonetransfer.me
```

* Linux DNS zone transfer

```text
dig axfr zonetransfer.me @ns1.zonetransfer.me
```

* Dnsrecon DNS Brute Force

```text
dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml
```

* Dnsrecon DNS List of megacorp

```text
dnsrecon -d zonetransfer.me -t axfr
```

* DNSEnum

```text
dnsenum zonetransfer.me
```



If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!

