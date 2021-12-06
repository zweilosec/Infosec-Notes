# Basic Enumeration

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here. &#x20;
{% endhint %}

## Host Enumeration

### Live host enumeration with cmd.exe

```bash
for /L %i in (1,1,255) do @ping -n 1 10.10.10.%i | find "TTL="
```

### Hostname enumeration with `host` (Linux)

Uses DNS reverse lookups to find hostnames for IP in a range.  In this example it will scan the subnet 10.10.10.0/24. &#x20;

```bash
for ip in $(seq 1 254); do host 10.10.10.$ip; done | grep -v "not found"
```

## Port Scanning

### Nmap

A basic bash script for doing enumeration based on a list of IPs gathered from a ping sweep of a network.

```bash
#!/bin/bash
nmap -sn -oN ip_list 192.168.1.0/24
cat ip_list | while read ip
do
nmap -sCV -p- -vvv -oA $ip.map $ip
done
```

The options I regularly use are:&#x20;

| `Flag`      | Purpose                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------- |
| `-p-`       | A shortcut which tells nmap to scan all ports                                                                               |
| `-vvv`      | Gives very verbose output so I can see the results as they are found, and also includes some information not normally shown |
| `-sC`       | Equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target                       |
| `-sV`       | Does a service version scan                                                                                                 |
| `-oA $name` | Saves all three formats (standard, greppable, and XML) of output with a filename of `$name`                                 |

### NmapAutomator

NmapAutomator by @21y4d ([https://github.com/21y4d/nmapAutomator](https://github.com/21y4d/nmapAutomator)) is a great tool for automating your basic enumeration.  I highly recommend learning how to do it manually so you know what is happening behind the scenes.  Very noisy tool.  Best for CTF-type environments and not real Red Team engagements.

### Port scanning with netcat

Not recommended to scan all ports as it will take a very long time.  Better to use this for targeted scans of a few ports, and only when better tools are not available.

#### TCP:

```bash
nc -n -vv -w 1 -z $ip 1-65535 | grep "open"
```

#### UDP:

```bash
nc -n -v -u -z -w 1 $ip 1-65535 | grep "open"
```

### Masscan

[https://github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan)

Masscan is an incredibly fast network scanner. Using this to find open ports, then sending the results to nmap to do a more thorough enumeration could speed things up.  Masscan requires `sudo` privileges to run.

```
sudo masscan -p 0-65535 10.10.10.0/24 --rate=1000
```

## SMB/Samba



## NetBIOS

```
sudo nbtscan -r 10.10.10.0/24
```

Does a NBT name scan using source port 137 (`-r`). &#x20;
