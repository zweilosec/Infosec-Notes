# Basic Enumeration

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here. &#x20;
{% endhint %}

## Nmap

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

### Host enumeration with cmd

```bash
for /L %i in (1,1,255) do @ping -n 1 10.10.10.%i | find "TTL="
```
